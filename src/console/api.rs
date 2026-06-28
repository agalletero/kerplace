//! JSON API consumed by the web console SPA.
//!
//! All endpoints (except `login`) require a valid bearer session token issued
//! by [`login`] and validated by [`require_auth`]. Operations are fulfilled
//! directly against the shared [`ObjectStore`], so the console does not need to
//! sign S3/SigV4 requests itself.

use std::collections::{BTreeMap, HashMap};

use axum::body::Body;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_util::io::ReaderStream;

use super::auth::{issue_token, now_secs, verify_token};
use crate::auth::body_to_reader;
use crate::error::S3Error;
use crate::s3::iso8601;
use crate::state::AppState;

/// Render an [`S3Error`] as a JSON error response for the console.
///
/// # Parameters
/// - `e`: the storage error.
///
/// # Returns
/// A response with the error's HTTP status and a `{error, message}` body.
fn api_err(e: S3Error) -> Response {
    (
        e.status(),
        Json(json!({ "error": e.code(), "message": e.message() })),
    )
        .into_response()
}

/// Credentials posted to [`login`].
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginReq {
    access_key: String,
    secret_key: String,
}

/// `POST /api/login` — exchange root credentials for a session token.
///
/// # Parameters
/// - `state`: shared application state.
/// - `req`: the submitted access/secret key.
///
/// # Returns
/// `{token}` on success, or `401` with an error body on bad credentials.
pub async fn login(State(state): State<AppState>, Json(req): Json<LoginReq>) -> Response {
    if req.access_key == state.config.root_user && req.secret_key == state.config.root_password {
        let token = issue_token(&state.config.root_password, now_secs());
        Json(json!({ "token": token })).into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "AccessDenied", "message": "Invalid credentials" })),
        )
            .into_response()
    }
}

/// Middleware that rejects console API requests without a valid bearer token.
///
/// # Parameters
/// - `state`: shared application state (provides the signing secret).
/// - `req`: the incoming request.
/// - `next`: the remainder of the chain.
///
/// # Returns
/// The downstream response, or `401` if the token is missing/invalid.
pub async fn require_auth(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let authorized = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|t| verify_token(&state.config.root_password, t, now_secs()))
        .unwrap_or(false);
    if authorized {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Unauthorized", "message": "Login required" })),
        )
            .into_response()
    }
}

/// `GET /api/info` — basic server information for the dashboard.
///
/// # Parameters
/// - `state`: shared application state.
///
/// # Returns
/// A JSON object with version, region, API address and bucket count.
pub async fn info(State(state): State<AppState>) -> Response {
    let buckets = state.store.list_buckets().await.map(|b| b.len()).unwrap_or(0);
    let users = state.iam.list().len();
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "region": state.config.region,
        "apiAddress": state.config.address,
        "profile": state.config.profile.as_str(),
        "buckets": buckets,
        "users": users,
        "capabilities": {
            "auth": state.config.auth_enabled,
            "tls": state.config.tls_enabled,
            "encryptionDefault": state.config.encryption_enabled,
            "postQuantum": true,
            "versioning": true,
            "objectLock": true,
            "lifecycle": true,
            "oidcEnabled": state.oidc.is_some(),
        }
    }))
    .into_response()
}

/// `GET /api/storage` — backend topology + per-drive health + key custody for the
/// console.
///
/// # Parameters
/// - `state`: shared application state (store + key provider).
///
/// # Returns
/// `{backendType, dataShards, parityShards, drives:[{path, state}], keyProvider,
/// keyPosture}` — the custody fields let the console honestly display where the
/// at-rest key lives and what that posture does (not) protect.
pub async fn storage(State(state): State<AppState>) -> Response {
    let b = state.store.backend_info().await;
    Json(json!({
        "backendType": b.backend_type,
        "dataShards": b.data_shards,
        "parityShards": b.parity_shards,
        "drives": b.drives.iter().map(|d| json!({ "path": d.path, "state": d.state })).collect::<Vec<_>>(),
        "keyProvider": state.crypto.provider.kind(),
        "keyPosture": state.crypto.provider.posture().to_json(),
    }))
    .into_response()
}

/// `POST /api/heal` — scan for and repair degraded objects.
///
/// # Parameters
/// - `state`: shared application state (store).
/// - `query`: optional `dryRun=true`.
///
/// # Returns
/// A JSON heal report, or an error response.
pub async fn heal(State(state): State<AppState>, Query(query): Query<HashMap<String, String>>) -> Response {
    let dry_run = query.get("dryRun").map(|v| v == "true").unwrap_or(false);
    match state.store.heal(None, dry_run).await {
        Ok(r) => Json(json!({
            "dryRun": r.dry_run,
            "objectsScanned": r.objects_scanned,
            "objectsHealed": r.objects_healed,
            "shardsRewritten": r.shards_rewritten,
            "objectsUnrecoverable": r.objects_unrecoverable,
        }))
        .into_response(),
        Err(e) => api_err(e),
    }
}

/// A bucket entry returned to the console.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BucketJson {
    name: String,
    creation_date: String,
}

/// `GET /api/buckets` — list all buckets.
///
/// # Parameters
/// - `state`: shared application state.
///
/// # Returns
/// A JSON array of `{name, creationDate}`, or an error response.
pub async fn list_buckets(State(state): State<AppState>) -> Response {
    match state.store.list_buckets().await {
        Ok(buckets) => Json(
            buckets
                .into_iter()
                .map(|b| BucketJson {
                    name: b.name,
                    creation_date: iso8601(b.creation_date),
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => api_err(e),
    }
}

/// Body of [`create_bucket`].
#[derive(Deserialize)]
pub struct CreateBucketReq {
    name: String,
}

/// `POST /api/buckets` — create a bucket.
///
/// # Parameters
/// - `state`: shared application state.
/// - `req`: the bucket name to create.
///
/// # Returns
/// `{ok:true}` on success, or an error response.
pub async fn create_bucket(State(state): State<AppState>, Json(req): Json<CreateBucketReq>) -> Response {
    match state.store.create_bucket(&req.name).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => api_err(e),
    }
}

/// `DELETE /api/buckets/{bucket}` — delete a bucket, optionally emptying it
/// first when `?force=true` is supplied.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: the bucket name.
/// - `query`: query parameters (`force` enables recursive delete).
///
/// # Returns
/// `{ok:true}` on success, or an error response (e.g. `BucketNotEmpty`).
pub async fn delete_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let force = query
        .get("force")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    if force {
        // Drain the bucket page by page until no objects remain.
        loop {
            match state
                .store
                .list_objects_v2(&bucket, "", None, None, None, 1000)
                .await
            {
                Ok(listing) if listing.objects.is_empty() => break,
                Ok(listing) => {
                    for obj in &listing.objects {
                        let _ = state.store.delete_object(&bucket, &obj.key).await;
                    }
                }
                Err(e) => return api_err(e),
            }
        }
    }
    match state.store.delete_bucket(&bucket).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => api_err(e),
    }
}

/// An object entry returned to the console.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ObjectJson {
    key: String,
    size: u64,
    last_modified: String,
    etag: String,
}

/// `GET /api/buckets/{bucket}/objects?prefix=` — list one "folder" of a bucket.
///
/// Uses delimiter `/` so the console can browse keys as a directory tree.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: the bucket name.
/// - `query`: query parameters (`prefix` selects the folder).
///
/// # Returns
/// `{prefix, prefixes, objects, isTruncated}`, or an error response.
pub async fn list_objects(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let prefix = query.get("prefix").cloned().unwrap_or_default();
    match state
        .store
        .list_objects_v2(&bucket, &prefix, Some("/"), None, None, 1000)
        .await
    {
        Ok(listing) => {
            let objects: Vec<ObjectJson> = listing
                .objects
                .into_iter()
                .map(|m| ObjectJson {
                    key: m.key,
                    size: m.size,
                    last_modified: iso8601(m.last_modified),
                    etag: m.etag,
                })
                .collect();
            Json(json!({
                "prefix": prefix,
                "prefixes": listing.common_prefixes,
                "objects": objects,
                "isTruncated": listing.is_truncated,
            }))
            .into_response()
        }
        Err(e) => api_err(e),
    }
}

/// `PUT /api/buckets/{bucket}/objects/{key}` — upload an object.
///
/// # Parameters
/// - `state`: shared application state.
/// - `path`: `(bucket, key)`.
/// - `headers`: request headers (used for `Content-Type`).
/// - `body`: the object payload.
///
/// # Returns
/// `{ok:true, etag, size}` on success, or an error response.
pub async fn upload(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    // Honour the bucket's per-bucket SSE config (matching the S3 API path), not
    // just the global KP_ENCRYPT flag, so console uploads to an encrypted
    // bucket are actually encrypted at rest.
    let bucket_sse = state.store.get_bucket_encryption(&bucket).await.ok().flatten().is_some();
    let encrypt = bucket_sse || state.config.encryption_enabled;
    match state
        .store
        .put_object(&bucket, &key, body_to_reader(body), content_type, BTreeMap::new(), encrypt)
        .await
    {
        Ok(meta) => Json(json!({ "ok": true, "etag": meta.etag, "size": meta.size })).into_response(),
        Err(e) => api_err(e),
    }
}

/// `GET /api/buckets/{bucket}/objects/{key}` — download an object as an
/// attachment.
///
/// # Parameters
/// - `state`: shared application state.
/// - `path`: `(bucket, key)`.
///
/// # Returns
/// A streaming response with `Content-Disposition: attachment`, or an error.
pub async fn download(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    // Read a specific version when `?versionId=` is supplied, else the current.
    let result = match query.get("versionId") {
        Some(vid) => state.store.get_object_version(&bucket, &key, vid).await,
        None => state.store.get_object(&bucket, &key).await,
    };
    match result {
        Ok((meta, body)) => {
            let filename = key.rsplit('/').next().unwrap_or("download").replace('"', "");
            let mut headers = HeaderMap::new();
            if let Ok(v) = HeaderValue::from_str(&meta.content_type) {
                headers.insert(header::CONTENT_TYPE, v);
            }
            if let Ok(v) = HeaderValue::from_str(&meta.size.to_string()) {
                headers.insert(header::CONTENT_LENGTH, v);
            }
            if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
                headers.insert(header::CONTENT_DISPOSITION, v);
            }
            (headers, Body::from_stream(ReaderStream::new(body))).into_response()
        }
        Err(e) => api_err(e),
    }
}

/// `DELETE /api/buckets/{bucket}/objects/{key}` — delete an object, or a
/// specific version when `?versionId=` is supplied.
///
/// # Parameters
/// - `state`: shared application state.
/// - `path`: `(bucket, key)`.
/// - `query`: query parameters (`versionId` targets one version/marker).
///
/// # Returns
/// `{ok:true}` on success, or an error response.
pub async fn delete_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let result = match query.get("versionId") {
        Some(vid) => state.store.delete_object_version(&bucket, &key, vid).await,
        None => state.store.delete_object(&bucket, &key).await,
    };
    match result {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(e) => api_err(e),
    }
}

// ── Bucket settings: versioning + encryption ──────────────────────────────────

/// `GET /api/buckets/{bucket}/settings` — current versioning + encryption state.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: the bucket name.
///
/// # Returns
/// `{versioning: "Enabled"|"Suspended"|"", encryption: "AES256"|null}`.
pub async fn bucket_settings(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> Response {
    let versioning = state.store.get_bucket_versioning(&bucket).await.unwrap_or_default();
    let encryption = state.store.get_bucket_encryption(&bucket).await.ok().flatten();
    Json(json!({ "versioning": versioning, "encryption": encryption })).into_response()
}

/// Body for [`set_bucket_versioning`].
#[derive(Deserialize)]
pub struct VersioningReq {
    status: String,
}

/// `PUT /api/buckets/{bucket}/versioning` — set versioning (`Enabled`/`Suspended`).
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: the bucket name.
/// - `req`: `{status}`.
///
/// # Returns
/// `{ok:true}` on success, or an error response.
pub async fn set_bucket_versioning(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Json(req): Json<VersioningReq>,
) -> Response {
    match state.store.set_bucket_versioning(&bucket, &req.status).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => api_err(e),
    }
}

/// Body for [`set_bucket_encryption`].
#[derive(Deserialize)]
pub struct EncryptionReq {
    enabled: bool,
}

/// `PUT /api/buckets/{bucket}/encryption` — enable (`AES256`) or clear bucket SSE.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: the bucket name.
/// - `req`: `{enabled}`.
///
/// # Returns
/// `{ok:true}` on success, or an error response.
pub async fn set_bucket_encryption(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Json(req): Json<EncryptionReq>,
) -> Response {
    let result = if req.enabled {
        state.store.set_bucket_encryption(&bucket, "AES256").await
    } else {
        state.store.delete_bucket_encryption(&bucket).await
    };
    match result {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => api_err(e),
    }
}

/// `GET /api/buckets/{bucket}/versions?prefix=` — list object versions + markers.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: the bucket name.
/// - `query`: query parameters (`prefix` filters keys).
///
/// # Returns
/// `{versions: [{key, versionId, isLatest, isDeleteMarker, size, lastModified}]}`.
pub async fn list_versions(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let prefix = query.get("prefix").cloned().unwrap_or_default();
    match state
        .store
        .list_object_versions(&bucket, &prefix, None, None, None, 1000)
        .await
    {
        Ok(listing) => {
            let versions: Vec<_> = listing
                .versions
                .into_iter()
                .map(|v| {
                    json!({
                        "key": v.key,
                        "versionId": v.version_id,
                        "isLatest": v.is_latest,
                        "isDeleteMarker": v.is_delete_marker,
                        "size": v.size,
                        "etag": v.etag,
                        "lastModified": iso8601(v.last_modified),
                        // KerPlace audit differentiator: who wrote this version, from where.
                        "author": v.audit.as_ref().and_then(|a| a.author.clone()),
                        "sourceIp": v.audit.as_ref().and_then(|a| a.source_ip.clone()),
                    })
                })
                .collect();
            Json(json!({ "versions": versions })).into_response()
        }
        Err(e) => api_err(e),
    }
}

// ── IAM user management ───────────────────────────────────────────────────────

/// Body for [`add_user`].
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddUserReq {
    access_key: String,
    secret_key: String,
    #[serde(default)]
    policy: Option<String>,
}

/// Body for [`set_user_status`].
#[derive(Deserialize)]
pub struct StatusReq {
    enabled: bool,
}

/// `GET /api/users` — list IAM identities (secret keys are masked).
///
/// # Parameters
/// - `state`: shared application state.
///
/// # Returns
/// `{users: [{accessKey, policy, enabled, isRoot}]}`.
pub async fn list_users(State(state): State<AppState>) -> Response {
    let root = state.config.root_user.clone();
    let users: Vec<_> = state
        .iam
        .list()
        .into_iter()
        .map(|i| {
            json!({
                "accessKey": i.access_key,
                "policy": i.policy,
                "enabled": i.enabled,
                "isRoot": i.access_key == root,
            })
        })
        .collect();
    Json(json!({ "users": users })).into_response()
}

/// `POST /api/users` — create (or replace) an IAM user.
///
/// # Parameters
/// - `state`: shared application state.
/// - `req`: `{accessKey, secretKey, policy?}` (policy defaults to `readwrite`).
///
/// # Returns
/// `{ok:true}` on success, or an error response.
pub async fn add_user(State(state): State<AppState>, Json(req): Json<AddUserReq>) -> Response {
    let policy = req.policy.unwrap_or_else(|| "readwrite".to_string());
    match state.iam.add_user(&req.access_key, &req.secret_key, &policy).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => api_err(e),
    }
}

/// `DELETE /api/users/{accessKey}` — remove an IAM user.
///
/// # Parameters
/// - `state`: shared application state.
/// - `path`: the access key to remove.
///
/// # Returns
/// `{ok:true}` on success, or an error response.
pub async fn delete_user(
    State(state): State<AppState>,
    Path(access_key): Path<String>,
) -> Response {
    match state.iam.remove_user(&access_key).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => api_err(e),
    }
}

/// `POST /api/users/{accessKey}/status` — enable or disable an IAM user.
///
/// # Parameters
/// - `state`: shared application state.
/// - `path`: the access key to update.
/// - `req`: `{enabled: bool}`.
///
/// # Returns
/// `{ok:true}` on success, or an error response.
pub async fn set_user_status(
    State(state): State<AppState>,
    Path(access_key): Path<String>,
    Json(req): Json<StatusReq>,
) -> Response {
    match state.iam.set_status(&access_key, req.enabled).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => api_err(e),
    }
}
