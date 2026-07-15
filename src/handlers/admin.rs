//! Minimal MinIO admin API surface.
//!
//! Implements `GET /minio/admin/v3/info` returning a `madmin.InfoMessage`-shaped
//! JSON document so that `mc admin info`, the MinIO console and SDKs detect
//! KerPlace as a running server. Authentication is handled by the normal SigV4
//! middleware (the admin credential scope uses an empty region, which our
//! verifier accepts).

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Instant;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde_json::json;
use uuid::Uuid;

use crate::error::S3Error;
use crate::iam::{Identity, Policy};
use crate::madmin;
use crate::state::AppState;

/// Resolve the secret key of the request's authenticated identity, used as the
/// shared key for madmin payload (de)cryption. Falls back to the root secret
/// when auth is disabled (no identity attached).
///
/// # Parameters
/// - `identity`: the optional identity attached by the auth middleware.
/// - `state`: shared application state (for the root secret fallback).
///
/// # Returns
/// The secret key string to derive the madmin key from.
fn requester_secret(identity: &Option<Identity>, state: &AppState) -> String {
    identity
        .as_ref()
        .map(|i| i.secret_key.clone())
        .unwrap_or_else(|| state.config.root_password.clone())
}

/// Process start time, used to report server uptime.
static START: OnceLock<Instant> = OnceLock::new();
/// Stable per-process deployment id.
static DEPLOYMENT_ID: OnceLock<String> = OnceLock::new();

/// Record the process start time and deployment id. Call once at startup.
///
/// # Returns
/// `()` — initializes the module's `OnceLock`s (no-op if already set).
pub fn mark_start() {
    let _ = START.set(Instant::now());
    let _ = DEPLOYMENT_ID.set(Uuid::new_v4().to_string());
}

/// Seconds elapsed since [`mark_start`] was called.
///
/// # Returns
/// The server uptime in seconds (0 if uninitialized).
fn uptime_secs() -> u64 {
    START.get().map(|s| s.elapsed().as_secs()).unwrap_or(0)
}

/// The stable deployment id for this process.
///
/// # Returns
/// The deployment id string (empty if uninitialized).
fn deployment_id() -> String {
    DEPLOYMENT_ID.get().cloned().unwrap_or_default()
}

/// Handle `GET /minio/admin/v3/info` — report cluster/server information.
///
/// # Parameters
/// - `state`: shared application state (config + store).
///
/// # Returns
/// A `200 OK` JSON `InfoMessage` describing this single-node server.
pub async fn info(State(state): State<AppState>) -> Response {
    let bucket_count = state.store.list_buckets().await.map(|b| b.len()).unwrap_or(0) as u64;
    let endpoint = state.config.address.clone();
    let backend = state.store.backend_info().await;

    let mut network = serde_json::Map::new();
    network.insert(endpoint.clone(), json!("online"));

    // Report the real drive set (erasure spreads across several drives; FS has
    // one). `mc admin info` renders these as the per-server drive list.
    let drives: Vec<serde_json::Value> = backend
        .drives
        .iter()
        .map(|d| {
            json!({
                "endpoint": d.path,
                "drivePath": d.path,
                "state": d.state,
                "uuid": deployment_id(),
            })
        })
        .collect();

    // MinIO reports the erasure profile as `Standard` parity (drives per set).
    let backend_json = if backend.backend_type == "Erasure" {
        json!({
            "backendType": "Erasure",
            "standardSCParity": backend.parity_shards,
            "standardSCData": backend.data_shards,
            "totalSets": [1],
            "drivesPerSet": [backend.drives.len()],
        })
    } else {
        json!({ "backendType": "FS" })
    };

    let body = json!({
        "mode": "online",
        "deploymentID": deployment_id(),
        "region": state.config.region,
        "buckets": { "count": bucket_count },
        "objects": { "count": 0 },
        "usage": { "size": 0 },
        "backend": backend_json,
        "keyProvider": state.crypto.provider.kind(),
        "keyPosture": state.crypto.provider.posture().to_json(),
        "profile": state.config.profile.as_str(),
        "servers": [{
            "state": "online",
            "endpoint": endpoint,
            "scheme": "http",
            "uptime": uptime_secs(),
            "version": env!("CARGO_PKG_VERSION"),
            "commitID": "kerplace",
            "network": network,
            "drives": drives,
        }],
    });

    Json(body).into_response()
}

/// Handle `POST /minio/admin/v3/heal?bucket=&dryRun=` — scan for and repair
/// degraded objects (missing/corrupt erasure shards).
///
/// A KerPlace-native heal endpoint (simpler than MinIO's streaming heal protocol):
/// it runs the scan synchronously and returns a JSON summary. On the single
/// FS mirror this is a no-op; on the erasure backend it rewrites recoverable
/// shards back to full redundancy.
///
/// # Parameters
/// - `state`: shared application state (store).
/// - `query`: optional `bucket` (scope to one bucket) and `dryRun=true`.
///
/// # Returns
/// `200 OK` with a JSON heal report, or an S3-style error response.
pub async fn heal(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let bucket = query.get("bucket").filter(|s| !s.is_empty()).cloned();
    let dry_run = query.get("dryRun").map(|v| v == "true").unwrap_or(false);
    match state.store.heal(bucket.as_deref(), dry_run).await {
        Ok(r) => Json(json!({
            "dryRun": r.dry_run,
            "objectsScanned": r.objects_scanned,
            "objectsHealed": r.objects_healed,
            "shardsRewritten": r.shards_rewritten,
            "objectsUnrecoverable": r.objects_unrecoverable,
        }))
        .into_response(),
        Err(e) => e.into_response(),
    }
}

// ── User management (`mc admin user ...`) ─────────────────────────────────────

/// Map a KerPlace policy name to a madmin `AccountStatus`/`UserInfo` JSON value.
///
/// # Parameters
/// - `enabled`: whether the account is enabled.
///
/// # Returns
/// `"enabled"` or `"disabled"`.
fn account_status(enabled: bool) -> &'static str {
    if enabled { "enabled" } else { "disabled" }
}

/// Handle `PUT /minio/admin/v3/add-user?accessKey=X` — create/update a user.
///
/// The request body is a madmin-encrypted `UserInfo` JSON (`{secretKey, status,
/// policyName?}`) sealed with the requester's secret key.
///
/// # Parameters
/// - `state`: shared application state.
/// - `identity`: the authenticated requester (for the decryption key).
/// - `query`: query parameters (`accessKey`).
/// - `body`: the encrypted request body.
///
/// # Returns
/// `200 OK` on success, or an S3-style error response.
pub async fn add_user(
    State(state): State<AppState>,
    identity: Option<Extension<Identity>>,
    Query(query): Query<HashMap<String, String>>,
    body: axum::body::Bytes,
) -> Response {
    let access_key = match query.get("accessKey") {
        Some(k) => k.clone(),
        None => return S3Error::InvalidArgument("missing accessKey".into()).into_response(),
    };
    let id = identity.map(|e| e.0);
    let secret = requester_secret(&id, &state);

    let plain = match madmin::decrypt_data(&secret, &body) {
        Ok(p) => p,
        Err(e) => return S3Error::InvalidArgument(format!("decrypt: {e}")).into_response(),
    };
    let doc: serde_json::Value = match serde_json::from_slice(&plain) {
        Ok(v) => v,
        Err(e) => return S3Error::InvalidArgument(format!("bad UserInfo: {e}")).into_response(),
    };
    let secret_key = doc.get("secretKey").and_then(|v| v.as_str()).unwrap_or("");
    // Default admin-created users to readwrite, but honour an explicit
    // policyName if supplied (and `policy attach` can change it afterwards).
    let policy = doc
        .get("policyName")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("readwrite");

    match state.iam.add_user(&access_key, secret_key, policy).await {
        Ok(()) => {
            // Honour an explicit disabled status in the same request.
            if doc.get("status").and_then(|v| v.as_str()) == Some("disabled") {
                let _ = state.iam.set_status(&access_key, false).await;
            }
            StatusCode::OK.into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// Handle `POST /minio/admin/v3/idp/builtin/policy/attach` — attach a canned
/// policy to a user (what `mc admin policy attach … --user …` calls).
///
/// # Parameters
/// - `state`: shared application state.
/// - `identity`: the authenticated requester (for the (de)cryption key).
/// - `body`: madmin-encrypted `PolicyAssociationReq` (`{policies[], user, group?}`).
///
/// # Returns
/// `200 OK` with an encrypted `PolicyAssociationResp`, or an S3-style error.
pub async fn attach_policy(
    State(state): State<AppState>,
    identity: Option<Extension<Identity>>,
    body: axum::body::Bytes,
) -> Response {
    policy_assoc(state, identity, body, true).await
}

/// Handle `POST /minio/admin/v3/idp/builtin/policy/detach` — detach a user's
/// policy, leaving it with no permissions (KerPlace users hold one canned policy).
///
/// # Parameters
/// - `state`: shared application state.
/// - `identity`: the authenticated requester (for the (de)cryption key).
/// - `body`: madmin-encrypted `PolicyAssociationReq`.
///
/// # Returns
/// `200 OK` with an encrypted `PolicyAssociationResp`, or an S3-style error.
pub async fn detach_policy(
    State(state): State<AppState>,
    identity: Option<Extension<Identity>>,
    body: axum::body::Bytes,
) -> Response {
    policy_assoc(state, identity, body, false).await
}

/// Shared implementation of policy attach/detach.
///
/// Decrypts the `PolicyAssociationReq`, applies the (first) policy to the named
/// user via [`crate::iam::Iam::set_policy`] — KerPlace maps a user to a single
/// canned policy — and returns the encrypted `PolicyAssociationResp` `mc`
/// expects. Group associations are not supported.
///
/// # Parameters
/// - `state`: shared application state.
/// - `identity`: the authenticated requester (for the (de)cryption key).
/// - `body`: the encrypted request body.
/// - `attach`: `true` to attach the policy, `false` to detach it.
///
/// # Returns
/// `200 OK` with the encrypted response, or an S3-style error response.
async fn policy_assoc(
    state: AppState,
    identity: Option<Extension<Identity>>,
    body: axum::body::Bytes,
    attach: bool,
) -> Response {
    let id = identity.map(|e| e.0);
    let secret = requester_secret(&id, &state);

    let plain = match madmin::decrypt_data(&secret, &body) {
        Ok(p) => p,
        Err(e) => return S3Error::InvalidArgument(format!("decrypt: {e}")).into_response(),
    };
    let doc: serde_json::Value = match serde_json::from_slice(&plain) {
        Ok(v) => v,
        Err(e) => return S3Error::InvalidArgument(format!("bad PolicyAssociationReq: {e}")).into_response(),
    };

    let user = doc.get("user").and_then(|v| v.as_str()).unwrap_or("");
    if user.is_empty() {
        return S3Error::InvalidArgument("group policy association is not supported".into())
            .into_response();
    }
    let policies: Vec<String> = doc
        .get("policies")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|p| p.as_str().map(String::from)).collect())
        .unwrap_or_default();
    // KerPlace holds one canned policy per user; attach takes the first, detach clears.
    let new_policy = if attach { policies.first().map(String::as_str).unwrap_or("") } else { "" };

    if let Err(e) = state.iam.set_policy(user, new_policy).await {
        return e.into_response();
    }

    let resp = if attach {
        json!({ "PoliciesAttached": policies, "PoliciesDetached": [] })
    } else {
        json!({ "PoliciesAttached": [], "PoliciesDetached": policies })
    };
    let enc = madmin::encrypt_data(&secret, &serde_json::to_vec(&resp).unwrap_or_default());
    (StatusCode::OK, enc).into_response()
}

/// Handle `GET /minio/admin/v3/list-users` — list users (madmin-encrypted).
///
/// Returns a madmin-encrypted JSON map `accessKey -> {status, policyName}`
/// (secret keys are never returned), sealed with the requester's secret key.
///
/// # Parameters
/// - `state`: shared application state.
/// - `identity`: the authenticated requester (for the encryption key).
///
/// # Returns
/// `200 OK` with the encrypted body, or an error response.
pub async fn list_users(
    State(state): State<AppState>,
    identity: Option<Extension<Identity>>,
) -> Response {
    let id = identity.map(|e| e.0);
    let secret = requester_secret(&id, &state);
    let root = state.config.root_user.clone();

    let mut map = serde_json::Map::new();
    for user in state.iam.list() {
        // The root account is implicit in MinIO and not listed by `mc admin user`.
        if user.access_key == root {
            continue;
        }
        map.insert(
            user.access_key.clone(),
            json!({
                "status": account_status(user.enabled),
                "policyName": Policy::from_name(&user.policy).name(),
            }),
        );
    }
    let plain = serde_json::to_vec(&map).unwrap_or_default();
    let encrypted = madmin::encrypt_data(&secret, &plain);
    (StatusCode::OK, encrypted).into_response()
}

/// Handle `DELETE /minio/admin/v3/remove-user?accessKey=X` — remove a user.
///
/// # Parameters
/// - `state`: shared application state.
/// - `query`: query parameters (`accessKey`).
///
/// # Returns
/// `200 OK` on success, or an error response.
pub async fn remove_user(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let access_key = match query.get("accessKey") {
        Some(k) => k.clone(),
        None => return S3Error::InvalidArgument("missing accessKey".into()).into_response(),
    };
    match state.iam.remove_user(&access_key).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => e.into_response(),
    }
}

/// Handle `PUT /minio/admin/v3/set-user-status?accessKey=X&status=...` —
/// enable or disable a user.
///
/// # Parameters
/// - `state`: shared application state.
/// - `query`: query parameters (`accessKey`, `status`).
///
/// # Returns
/// `200 OK` on success, or an error response.
pub async fn set_user_status(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let access_key = match query.get("accessKey") {
        Some(k) => k.clone(),
        None => return S3Error::InvalidArgument("missing accessKey".into()).into_response(),
    };
    let enabled = query.get("status").map(|s| s == "enabled").unwrap_or(true);
    match state.iam.set_status(&access_key, enabled).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => e.into_response(),
    }
}

/// Handle `PUT /kerplace/admin/v3/set-user-buckets?accessKey=X&buckets=a|b` —
/// scope a user to a bucket allow-list.
///
/// This is the *where* half of authorization (the canned policy remains the
/// *what*); both are enforced together. `buckets` is pipe-separated. Passing it
/// **empty** (`&buckets=`) clears the scope, letting the user reach every bucket
/// again — a privilege-widening operation, so it must be spelled out rather than
/// implied by omitting the parameter.
///
/// # Parameters
/// - `state`: shared application state.
/// - `query`: query parameters (`accessKey`, `buckets`).
///
/// # Returns
/// `200 OK` on success, or an error response.
pub async fn set_user_buckets(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let access_key = match query.get("accessKey") {
        Some(k) => k.clone(),
        None => return S3Error::InvalidArgument("missing accessKey".into()).into_response(),
    };
    let raw = match query.get("buckets") {
        Some(b) => b.clone(),
        None => {
            return S3Error::InvalidArgument(
                "missing buckets (pass an empty value to clear the scope)".into(),
            )
            .into_response()
        }
    };
    match state.iam.set_buckets(&access_key, crate::iam::parse_bucket_list(&raw)).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => e.into_response(),
    }
}

/// Handle `GET /minio/admin/v3/user-info?accessKey=X` — return one user's info.
///
/// Responds with plain `UserInfo` JSON (`mc admin user info` reads it directly).
/// The KerPlace-specific `buckets` field reports the credential's bucket scope
/// (`null` = every bucket); madmin clients ignore the extra field.
///
/// # Parameters
/// - `state`: shared application state.
/// - `query`: query parameters (`accessKey`).
///
/// # Returns
/// `200 OK` with a `UserInfo` JSON document, or `404`-style error.
pub async fn user_info(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let access_key = match query.get("accessKey") {
        Some(k) => k.clone(),
        None => return S3Error::InvalidArgument("missing accessKey".into()).into_response(),
    };
    match state.iam.resolve(&access_key) {
        Some(user) if access_key != state.config.root_user => Json(json!({
            "status": account_status(user.enabled),
            "policyName": Policy::from_name(&user.policy).name(),
            "buckets": user.buckets,
        }))
        .into_response(),
        _ => S3Error::NoSuchKey.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::{CryptoContext, MasterKey};

    /// DoD #5 (info-surface half): `info` reports the active provider's kind and an
    /// honest custody posture via [`crate::crypto::KeyPosture::to_json`].
    #[test]
    fn provider_kind_and_posture_surfaced() {
        let ctx = CryptoContext::new_aes(MasterKey::generate());
        assert_eq!(ctx.provider.kind(), "file");

        let v = ctx.provider.posture().to_json();
        assert_eq!(v["kind"], "file");
        assert_eq!(v["unattendedBoot"], true);
        assert_eq!(v["keyOnHost"], true);
        assert!(v["protects"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(v["doesNotProtect"].as_str().is_some_and(|s| !s.is_empty()));
    }
}
