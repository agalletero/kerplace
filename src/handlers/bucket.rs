//! Bucket-level handlers: list/create/delete/head buckets, list objects and
//! the batch `DeleteObjects` operation, plus per-bucket sub-resources
//! (encryption, policy, tagging, versioning, lifecycle, object-lock config).
//!
//! Each operation is split into a thin axum handler (which extracts request
//! parts) and an `*_inner` function taking already-extracted arguments. The
//! object dispatchers reuse the `*_inner` functions for trailing-slash
//! requests such as `PUT /{bucket}/`, which S3 treats as bucket operations.

use std::collections::{BTreeMap, HashMap};

use axum::body::Body;
use axum::extract::{Path, RawQuery, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures::TryStreamExt;
use tokio_util::io::StreamReader;

use super::{encode_key, parse_query, quote_etag, xml_response};
use crate::error::S3Error;
use crate::s3::iso8601;
use crate::s3::xml::{
    self, Bucket, Buckets, CommonPrefix, Contents, Delete, DeleteError, DeleteResult, Deleted,
    LifecycleConfiguration, ListAllMyBucketsResult, ListBucketResult, ObjectLockConfiguration,
    ServerSideEncryptionConfiguration, SseDefault, SseRule, Tag, TagSet, Tagging,
    VersioningConfiguration, Owner, S3_NS,
};
use crate::state::AppState;

// ── Standard bucket CRUD ──────────────────────────────────────────────────────

/// Handle `GET /` — list all buckets owned by the caller.
///
/// # Parameters
/// - `state`: shared application state.
///
/// # Returns
/// A `200 OK` `ListAllMyBucketsResult` document, or an S3 error response.
pub async fn list_buckets(State(state): State<AppState>) -> Response {
    match state.store.list_buckets().await {
        Ok(buckets) => {
            let result = ListAllMyBucketsResult {
                xmlns: S3_NS,
                owner: Owner { id: "kerplace".to_string(), display_name: "kerplace".to_string() },
                buckets: Buckets {
                    bucket: buckets
                        .into_iter()
                        .map(|b| Bucket {
                            name: b.name,
                            creation_date: iso8601(b.creation_date),
                        })
                        .collect(),
                },
            };
            xml_response(StatusCode::OK, xml::to_xml("ListAllMyBucketsResult", &result))
        }
        Err(e) => e.into_response(),
    }
}

/// Handle `PUT /{bucket}` — create a bucket or dispatch a sub-resource.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name from the path.
/// - `query`: raw query string (selects sub-resource when present).
/// - `body`: request body (used by sub-resources).
///
/// # Returns
/// See [`create_bucket_inner`] or the relevant sub-resource handler.
pub async fn create_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    RawQuery(query): RawQuery,
    body: Body,
) -> Response {
    let params = parse_query(query.as_deref());
    if params.contains_key("encryption") {
        return put_bucket_encryption(state, bucket, body).await;
    }
    if params.contains_key("policy") {
        return put_bucket_policy(state, bucket, body).await;
    }
    if params.contains_key("tagging") {
        return put_bucket_tagging(state, bucket, body).await;
    }
    if params.contains_key("versioning") {
        return put_bucket_versioning(state, bucket, body).await;
    }
    if params.contains_key("lifecycle") {
        return put_bucket_lifecycle(state, bucket, body).await;
    }
    if params.contains_key("object-lock") {
        return put_bucket_object_lock(state, bucket, body).await;
    }
    create_bucket_inner(state, bucket).await
}

/// Create a bucket (shared implementation).
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name to create.
///
/// # Returns
/// `200 OK` with a `Location` header on success, or an S3 error response.
pub async fn create_bucket_inner(state: AppState, bucket: String) -> Response {
    match state.store.create_bucket(&bucket).await {
        Ok(()) => (StatusCode::OK, [(header::LOCATION, format!("/{bucket}"))]).into_response(),
        Err(e) => e.into_response_with_resource(&format!("/{bucket}")),
    }
}

/// Handle `DELETE /{bucket}` — delete an empty bucket or dispatch sub-resource.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name from the path.
/// - `query`: raw query string (selects sub-resource when present).
///
/// # Returns
/// See [`delete_bucket_inner`] or the relevant sub-resource handler.
pub async fn delete_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    let params = parse_query(query.as_deref());
    if params.contains_key("encryption") {
        return match state.store.delete_bucket_encryption(&bucket).await {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(e) => e.into_response_with_resource(&format!("/{bucket}")),
        };
    }
    if params.contains_key("policy") {
        return match state.store.delete_bucket_policy(&bucket).await {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(e) => e.into_response_with_resource(&format!("/{bucket}")),
        };
    }
    if params.contains_key("tagging") {
        return match state.store.delete_bucket_tags(&bucket).await {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(e) => e.into_response_with_resource(&format!("/{bucket}")),
        };
    }
    if params.contains_key("lifecycle") {
        return match state.store.delete_bucket_lifecycle(&bucket).await {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(e) => e.into_response_with_resource(&format!("/{bucket}")),
        };
    }
    delete_bucket_inner(state, bucket).await
}

/// Delete an empty bucket (shared implementation).
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name to delete.
///
/// # Returns
/// `204 No Content` on success, or an S3 error response.
pub async fn delete_bucket_inner(state: AppState, bucket: String) -> Response {
    match state.store.delete_bucket(&bucket).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response_with_resource(&format!("/{bucket}")),
    }
}

/// Handle `HEAD /{bucket}` — test bucket existence.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name from the path.
///
/// # Returns
/// See [`head_bucket_inner`].
pub async fn head_bucket(State(state): State<AppState>, Path(bucket): Path<String>) -> Response {
    head_bucket_inner(state, bucket).await
}

/// Test bucket existence (shared implementation).
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name to test.
///
/// # Returns
/// `200 OK` if present, otherwise a `404`-class S3 error response.
pub async fn head_bucket_inner(state: AppState, bucket: String) -> Response {
    match state.store.head_bucket(&bucket).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => e.into_response_with_resource(&format!("/{bucket}")),
    }
}

/// Handle `GET /{bucket}` — list objects or dispatch a sub-resource.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name from the path.
/// - `query`: the raw query string.
///
/// # Returns
/// See [`list_objects_inner`] or the relevant sub-resource handler.
pub async fn list_objects(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    let params = parse_query(query.as_deref());
    if params.contains_key("versions") {
        return list_object_versions_handler(state, bucket, params).await;
    }
    if params.contains_key("encryption") {
        return get_bucket_encryption(state, bucket).await;
    }
    if params.contains_key("policy") {
        return get_bucket_policy(state, bucket).await;
    }
    if params.contains_key("tagging") {
        return get_bucket_tagging(state, bucket).await;
    }
    if params.contains_key("versioning") {
        return get_bucket_versioning(state, bucket).await;
    }
    if params.contains_key("lifecycle") {
        return get_bucket_lifecycle(state, bucket).await;
    }
    if params.contains_key("object-lock") {
        return get_bucket_object_lock(state, bucket).await;
    }
    list_objects_inner(state, bucket, params).await
}

/// List objects in a bucket (shared implementation).
///
/// Honors `prefix`, `delimiter`, `continuation-token`, `start-after` and
/// `max-keys` query parameters.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name to list.
/// - `params`: parsed query parameters.
///
/// # Returns
/// A `200 OK` `ListBucketResult` document, or an S3 error response.
pub async fn list_objects_inner(
    state: AppState,
    bucket: String,
    params: HashMap<String, String>,
) -> Response {
    let prefix = params.get("prefix").cloned().unwrap_or_default();
    let delimiter =
        params.get("delimiter").filter(|d| !d.is_empty()).cloned();
    let continuation = params.get("continuation-token").cloned();
    let start_after = params.get("start-after").cloned();
    let encode = params
        .get("encoding-type")
        .map(|e| e.eq_ignore_ascii_case("url"))
        .unwrap_or(false);
    let max_keys = params
        .get("max-keys")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1000)
        .min(1000);

    match state
        .store
        .list_objects_v2(
            &bucket,
            &prefix,
            delimiter.as_deref(),
            continuation.as_deref(),
            start_after.as_deref(),
            max_keys,
        )
        .await
    {
        Ok(listing) => {
            let enc = |s: String| if encode { encode_key(&s) } else { s };
            let contents: Vec<Contents> = listing
                .objects
                .into_iter()
                .map(|m| Contents {
                    key: enc(m.key),
                    last_modified: iso8601(m.last_modified),
                    etag: quote_etag(&m.etag),
                    size: m.size,
                    storage_class: "STANDARD".to_string(),
                })
                .collect();
            let common_prefixes: Vec<CommonPrefix> = listing
                .common_prefixes
                .into_iter()
                .map(|p| CommonPrefix { prefix: enc(p) })
                .collect();
            let key_count = contents.len() + common_prefixes.len();
            let result = ListBucketResult {
                xmlns: S3_NS,
                name: bucket,
                prefix: enc(prefix),
                key_count,
                max_keys,
                delimiter: delimiter.map(&enc),
                encoding_type: encode.then(|| "url".to_string()),
                is_truncated: listing.is_truncated,
                next_continuation_token: listing.next_continuation_token.map(enc),
                contents,
                common_prefixes,
            };
            xml_response(StatusCode::OK, xml::to_xml("ListBucketResult", &result))
        }
        Err(e) => e.into_response_with_resource(&format!("/{bucket}")),
    }
}

/// Handle `GET /{bucket}?versions` — list all object versions and delete markers.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name.
/// - `params`: parsed query parameters (`prefix`, `delimiter`, `key-marker`,
///   `version-id-marker`, `max-keys`).
///
/// # Returns
/// A `200 OK` `ListVersionsResult` document, or an S3 error response.
async fn list_object_versions_handler(
    state: AppState,
    bucket: String,
    params: HashMap<String, String>,
) -> Response {
    let prefix = params.get("prefix").cloned().unwrap_or_default();
    let delimiter = params.get("delimiter").filter(|d| !d.is_empty()).cloned();
    let key_marker = params.get("key-marker").cloned();
    let version_id_marker = params.get("version-id-marker").cloned();
    let max_keys = params
        .get("max-keys")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1000)
        .min(1000);

    match state
        .store
        .list_object_versions(
            &bucket,
            &prefix,
            delimiter.as_deref(),
            key_marker.as_deref(),
            version_id_marker.as_deref(),
            max_keys,
        )
        .await
    {
        Ok(listing) => {
            let mut versions = Vec::new();
            let mut delete_markers = Vec::new();
            for v in listing.versions {
                if v.is_delete_marker {
                    delete_markers.push(crate::s3::xml::DeleteMarkerXml {
                        key: v.key,
                        version_id: v.version_id,
                        is_latest: v.is_latest,
                        last_modified: iso8601(v.last_modified),
                    });
                } else {
                    // Surface the audit "who" via the standard S3 <Owner> block.
                    let owner = v
                        .audit
                        .as_ref()
                        .and_then(|a| a.author.clone())
                        .map(|who| crate::s3::xml::Owner {
                            id: who.clone(),
                            display_name: who,
                        });
                    versions.push(crate::s3::xml::VersionXml {
                        key: v.key,
                        version_id: v.version_id,
                        is_latest: v.is_latest,
                        last_modified: iso8601(v.last_modified),
                        etag: quote_etag(&v.etag),
                        size: v.size,
                        storage_class: "STANDARD".to_string(),
                        owner,
                    });
                }
            }
            let common_prefixes: Vec<CommonPrefix> = listing
                .common_prefixes
                .into_iter()
                .map(|p| CommonPrefix { prefix: p })
                .collect();
            let result = crate::s3::xml::ListVersionsResult {
                xmlns: S3_NS,
                name: bucket,
                prefix,
                key_marker: key_marker.unwrap_or_default(),
                version_id_marker: version_id_marker.unwrap_or_default(),
                max_keys,
                delimiter,
                is_truncated: listing.is_truncated,
                next_key_marker: listing.next_key_marker,
                next_version_id_marker: listing.next_version_id_marker,
                version: versions,
                delete_marker: delete_markers,
                common_prefixes,
            };
            xml_response(StatusCode::OK, xml::to_xml("ListVersionsResult", &result))
        }
        Err(e) => e.into_response_with_resource(&format!("/{bucket}")),
    }
}

/// Handle `POST /{bucket}` — dispatch S3 form upload or `DeleteObjects`.
///
/// S3 HTML form upload (`multipart/form-data` with no `?delete`) is routed to
/// [`post_form_object`]; all other sub-resources fall through to
/// [`post_bucket_inner`].
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name from the path.
/// - `headers`: request headers (used to detect multipart form upload).
/// - `query`: the raw query string (`?delete` selects batch delete).
/// - `body`: the raw request body.
///
/// # Returns
/// See [`post_form_object`] or [`post_bucket_inner`].
pub async fn post_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Body,
) -> Response {
    let params = parse_query(query.as_deref());

    // S3 POST Object (HTML form upload): multipart/form-data without ?delete
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !params.contains_key("delete") && ct.contains("multipart/form-data") {
        return post_form_object(state, bucket, ct.to_string(), body).await;
    }

    let body_str = match axum::body::to_bytes(body, 16 << 20).await {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(_) => String::new(),
    };
    post_bucket_inner(state, bucket, params, body_str).await
}

/// Execute a bucket-level POST sub-resource (shared implementation).
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name.
/// - `params`: parsed query parameters (`delete` selects batch delete).
/// - `body`: the XML request body.
///
/// # Returns
/// A `200 OK` `DeleteResult` document for batch delete, or an S3 error
/// response. Unknown sub-resources yield [`S3Error::NotImplemented`].
pub async fn post_bucket_inner(
    state: AppState,
    bucket: String,
    params: HashMap<String, String>,
    body: String,
) -> Response {
    if !params.contains_key("delete") {
        return S3Error::NotImplemented.into_response_with_resource(&format!("/{bucket}"));
    }

    let request: Delete = match xml::from_xml(&body) {
        Ok(d) => d,
        Err(e) => {
            return S3Error::InvalidArgument(format!("malformed Delete body: {e}"))
                .into_response_with_resource(&format!("/{bucket}"));
        }
    };

    let mut deleted = Vec::new();
    let mut errors = Vec::new();
    for obj in request.objects {
        match state.store.delete_object(&bucket, &obj.key).await {
            Ok(_) => {
                if !request.quiet {
                    deleted.push(Deleted { key: obj.key });
                }
            }
            Err(e) => errors.push(DeleteError {
                key: obj.key,
                code: e.code().to_string(),
                message: e.message(),
            }),
        }
    }

    let result = DeleteResult { xmlns: S3_NS, deleted, errors };
    xml_response(StatusCode::OK, xml::to_xml("DeleteResult", &result))
}

// ── SSE (Encryption) ──────────────────────────────────────────────────────────

/// `GET /{bucket}?encryption` — return the bucket default SSE configuration.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name.
///
/// # Returns
/// `200 OK` with a `ServerSideEncryptionConfiguration` XML document, or
/// `404 ServerSideEncryptionConfigurationNotFoundError` if not set.
async fn get_bucket_encryption(state: AppState, bucket: String) -> Response {
    match state.store.get_bucket_encryption(&bucket).await {
        Err(e) => e.into_response_with_resource(&format!("/{bucket}")),
        Ok(None) => S3Error::NoSuchBucketEncryption
            .into_response_with_resource(&format!("/{bucket}")),
        Ok(Some(sse_type)) => {
            let doc = ServerSideEncryptionConfiguration {
                rule: SseRule {
                    default: SseDefault { sse_algorithm: sse_type },
                    bucket_key_enabled: Some(false),
                },
            };
            xml_response(
                StatusCode::OK,
                xml::to_xml("ServerSideEncryptionConfiguration", &doc),
            )
        }
    }
}

/// `PUT /{bucket}?encryption` — set the bucket default SSE configuration.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name.
/// - `body`: XML `ServerSideEncryptionConfiguration` document.
///
/// # Returns
/// `200 OK` on success, or an S3 error response.
async fn put_bucket_encryption(state: AppState, bucket: String, body: Body) -> Response {
    let bytes = match read_body(body).await {
        Ok(b) => b,
        Err(e) => return e.into_response_with_resource(&format!("/{bucket}")),
    };
    let doc: ServerSideEncryptionConfiguration =
        match xml::from_xml(&String::from_utf8_lossy(&bytes)) {
            Ok(d) => d,
            Err(e) => {
                return S3Error::InvalidArgument(format!("bad SSE XML: {e}"))
                    .into_response_with_resource(&format!("/{bucket}"))
            }
        };
    let sse_type = doc.rule.default.sse_algorithm;
    match state.store.set_bucket_encryption(&bucket, &sse_type).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => e.into_response_with_resource(&format!("/{bucket}")),
    }
}

// ── Bucket Policy (anonymous access) ─────────────────────────────────────────

/// `GET /{bucket}?policy` — return the bucket IAM policy.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name.
///
/// # Returns
/// `200 OK` with the raw JSON policy, or `404 NoSuchBucketPolicy` if absent.
async fn get_bucket_policy(state: AppState, bucket: String) -> Response {
    match state.store.get_bucket_policy(&bucket).await {
        Err(e) => e.into_response_with_resource(&format!("/{bucket}")),
        Ok(None) => S3Error::NoSuchBucketPolicy
            .into_response_with_resource(&format!("/{bucket}")),
        Ok(Some(policy)) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            policy,
        )
            .into_response(),
    }
}

/// `PUT /{bucket}?policy` — set the bucket IAM policy.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name.
/// - `body`: raw JSON policy document.
///
/// # Returns
/// `204 No Content` on success, or an S3 error response.
async fn put_bucket_policy(state: AppState, bucket: String, body: Body) -> Response {
    let bytes = match read_body(body).await {
        Ok(b) => b,
        Err(e) => return e.into_response_with_resource(&format!("/{bucket}")),
    };
    let policy = String::from_utf8_lossy(&bytes).into_owned();
    match state.store.set_bucket_policy(&bucket, policy).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response_with_resource(&format!("/{bucket}")),
    }
}

// ── Bucket Tagging ────────────────────────────────────────────────────────────

/// `GET /{bucket}?tagging` — return the bucket tag set.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name.
///
/// # Returns
/// `200 OK` with a `Tagging` XML document.
async fn get_bucket_tagging(state: AppState, bucket: String) -> Response {
    match state.store.get_bucket_tags(&bucket).await {
        Err(e) => e.into_response_with_resource(&format!("/{bucket}")),
        Ok(tags) => {
            let tag_vec: Vec<Tag> = tags
                .unwrap_or_default()
                .into_iter()
                .map(|(k, v)| Tag { key: k, value: v })
                .collect();
            let doc = Tagging { tag_set: TagSet { tags: tag_vec } };
            xml_response(StatusCode::OK, xml::to_xml("Tagging", &doc))
        }
    }
}

/// `PUT /{bucket}?tagging` — set the bucket tag set.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name.
/// - `body`: XML `Tagging` document.
///
/// # Returns
/// `200 OK` on success, or an S3 error response.
async fn put_bucket_tagging(state: AppState, bucket: String, body: Body) -> Response {
    let bytes = match read_body(body).await {
        Ok(b) => b,
        Err(e) => return e.into_response_with_resource(&format!("/{bucket}")),
    };
    let doc: Tagging = match xml::from_xml(&String::from_utf8_lossy(&bytes)) {
        Ok(d) => d,
        Err(e) => {
            return S3Error::InvalidArgument(format!("bad Tagging XML: {e}"))
                .into_response_with_resource(&format!("/{bucket}"))
        }
    };
    let tags: BTreeMap<String, String> =
        doc.tag_set.tags.into_iter().map(|t| (t.key, t.value)).collect();
    match state.store.set_bucket_tags(&bucket, tags).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => e.into_response_with_resource(&format!("/{bucket}")),
    }
}

// ── Bucket Versioning ─────────────────────────────────────────────────────────

/// `GET /{bucket}?versioning` — return the bucket versioning status.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name.
///
/// # Returns
/// `200 OK` with a `VersioningConfiguration` XML document.
async fn get_bucket_versioning(state: AppState, bucket: String) -> Response {
    match state.store.get_bucket_versioning(&bucket).await {
        Err(e) => e.into_response_with_resource(&format!("/{bucket}")),
        Ok(status) => {
            let doc = VersioningConfiguration {
                status: if status.is_empty() { None } else { Some(status) },
            };
            xml_response(StatusCode::OK, xml::to_xml("VersioningConfiguration", &doc))
        }
    }
}

/// `PUT /{bucket}?versioning` — enable or suspend bucket versioning.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name.
/// - `body`: XML `VersioningConfiguration` document.
///
/// # Returns
/// `200 OK` on success, or an S3 error response.
async fn put_bucket_versioning(state: AppState, bucket: String, body: Body) -> Response {
    let bytes = match read_body(body).await {
        Ok(b) => b,
        Err(e) => return e.into_response_with_resource(&format!("/{bucket}")),
    };
    let doc: VersioningConfiguration = match xml::from_xml(&String::from_utf8_lossy(&bytes)) {
        Ok(d) => d,
        Err(e) => {
            return S3Error::InvalidArgument(format!("bad VersioningConfiguration: {e}"))
                .into_response_with_resource(&format!("/{bucket}"))
        }
    };
    let status = doc.status.unwrap_or_default();
    match state.store.set_bucket_versioning(&bucket, &status).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => e.into_response_with_resource(&format!("/{bucket}")),
    }
}

// ── Lifecycle / ILM ───────────────────────────────────────────────────────────

/// `GET /{bucket}?lifecycle` — return the bucket lifecycle configuration.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name.
///
/// # Returns
/// `200 OK` with the stored XML, or `404 NoSuchLifecycleConfiguration`.
async fn get_bucket_lifecycle(state: AppState, bucket: String) -> Response {
    match state.store.get_bucket_lifecycle(&bucket).await {
        Err(e) => e.into_response_with_resource(&format!("/{bucket}")),
        Ok(None) => S3Error::NoSuchLifecycleConfiguration
            .into_response_with_resource(&format!("/{bucket}")),
        Ok(Some(raw_xml)) => xml_response(StatusCode::OK, raw_xml),
    }
}

/// `PUT /{bucket}?lifecycle` — set the bucket lifecycle configuration.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name.
/// - `body`: raw XML `LifecycleConfiguration` document.
///
/// # Returns
/// `200 OK` on success, or an S3 error response.
async fn put_bucket_lifecycle(state: AppState, bucket: String, body: Body) -> Response {
    let bytes = match read_body(body).await {
        Ok(b) => b,
        Err(e) => return e.into_response_with_resource(&format!("/{bucket}")),
    };
    // Validate that the XML parses (basic sanity check).
    let raw = String::from_utf8_lossy(&bytes).into_owned();
    if xml::from_xml::<LifecycleConfiguration>(&raw).is_err() {
        return S3Error::InvalidArgument("bad LifecycleConfiguration XML".into())
            .into_response_with_resource(&format!("/{bucket}"));
    }
    match state.store.set_bucket_lifecycle(&bucket, raw).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => e.into_response_with_resource(&format!("/{bucket}")),
    }
}

// ── Object Lock Configuration ─────────────────────────────────────────────────

/// `GET /{bucket}?object-lock` — return the bucket object-lock configuration.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name.
///
/// # Returns
/// `200 OK` with an `ObjectLockConfiguration` XML document.
async fn get_bucket_object_lock(state: AppState, bucket: String) -> Response {
    match state.store.head_bucket(&bucket).await {
        Err(e) => e.into_response_with_resource(&format!("/{bucket}")),
        Ok(()) => {
            // Object lock configuration stub — full retention engine is task #10.
            let doc = ObjectLockConfiguration {
                object_lock_enabled: Some("Disabled".to_string()),
                rule: None,
            };
            xml_response(StatusCode::OK, xml::to_xml("ObjectLockConfiguration", &doc))
        }
    }
}

/// `PUT /{bucket}?object-lock` — set the bucket object-lock configuration.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name.
/// - `body`: raw XML body (stored as-is; not enforced yet).
///
/// # Returns
/// `200 OK` — accepted (not yet enforced in this milestone).
async fn put_bucket_object_lock(state: AppState, bucket: String, body: Body) -> Response {
    let _ = read_body(body).await;
    match state.store.head_bucket(&bucket).await {
        Err(e) => e.into_response_with_resource(&format!("/{bucket}")),
        Ok(()) => StatusCode::OK.into_response(),
    }
}

// ── POST Object (HTML form upload) ────────────────────────────────────────────

/// Handle S3 POST Object — `POST /{bucket}` with `Content-Type: multipart/form-data`.
///
/// Parses the form fields in order; all text fields before `file` are collected
/// as metadata, then the `file` field is streamed directly to storage with no
/// in-memory buffering.  Supports `${filename}` substitution in the `key` field
/// and the `success_action_redirect` / `success_action_status` response controls.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: destination bucket name.
/// - `content_type`: the full `Content-Type` header value (including boundary).
/// - `body`: raw request body stream.
///
/// # Returns
/// 303 redirect if `success_action_redirect` is set; 200/201 `PostResponse` XML
/// for `success_action_status` 200/201; otherwise 204 No Content.
async fn post_form_object(
    state: AppState,
    bucket: String,
    content_type: String,
    body: Body,
) -> Response {
    let boundary = match multer::parse_boundary(&content_type) {
        Ok(b) => b,
        Err(_) => {
            return S3Error::InvalidArgument("missing multipart boundary".into())
                .into_response_with_resource(&format!("/{bucket}"));
        }
    };

    // Body stream with errors mapped to io::Error so multer + StreamReader accept it.
    let stream = body
        .into_data_stream()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));
    // 'static lifetime because the body stream is owned ('static).
    let mut multipart = multer::Multipart::new(stream, boundary);

    let mut key: Option<String> = None;
    let mut object_ct = "application/octet-stream".to_string();
    let mut success_redirect: Option<String> = None;
    let mut success_status: Option<String> = None;

    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(_) => break,
        };

        let name = field.name().unwrap_or("").to_string();

        if name == "file" {
            let resolved_key = match key {
                Some(ref k) => {
                    if k.contains("${filename}") {
                        let fname = field.file_name().unwrap_or("upload").to_string();
                        k.replace("${filename}", &fname)
                    } else {
                        k.clone()
                    }
                }
                None => {
                    return S3Error::InvalidArgument("missing 'key' field".into())
                        .into_response_with_resource(&format!("/{bucket}"));
                }
            };

            let bucket_sse = state
                .store
                .get_bucket_encryption(&bucket)
                .await
                .ok()
                .flatten()
                .is_some();
            let encrypt = bucket_sse || state.config.encryption_enabled;

            // Stream field directly into storage — no memory buffering.
            let io_stream = field
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));
            let reader: crate::storage::BodyReader =
                Box::pin(StreamReader::new(io_stream));

            let result = state
                .store
                .put_object(
                    &bucket,
                    &resolved_key,
                    reader,
                    object_ct,
                    BTreeMap::new(),
                    encrypt,
                )
                .await;

            return match result {
                Err(e) => e.into_response_with_resource(&format!("/{bucket}/{resolved_key}")),
                Ok(meta) => build_post_response(
                    &bucket,
                    &resolved_key,
                    &meta.etag,
                    success_redirect.as_deref(),
                    success_status.as_deref(),
                ),
            };
        }

        // Collect text fields that precede the file field.
        let value = match field.text().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        match name.as_str() {
            "key" => key = Some(value),
            "Content-Type" => object_ct = value,
            "success_action_redirect" => success_redirect = Some(value),
            "success_action_status" => success_status = Some(value),
            _ => {} // policy, signature, x-amz-* conditions — accepted but not validated
        }
    }

    S3Error::InvalidArgument("missing 'file' field in multipart form".into())
        .into_response_with_resource(&format!("/{bucket}"))
}

/// Build the HTTP response for a successful POST Object upload.
///
/// # Parameters
/// - `bucket`: destination bucket name.
/// - `key`: resolved object key.
/// - `etag`: the object ETag (without quotes).
/// - `redirect`: optional `success_action_redirect` URL from the form.
/// - `status`: optional `success_action_status` ("200" or "201").
///
/// # Returns
/// 303 See Other (with `bucket`, `key`, `etag` query params appended to the
/// redirect URL), 200/201 `PostResponse` XML, or 204 No Content.
fn build_post_response(
    bucket: &str,
    key: &str,
    etag: &str,
    redirect: Option<&str>,
    status: Option<&str>,
) -> Response {
    let quoted = format!("\"{etag}\"");

    if let Some(url) = redirect {
        let sep = if url.contains('?') { '&' } else { '?' };
        let enc_etag =
            percent_encoding::utf8_percent_encode(&quoted, percent_encoding::NON_ALPHANUMERIC);
        let location = format!("{url}{sep}bucket={bucket}&key={key}&etag={enc_etag}");
        return (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response();
    }

    match status {
        Some(s @ ("200" | "201")) => {
            let code = if s == "201" { StatusCode::CREATED } else { StatusCode::OK };
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<PostResponse>\
<Location>/{bucket}/{key}</Location>\
<Bucket>{bucket}</Bucket>\
<Key>{key}</Key>\
<ETag>{quoted}</ETag>\
</PostResponse>"
            );
            xml_response(code, xml)
        }
        _ => StatusCode::NO_CONTENT.into_response(),
    }
}

// ── Utility ───────────────────────────────────────────────────────────────────

/// Read the request body into a byte vector (limit 8 MiB).
///
/// # Parameters
/// - `body`: the request body.
///
/// # Returns
/// `Ok(bytes)` or an `S3Error::InvalidArgument` if reading fails.
async fn read_body(body: Body) -> Result<bytes::Bytes, S3Error> {
    axum::body::to_bytes(body, 8 << 20)
        .await
        .map_err(|e| S3Error::InvalidArgument(format!("body read error: {e}")))
}
