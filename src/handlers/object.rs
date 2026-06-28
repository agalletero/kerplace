//! Object-level handlers: PUT/GET/HEAD/DELETE plus server-side copy and
//! `Range` reads. Sub-resources selected by query string (`uploadId`,
//! `partNumber`, `uploads`) are dispatched to the multipart handlers.

use axum::body::Body;
use axum::extract::{Path, RawQuery, State};
use axum::http::header::{
    ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, LAST_MODIFIED, RANGE,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use tokio_util::io::ReaderStream;

use super::{bucket, multipart};
use super::{
    content_type_of, extract_user_metadata, parse_query, quote_etag, sse_requested, xml_response,
    X_AMZ_SSE,
};
use crate::auth::body_to_reader;
use crate::error::S3Error;
use crate::s3::http_date;
use crate::s3::xml::{self, LegalHold, ObjectRetention, Tag, TagSet, Tagging};
use crate::state::AppState;
use crate::storage::ObjectMeta;

/// Build the standard response headers describing an object.
///
/// Adds `x-amz-server-side-encryption: AES256` when the object is encrypted.
///
/// # Parameters
/// - `meta`: the object's metadata.
///
/// # Returns
/// A [`HeaderMap`] with `Content-Type`, `ETag`, `Last-Modified`,
/// `Accept-Ranges`, optional SSE header, and any `x-amz-meta-*` user metadata.
fn object_headers(meta: &ObjectMeta) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&meta.content_type) {
        headers.insert(CONTENT_TYPE, v);
    }
    if let Ok(v) = HeaderValue::from_str(&quote_etag(&meta.etag)) {
        headers.insert(ETAG, v);
    }
    if let Ok(v) = HeaderValue::from_str(&http_date(meta.last_modified)) {
        headers.insert(LAST_MODIFIED, v);
    }
    headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if meta.encrypted {
        if let Ok(name) = HeaderName::from_bytes(X_AMZ_SSE.as_bytes()) {
            headers.insert(name, HeaderValue::from_static("AES256"));
        }
    }
    if let Some(vid) = &meta.version_id {
        if let Ok(v) = HeaderValue::from_str(vid) {
            headers.insert(HeaderName::from_static("x-amz-version-id"), v);
        }
    }
    // KerPlace audit trail: who wrote this version and from where. Custom
    // `x-kerplace-*` headers — unknown to S3 clients, so they ignore them.
    if let Some(audit) = &meta.audit {
        if let Some(author) = &audit.author {
            if let Ok(v) = HeaderValue::from_str(author) {
                headers.insert(HeaderName::from_static("x-kerplace-author"), v);
            }
        }
        if let Some(ip) = &audit.source_ip {
            if let Ok(v) = HeaderValue::from_str(ip) {
                headers.insert(HeaderName::from_static("x-kerplace-source-ip"), v);
            }
        }
    }
    for (k, val) in &meta.user_metadata {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(format!("x-amz-meta-{k}").as_bytes()),
            HeaderValue::from_str(val),
        ) {
            headers.insert(name, value);
        }
    }
    headers
}


/// Parse an HTTP `Range` header value of the form `bytes=...`.
///
/// # Parameters
/// - `value`: the raw `Range` header value.
///
/// # Returns
/// `Some((start, end))` where either bound may be `None` (open-ended start
/// means a suffix length, open-ended end means "to end of object"), or `None`
/// if the value is not a single, well-formed byte range.
fn parse_range(value: &str) -> Option<(Option<u64>, Option<u64>)> {
    let spec = value.strip_prefix("bytes=")?;
    // Only a single range is supported in v0.1.
    if spec.contains(',') {
        return None;
    }
    let (start, end) = spec.split_once('-')?;
    let start = if start.is_empty() {
        None
    } else {
        Some(start.parse::<u64>().ok()?)
    };
    let end = if end.is_empty() {
        None
    } else {
        Some(end.parse::<u64>().ok()?)
    };
    if start.is_none() && end.is_none() {
        return None;
    }
    Some((start, end))
}

/// Handle `PUT /{bucket}/{key}` — dispatch to upload-part, server-side copy or
/// a plain object write depending on query/headers.
///
/// # Parameters
/// - `state`: shared application state.
/// - `path`: `(bucket, key)` from the path.
/// - `headers`: request headers (copy source, content type, user metadata).
/// - `query`: raw query string (`partNumber`/`uploadId` select upload-part).
/// - `body`: the request body (already de-chunked by middleware).
///
/// # Returns
/// The appropriate S3 response for the selected operation.
pub async fn put_object_dispatch(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Body,
) -> Response {
    let params = parse_query(query.as_deref());

    // A trailing-slash request (`PUT /{bucket}/`) carries an empty key and is
    // a bucket create in S3 path-style addressing.
    if key.is_empty() {
        return bucket::create_bucket_inner(state, bucket).await;
    }

    if let (Some(part_number), Some(upload_id)) =
        (params.get("partNumber"), params.get("uploadId"))
    {
        return multipart::upload_part(state, bucket, key, upload_id.clone(), part_number.clone(), body)
            .await;
    }

    if params.contains_key("tagging") {
        return handle_object_tagging(state, bucket, key, "PUT", body).await;
    }
    if params.contains_key("retention") {
        return put_object_retention(state, bucket, key, body).await;
    }
    if params.contains_key("legal-hold") {
        return put_object_legal_hold(state, bucket, key, body).await;
    }

    if let Some(source) = headers.get("x-amz-copy-source").and_then(|v| v.to_str().ok()) {
        return copy_object(state, bucket, key, source, &headers).await;
    }

    // Decide whether to encrypt: SSE header OR bucket default SSE config.
    let sse_hdr = sse_requested(&headers);
    let bucket_sse = state
        .store
        .get_bucket_encryption(&bucket)
        .await
        .ok()
        .flatten()
        .is_some();
    let encrypt = sse_hdr || bucket_sse || state.config.encryption_enabled;

    let content_type = content_type_of(&headers);
    let user_metadata = extract_user_metadata(&headers);
    match state
        .store
        .put_object(&bucket, &key, body_to_reader(body), content_type, user_metadata, encrypt)
        .await
    {
        Ok(meta) => {
            let mut h = HeaderMap::new();
            if let Ok(v) = HeaderValue::from_str(&quote_etag(&meta.etag)) {
                h.insert(ETAG, v);
            }
            if meta.encrypted {
                if let Ok(name) = HeaderName::from_bytes(X_AMZ_SSE.as_bytes()) {
                    h.insert(name, HeaderValue::from_static("AES256"));
                }
            }
            if let Some(vid) = &meta.version_id {
                if let Ok(v) = HeaderValue::from_str(vid) {
                    h.insert(HeaderName::from_static("x-amz-version-id"), v);
                }
            }
            (StatusCode::OK, h).into_response()
        }
        Err(e) => e.into_response_with_resource(&format!("/{bucket}/{key}")),
    }
}

/// Handle `GET/PUT/DELETE /{bucket}/{key}?tagging` — object tag operations.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name.
/// - `key`: object key.
/// - `method`: the HTTP method as a string.
/// - `body`: the raw request body (used for PUT).
///
/// # Returns
/// The appropriate XML response or `204 No Content`.
async fn handle_object_tagging(
    state: AppState,
    bucket: String,
    key: String,
    method: &str,
    body: Body,
) -> Response {
    let resource = format!("/{bucket}/{key}");
    match method {
        "GET" => match state.store.get_object_tags(&bucket, &key).await {
            Ok(tags) => {
                let tag_vec: Vec<Tag> = tags
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(k, v)| Tag { key: k, value: v })
                    .collect();
                let body = Tagging { tag_set: TagSet { tags: tag_vec } };
                xml_response(StatusCode::OK, xml::to_xml("Tagging", &body))
            }
            Err(e) => e.into_response_with_resource(&resource),
        },
        "PUT" => {
            let bytes = match axum::body::to_bytes(body, 1 << 20).await {
                Ok(b) => b,
                Err(_) => return S3Error::InvalidArgument("bad body".into())
                    .into_response_with_resource(&resource),
            };
            let parsed: Tagging = match xml::from_xml(&String::from_utf8_lossy(&bytes)) {
                Ok(t) => t,
                Err(e) => return S3Error::InvalidArgument(format!("bad Tagging: {e}"))
                    .into_response_with_resource(&resource),
            };
            let tags: std::collections::BTreeMap<String, String> = parsed
                .tag_set
                .tags
                .into_iter()
                .map(|t| (t.key, t.value))
                .collect();
            match state.store.set_object_tags(&bucket, &key, tags).await {
                Ok(()) => StatusCode::OK.into_response(),
                Err(e) => e.into_response_with_resource(&resource),
            }
        }
        "DELETE" => match state.store.delete_object_tags(&bucket, &key).await {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(e) => e.into_response_with_resource(&resource),
        },
        _ => S3Error::NotImplemented.into_response_with_resource(&resource),
    }
}

/// Perform a server-side copy from the `x-amz-copy-source` reference.
///
/// # Parameters
/// - `state`: shared application state.
/// - `dst_bucket`: destination bucket.
/// - `dst_key`: destination key.
/// - `source`: the raw `x-amz-copy-source` header (`/src-bucket/src-key`).
/// - `req_headers`: the full PUT request headers (used to detect SSE for dst).
///
/// # Returns
/// A `200 OK` `CopyObjectResult` document, or an S3 error response.
async fn copy_object(
    state: AppState,
    dst_bucket: String,
    dst_key: String,
    source: &str,
    req_headers: &HeaderMap,
) -> Response {
    // Strip any leading slash and trailing `?versionId=...`, then split.
    let trimmed = source.trim_start_matches('/');
    let trimmed = trimmed.split('?').next().unwrap_or(trimmed);
    let decoded =
        percent_encoding::percent_decode_str(trimmed).decode_utf8_lossy().into_owned();
    let (src_bucket, src_key) = match decoded.split_once('/') {
        Some((b, k)) => (b.to_string(), k.to_string()),
        None => {
            return S3Error::InvalidArgument("malformed x-amz-copy-source".into())
                .into_response_with_resource(&format!("/{dst_bucket}/{dst_key}"));
        }
    };

    // Determine encryption for the destination.
    let sse_hdr = sse_requested(req_headers);
    let bucket_sse = state
        .store
        .get_bucket_encryption(&dst_bucket)
        .await
        .ok()
        .flatten()
        .is_some();
    let encrypt = sse_hdr || bucket_sse || state.config.encryption_enabled;

    match state
        .store
        .copy_object(&src_bucket, &src_key, &dst_bucket, &dst_key, encrypt)
        .await
    {
        Ok(meta) => {
            let result = crate::s3::xml::CopyObjectResult {
                xmlns: crate::s3::xml::S3_NS,
                last_modified: crate::s3::iso8601(meta.last_modified),
                etag: quote_etag(&meta.etag),
            };
            super::xml_response(
                StatusCode::OK,
                crate::s3::xml::to_xml("CopyObjectResult", &result),
            )
        }
        Err(e) => e.into_response_with_resource(&format!("/{dst_bucket}/{dst_key}")),
    }
}

/// Handle `GET /{bucket}/{key}` — dispatch to list-parts, tagging, or read the
/// object (optionally a byte range).
///
/// # Parameters
/// - `state`: shared application state.
/// - `path`: `(bucket, key)` from the path.
/// - `headers`: request headers (used for `Range`).
/// - `query`: raw query string (`uploadId` selects list-parts).
///
/// # Returns
/// A streaming `200 OK` (or `206 Partial Content`) response, or an S3 error.
pub async fn get_object_dispatch(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let params = parse_query(query.as_deref());
    // `GET /{bucket}/` (empty key) lists the bucket.
    if key.is_empty() {
        return bucket::list_objects_inner(state, bucket, params).await;
    }
    if let Some(upload_id) = params.get("uploadId") {
        return multipart::list_parts(state, bucket, key, upload_id.clone()).await;
    }
    if params.contains_key("tagging") {
        return handle_object_tagging(state, bucket, key, "GET", Body::empty()).await;
    }
    if params.contains_key("retention") {
        return get_object_retention(state, bucket, key).await;
    }
    if params.contains_key("legal-hold") {
        return get_object_legal_hold(state, bucket, key).await;
    }
    // `GET ...?versionId=X` reads a specific version (ignores Range in v0.1).
    if let Some(vid) = params.get("versionId") {
        return get_object_version_response(state, bucket, key, vid).await;
    }

    let resource = format!("/{bucket}/{key}");
    let range = headers
        .get(RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_range);

    if let Some((start, end)) = range {
        // Resolve a concrete absolute range against the object size.
        let size = match state.store.head_object(&bucket, &key).await {
            Ok(m) => m.size,
            Err(e) => return e.into_response_with_resource(&resource),
        };
        let (abs_start, abs_last) = match (start, end) {
            (Some(s), Some(e)) => (s.min(size), e.min(size.saturating_sub(1))),
            (Some(s), None) => (s.min(size), size.saturating_sub(1)),
            (None, Some(n)) => (size.saturating_sub(n.min(size)), size.saturating_sub(1)),
            (None, None) => (0, size.saturating_sub(1)),
        };
        match state
            .store
            .get_object_range(&bucket, &key, abs_start, Some(abs_last))
            .await
        {
            Ok((meta, len, body)) => {
                let mut h = object_headers(&meta);
                if let Ok(v) = HeaderValue::from_str(&len.to_string()) {
                    h.insert(CONTENT_LENGTH, v);
                }
                if let Ok(v) =
                    HeaderValue::from_str(&format!("bytes {abs_start}-{abs_last}/{size}"))
                {
                    h.insert(CONTENT_RANGE, v);
                }
                let stream = Body::from_stream(ReaderStream::new(body));
                (StatusCode::PARTIAL_CONTENT, h, stream).into_response()
            }
            Err(e) => e.into_response_with_resource(&resource),
        }
    } else {
        match state.store.get_object(&bucket, &key).await {
            Ok((meta, body)) => {
                let mut h = object_headers(&meta);
                if let Ok(v) = HeaderValue::from_str(&meta.size.to_string()) {
                    h.insert(CONTENT_LENGTH, v);
                }
                let stream = Body::from_stream(ReaderStream::new(body));
                (StatusCode::OK, h, stream).into_response()
            }
            Err(e) => e.into_response_with_resource(&resource),
        }
    }
}

/// Handle `HEAD /{bucket}/{key}` — return object metadata headers, no body.
///
/// # Parameters
/// - `state`: shared application state.
/// - `path`: `(bucket, key)` from the path.
/// - `query`: raw query string (`versionId` selects a specific version).
///
/// # Returns
/// A `200 OK` with object headers, or an S3 error response.
pub async fn head_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> Response {
    // `HEAD /{bucket}/` (empty key) tests the bucket.
    if key.is_empty() {
        return bucket::head_bucket_inner(state, bucket).await;
    }
    let params = parse_query(query.as_deref());
    let result = match params.get("versionId") {
        Some(vid) => state.store.head_object_version(&bucket, &key, vid).await,
        None => state.store.head_object(&bucket, &key).await,
    };
    match result {
        Ok(meta) => {
            let mut h = object_headers(&meta);
            if let Ok(v) = HeaderValue::from_str(&meta.size.to_string()) {
                h.insert(CONTENT_LENGTH, v);
            }
            (StatusCode::OK, h).into_response()
        }
        Err(e) => e.into_response_with_resource(&format!("/{bucket}/{key}")),
    }
}

/// Handle `DELETE /{bucket}/{key}` — dispatch to abort-multipart, tagging, or
/// delete the object.
///
/// # Parameters
/// - `state`: shared application state.
/// - `path`: `(bucket, key)` from the path.
/// - `query`: raw query string (`uploadId` selects abort-multipart).
///
/// # Returns
/// `204 No Content` on success, or an S3 error response.
pub async fn delete_object_dispatch(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> Response {
    let params = parse_query(query.as_deref());
    // `DELETE /{bucket}/` (empty key) deletes the bucket.
    if key.is_empty() {
        return bucket::delete_bucket_inner(state, bucket).await;
    }
    if let Some(upload_id) = params.get("uploadId") {
        return multipart::abort(state, bucket, key, upload_id.clone()).await;
    }
    if params.contains_key("tagging") {
        return handle_object_tagging(state, bucket, key, "DELETE", Body::empty()).await;
    }
    let resource = format!("/{bucket}/{key}");

    // `DELETE ...?versionId=X` permanently removes a single version/marker.
    if let Some(vid) = params.get("versionId") {
        // Object lock is enforced per-version on the current version only.
        if let Err(e) = check_object_lock(&state, &bucket, &key).await {
            return e.into_response_with_resource(&resource);
        }
        return match state.store.delete_object_version(&bucket, &key, vid).await {
            Ok(outcome) => delete_response(outcome),
            Err(e) => e.into_response_with_resource(&resource),
        };
    }

    // Enforce object lock before allowing the delete.
    if let Err(e) = check_object_lock(&state, &bucket, &key).await {
        return e.into_response_with_resource(&resource);
    }
    match state.store.delete_object(&bucket, &key).await {
        Ok(outcome) => delete_response(outcome),
        Err(e) => e.into_response_with_resource(&resource),
    }
}

/// Build a `204 No Content` delete response, attaching `x-amz-version-id` and
/// `x-amz-delete-marker` headers when a versioned delete created or removed a
/// marker.
///
/// # Parameters
/// - `outcome`: the storage layer's [`crate::storage::DeleteOutcome`].
///
/// # Returns
/// A `204 No Content` response with any versioning headers set.
fn delete_response(outcome: crate::storage::DeleteOutcome) -> Response {
    let mut h = HeaderMap::new();
    if let Some(vid) = &outcome.version_id {
        if let Ok(v) = HeaderValue::from_str(vid) {
            h.insert(HeaderName::from_static("x-amz-version-id"), v);
        }
    }
    if outcome.delete_marker {
        h.insert(
            HeaderName::from_static("x-amz-delete-marker"),
            HeaderValue::from_static("true"),
        );
    }
    (StatusCode::NO_CONTENT, h).into_response()
}

/// Handle `POST /{bucket}/{key}` — dispatch to create- or
/// complete-multipart-upload.
///
/// # Parameters
/// - `state`: shared application state.
/// - `path`: `(bucket, key)` from the path.
/// - `headers`: request headers (content type / user metadata on create).
/// - `query`: raw query string (`uploads` or `uploadId`).
/// - `body`: request body (the part list, on complete).
///
/// # Returns
/// The appropriate multipart response, or [`S3Error::NotImplemented`].
pub async fn post_object_dispatch(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Body,
) -> Response {
    let params = parse_query(query.as_deref());
    // `POST /{bucket}/` (empty key) is a bucket-level sub-resource, e.g.
    // batch `DeleteObjects` (`?delete`).
    if key.is_empty() {
        let body_str = match axum::body::to_bytes(body, 16 << 20).await {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(_) => String::new(),
        };
        return bucket::post_bucket_inner(state, bucket, params, body_str).await;
    }
    if params.contains_key("uploads") {
        return multipart::create(state, bucket, key, &headers).await;
    }
    if let Some(upload_id) = params.get("uploadId") {
        return multipart::complete(state, bucket, key, upload_id.clone(), body).await;
    }
    if params.contains_key("tagging") {
        return handle_object_tagging(state, bucket, key, "PUT", body).await;
    }
    S3Error::NotImplemented.into_response_with_resource(&format!("/{bucket}/{key}"))
}

// ── Object lock: retention + legal hold ───────────────────────────────────────

/// Check whether an object is currently protected by a legal hold or an active
/// retention period.  Called before any delete operation.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket containing the object.
/// - `key`: object key to check.
///
/// # Returns
/// `Ok(())` if the object may be deleted; `Err(S3Error::ObjectLocked)` if a
/// legal hold is active or the retention date has not yet passed.
async fn check_object_lock(
    state: &AppState,
    bucket: &str,
    key: &str,
) -> Result<(), S3Error> {
    // Legal hold takes precedence: any "ON" hold blocks unconditionally.
    if let Ok(Some(status)) = state.store.get_object_legal_hold(bucket, key).await {
        if status.eq_ignore_ascii_case("ON") {
            return Err(S3Error::ObjectLocked);
        }
    }

    // Retention: parse the stored date and compare to now.
    if let Ok(Some(raw)) = state.store.get_object_retention(bucket, key).await {
        if let Ok(r) = xml::from_xml::<ObjectRetention>(&raw) {
            if let Some(date_str) = r.retain_until_date {
                let until = time::OffsetDateTime::parse(
                    &date_str,
                    &time::format_description::well_known::Rfc3339,
                );
                if let Ok(dt) = until {
                    if dt > time::OffsetDateTime::now_utc() {
                        return Err(S3Error::ObjectLocked);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Handle `GET /{bucket}/{key}?retention` — return the object's retention config.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name.
/// - `key`: object key.
///
/// # Returns
/// `200 OK` with a `Retention` XML document, or an S3 error response.
async fn get_object_retention(state: AppState, bucket: String, key: String) -> Response {
    let resource = format!("/{bucket}/{key}");
    match state.store.get_object_retention(&bucket, &key).await {
        Err(e) => e.into_response_with_resource(&resource),
        Ok(None) => {
            // No retention set — return an empty Retention document (not 404).
            xml_response(
                StatusCode::OK,
                xml::to_xml("Retention", &ObjectRetention::default()),
            )
        }
        Ok(Some(raw)) => {
            // Raw JSON stored by put_object_retention; convert back to XML for the response.
            match xml::from_xml::<ObjectRetention>(&raw) {
                Ok(r) => xml_response(StatusCode::OK, xml::to_xml("Retention", &r)),
                Err(_) => xml_response(
                    StatusCode::OK,
                    xml::to_xml("Retention", &ObjectRetention::default()),
                ),
            }
        }
    }
}

/// Handle `PUT /{bucket}/{key}?retention` — set the object's retention config.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name.
/// - `key`: object key.
/// - `body`: XML `Retention` document.
///
/// # Returns
/// `200 OK` on success, or an S3 error response.
async fn put_object_retention(
    state: AppState,
    bucket: String,
    key: String,
    body: Body,
) -> Response {
    let resource = format!("/{bucket}/{key}");
    let bytes = match axum::body::to_bytes(body, 1 << 20).await {
        Ok(b) => b,
        Err(_) => {
            return S3Error::InvalidArgument("bad body".into())
                .into_response_with_resource(&resource)
        }
    };
    let parsed: ObjectRetention = match xml::from_xml(&String::from_utf8_lossy(&bytes)) {
        Ok(r) => r,
        Err(e) => {
            return S3Error::InvalidArgument(format!("bad Retention XML: {e}"))
                .into_response_with_resource(&resource)
        }
    };
    // Store the retention as XML so get_object_retention can re-parse it.
    let to_store = xml::to_xml("Retention", &parsed);
    match state.store.set_object_retention(&bucket, &key, to_store).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => e.into_response_with_resource(&resource),
    }
}

/// Handle `GET /{bucket}/{key}?legal-hold` — return the object's legal hold status.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name.
/// - `key`: object key.
///
/// # Returns
/// `200 OK` with a `LegalHold` XML document, or an S3 error response.
async fn get_object_legal_hold(state: AppState, bucket: String, key: String) -> Response {
    let resource = format!("/{bucket}/{key}");
    match state.store.get_object_legal_hold(&bucket, &key).await {
        Err(e) => e.into_response_with_resource(&resource),
        Ok(status) => {
            let hold = LegalHold { status: status.unwrap_or_else(|| "OFF".to_string()) };
            xml_response(StatusCode::OK, xml::to_xml("LegalHold", &hold))
        }
    }
}

/// Handle `PUT /{bucket}/{key}?legal-hold` — set the object's legal hold status.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name.
/// - `key`: object key.
/// - `body`: XML `LegalHold` document containing `<Status>ON</Status>` or `OFF`.
///
/// # Returns
/// `200 OK` on success, or an S3 error response.
async fn put_object_legal_hold(
    state: AppState,
    bucket: String,
    key: String,
    body: Body,
) -> Response {
    let resource = format!("/{bucket}/{key}");
    let bytes = match axum::body::to_bytes(body, 1 << 20).await {
        Ok(b) => b,
        Err(_) => {
            return S3Error::InvalidArgument("bad body".into())
                .into_response_with_resource(&resource)
        }
    };
    let parsed: LegalHold = match xml::from_xml(&String::from_utf8_lossy(&bytes)) {
        Ok(h) => h,
        Err(e) => {
            return S3Error::InvalidArgument(format!("bad LegalHold XML: {e}"))
                .into_response_with_resource(&resource)
        }
    };
    let status = parsed.status.to_uppercase();
    if status != "ON" && status != "OFF" {
        return S3Error::InvalidArgument("LegalHold Status must be ON or OFF".into())
            .into_response_with_resource(&resource);
    }
    match state.store.set_object_legal_hold(&bucket, &key, &status).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => e.into_response_with_resource(&resource),
    }
}

// ── Versioning ────────────────────────────────────────────────────────────────

/// Handle `GET /{bucket}/{key}?versionId=X` — stream a specific object version.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: bucket name.
/// - `key`: object key.
/// - `version_id`: the version to read.
///
/// # Returns
/// A streaming `200 OK` with the version's bytes and `x-amz-version-id`, or an
/// S3 error (`404 NoSuchVersion`, `405` for a delete marker).
async fn get_object_version_response(
    state: AppState,
    bucket: String,
    key: String,
    version_id: &str,
) -> Response {
    let resource = format!("/{bucket}/{key}");
    match state.store.get_object_version(&bucket, &key, version_id).await {
        Ok((meta, body)) => {
            let mut h = object_headers(&meta);
            if let Ok(v) = HeaderValue::from_str(&meta.size.to_string()) {
                h.insert(CONTENT_LENGTH, v);
            }
            let stream = Body::from_stream(ReaderStream::new(body));
            (StatusCode::OK, h, stream).into_response()
        }
        Err(e) => e.into_response_with_resource(&resource),
    }
}
