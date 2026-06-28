//! Multipart-upload handlers. These are invoked by the object dispatchers in
//! [`super::object`] once the relevant query sub-resource is detected.

use axum::body::Body;
use axum::http::header::ETAG;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use super::{content_type_of, extract_user_metadata, sse_requested, quote_etag, xml_response};
use crate::auth::body_to_reader;
use crate::error::S3Error;
use crate::s3::iso8601;
use crate::s3::xml::{
    self, CompleteMultipartUpload, CompleteMultipartUploadResult, InitiateMultipartUploadResult,
    ListPartsResult, PartXml, S3_NS,
};
use crate::state::AppState;
use crate::storage::CompletedPart;

/// Maximum accepted size for a multipart control body (part list).
const CONTROL_BODY_LIMIT: usize = 1 << 20; // 1 MiB

/// Handle `POST /{bucket}/{key}?uploads` — initiate a multipart upload.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: destination bucket.
/// - `key`: destination key.
/// - `headers`: request headers (content type / user metadata to persist).
///
/// # Returns
/// A `200 OK` `InitiateMultipartUploadResult` document, or an S3 error.
pub async fn create(
    state: AppState,
    bucket: String,
    key: String,
    headers: &axum::http::HeaderMap,
) -> Response {
    let content_type = content_type_of(headers);
    let user_metadata = extract_user_metadata(headers);
    // Propagate SSE intent into the manifest so complete_multipart encrypts.
    let sse_hdr = sse_requested(headers);
    let bucket_sse = state
        .store
        .get_bucket_encryption(&bucket)
        .await
        .ok()
        .flatten()
        .is_some();
    let encrypt = sse_hdr || bucket_sse || state.config.encryption_enabled;
    match state
        .store
        .create_multipart(&bucket, &key, content_type, user_metadata, encrypt)
        .await
    {
        Ok(upload_id) => {
            let result = InitiateMultipartUploadResult {
                xmlns: S3_NS,
                bucket,
                key,
                upload_id,
            };
            xml_response(
                StatusCode::OK,
                xml::to_xml("InitiateMultipartUploadResult", &result),
            )
        }
        Err(e) => e.into_response_with_resource(&format!("/{bucket}/{key}")),
    }
}

/// Handle `PUT /{bucket}/{key}?partNumber=N&uploadId=...` — upload one part.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: destination bucket.
/// - `key`: destination key.
/// - `upload_id`: the multipart upload id.
/// - `part_number`: the part number as a string (validated to be ≥ 1).
/// - `body`: the part payload.
///
/// # Returns
/// A `200 OK` with the part's `ETag` header, or an S3 error response.
pub async fn upload_part(
    state: AppState,
    bucket: String,
    key: String,
    upload_id: String,
    part_number: String,
    body: Body,
) -> Response {
    let part_number = match part_number.parse::<u32>() {
        Ok(n) if (1..=10_000).contains(&n) => n,
        _ => {
            return S3Error::InvalidArgument("invalid partNumber".into())
                .into_response_with_resource(&format!("/{bucket}/{key}"))
        }
    };
    match state
        .store
        .upload_part(&bucket, &key, &upload_id, part_number, body_to_reader(body))
        .await
    {
        Ok(etag) => (StatusCode::OK, [(ETAG, quote_etag(&etag))]).into_response(),
        Err(e) => e.into_response_with_resource(&format!("/{bucket}/{key}")),
    }
}

/// Handle `POST /{bucket}/{key}?uploadId=...` — complete a multipart upload.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: destination bucket.
/// - `key`: destination key.
/// - `upload_id`: the multipart upload id.
/// - `body`: the XML body listing parts (number + ETag) in assembly order.
///
/// # Returns
/// A `200 OK` `CompleteMultipartUploadResult` document, or an S3 error.
pub async fn complete(
    state: AppState,
    bucket: String,
    key: String,
    upload_id: String,
    body: Body,
) -> Response {
    let resource = format!("/{bucket}/{key}");
    let bytes = match axum::body::to_bytes(body, CONTROL_BODY_LIMIT).await {
        Ok(b) => b,
        Err(_) => {
            return S3Error::InvalidArgument("could not read body".into())
                .into_response_with_resource(&resource)
        }
    };
    let parsed: CompleteMultipartUpload = match xml::from_xml(&String::from_utf8_lossy(&bytes)) {
        Ok(p) => p,
        Err(e) => {
            return S3Error::InvalidArgument(format!("malformed CompleteMultipartUpload: {e}"))
                .into_response_with_resource(&resource)
        }
    };
    let parts: Vec<CompletedPart> = parsed
        .parts
        .into_iter()
        .map(|p| CompletedPart {
            part_number: p.part_number,
            etag: p.etag,
        })
        .collect();

    match state
        .store
        .complete_multipart(&bucket, &key, &upload_id, parts)
        .await
    {
        Ok(meta) => {
            let result = CompleteMultipartUploadResult {
                xmlns: S3_NS,
                location: format!("/{bucket}/{key}"),
                bucket,
                key,
                etag: quote_etag(&meta.etag),
            };
            xml_response(
                StatusCode::OK,
                xml::to_xml("CompleteMultipartUploadResult", &result),
            )
        }
        Err(e) => e.into_response_with_resource(&resource),
    }
}

/// Handle `DELETE /{bucket}/{key}?uploadId=...` — abort a multipart upload.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: destination bucket.
/// - `key`: destination key.
/// - `upload_id`: the multipart upload id.
///
/// # Returns
/// `204 No Content` on success, or an S3 error response.
pub async fn abort(state: AppState, bucket: String, key: String, upload_id: String) -> Response {
    match state
        .store
        .abort_multipart(&bucket, &key, &upload_id)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response_with_resource(&format!("/{bucket}/{key}")),
    }
}

/// Handle `GET /{bucket}/{key}?uploadId=...` — list uploaded parts.
///
/// # Parameters
/// - `state`: shared application state.
/// - `bucket`: destination bucket.
/// - `key`: destination key.
/// - `upload_id`: the multipart upload id.
///
/// # Returns
/// A `200 OK` `ListPartsResult` document, or an S3 error response.
pub async fn list_parts(
    state: AppState,
    bucket: String,
    key: String,
    upload_id: String,
) -> Response {
    match state.store.list_parts(&bucket, &key, &upload_id).await {
        Ok(parts) => {
            let result = ListPartsResult {
                xmlns: S3_NS,
                bucket,
                key,
                upload_id,
                part: parts
                    .into_iter()
                    .map(|p| PartXml {
                        part_number: p.part_number,
                        last_modified: iso8601(p.last_modified),
                        etag: quote_etag(&p.etag),
                        size: p.size,
                    })
                    .collect(),
            };
            xml_response(StatusCode::OK, xml::to_xml("ListPartsResult", &result))
        }
        Err(e) => e.into_response_with_resource(&format!("/{bucket}/{key}")),
    }
}
