//! HTTP handlers implementing the S3 API surface, grouped by resource.

pub mod admin;
pub mod bucket;
pub mod multipart;
pub mod object;
pub mod sts;

use std::collections::{BTreeMap, HashMap};

use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};

/// The `x-amz-server-side-encryption` header name (shared by object + multipart).
pub(super) const X_AMZ_SSE: &str = "x-amz-server-side-encryption";

/// Returns `true` if the request carries `x-amz-server-side-encryption: AES256`.
///
/// # Parameters
/// - `headers`: the incoming request headers.
pub(super) fn sse_requested(headers: &HeaderMap) -> bool {
    headers
        .get(X_AMZ_SSE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("AES256"))
        .unwrap_or(false)
}

/// Characters left un-encoded when URL-encoding object keys for
/// `encoding-type=url` list responses: the RFC 3986 unreserved set plus `/`.
const KEY_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'/');

/// Percent-decode a string into an owned `String`, lossily for invalid UTF-8.
///
/// # Parameters
/// - `s`: the percent-encoded input.
///
/// # Returns
/// The decoded string.
fn percent_decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

/// Parse a raw URI query string into a map of decoded key/value pairs.
///
/// Bare flags (e.g. `?uploads`, `?delete`) are stored with an empty value.
///
/// # Parameters
/// - `raw`: the raw query string from the request URI, if present.
///
/// # Returns
/// A map from decoded parameter name to decoded value.
pub fn parse_query(raw: Option<&str>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(q) = raw {
        for pair in q.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            map.insert(percent_decode(k), percent_decode(v));
        }
    }
    map
}

/// Collect user metadata (`x-amz-meta-*` headers) into a map with the prefix
/// stripped from each key.
///
/// # Parameters
/// - `headers`: the incoming request headers.
///
/// # Returns
/// A map of metadata name (without the `x-amz-meta-` prefix) to value.
pub fn extract_user_metadata(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut meta = BTreeMap::new();
    for (name, value) in headers.iter() {
        let name = name.as_str();
        if let Some(suffix) = name.strip_prefix("x-amz-meta-") {
            if let Ok(v) = value.to_str() {
                meta.insert(suffix.to_string(), v.to_string());
            }
        }
    }
    meta
}

/// Determine the request's declared content type, defaulting to a binary type.
///
/// # Parameters
/// - `headers`: the incoming request headers.
///
/// # Returns
/// The `Content-Type` value, or `application/octet-stream` if absent.
pub fn content_type_of(headers: &HeaderMap) -> String {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string()
}

/// Build an `application/xml` HTTP response.
///
/// # Parameters
/// - `status`: the HTTP status code.
/// - `body`: the XML document body.
///
/// # Returns
/// A [`Response`] with the XML content type and the given status and body.
pub fn xml_response(status: StatusCode, body: String) -> Response {
    (status, [(header::CONTENT_TYPE, "application/xml")], body).into_response()
}

/// URL-encode an object key/prefix for `encoding-type=url` list responses.
///
/// # Parameters
/// - `s`: the raw key or prefix.
///
/// # Returns
/// The value percent-encoded, leaving unreserved characters and `/` intact.
pub fn encode_key(s: &str) -> String {
    utf8_percent_encode(s, KEY_ENCODE_SET).to_string()
}

/// Quote an ETag value as S3 does on the wire (e.g. `"<md5>"`).
///
/// # Parameters
/// - `etag`: the raw ETag value.
///
/// # Returns
/// The ETag wrapped in double quotes.
pub fn quote_etag(etag: &str) -> String {
    format!("\"{etag}\"")
}
