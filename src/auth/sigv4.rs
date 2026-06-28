//! AWS Signature Version 4 verification (header-based authorization).
//!
//! Implements the canonical-request / string-to-sign / signing-key derivation
//! described by the AWS SigV4 spec, sufficient to authenticate `aws` CLI and
//! `mc` requests against a single root credential. Presigned-URL (query)
//! authorization is not implemented in v0.1.

use axum::http::{HeaderMap, Method, Uri};
use hmac::{Hmac, Mac};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use sha2::{Digest, Sha256};
use time::format_description::FormatItem;
use time::macros::format_description;
use time::{Duration, OffsetDateTime, PrimitiveDateTime};

use crate::error::S3Error;
use crate::iam::{Identity, IamStore};

type HmacSha256 = Hmac<Sha256>;

/// Format of the `X-Amz-Date` / `x-amz-date` timestamp (e.g. `20130524T000000Z`).
const AMZ_DATETIME: &[FormatItem<'_>] =
    format_description!("[year][month][day]T[hour][minute][second]Z");

/// The fields parsed out of an `Authorization: AWS4-HMAC-SHA256 ...` header.
struct ParsedAuth {
    access_key: String,
    date: String,
    region: String,
    service: String,
    signed_headers: Vec<String>,
    signature: String,
}

/// Compute the lowercase hex SHA-256 of a byte slice.
///
/// # Parameters
/// - `data`: the bytes to hash.
///
/// # Returns
/// A 64-character lowercase hex string.
fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Compute HMAC-SHA256 of `data` under `key`.
///
/// # Parameters
/// - `key`: the secret key bytes.
/// - `data`: the message bytes.
///
/// # Returns
/// The 32-byte MAC.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Derive the SigV4 signing key for a given credential scope.
///
/// # Parameters
/// - `secret`: the secret access key.
/// - `date`: the scope date in `YYYYMMDD` form.
/// - `region`: the scope region (e.g. `us-east-1`).
/// - `service`: the scope service (always `s3` here).
///
/// # Returns
/// The 32-byte signing key.
fn derive_signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// Parse the `Authorization` header value into its components.
///
/// # Parameters
/// - `value`: the full header value, beginning with `AWS4-HMAC-SHA256`.
///
/// # Returns
/// A [`ParsedAuth`] on success, or [`S3Error::AuthorizationHeaderMalformed`]
/// if any required component is missing or malformed.
fn parse_authorization(value: &str) -> Result<ParsedAuth, S3Error> {
    let rest = value
        .strip_prefix("AWS4-HMAC-SHA256")
        .ok_or(S3Error::AuthorizationHeaderMalformed)?
        .trim_start();

    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for part in rest.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("Credential=") {
            credential = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("SignedHeaders=") {
            signed_headers = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("Signature=") {
            signature = Some(v.to_string());
        }
    }

    let credential = credential.ok_or(S3Error::AuthorizationHeaderMalformed)?;
    let signed_headers = signed_headers.ok_or(S3Error::AuthorizationHeaderMalformed)?;
    let signature = signature.ok_or(S3Error::AuthorizationHeaderMalformed)?;

    // Credential = AccessKey/Date/Region/Service/aws4_request
    let scope: Vec<&str> = credential.split('/').collect();
    if scope.len() != 5 {
        return Err(S3Error::AuthorizationHeaderMalformed);
    }

    let mut headers: Vec<String> = signed_headers
        .split(';')
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    headers.sort();

    Ok(ParsedAuth {
        access_key: scope[0].to_string(),
        date: scope[1].to_string(),
        region: scope[2].to_string(),
        service: scope[3].to_string(),
        signed_headers: headers,
        signature,
    })
}

/// The RFC 3986 *unreserved* set: the only characters AWS SigV4 leaves
/// un-escaped when building the canonical query string. Everything else
/// (including `/`) is percent-encoded.
const SIGV4_UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Percent-encode a single query token per AWS SigV4 rules.
///
/// The wire token is first percent-*decoded* to recover the raw value, then
/// re-encoded so that the result matches what the client signed — regardless of
/// whether the client sent reserved characters (notably `/`) encoded or raw.
///
/// # Parameters
/// - `token`: a raw query key or value as it appears on the wire.
///
/// # Returns
/// The SigV4-canonical encoding of the token.
fn sigv4_encode_token(token: &str) -> String {
    let decoded = percent_decode_str(token).decode_utf8_lossy();
    utf8_percent_encode(&decoded, SIGV4_UNRESERVED).to_string()
}

/// Build the SigV4 canonical query string from a raw wire query.
///
/// Each parameter is re-encoded per [`sigv4_encode_token`] (so `delimiter=/`
/// and `delimiter=%2F` canonicalize identically), then the pairs are sorted by
/// encoded key and rejoined. This matches AWS clients (`aws`, `mc`) that send
/// reserved characters pre-encoded as well as clients like `s3fs` that send
/// `/` raw on the wire while signing the encoded form.
///
/// # Parameters
/// - `query`: the raw query string from the request URI, if any.
///
/// # Returns
/// The canonical query string (sorted `key=value` pairs joined by `&`), or an
/// empty string when there is no query.
fn build_canonical_query(query: Option<&str>) -> String {
    let q = match query {
        Some(q) if !q.is_empty() => q,
        _ => return String::new(),
    };
    canonical_query_from_pairs(q.split('&').map(|kv| kv.split_once('=').unwrap_or((kv, ""))))
}

/// Canonicalize an iterator of raw `(key, value)` query pairs into the SigV4
/// canonical query string (encode each token, sort by encoded key, join).
///
/// # Parameters
/// - `pairs`: the raw wire query pairs.
///
/// # Returns
/// The canonical query string.
fn canonical_query_from_pairs<'a>(pairs: impl Iterator<Item = (&'a str, &'a str)>) -> String {
    let mut encoded: Vec<(String, String)> = pairs
        .map(|(k, v)| (sigv4_encode_token(k), sigv4_encode_token(v)))
        .collect();
    encoded.sort();
    encoded
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Verify the SigV4 signature on an incoming request.
///
/// # Parameters
/// - `iam`: identity store used to resolve the secret for the access key.
/// - `method`: the HTTP method.
/// - `uri`: the request URI (path + query, as received on the wire).
/// - `headers`: the request headers.
///
/// # Returns
/// The authenticated [`Identity`] if the signature is valid. Otherwise one of
/// [`S3Error::AccessDenied`] (no/garbled auth header, or disabled credential),
/// [`S3Error::InvalidAccessKeyId`] (unknown key),
/// [`S3Error::AuthorizationHeaderMalformed`] (missing required headers), or
/// [`S3Error::SignatureDoesNotMatch`] (bad signature).
pub fn verify(
    iam: &IamStore,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<Identity, S3Error> {
    let auth_value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(S3Error::AccessDenied)?;
    let parsed = parse_authorization(auth_value)?;

    let identity = iam
        .resolve(&parsed.access_key)
        .ok_or(S3Error::InvalidAccessKeyId)?;
    if !identity.enabled {
        return Err(S3Error::AccessDenied);
    }

    let amz_date = headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .ok_or(S3Error::AuthorizationHeaderMalformed)?;
    let payload_hash = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("UNSIGNED-PAYLOAD");

    // Canonical headers, in the order listed by SignedHeaders (already sorted).
    let mut canonical_headers = String::new();
    for name in &parsed.signed_headers {
        let value = headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .trim();
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(value);
        canonical_headers.push('\n');
    }

    let canonical_request = format!(
        "{method}\n{uri}\n{query}\n{headers}\n{signed}\n{payload}",
        method = method.as_str(),
        uri = uri.path(),
        query = build_canonical_query(uri.query()),
        headers = canonical_headers,
        signed = parsed.signed_headers.join(";"),
        payload = payload_hash,
    );

    let scope = format!(
        "{}/{}/{}/aws4_request",
        parsed.date, parsed.region, parsed.service
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{hash}",
        hash = sha256_hex(canonical_request.as_bytes()),
    );

    let signing_key = derive_signing_key(
        &identity.secret_key,
        &parsed.date,
        &parsed.region,
        &parsed.service,
    );
    let expected = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    if expected == parsed.signature {
        Ok(identity)
    } else {
        Err(S3Error::SignatureDoesNotMatch)
    }
}

/// Parse an `X-Amz-Date` timestamp into a UTC [`OffsetDateTime`].
///
/// # Parameters
/// - `s`: the timestamp string in `YYYYMMDDTHHMMSSZ` form.
///
/// # Returns
/// The parsed UTC time, or [`S3Error::AuthorizationHeaderMalformed`] if it does
/// not match the expected format.
fn parse_amz_datetime(s: &str) -> Result<OffsetDateTime, S3Error> {
    PrimitiveDateTime::parse(s, &AMZ_DATETIME)
        .map(|dt| dt.assume_utc())
        .map_err(|_| S3Error::AuthorizationHeaderMalformed)
}

/// Verify a presigned-URL request (SigV4 authorization carried in the query
/// string), as produced by `aws s3 presign`, `mc share` and browser uploads.
///
/// The canonical request uses `UNSIGNED-PAYLOAD` and a canonical query string
/// that includes every query parameter except `X-Amz-Signature`.
///
/// # Parameters
/// - `iam`: identity store used to resolve the secret for the access key.
/// - `method`: the HTTP method.
/// - `uri`: the request URI (path + the signing query parameters).
/// - `headers`: the request headers (the signed headers, typically `host`).
/// - `now`: the current time, used to enforce `X-Amz-Expires`.
///
/// # Returns
/// The authenticated [`Identity`] if valid, otherwise [`S3Error::AccessDenied`]
/// (missing params, expired, or disabled), [`S3Error::InvalidAccessKeyId`], or
/// [`S3Error::SignatureDoesNotMatch`].
pub fn verify_presigned(
    iam: &IamStore,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Result<Identity, S3Error> {
    let query = uri.query().unwrap_or("");
    // Raw (still percent-encoded) query pairs, as they appear on the wire.
    let raw_pairs: Vec<(&str, &str)> = query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| kv.split_once('=').unwrap_or((kv, "")))
        .collect();

    // Decoded lookup for reading signing parameters.
    let get = |key: &str| -> Option<String> {
        raw_pairs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| percent_decode_str(v).decode_utf8_lossy().into_owned())
    };

    let credential = get("X-Amz-Credential").ok_or(S3Error::AccessDenied)?;
    let amz_date = get("X-Amz-Date").ok_or(S3Error::AuthorizationHeaderMalformed)?;
    let expires: i64 = get("X-Amz-Expires")
        .and_then(|e| e.parse().ok())
        .ok_or(S3Error::AuthorizationHeaderMalformed)?;
    let signed_headers_str = get("X-Amz-SignedHeaders").ok_or(S3Error::AuthorizationHeaderMalformed)?;
    let provided_signature = get("X-Amz-Signature").ok_or(S3Error::AccessDenied)?;

    // Credential = AccessKey/Date/Region/Service/aws4_request
    let scope: Vec<&str> = credential.split('/').collect();
    if scope.len() != 5 {
        return Err(S3Error::AuthorizationHeaderMalformed);
    }
    let (access_key, date, region, service) = (scope[0], scope[1], scope[2], scope[3]);
    let identity = iam.resolve(access_key).ok_or(S3Error::InvalidAccessKeyId)?;
    if !identity.enabled {
        return Err(S3Error::AccessDenied);
    }

    // Enforce expiry: now must be within [signed_time, signed_time + expires].
    let signed_time = parse_amz_datetime(&amz_date)?;
    if now > signed_time + Duration::seconds(expires) {
        return Err(S3Error::AccessDenied);
    }

    let mut signed_headers: Vec<String> = signed_headers_str
        .split(';')
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    signed_headers.sort();

    let mut canonical_headers = String::new();
    for name in &signed_headers {
        let value = headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .trim();
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(value);
        canonical_headers.push('\n');
    }

    // Canonical query: every wire parameter except the signature, SigV4-encoded
    // and sorted (matches clients that send reserved characters raw).
    let canonical_query = canonical_query_from_pairs(
        raw_pairs
            .iter()
            .filter(|(k, _)| *k != "X-Amz-Signature")
            .copied(),
    );

    let canonical_request = format!(
        "{method}\n{uri}\n{query}\n{headers}\n{signed}\nUNSIGNED-PAYLOAD",
        method = method.as_str(),
        uri = uri.path(),
        query = canonical_query,
        headers = canonical_headers,
        signed = signed_headers.join(";"),
    );

    let scope_str = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope_str}\n{hash}",
        hash = sha256_hex(canonical_request.as_bytes()),
    );
    let signing_key = derive_signing_key(&identity.secret_key, date, region, service);
    let expected = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    if expected == provided_signature {
        Ok(identity)
    } else {
        Err(S3Error::SignatureDoesNotMatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    /// Build an [`IamStore`] whose root credential matches the given access key
    /// and secret (used as the expected credential in the SigV4 tests).
    ///
    /// # Parameters
    /// - `secret`: the secret access key to install as the root secret.
    /// - `user`: the access key id to install as the root key.
    ///
    /// # Returns
    /// A root-only `IamStore`.
    fn cfg(secret: &str, user: &str) -> IamStore {
        IamStore::root_only(user, secret)
    }

    /// Headers for the AWS documented "GET Object" SigV4 example.
    ///
    /// # Parameters
    /// - `signature`: the hex signature to place in the `Authorization` header.
    ///
    /// # Returns
    /// A populated [`HeaderMap`].
    fn example_headers(signature: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("host", HeaderValue::from_static("examplebucket.s3.amazonaws.com"));
        h.insert("range", HeaderValue::from_static("bytes=0-9"));
        h.insert(
            "x-amz-content-sha256",
            HeaderValue::from_static(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
        );
        h.insert("x-amz-date", HeaderValue::from_static("20130524T000000Z"));
        let auth = format!(
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature={signature}"
        );
        h.insert("authorization", HeaderValue::from_str(&auth).unwrap());
        h
    }

    /// The canonical query string is sorted and renders bare flags as `k=`.
    #[test]
    fn canonical_query_is_sorted() {
        assert_eq!(build_canonical_query(Some("b=2&a=1")), "a=1&b=2");
        assert_eq!(build_canonical_query(Some("uploads")), "uploads=");
        assert_eq!(build_canonical_query(None), "");
    }

    /// Reserved characters are SigV4-encoded whether sent raw or pre-encoded, so
    /// a raw `delimiter=/` (as `s3fs` sends) canonicalizes to `delimiter=%2F`
    /// and matches the same request signed with the encoded form.
    #[test]
    fn canonical_query_encodes_reserved() {
        assert_eq!(
            build_canonical_query(Some("delimiter=/&max-keys=2&prefix=")),
            "delimiter=%2F&max-keys=2&prefix="
        );
        // Already-encoded input canonicalizes identically (idempotent).
        assert_eq!(
            build_canonical_query(Some("delimiter=%2F&prefix=a/b")),
            build_canonical_query(Some("delimiter=/&prefix=a%2Fb"))
        );
    }

    /// The `Authorization` header parses into its components (headers sorted).
    #[test]
    fn parse_authorization_components() {
        let h = "AWS4-HMAC-SHA256 Credential=AK/20130524/us-east-1/s3/aws4_request, \
SignedHeaders=host;x-amz-date, Signature=abc";
        let p = parse_authorization(h).unwrap();
        assert_eq!(p.access_key, "AK");
        assert_eq!(p.region, "us-east-1");
        assert_eq!(p.service, "s3");
        assert_eq!(p.signed_headers, vec!["host".to_string(), "x-amz-date".to_string()]);
        assert_eq!(p.signature, "abc");
    }

    /// The AWS documented GET-object example signature verifies successfully.
    #[test]
    fn aws_known_vector_verifies() {
        let config = cfg(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "AKIAIOSFODNN7EXAMPLE",
        );
        let headers =
            example_headers("f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41");
        let uri: Uri = "/test.txt".parse().unwrap();
        verify(&config, &Method::GET, &uri, &headers).unwrap();
    }

    /// A wrong secret yields a signature mismatch.
    #[test]
    fn wrong_secret_fails() {
        let config = cfg("not-the-secret", "AKIAIOSFODNN7EXAMPLE");
        let headers =
            example_headers("f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41");
        let uri: Uri = "/test.txt".parse().unwrap();
        assert!(matches!(
            verify(&config, &Method::GET, &uri, &headers),
            Err(S3Error::SignatureDoesNotMatch)
        ));
    }

    /// An unknown access key is rejected before signature checking.
    #[test]
    fn unknown_access_key_fails() {
        let config = cfg("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "SOMEOTHERKEY");
        let headers =
            example_headers("f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41");
        let uri: Uri = "/test.txt".parse().unwrap();
        assert!(matches!(
            verify(&config, &Method::GET, &uri, &headers),
            Err(S3Error::InvalidAccessKeyId)
        ));
    }

    /// The AWS documented presigned-URL example verifies within its window.
    #[test]
    fn aws_presigned_vector_verifies() {
        let config = cfg(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "AKIAIOSFODNN7EXAMPLE",
        );
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("examplebucket.s3.amazonaws.com"));
        let uri: Uri = "/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256\
&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request\
&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host\
&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
            .parse()
            .unwrap();
        // One hour after signing — inside the 24h expiry window.
        let now = time::macros::datetime!(2013-05-24 01:00:00 UTC);
        verify_presigned(&config, &Method::GET, &uri, &headers, now).unwrap();
    }

    /// A presigned URL used after its expiry window is rejected.
    #[test]
    fn presigned_expired_rejected() {
        let config = cfg(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "AKIAIOSFODNN7EXAMPLE",
        );
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("examplebucket.s3.amazonaws.com"));
        let uri: Uri = "/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256\
&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request\
&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host\
&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
            .parse()
            .unwrap();
        // Two days later — outside the 24h window.
        let now = time::macros::datetime!(2013-05-26 00:00:00 UTC);
        assert!(matches!(
            verify_presigned(&config, &Method::GET, &uri, &headers, now),
            Err(S3Error::AccessDenied)
        ));
    }
}
