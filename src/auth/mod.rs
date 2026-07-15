//! Request authentication middleware and the `aws-chunked` body adapter.

pub mod chunked;
pub mod oidc;
pub mod sigv4;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;
use futures::TryStreamExt;
use time::OffsetDateTime;
use tokio_util::io::{ReaderStream, StreamReader};

use crate::error::S3Error;
use crate::state::AppState;
use crate::storage::BodyReader;

/// Return whether a request body uses the `aws-chunked` streaming encoding.
///
/// # Parameters
/// - `headers`: the incoming request headers.
///
/// # Returns
/// `true` if `x-amz-content-sha256` indicates a streaming/chunked payload.
fn is_aws_chunked(headers: &HeaderMap) -> bool {
    headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("STREAMING-"))
        .unwrap_or(false)
}

/// Convert an axum [`Body`] into an owned, boxed async reader.
///
/// # Parameters
/// - `body`: the request body.
///
/// # Returns
/// A [`BodyReader`] streaming the body's bytes, surfacing transport errors as
/// [`std::io::Error`].
pub fn body_to_reader(body: Body) -> BodyReader {
    let stream = body
        .into_data_stream()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));
    Box::pin(StreamReader::new(stream))
}

/// Axum middleware that authenticates requests and transparently de-chunks
/// `aws-chunked` bodies before they reach the handlers.
///
/// Health endpoints under `/kerplace/health` (and the `/minio/health` compat
/// alias) bypass authentication. When auth is disabled in config, only the
/// de-chunking step runs.
///
/// # Parameters
/// - `state`: shared application state (config + store).
/// - `req`: the incoming request (possibly rewritten with a decoded body).
/// - `next`: the remainder of the middleware/handler chain.
///
/// # Returns
/// The downstream [`Response`], or an S3 error response if authentication
/// fails.
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();

    // Health checks are unauthenticated and have no body to decode (served under
    // both the canonical `/kerplace/health` and the compat `/minio/health`).
    if path.starts_with("/kerplace/health") || path.starts_with("/minio/health") {
        return next.run(req).await;
    }

    // STS lives at `POST /` and authenticates via the WebIdentityToken in its body
    // (its whole purpose is to issue a credential), so it bypasses SigV4.
    if path == "/" && req.method() == axum::http::Method::POST {
        return next.run(req).await;
    }

    // Best-effort client IP for the audit trail: trust the first
    // `X-Forwarded-For` hop when present (reverse-proxy deployments), else the
    // transport peer address exposed via `ConnectInfo`.
    let remote_ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            req.extensions()
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|ci| ci.0.ip().to_string())
        });
    let mut access_key: Option<String> = None;

    if state.config.auth_enabled {
        let has_auth_header = req.headers().contains_key(axum::http::header::AUTHORIZATION);
        let is_presigned = req
            .uri()
            .query()
            .map(|q| q.contains("X-Amz-Signature"))
            .unwrap_or(false);
        let result = if has_auth_header {
            sigv4::verify(&state.iam, req.method(), req.uri(), req.headers())
        } else if is_presigned {
            sigv4::verify_presigned(
                &state.iam,
                req.method(),
                req.uri(),
                req.headers(),
                OffsetDateTime::now_utc(),
            )
        } else {
            Err(S3Error::AccessDenied)
        };
        let identity = match result {
            Ok(id) => id,
            Err(e) => return e.into_response_with_resource(&path),
        };

        // Enforce the identity's policy against the requested action (*what*).
        let action = crate::iam::action_for(req.method(), &path);
        if !crate::iam::Policy::from_name(&identity.policy).allows(action) {
            return S3Error::AccessDenied.into_response_with_resource(&path);
        }

        // Enforce the identity's bucket scope (*where*). ANDed with the policy:
        // a `readwrite` credential scoped to one bucket may not touch another.
        // Unscoped credentials (the default) pass unchanged.
        if !identity.allows_bucket(crate::iam::bucket_for(&path)) {
            return S3Error::AccessDenied.into_response_with_resource(&path);
        }

        // Record the requester for the audit trail before the identity is moved
        // into the request extensions (admin handlers need the secret key there
        // for madmin payload (de)cryption).
        access_key = Some(identity.access_key.clone());
        req.extensions_mut().insert(identity);
    }

    // Replace an aws-chunked body with its decoded form so handlers always see
    // the raw object bytes regardless of how the client framed them.
    if is_aws_chunked(req.headers()) {
        let (parts, body) = req.into_parts();
        let decoded = chunked::decode_aws_chunked(body_to_reader(body));
        let new_body = Body::from_stream(ReaderStream::new(decoded));
        req = Request::from_parts(parts, new_body);
    }

    // Publish who/where for the storage layer to stamp onto version writes.
    let ctx = crate::audit::AuditContext { access_key, remote_ip };
    crate::audit::scope(ctx, next.run(req)).await
}
