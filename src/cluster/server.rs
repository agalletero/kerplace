//! The drive server: a node in "drive mode" exposes its local shard storage
//! ([`LocalDrive`]) over an authenticated internal HTTP API so a remote gateway
//! can use it as one erasure shard slot. Bind this to the overlay-mesh
//! interface only; every request must carry the cluster bearer secret.

use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use axum::body::Body;
use axum::extract::{Query, Request, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, RANGE};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::TryStreamExt;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio_util::io::{ReaderStream, StreamReader};

use super::lock::LockTable;
use super::{DirEntryDto, StatDto, WalkEntryDto, DRIVE_API};
use crate::erasure::drive::{Drive, LocalDrive};

/// Shared state for the drive server.
#[derive(Clone)]
struct DriveState {
    drive: Arc<LocalDrive>,
    secret: Arc<String>,
    locks: Arc<LockTable>,
}

/// A single `p=<rel>` query parameter.
#[derive(Deserialize)]
struct PQuery {
    p: String,
}

/// `from`/`to` relative paths for a rename.
#[derive(Deserialize)]
struct RenameQuery {
    from: String,
    to: String,
}

/// `p=<rel>` plus the `kind` of removal (`file`, `dir`, or `tree`).
#[derive(Deserialize)]
struct DelQuery {
    p: String,
    kind: String,
}

/// Reject path-traversal / absolute paths, returning a drive-relative `PathBuf`.
///
/// # Parameters
/// - `p`: the forward-slash relative path from the request.
///
/// # Returns
/// The validated [`PathBuf`], or `400 Bad Request` for an unsafe path.
fn safe_rel(p: &str) -> Result<PathBuf, StatusCode> {
    let rel = PathBuf::from(p);
    for c in rel.components() {
        match c {
            Component::Normal(_) | Component::CurDir => {}
            _ => return Err(StatusCode::BAD_REQUEST),
        }
    }
    Ok(rel)
}

/// Parse a single-range `bytes=start-end` header into `(offset, len)`.
///
/// # Parameters
/// - `v`: the raw `Range` header value.
///
/// # Returns
/// `(offset, len)` for a well-formed inclusive range, else `None`.
fn parse_range(v: &str) -> Option<(u64, usize)> {
    let spec = v.strip_prefix("bytes=")?;
    let (s, e) = spec.split_once('-')?;
    let start: u64 = s.parse().ok()?;
    let end: u64 = e.parse().ok()?;
    if end < start {
        return None;
    }
    Some((start, (end - start + 1) as usize))
}

/// Build the drive-server router over `drive`, gated by the bearer `secret`.
///
/// # Parameters
/// - `drive`: the local shard storage to expose.
/// - `secret`: the shared cluster bearer secret required on every request.
///
/// # Returns
/// An axum [`Router`] serving the `/_kerplace/drive/v1/*` API.
pub fn drive_router(drive: Arc<LocalDrive>, secret: String) -> Router {
    let state = DriveState {
        drive,
        secret: Arc::new(secret),
        locks: Arc::new(LockTable::new()),
    };
    Router::new()
        .route(&format!("{DRIVE_API}/health"), get(health))
        .route(&format!("{DRIVE_API}/file"), get(get_file).put(put_file).delete(del_file))
        .route(&format!("{DRIVE_API}/mkdir"), post(mkdir))
        .route(&format!("{DRIVE_API}/rename"), post(rename))
        .route(&format!("{DRIVE_API}/stat"), get(stat))
        .route(&format!("{DRIVE_API}/readdir"), get(readdir))
        .route(&format!("{DRIVE_API}/walk"), get(walk))
        .route(&format!("{DRIVE_API}/lock/acquire"), post(lock_acquire))
        .route(&format!("{DRIVE_API}/lock/release"), post(lock_release))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth))
        .with_state(state)
}

/// Serve the drive API on `addr`, storing shards under `data_dir`.
///
/// # Parameters
/// - `addr`: the bind address (should be the overlay-mesh interface).
/// - `data_dir`: this node's shard-slot directory.
/// - `secret`: the shared cluster bearer secret.
///
/// # Returns
/// Runs until the server stops; `Err` on a bind/serve failure.
pub async fn serve_drive(
    addr: SocketAddr,
    data_dir: PathBuf,
    secret: String,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::fs::create_dir_all(&data_dir).await?;
    let drive = Arc::new(LocalDrive::new(data_dir));
    let app = drive_router(drive, secret);

    // Mutual TLS (KP_CLUSTER_TLS=true): require a CA-issued client certificate from
    // every gateway. Otherwise serve plain HTTP over the trusted overlay.
    if let Some(tls) = crate::cluster::mtls::ClusterTls::from_env()? {
        let config = axum_server::tls_rustls::RustlsConfig::from_config(tls.server_config()?);
        tracing::info!("KerPlace drive node listening on https://{addr} (mutual TLS)");
        axum_server::bind_rustls(addr, config).serve(app.into_make_service()).await?;
    } else {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("KerPlace drive node listening on http://{addr}");
        axum::serve(listener, app).await?;
    }
    Ok(())
}

/// Bearer-secret middleware guarding every drive endpoint.
async fn auth(State(st): State<DriveState>, req: Request, next: Next) -> Response {
    let ok = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t == st.secret.as_str())
        .unwrap_or(false);
    if !ok {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(req).await
}

/// Liveness probe for `online()` / quorum checks.
async fn health() -> &'static str {
    "ok"
}

/// Header carrying the locked resource a write is fenced against.
const FENCE_RES: &str = "x-kerplace-fence-resource";
/// Header carrying the caller's fencing token for that resource.
const FENCE_TOK: &str = "x-kerplace-fence-token";

/// Reject a mutating request that carries a **stale** fencing token (its lock
/// was superseded). A request with no fencing headers is unaffected, so the
/// non-clustered and local-only paths behave exactly as before.
///
/// # Parameters
/// - `st`: the drive state (holds the [`LockTable`]).
/// - `headers`: the request headers (checked for the fence token).
///
/// # Returns
/// `Some(412 Precondition Failed)` if fenced out, else `None` to proceed.
fn fenced_out(st: &DriveState, headers: &HeaderMap) -> Option<Response> {
    let res = headers.get(FENCE_RES).and_then(|v| v.to_str().ok())?;
    let tok = headers.get(FENCE_TOK).and_then(|v| v.to_str().ok()).and_then(|s| s.parse::<u64>().ok())?;
    if st.locks.fence_ok(res, tok) {
        None
    } else {
        Some(StatusCode::PRECONDITION_FAILED.into_response())
    }
}

/// Map a drive I/O error to a status code (missing ⇒ 404, else 500).
fn io_status(e: &std::io::Error) -> StatusCode {
    if e.kind() == std::io::ErrorKind::NotFound {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

/// `GET /file?p=` — stream a whole file, or buffer a `Range` slice (positioned
/// shard read). The full-file path streams from disk so a large object never
/// sits wholly in the node's memory.
async fn get_file(State(st): State<DriveState>, Query(q): Query<PQuery>, headers: HeaderMap) -> Response {
    let rel = match safe_rel(&q.p) {
        Ok(r) => r,
        Err(c) => return c.into_response(),
    };
    let octet = [(CONTENT_TYPE, "application/octet-stream")];
    if let Some((offset, len)) = headers.get(RANGE).and_then(|v| v.to_str().ok()).and_then(parse_range) {
        match st.drive.read_at(&rel, offset, len).await {
            Ok(bytes) => (StatusCode::PARTIAL_CONTENT, octet, bytes).into_response(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => StatusCode::NOT_FOUND.into_response(),
            Err(_) => StatusCode::RANGE_NOT_SATISFIABLE.into_response(),
        }
    } else {
        match st.drive.open(&rel).await {
            Ok(reader) => (octet, Body::from_stream(ReaderStream::new(reader))).into_response(),
            Err(e) => io_status(&e).into_response(),
        }
    }
}

/// `PUT /file?p=` — stream the request body to disk (parent dir must already
/// exist). Streaming keeps a large object out of the node's memory.
async fn put_file(State(st): State<DriveState>, Query(q): Query<PQuery>, headers: HeaderMap, body: Body) -> Response {
    if let Some(r) = fenced_out(&st, &headers) {
        return r;
    }
    let rel = match safe_rel(&q.p) {
        Ok(r) => r,
        Err(c) => return c.into_response(),
    };
    let mut writer = match st.drive.create(&rel).await {
        Ok(w) => w,
        Err(e) => return io_status(&e).into_response(),
    };
    let stream = body.into_data_stream().map_err(std::io::Error::other);
    let mut reader = StreamReader::new(stream);
    match tokio::io::copy(&mut reader, &mut writer).await {
        Ok(_) => match writer.shutdown().await {
            Ok(()) => StatusCode::OK.into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// `DELETE /file?p=&kind=` — remove a file (`file`), empty dir (`dir`) or tree (`tree`).
async fn del_file(State(st): State<DriveState>, Query(q): Query<DelQuery>, headers: HeaderMap) -> Response {
    if let Some(r) = fenced_out(&st, &headers) {
        return r;
    }
    let rel = match safe_rel(&q.p) {
        Ok(r) => r,
        Err(c) => return c.into_response(),
    };
    let res = match q.kind.as_str() {
        "file" => st.drive.remove_file(&rel).await,
        "dir" => st.drive.remove_dir(&rel).await,
        "tree" => st.drive.remove_dir_all(&rel).await,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    match res {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => io_status(&e).into_response(),
    }
}

/// `POST /mkdir?p=` — create a directory and any missing parents.
async fn mkdir(State(st): State<DriveState>, Query(q): Query<PQuery>, headers: HeaderMap) -> Response {
    if let Some(r) = fenced_out(&st, &headers) {
        return r;
    }
    let rel = match safe_rel(&q.p) {
        Ok(r) => r,
        Err(c) => return c.into_response(),
    };
    match st.drive.create_dir_all(&rel).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => io_status(&e).into_response(),
    }
}

/// `POST /rename?from=&to=` — atomic rename within the drive.
async fn rename(State(st): State<DriveState>, Query(q): Query<RenameQuery>, headers: HeaderMap) -> Response {
    if let Some(r) = fenced_out(&st, &headers) {
        return r;
    }
    let (from, to) = match (safe_rel(&q.from), safe_rel(&q.to)) {
        (Ok(f), Ok(t)) => (f, t),
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    match st.drive.rename(&from, &to).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => io_status(&e).into_response(),
    }
}

/// `GET /stat?p=` — length + is-dir.
async fn stat(State(st): State<DriveState>, Query(q): Query<PQuery>) -> Response {
    let rel = match safe_rel(&q.p) {
        Ok(r) => r,
        Err(c) => return c.into_response(),
    };
    match st.drive.stat(&rel).await {
        Ok(s) => Json(StatDto { len: s.len, is_dir: s.is_dir }).into_response(),
        Err(e) => io_status(&e).into_response(),
    }
}

/// Convert a `SystemTime` to a Unix timestamp in seconds.
fn unix_secs(t: std::time::SystemTime) -> Option<i64> {
    t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs() as i64)
}

/// `GET /readdir?p=` — immediate children.
async fn readdir(State(st): State<DriveState>, Query(q): Query<PQuery>) -> Response {
    let rel = match safe_rel(&q.p) {
        Ok(r) => r,
        Err(c) => return c.into_response(),
    };
    match st.drive.read_dir(&rel).await {
        Ok(entries) => {
            let dto: Vec<DirEntryDto> = entries
                .into_iter()
                .map(|e| DirEntryDto { name: e.name, is_dir: e.is_dir, created_unix: e.created.and_then(unix_secs) })
                .collect();
            Json(dto).into_response()
        }
        Err(e) => io_status(&e).into_response(),
    }
}

/// `GET /walk?p=` — recursive listing (entries relative to `p`).
async fn walk(State(st): State<DriveState>, Query(q): Query<PQuery>) -> Response {
    let rel = match safe_rel(&q.p) {
        Ok(r) => r,
        Err(c) => return c.into_response(),
    };
    match st.drive.walk(&rel).await {
        Ok(entries) => {
            let dto: Vec<WalkEntryDto> = entries
                .into_iter()
                .map(|e| WalkEntryDto { rel: rel_to_string(&e.rel), is_file: e.is_file })
                .collect();
            Json(dto).into_response()
        }
        Err(e) => io_status(&e).into_response(),
    }
}

/// Query for a distributed-lock acquire.
#[derive(Deserialize)]
struct LockAcquireQuery {
    resource: String,
    owner: String,
    ttl_ms: u64,
}

/// Query for a distributed-lock release.
#[derive(Deserialize)]
struct LockReleaseQuery {
    resource: String,
    owner: String,
}

/// `POST /lock/acquire?resource=&owner=&ttl_ms=` — grant the lock (the response
/// body is the fencing token) or `409` if held.
async fn lock_acquire(State(st): State<DriveState>, Query(q): Query<LockAcquireQuery>) -> Response {
    let ttl = std::time::Duration::from_millis(q.ttl_ms);
    match st.locks.acquire(&q.resource, &q.owner, ttl) {
        Some(token) => (StatusCode::OK, token.to_string()).into_response(),
        None => StatusCode::CONFLICT.into_response(),
    }
}

/// `POST /lock/release?resource=&owner=` — release the lock if owned.
async fn lock_release(State(st): State<DriveState>, Query(q): Query<LockReleaseQuery>) -> Response {
    st.locks.release(&q.resource, &q.owner);
    StatusCode::OK.into_response()
}

/// Render a path as a forward-slash string for the wire.
fn rel_to_string(p: &Path) -> String {
    p.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/")
}
