//! Structured access log: the fine-grained audit trail (who did what, when).
//!
//! [`crate::audit`] stamps *who wrote* each object version into the version's
//! own metadata — durable provenance, but only for writes, and only visible by
//! inspecting the object afterwards. Compliance regimes (and the plain question
//! "who read this file?") need the other half: a chronological, append-only
//! record of **every** authenticated request, reads included.
//!
//! One JSON object per line (JSONL) is appended to the path in `KP_ACCESS_LOG`.
//! Records are written by a background task fed through an unbounded channel, so
//! the request path never blocks on disk I/O. When the variable is unset no
//! logger is built and the hook costs one `Option` check per request.
//!
//! The record carries **no object content and no credentials** — only identity,
//! target and outcome. The query string is not logged either (it can hold a
//! presigned signature); only `versionId` is lifted out of it.

use std::path::Path;

use axum::http::{Method, Uri};
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use crate::audit::AuditContext;

/// One access-log record: who, from where, did what, to which target, when, and
/// with what outcome.
#[derive(Debug, Serialize)]
pub struct AccessEntry {
    /// RFC 3339 timestamp of when the response was produced.
    pub ts: String,
    /// Authenticated access key, or `None` when auth is disabled/anonymous.
    pub access_key: Option<String>,
    /// Best-effort client IP (first `X-Forwarded-For` hop, else peer address).
    pub remote_ip: Option<String>,
    /// HTTP method.
    pub method: String,
    /// Coarse S3 operation name (e.g. `GetObject`), derived from method+path.
    pub op: String,
    /// Target bucket, when the request addresses one.
    pub bucket: Option<String>,
    /// Target object key, when the request addresses one.
    pub key: Option<String>,
    /// `versionId` when the request targets a specific version.
    pub version_id: Option<String>,
    /// HTTP status of the response (200, 403, 404 …). Denials are recorded too:
    /// an attempt that was refused is exactly what an auditor wants to see.
    pub status: u16,
}

/// Extract the object key a request path targets (everything after the bucket).
///
/// # Parameters
/// - `path`: the request path.
///
/// # Returns
/// `Some(key)` for `/{bucket}/{key…}`, `None` for `/` and `/{bucket}` (and for a
/// trailing-slash bucket path, which addresses the bucket, not an object).
pub fn key_for(path: &str) -> Option<&str> {
    let (_, key) = path.trim_start_matches('/').split_once('/')?;
    (!key.is_empty()).then_some(key)
}

/// Lift `versionId` out of a query string without logging the rest of it.
///
/// # Parameters
/// - `query`: the raw query string, if any.
///
/// # Returns
/// The `versionId` value when present.
fn version_id_from_query(query: Option<&str>) -> Option<String> {
    query?
        .split('&')
        .find_map(|p| p.strip_prefix("versionId="))
        .map(|v| v.to_string())
}

/// Name the S3 operation a request represents, for readable audit records.
///
/// # Parameters
/// - `method`: the HTTP method.
/// - `has_bucket`: whether the path addresses a bucket.
/// - `has_key`: whether the path addresses an object key.
/// - `path`: the request path (used to spot admin endpoints).
///
/// # Returns
/// A coarse operation name; `Other` when the shape is not recognised.
fn op_for(method: &Method, has_bucket: bool, has_key: bool, path: &str) -> &'static str {
    if path.starts_with("/kerplace/admin") || path.starts_with("/minio/admin") {
        return "AdminRequest";
    }
    match (has_bucket, has_key) {
        (false, _) => match *method {
            Method::GET => "ListBuckets",
            Method::POST => "AssumeRole",
            _ => "Other",
        },
        (true, false) => match *method {
            Method::GET => "ListObjects",
            Method::HEAD => "HeadBucket",
            Method::PUT => "CreateBucket",
            Method::DELETE => "DeleteBucket",
            Method::POST => "PostBucket",
            _ => "Other",
        },
        (true, true) => match *method {
            Method::GET => "GetObject",
            Method::HEAD => "HeadObject",
            Method::PUT => "PutObject",
            Method::DELETE => "DeleteObject",
            Method::POST => "PostObject",
            _ => "Other",
        },
    }
}

/// Build the record for a finished request.
///
/// # Parameters
/// - `method`: the request method.
/// - `uri`: the request URI (path + query).
/// - `ctx`: the audit context published by the auth middleware (who / where).
/// - `status`: the HTTP status of the response.
///
/// # Returns
/// A fully-populated [`AccessEntry`].
pub fn entry_for(method: &Method, uri: &Uri, ctx: &AuditContext, status: u16) -> AccessEntry {
    let path = uri.path();
    let bucket = crate::iam::bucket_for(path);
    let key = key_for(path);
    let ts = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    AccessEntry {
        ts,
        access_key: ctx.access_key.clone(),
        remote_ip: ctx.remote_ip.clone(),
        method: method.as_str().to_string(),
        op: op_for(method, bucket.is_some(), key.is_some(), path).to_string(),
        bucket: bucket.map(|s| s.to_string()),
        key: key.map(|s| s.to_string()),
        version_id: version_id_from_query(uri.query()),
        status,
    }
}

/// Append-only JSONL sink for [`AccessEntry`] records.
///
/// Cloning is cheap (the sender is an `mpsc` handle); the writer task lives for
/// the process lifetime and stops when every sender is dropped.
#[derive(Clone)]
pub struct AccessLogger {
    tx: mpsc::UnboundedSender<String>,
}

impl AccessLogger {
    /// Open (or create) the log file and start its background writer.
    ///
    /// # Parameters
    /// - `path`: file to append records to; parent directories are created.
    ///
    /// # Returns
    /// The logger, or an [`std::io::Error`] if the file cannot be opened — the
    /// caller should treat that as fatal in a regulated posture rather than
    /// serving with the audit trail silently off.
    pub async fn new(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;

        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            while let Some(line) = rx.recv().await {
                if let Err(e) = file.write_all(line.as_bytes()).await {
                    tracing::warn!("access log: write failed: {e}");
                    continue;
                }
                // Durability beats throughput for an audit trail: flush every
                // record so a crash cannot silently swallow its tail.
                if let Err(e) = file.flush().await {
                    tracing::warn!("access log: flush failed: {e}");
                }
            }
        });
        Ok(AccessLogger { tx })
    }

    /// Queue one record for writing. Never blocks and never fails the request.
    ///
    /// # Parameters
    /// - `entry`: the record to append.
    pub fn log(&self, entry: &AccessEntry) {
        match serde_json::to_string(entry) {
            Ok(mut line) => {
                line.push('\n');
                // A closed channel means the writer task is gone (shutdown);
                // losing the record is preferable to panicking a live request.
                let _ = self.tx.send(line);
            }
            Err(e) => tracing::warn!("access log: encode failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_for_splits_bucket_from_key() {
        assert_eq!(key_for("/bucket/dir/file.txt"), Some("dir/file.txt"));
        assert_eq!(key_for("/bucket/obj"), Some("obj"));
        assert_eq!(key_for("/bucket"), None);
        assert_eq!(key_for("/bucket/"), None);
        assert_eq!(key_for("/"), None);
    }

    #[test]
    fn version_id_is_lifted_from_query() {
        assert_eq!(version_id_from_query(Some("versionId=abc")), Some("abc".into()));
        assert_eq!(
            version_id_from_query(Some("x=1&versionId=v2&y=3")),
            Some("v2".into())
        );
        assert_eq!(version_id_from_query(Some("x=1")), None);
        assert_eq!(version_id_from_query(None), None);
    }

    #[test]
    fn op_names_cover_the_common_shapes() {
        assert_eq!(op_for(&Method::GET, false, false, "/"), "ListBuckets");
        assert_eq!(op_for(&Method::GET, true, false, "/b"), "ListObjects");
        assert_eq!(op_for(&Method::PUT, true, false, "/b"), "CreateBucket");
        assert_eq!(op_for(&Method::GET, true, true, "/b/k"), "GetObject");
        assert_eq!(op_for(&Method::PUT, true, true, "/b/k"), "PutObject");
        assert_eq!(op_for(&Method::DELETE, true, true, "/b/k"), "DeleteObject");
        assert_eq!(
            op_for(&Method::GET, false, false, "/kerplace/admin/v3/info"),
            "AdminRequest"
        );
    }

    #[test]
    fn entry_records_identity_target_and_outcome() {
        let ctx = AuditContext {
            access_key: Some("alice".into()),
            remote_ip: Some("10.0.0.9".into()),
        };
        let uri: Uri = "/reports/q1.pdf?versionId=v7".parse().unwrap();
        let e = entry_for(&Method::GET, &uri, &ctx, 200);
        assert_eq!(e.access_key.as_deref(), Some("alice"));
        assert_eq!(e.remote_ip.as_deref(), Some("10.0.0.9"));
        assert_eq!(e.bucket.as_deref(), Some("reports"));
        assert_eq!(e.key.as_deref(), Some("q1.pdf"));
        assert_eq!(e.version_id.as_deref(), Some("v7"));
        assert_eq!(e.op, "GetObject");
        assert_eq!(e.status, 200);
        assert!(e.ts.contains('T'), "timestamp should be RFC3339: {}", e.ts);
    }

    #[tokio::test]
    async fn logger_appends_jsonl_records() {
        let dir = std::env::temp_dir().join(format!("kp-access-log-{}", std::process::id()));
        let path = dir.join("access.jsonl");
        let logger = AccessLogger::new(&path).await.expect("open log");
        let ctx = AuditContext {
            access_key: Some("bob".into()),
            remote_ip: None,
        };
        let uri: Uri = "/logs/a.txt".parse().unwrap();
        logger.log(&entry_for(&Method::PUT, &uri, &ctx, 200));
        logger.log(&entry_for(&Method::GET, &uri, &ctx, 403));

        // Give the background writer a moment to drain the channel.
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            if let Ok(s) = tokio::fs::read_to_string(&path).await {
                if s.lines().count() >= 2 {
                    let lines: Vec<&str> = s.lines().collect();
                    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
                    let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
                    assert_eq!(first["op"], "PutObject");
                    assert_eq!(first["access_key"], "bob");
                    assert_eq!(second["op"], "GetObject");
                    assert_eq!(second["status"], 403);
                    return;
                }
            }
        }
        panic!("access log did not receive both records");
    }
}
