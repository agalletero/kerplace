//! [`RemoteDrive`] — a [`Drive`] backed by another node's drive server
//! ([`super::server`]) over the internal HTTP RPC. To `ErasureStore` it is
//! indistinguishable from a [`LocalDrive`](crate::erasure::drive::LocalDrive):
//! the same trait, just network-addressed.
//!
//! Reads/stat/list are one-shot request/response. Streaming reads are buffered
//! for now (`open` reads the whole file); writes accumulate in memory and are
//! flushed as a single `PUT` on `shutdown` (see [`RemoteWriter`]). Streaming
//! both directions is a later optimisation (`docs/DISTRIBUTED_DESIGN.md`).

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use futures::TryStreamExt;
use reqwest::Client;
use tokio::io::AsyncWrite;
use tokio_util::io::{ReaderStream, StreamReader};

use super::{DirEntryDto, StatDto, WalkEntryDto, DRIVE_API};
use crate::erasure::drive::{DirEntry, Drive, DriveReader, DriveStat, DriveWriter, WalkEntry};

/// Map any error into an `io::Error` (kind `Other`).
fn io_other<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// The canonical "not found" error for a missing remote path.
fn io_notfound() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::NotFound, "remote drive: not found")
}

/// A [`Drive`] that proxies to a remote node's drive server.
pub struct RemoteDrive {
    base: String,
    secret: String,
    http: Client,
}

impl RemoteDrive {
    /// Connect a remote drive at `base` (e.g. `http://100.x.y.z:9100`),
    /// authenticating with the shared cluster `secret` over a default HTTP client.
    ///
    /// # Parameters
    /// - `base`: the node's drive-server base URL (scheme + host + port).
    /// - `secret`: the shared cluster bearer secret.
    pub fn new(base: impl Into<String>, secret: impl Into<String>) -> Self {
        Self::with_client(base, secret, Client::new())
    }

    /// Connect a remote drive using a caller-supplied HTTP client (e.g. one
    /// configured for mutual TLS — see [`crate::cluster::mtls`]).
    ///
    /// # Parameters
    /// - `base`: the node's drive-server base URL (use `https://…` for mTLS).
    /// - `secret`: the shared cluster bearer secret.
    /// - `http`: the configured `reqwest` client.
    pub fn with_client(base: impl Into<String>, secret: impl Into<String>, http: Client) -> Self {
        RemoteDrive { base: base.into(), secret: secret.into(), http }
    }

    /// Full URL for a drive endpoint (`<base>/_kerplace/drive/v1/<ep>`).
    fn url(&self, ep: &str) -> String {
        format!("{}{}/{}", self.base, DRIVE_API, ep)
    }

    /// Render a drive-relative path as a forward-slash query string.
    fn rel_str(rel: &Path) -> String {
        rel.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/")
    }

    /// Attach this task's fencing token for this node (if a lock is held) to a
    /// mutating request, so a superseded gateway is rejected by the node.
    ///
    /// # Parameters
    /// - `rb`: the request builder to decorate.
    ///
    /// # Returns
    /// `rb` with the fence headers added when a token applies, else unchanged.
    fn fenced(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match crate::cluster::lock::fence_for(&self.base) {
            Some((res, tok)) => rb
                .header("x-kerplace-fence-resource", res)
                .header("x-kerplace-fence-token", tok.to_string()),
            None => rb,
        }
    }
}

#[async_trait]
impl Drive for RemoteDrive {
    fn id(&self) -> String {
        self.base.clone()
    }

    fn local_root(&self) -> Option<PathBuf> {
        None
    }

    async fn online(&self) -> bool {
        match self.http.get(self.url("health")).bearer_auth(&self.secret).send().await {
            Ok(r) => r.status().is_success(),
            Err(_) => false,
        }
    }

    async fn read(&self, rel: &Path) -> std::io::Result<Vec<u8>> {
        let resp = self
            .http
            .get(self.url("file"))
            .query(&[("p", Self::rel_str(rel))])
            .bearer_auth(&self.secret)
            .send()
            .await
            .map_err(io_other)?;
        if resp.status().as_u16() == 404 {
            return Err(io_notfound());
        }
        if !resp.status().is_success() {
            return Err(io_other(format!("read {}", resp.status())));
        }
        Ok(resp.bytes().await.map_err(io_other)?.to_vec())
    }

    async fn write(&self, rel: &Path, data: &[u8]) -> std::io::Result<()> {
        let resp = self
            .fenced(
                self.http
                    .put(self.url("file"))
                    .query(&[("p", Self::rel_str(rel))])
                    .bearer_auth(&self.secret)
                    .body(data.to_vec()),
            )
            .send()
            .await
            .map_err(io_other)?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(io_other(format!("write {}", resp.status())))
        }
    }

    async fn open(&self, rel: &Path) -> std::io::Result<DriveReader> {
        // Stream the response body straight through — never buffers the file.
        let resp = self
            .http
            .get(self.url("file"))
            .query(&[("p", Self::rel_str(rel))])
            .bearer_auth(&self.secret)
            .send()
            .await
            .map_err(io_other)?;
        if resp.status().as_u16() == 404 {
            return Err(io_notfound());
        }
        if !resp.status().is_success() {
            return Err(io_other(format!("open {}", resp.status())));
        }
        let stream = resp.bytes_stream().map_err(std::io::Error::other);
        Ok(Box::new(StreamReader::new(Box::pin(stream))))
    }

    async fn create(&self, rel: &Path) -> std::io::Result<DriveWriter> {
        // Stream the body: the caller writes into one half of a duplex pipe; a
        // spawned task PUTs the other half as the request body. So neither side
        // holds the whole file in memory.
        let (tx, rx) = tokio::io::duplex(64 * 1024);
        let client = self.http.clone();
        let url = self.url("file");
        let relstr = Self::rel_str(rel);
        let secret = self.secret.clone();
        // Read the fence token on THIS task — the spawned PUT task does not
        // inherit task-locals — and move it into the request below.
        let fence = crate::cluster::lock::fence_for(&self.base);
        let join = tokio::spawn(async move {
            let body = reqwest::Body::wrap_stream(ReaderStream::new(rx));
            let mut req = client.put(&url).query(&[("p", relstr)]).bearer_auth(secret).body(body);
            if let Some((res, tok)) = fence {
                req = req.header("x-kerplace-fence-resource", res).header("x-kerplace-fence-token", tok.to_string());
            }
            let resp = req.send().await.map_err(io_other)?;
            if resp.status().is_success() {
                Ok(())
            } else {
                Err(io_other(format!("remote write {}", resp.status())))
            }
        });
        Ok(Box::new(RemoteWriter { tx: Some(tx), join: Some(join) }))
    }

    async fn read_at(&self, rel: &Path, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
        let end = offset + len as u64 - 1;
        let resp = self
            .http
            .get(self.url("file"))
            .query(&[("p", Self::rel_str(rel))])
            .bearer_auth(&self.secret)
            .header("Range", format!("bytes={offset}-{end}"))
            .send()
            .await
            .map_err(io_other)?;
        if resp.status().as_u16() == 404 {
            return Err(io_notfound());
        }
        if !resp.status().is_success() {
            return Err(io_other(format!("read_at {}", resp.status())));
        }
        let bytes = resp.bytes().await.map_err(io_other)?;
        if bytes.len() != len {
            return Err(io_other(format!("read_at short read {} != {len}", bytes.len())));
        }
        Ok(bytes.to_vec())
    }

    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        let resp = self
            .fenced(
                self.http
                    .post(self.url("rename"))
                    .query(&[("from", Self::rel_str(from)), ("to", Self::rel_str(to))])
                    .bearer_auth(&self.secret),
            )
            .send()
            .await
            .map_err(io_other)?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(io_other(format!("rename {}", resp.status())))
        }
    }

    async fn remove_file(&self, rel: &Path) -> std::io::Result<()> {
        self.remove(rel, "file").await
    }

    async fn remove_dir(&self, rel: &Path) -> std::io::Result<()> {
        self.remove(rel, "dir").await
    }

    async fn remove_dir_all(&self, rel: &Path) -> std::io::Result<()> {
        self.remove(rel, "tree").await
    }

    async fn create_dir_all(&self, rel: &Path) -> std::io::Result<()> {
        let resp = self
            .fenced(
                self.http
                    .post(self.url("mkdir"))
                    .query(&[("p", Self::rel_str(rel))])
                    .bearer_auth(&self.secret),
            )
            .send()
            .await
            .map_err(io_other)?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(io_other(format!("mkdir {}", resp.status())))
        }
    }

    async fn stat(&self, rel: &Path) -> std::io::Result<DriveStat> {
        let resp = self
            .http
            .get(self.url("stat"))
            .query(&[("p", Self::rel_str(rel))])
            .bearer_auth(&self.secret)
            .send()
            .await
            .map_err(io_other)?;
        if resp.status().as_u16() == 404 {
            return Err(io_notfound());
        }
        if !resp.status().is_success() {
            return Err(io_other(format!("stat {}", resp.status())));
        }
        let dto: StatDto = resp.json().await.map_err(io_other)?;
        Ok(DriveStat { len: dto.len, is_dir: dto.is_dir })
    }

    async fn read_dir(&self, rel: &Path) -> std::io::Result<Vec<DirEntry>> {
        let resp = self
            .http
            .get(self.url("readdir"))
            .query(&[("p", Self::rel_str(rel))])
            .bearer_auth(&self.secret)
            .send()
            .await
            .map_err(io_other)?;
        if !resp.status().is_success() {
            return Err(io_other(format!("readdir {}", resp.status())));
        }
        let dto: Vec<DirEntryDto> = resp.json().await.map_err(io_other)?;
        Ok(dto
            .into_iter()
            .map(|d| DirEntry {
                name: d.name,
                is_dir: d.is_dir,
                created: d
                    .created_unix
                    .filter(|s| *s >= 0)
                    .map(|s| UNIX_EPOCH + Duration::from_secs(s as u64)),
            })
            .collect())
    }

    async fn walk(&self, rel: &Path) -> std::io::Result<Vec<WalkEntry>> {
        let resp = self
            .http
            .get(self.url("walk"))
            .query(&[("p", Self::rel_str(rel))])
            .bearer_auth(&self.secret)
            .send()
            .await
            .map_err(io_other)?;
        if !resp.status().is_success() {
            return Err(io_other(format!("walk {}", resp.status())));
        }
        let dto: Vec<WalkEntryDto> = resp.json().await.map_err(io_other)?;
        Ok(dto
            .into_iter()
            .map(|d| WalkEntry { rel: PathBuf::from(d.rel), is_file: d.is_file })
            .collect())
    }
}

impl RemoteDrive {
    /// Shared body for the three remove variants.
    async fn remove(&self, rel: &Path, kind: &str) -> std::io::Result<()> {
        let resp = self
            .fenced(
                self.http
                    .delete(self.url("file"))
                    .query(&[("p", Self::rel_str(rel)), ("kind", kind.to_string())])
                    .bearer_auth(&self.secret),
            )
            .send()
            .await
            .map_err(io_other)?;
        if resp.status().as_u16() == 404 {
            return Err(io_notfound());
        }
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(io_other(format!("remove {}", resp.status())))
        }
    }
}

/// A streaming [`DriveWriter`]: bytes the caller writes go into a duplex pipe
/// whose other half is the body of an in-flight `PUT`. `shutdown` closes the
/// pipe (EOF-ing the body) and then awaits the request, so the store's
/// `part.1.tmp` → `part.1` rename only happens once the data is durably stored.
pub struct RemoteWriter {
    /// Write half of the duplex pipe (the PUT body reads the other half).
    /// Taken/dropped on `shutdown` to signal end-of-body.
    tx: Option<tokio::io::DuplexStream>,
    /// The spawned `PUT` task; its result is surfaced from `poll_shutdown`.
    join: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}

impl AsyncWrite for RemoteWriter {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut().tx.as_mut() {
            Some(tx) => Pin::new(tx).poll_write(cx, buf),
            None => Poll::Ready(Ok(0)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut().tx.as_mut() {
            Some(tx) => Pin::new(tx).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // 1. Close the write half so the PUT body sees EOF.
        if let Some(tx) = this.tx.as_mut() {
            ready!(Pin::new(tx).poll_shutdown(cx))?;
            this.tx = None;
        }
        // 2. Await the PUT task and surface its result.
        match this.join.as_mut() {
            Some(join) => {
                let res = ready!(Pin::new(join).poll(cx));
                this.join = None;
                Poll::Ready(res.unwrap_or_else(|e| Err(std::io::Error::other(e))))
            }
            None => Poll::Ready(Ok(())),
        }
    }
}
