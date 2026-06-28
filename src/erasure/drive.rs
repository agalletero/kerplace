//! The `Drive` seam — where a shard's bytes physically live.
//!
//! `ErasureStore` treats each of its `N` shard slots as an opaque place to put
//! `xl.meta` + `part.1` (and the config/versioning sidecars). Phase 1–3 backed
//! every slot with a local directory. To go distributed (Phase 4) without
//! touching the codec, sharding, versioning, heal or audit logic, those slots
//! are abstracted behind this async trait: a slot is anything that can do the
//! handful of file operations the store needs, addressed by a path **relative
//! to the drive root** (`<bucket>/<key>/...`).
//!
//! - [`LocalDrive`] wraps `tokio::fs` against a root directory — behaviour is
//!   identical to the pre-seam store (the single-host path).
//! - A future `RemoteDrive` will implement the same trait over the cluster RPC
//!   (`docs/DISTRIBUTED_DESIGN.md`), so the store is unchanged.

use std::io::SeekFrom;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite};

/// A sequential streaming reader of a drive file (e.g. assembling multipart).
/// Positioned shard reads use [`Drive::read_at`] instead, so the reader needs
/// no `AsyncSeek` (two non-auto traits can't share one trait object anyway).
pub type DriveReader = Box<dyn AsyncRead + Send + Unpin>;
/// A streaming writer to a drive file.
pub type DriveWriter = Box<dyn AsyncWrite + Send + Unpin>;

/// Minimal stat of a drive path.
pub struct DriveStat {
    /// File length in bytes (0 for directories).
    pub len: u64,
    /// Whether the path is a directory.
    pub is_dir: bool,
}

/// One immediate child returned by [`Drive::read_dir`].
pub struct DirEntry {
    /// Final path component (file or directory name).
    pub name: String,
    /// Whether the child is a directory.
    pub is_dir: bool,
    /// Creation time (falling back to modification time), when the backend
    /// exposes it. `None` for backends without timestamps.
    pub created: Option<std::time::SystemTime>,
}

/// One node of a recursive [`Drive::walk`], path **relative to the walk base**.
pub struct WalkEntry {
    /// Path relative to the `rel` base passed to `walk`.
    pub rel: PathBuf,
    /// Whether this entry is a regular file.
    pub is_file: bool,
}

/// A single erasure shard slot: the operations `ErasureStore` performs on it.
///
/// All paths are **relative to the drive root**. Implementations must be
/// `Send + Sync` so the store can share them across requests.
#[async_trait]
pub trait Drive: Send + Sync {
    /// A stable human-readable id for this drive (used in heal / `backend_info`).
    fn id(&self) -> String;

    /// The local filesystem root, if this drive is local (`None` for remote).
    /// Used only for diagnostics / tests; the store never relies on it for I/O.
    fn local_root(&self) -> Option<PathBuf>;

    /// Whether the drive is currently reachable/usable.
    async fn online(&self) -> bool;

    /// Read an entire file into memory.
    async fn read(&self, rel: &Path) -> std::io::Result<Vec<u8>>;

    /// Write an entire file (creating parent dirs is the caller's job).
    async fn write(&self, rel: &Path, data: &[u8]) -> std::io::Result<()>;

    /// Open a file for sequential streaming reads (no seeking).
    async fn open(&self, rel: &Path) -> std::io::Result<DriveReader>;

    /// Read exactly `len` bytes starting at byte `offset` (a positioned/range
    /// read). Errors if the file is missing or shorter than `offset + len`.
    /// Maps to a local seek+read, or an HTTP Range for a remote drive.
    async fn read_at(&self, rel: &Path, offset: u64, len: usize) -> std::io::Result<Vec<u8>>;

    /// Create (or truncate) a file for streaming writes.
    async fn create(&self, rel: &Path) -> std::io::Result<DriveWriter>;

    /// Atomically rename within the drive.
    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()>;

    /// Remove a single file.
    async fn remove_file(&self, rel: &Path) -> std::io::Result<()>;

    /// Remove an empty directory.
    async fn remove_dir(&self, rel: &Path) -> std::io::Result<()>;

    /// Remove a directory and everything under it.
    async fn remove_dir_all(&self, rel: &Path) -> std::io::Result<()>;

    /// Create a directory and any missing parents.
    async fn create_dir_all(&self, rel: &Path) -> std::io::Result<()>;

    /// Stat a path (length + is-dir).
    async fn stat(&self, rel: &Path) -> std::io::Result<DriveStat>;

    /// List the immediate children of a directory.
    async fn read_dir(&self, rel: &Path) -> std::io::Result<Vec<DirEntry>>;

    /// Recursively walk a subtree, returning entries relative to `rel`.
    async fn walk(&self, rel: &Path) -> std::io::Result<Vec<WalkEntry>>;
}

/// A [`Drive`] backed by a local directory (the single-host path).
pub struct LocalDrive {
    root: PathBuf,
}

impl LocalDrive {
    /// Create a local drive rooted at `root`.
    ///
    /// # Parameters
    /// - `root`: the directory under which all relative paths resolve.
    pub fn new(root: PathBuf) -> Self {
        LocalDrive { root }
    }

    /// Resolve a drive-relative path to an absolute one.
    fn abs(&self, rel: &Path) -> PathBuf {
        self.root.join(rel)
    }
}

#[async_trait]
impl Drive for LocalDrive {
    fn id(&self) -> String {
        self.root.display().to_string()
    }

    fn local_root(&self) -> Option<PathBuf> {
        Some(self.root.clone())
    }

    async fn online(&self) -> bool {
        tokio::fs::metadata(&self.root).await.is_ok()
    }

    async fn read(&self, rel: &Path) -> std::io::Result<Vec<u8>> {
        tokio::fs::read(self.abs(rel)).await
    }

    async fn write(&self, rel: &Path, data: &[u8]) -> std::io::Result<()> {
        tokio::fs::write(self.abs(rel), data).await
    }

    async fn open(&self, rel: &Path) -> std::io::Result<DriveReader> {
        Ok(Box::new(File::open(self.abs(rel)).await?))
    }

    async fn read_at(&self, rel: &Path, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
        let mut f = File::open(self.abs(rel)).await?;
        f.seek(SeekFrom::Start(offset)).await?;
        let mut buf = vec![0u8; len];
        f.read_exact(&mut buf).await?;
        Ok(buf)
    }

    async fn create(&self, rel: &Path) -> std::io::Result<DriveWriter> {
        Ok(Box::new(File::create(self.abs(rel)).await?))
    }

    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        tokio::fs::rename(self.abs(from), self.abs(to)).await
    }

    async fn remove_file(&self, rel: &Path) -> std::io::Result<()> {
        tokio::fs::remove_file(self.abs(rel)).await
    }

    async fn remove_dir(&self, rel: &Path) -> std::io::Result<()> {
        tokio::fs::remove_dir(self.abs(rel)).await
    }

    async fn remove_dir_all(&self, rel: &Path) -> std::io::Result<()> {
        tokio::fs::remove_dir_all(self.abs(rel)).await
    }

    async fn create_dir_all(&self, rel: &Path) -> std::io::Result<()> {
        tokio::fs::create_dir_all(self.abs(rel)).await
    }

    async fn stat(&self, rel: &Path) -> std::io::Result<DriveStat> {
        let m = tokio::fs::metadata(self.abs(rel)).await?;
        Ok(DriveStat { len: m.len(), is_dir: m.is_dir() })
    }

    async fn read_dir(&self, rel: &Path) -> std::io::Result<Vec<DirEntry>> {
        let mut rd = tokio::fs::read_dir(self.abs(rel)).await?;
        let mut out = Vec::new();
        while let Some(e) = rd.next_entry().await? {
            let md = e.metadata().await.ok();
            let is_dir = md.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let created = md.as_ref().and_then(|m| m.created().or_else(|_| m.modified()).ok());
            out.push(DirEntry {
                name: e.file_name().to_string_lossy().into_owned(),
                is_dir,
                created,
            });
        }
        Ok(out)
    }

    async fn walk(&self, rel: &Path) -> std::io::Result<Vec<WalkEntry>> {
        let base = self.abs(rel);
        tokio::task::spawn_blocking(move || {
            let mut out = Vec::new();
            for entry in walkdir::WalkDir::new(&base).into_iter().filter_map(|e| e.ok()) {
                if let Ok(r) = entry.path().strip_prefix(&base) {
                    if r.as_os_str().is_empty() {
                        continue; // the base dir itself
                    }
                    out.push(WalkEntry { rel: r.to_path_buf(), is_file: entry.file_type().is_file() });
                }
            }
            out
        })
        .await
        .map_err(std::io::Error::other)
    }
}
