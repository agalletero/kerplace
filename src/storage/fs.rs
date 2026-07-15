//! Filesystem-backed [`ObjectStore`] implementation.
//!
//! Layout under the configured data directory:
//!
//! ```text
//! <root>/
//!   <bucket>/<key>                              object payloads
//!   .kerplace.sys/
//!     meta/<bucket>/<key>.json                  per-object metadata sidecars
//!     meta/<bucket>/<key>.tags.json             per-object tag sidecars
//!     meta/<bucket>/<key>.retention.json        per-object retention
//!     meta/<bucket>/<key>.legalhold.json        per-object legal-hold
//!     multipart/<bucket>/<uploadId>/            staged multipart parts + manifest
//!     buckets/<bucket>/sse.json                 per-bucket SSE config
//!     buckets/<bucket>/policy.json              per-bucket IAM policy (raw JSON)
//!     buckets/<bucket>/tags.json                per-bucket tags
//!     buckets/<bucket>/versioning.json          per-bucket versioning status
//!     buckets/<bucket>/lifecycle.json           per-bucket lifecycle rules (raw XML)
//!     tmp/                                      temp files for atomic writes
//! ```
//!
//! Object metadata lives in a parallel `.kerplace.sys` tree so it never pollutes
//! object listings. All payload writes go to a temp file and are atomically
//! renamed into place. Bodies are streamed, so object size is bounded by disk.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::fs;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;
use walkdir::WalkDir;

use super::{
    opaque_etag, validate_bucket_name, validate_key, BodyReader, BucketInfo, CompletedPart,
    DeleteOutcome, Listing, ObjectBody, ObjectMeta, ObjectStore, ObjectVersion, PartInfo,
    VersionListing,
};
use crate::crypto::{self, CryptoContext, ObjectCipher, CHUNK_BLOCK, CHUNK_SIZE};
use crate::error::S3Error;

/// Name of the reserved system directory holding metadata and temp files.
const SYS_DIR: &str = ".kerplace.sys";

/// Sentinel filename used to persist a "directory marker" object — an object
/// whose key ends with `/` (created by `mkdir` through s3fs/FUSE). A real file
/// cannot be named with a trailing slash, so the marker is stored inside the
/// directory under this name and translated back to the `<dir>/` key on listing.
const DIR_MARKER: &str = ".kerplace.dirobject";

/// On-disk JSON sidecar describing a stored object.
#[derive(Debug, Serialize, Deserialize)]
struct StoredMeta {
    etag: String,
    /// Logical (plaintext) size in bytes — what clients see.
    size: u64,
    content_type: String,
    #[serde(default)]
    user_metadata: BTreeMap<String, String>,
    /// Last-modified time as a Unix timestamp (seconds).
    last_modified: i64,
    /// Whether the payload on disk is encrypted (KerPlace `KPE1` container).
    #[serde(default)]
    encrypted: bool,
    /// Version id when the bucket is versioned. `None` for legacy/non-versioned
    /// objects; `Some("null")` for objects written while versioning was suspended.
    #[serde(default)]
    version_id: Option<String>,
}

/// One entry in a key's version history (newest-first ordering in
/// [`VersionHistory`]). Carries enough metadata to render `ListObjectVersions`
/// without opening each archived sidecar.
#[derive(Debug, Serialize, Deserialize, Clone)]
struct VersionEntry {
    /// Version id (`"null"` for suspended-mode / legacy versions).
    version_id: String,
    /// `true` if this entry is a delete marker (no payload on disk).
    #[serde(default)]
    delete_marker: bool,
    /// Last-modified time as a Unix timestamp (seconds).
    last_modified: i64,
    /// Entity tag (empty for delete markers).
    #[serde(default)]
    etag: String,
    /// Logical size in bytes (0 for delete markers).
    #[serde(default)]
    size: u64,
}

/// On-disk version history for a single key.
///
/// Invariant: when `versions[0]` is a real version (not a delete marker), the
/// canonical object file `<bucket>/<key>` holds its bytes; archived copies
/// under `.kerplace.sys/versions/` exist only for `versions[1..]`.
#[derive(Debug, Serialize, Deserialize, Default)]
struct VersionHistory {
    /// All versions and delete markers, newest first (`versions[0]` is latest).
    versions: Vec<VersionEntry>,
}

/// A bucket's effective versioning mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VMode {
    /// Versioning never configured — plain overwrite/delete semantics.
    Off,
    /// Versioning enabled — each write/delete creates a new UUID version.
    Enabled,
    /// Versioning suspended — writes/deletes use the `"null"` version id.
    Suspended,
}

/// On-disk manifest describing an in-progress multipart upload.
#[derive(Debug, Serialize, Deserialize)]
struct UploadManifest {
    key: String,
    content_type: String,
    #[serde(default)]
    user_metadata: BTreeMap<String, String>,
    created: i64,
    /// Whether the final assembled object should be encrypted.
    #[serde(default)]
    encrypt: bool,
}

/// On-disk sidecar describing a single staged multipart part.
#[derive(Debug, Serialize, Deserialize)]
struct PartMeta {
    etag: String,
    size: u64,
    created: i64,
}

/// A filesystem object store rooted at a single data directory.
pub struct FsStore {
    root: PathBuf,
    /// Combined crypto context: AES master key + optional ML-KEM-1024 keypair.
    crypto: CryptoContext,
    /// When true, every object written is encrypted (mirrors `KP_ENCRYPT`).
    encrypt_all: bool,
    /// Per-object locks so concurrent writes to the same key (version history +
    /// payload + metadata) can't interleave. FsStore is single-host, so local
    /// locking is sufficient (the distributed backend additionally fences).
    locks: crate::cluster::lock::LocalKeyLocks,
}

impl FsStore {
    /// Create a new filesystem store, ensuring the system directories exist.
    ///
    /// # Parameters
    /// - `root`: the data directory under which all state is kept.
    /// - `crypto`: the combined crypto context (master key + optional PQ keypair).
    /// - `encrypt_all`: when true encrypt every written object regardless of
    ///   the per-call `encrypt` flag (global `KP_ENCRYPT` override).
    ///
    /// # Returns
    /// A ready-to-use [`FsStore`], or an [`S3Error::Internal`] if the system
    /// directories cannot be created.
    pub async fn new(
        root: PathBuf,
        crypto: CryptoContext,
        encrypt_all: bool,
    ) -> Result<Self, S3Error> {
        let store = FsStore { root, crypto, encrypt_all, locks: crate::cluster::lock::LocalKeyLocks::new() };
        for dir in [store.tmp_dir(), store.meta_root(), store.multipart_root()] {
            fs::create_dir_all(&dir)
                .await
                .map_err(|e| S3Error::Internal(format!("init {dir:?}: {e}")))?;
        }
        Ok(store)
    }

    // ── Path helpers ──────────────────────────────────────────────────────────

    /// Path to the system temp directory used for atomic writes.
    fn tmp_dir(&self) -> PathBuf { self.root.join(SYS_DIR).join("tmp") }

    /// Path to the root of the object-metadata tree.
    fn meta_root(&self) -> PathBuf { self.root.join(SYS_DIR).join("meta") }

    /// Path to the root of the multipart staging tree.
    fn multipart_root(&self) -> PathBuf { self.root.join(SYS_DIR).join("multipart") }

    /// Path to the per-bucket config directory.
    fn bucket_cfg_dir(&self, bucket: &str) -> PathBuf {
        self.root.join(SYS_DIR).join("buckets").join(bucket)
    }

    /// Path to a bucket's payload directory.
    fn bucket_path(&self, bucket: &str) -> PathBuf { self.root.join(bucket) }

    /// Path to an object's payload file. Keys ending in `/` (directory markers)
    /// are stored under the [`DIR_MARKER`] sentinel inside the directory.
    fn object_path(&self, bucket: &str, key: &str) -> PathBuf {
        let base = self.bucket_path(bucket);
        match key.strip_suffix('/') {
            Some(dir) => base.join(dir).join(DIR_MARKER),
            None => base.join(key),
        }
    }

    /// Path to an object's metadata sidecar (directory markers use the sentinel).
    fn meta_path(&self, bucket: &str, key: &str) -> PathBuf {
        let base = self.meta_root().join(bucket);
        match key.strip_suffix('/') {
            Some(dir) => base.join(dir).join(format!("{DIR_MARKER}.json")),
            None => base.join(format!("{key}.json")),
        }
    }

    /// Path to a multipart upload's staging directory.
    fn upload_dir(&self, bucket: &str, upload_id: &str) -> PathBuf {
        self.multipart_root().join(bucket).join(upload_id)
    }

    /// Path to a per-bucket config file given a filename.
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    /// - `file`: config filename (e.g. `"sse.json"`).
    fn bucket_cfg_file(&self, bucket: &str, file: &str) -> PathBuf {
        self.bucket_cfg_dir(bucket).join(file)
    }

    /// Path to a per-object auxiliary sidecar given a suffix.
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    /// - `key`: object key.
    /// - `suffix`: sidecar suffix (e.g. `"tags.json"`).
    fn object_sidecar(&self, bucket: &str, key: &str, suffix: &str) -> PathBuf {
        self.meta_root().join(bucket).join(format!("{key}.{suffix}"))
    }

    // ── Generic bucket-config helpers ─────────────────────────────────────────

    /// Read a bucket-level config file, returning raw bytes or `None`.
    async fn read_bucket_cfg(&self, bucket: &str, file: &str) -> Option<Vec<u8>> {
        fs::read(self.bucket_cfg_file(bucket, file)).await.ok()
    }

    /// Write a bucket-level config file, creating parent dirs as needed.
    async fn write_bucket_cfg(
        &self,
        bucket: &str,
        file: &str,
        data: &[u8],
    ) -> Result<(), S3Error> {
        let path = self.bucket_cfg_file(bucket, file);
        fs::create_dir_all(path.parent().unwrap())
            .await
            .map_err(|e| S3Error::Internal(format!("mkdir bucket cfg: {e}")))?;
        fs::write(&path, data)
            .await
            .map_err(|e| S3Error::Internal(format!("write bucket cfg: {e}")))
    }

    /// Delete a bucket-level config file. Idempotent (missing is OK).
    async fn delete_bucket_cfg(&self, bucket: &str, file: &str) {
        let _ = fs::remove_file(self.bucket_cfg_file(bucket, file)).await;
    }

    // ── Generic object-sidecar helpers ────────────────────────────────────────

    /// Read an object sidecar file, returning raw bytes or `None`.
    async fn read_obj_sidecar(&self, bucket: &str, key: &str, suffix: &str) -> Option<Vec<u8>> {
        fs::read(self.object_sidecar(bucket, key, suffix)).await.ok()
    }

    /// Write an object sidecar file, creating parent dirs as needed.
    async fn write_obj_sidecar(
        &self,
        bucket: &str,
        key: &str,
        suffix: &str,
        data: &[u8],
    ) -> Result<(), S3Error> {
        let path = self.object_sidecar(bucket, key, suffix);
        fs::create_dir_all(path.parent().unwrap())
            .await
            .map_err(|e| S3Error::Internal(format!("mkdir sidecar: {e}")))?;
        fs::write(&path, data)
            .await
            .map_err(|e| S3Error::Internal(format!("write sidecar: {e}")))
    }

    /// Delete an object sidecar file. Idempotent.
    async fn delete_obj_sidecar(&self, bucket: &str, key: &str, suffix: &str) {
        let _ = fs::remove_file(self.object_sidecar(bucket, key, suffix)).await;
    }

    // ── Core I/O helpers ─────────────────────────────────────────────────────

    /// Stream a reader to a fresh temp file, computing its MD5 ETag as it goes.
    ///
    /// `need_md5` is the ETag/perf seam: when `false` (encrypted objects, or callers
    /// that discard the ETag), the MD5 pass is skipped and an [`opaque_etag`] is
    /// returned instead — the stored bytes are ciphertext under a fresh DEK so their
    /// MD5 carries no client-visible meaning (AWS-SSE semantics), and the hash was the
    /// #1 on-CPU cost of a write. When `true` (unencrypted single PUT) the real
    /// `md5(bytes)` ETag is computed, preserving plain-S3 behaviour.
    ///
    /// # Parameters
    /// - `body`: the streaming payload reader.
    /// - `need_md5`: compute the real MD5 ETag (`true`) or synthesize an opaque one.
    ///
    /// # Returns
    /// `(temp_path, etag, byte_count)` on success, or [`S3Error::Internal`].
    async fn stream_to_temp(&self, mut body: BodyReader, need_md5: bool) -> Result<(PathBuf, String, u64), S3Error> {
        let tmp = self.tmp_dir().join(Uuid::new_v4().simple().to_string());
        let mut file = File::create(&tmp)
            .await
            .map_err(|e| S3Error::Internal(format!("create temp: {e}")))?;
        let mut hasher = Md5::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total: u64 = 0;
        loop {
            let n = body
                .read(&mut buf)
                .await
                .map_err(|e| S3Error::Internal(format!("read body: {e}")))?;
            if n == 0 {
                break;
            }
            if need_md5 {
                hasher.update(&buf[..n]);
            }
            file.write_all(&buf[..n])
                .await
                .map_err(|e| S3Error::Internal(format!("write temp: {e}")))?;
            total += n as u64;
        }
        file.flush()
            .await
            .map_err(|e| S3Error::Internal(format!("flush temp: {e}")))?;
        let etag = if need_md5 { hex::encode(hasher.finalize()) } else { opaque_etag() };
        Ok((tmp, etag, total))
    }

    /// Atomically move a temp file to a destination, creating parent dirs.
    ///
    /// # Parameters
    /// - `tmp`: the source temp file (consumed/removed by the rename).
    /// - `dest`: the final destination path.
    ///
    /// # Returns
    /// `Ok(())` on success, or [`S3Error::Internal`] if the rename fails.
    async fn move_into_place(&self, tmp: &Path, dest: &Path) -> Result<(), S3Error> {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| S3Error::Internal(format!("mkdir {parent:?}: {e}")))?;
        }
        fs::rename(tmp, dest)
            .await
            .map_err(|e| S3Error::Internal(format!("rename: {e}")))
    }

    /// Remove now-empty directories walking upward from `start` to `stop`.
    ///
    /// # Parameters
    /// - `dir`: the deepest directory to attempt to remove.
    /// - `stop`: the boundary directory that is never removed.
    async fn prune_empty_dirs(&self, mut dir: PathBuf, stop: &Path) {
        while dir != stop && dir.starts_with(stop) {
            if fs::remove_dir(&dir).await.is_err() {
                break;
            }
            match dir.parent() {
                Some(parent) => dir = parent.to_path_buf(),
                None => break,
            }
        }
    }

    /// Persist an object's metadata sidecar.
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    /// - `key`: object key.
    /// - `meta`: the metadata to serialize.
    async fn write_meta(&self, bucket: &str, key: &str, meta: &StoredMeta) -> Result<(), S3Error> {
        let path = self.meta_path(bucket, key);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| S3Error::Internal(format!("mkdir meta: {e}")))?;
        }
        let json = serde_json::to_vec(meta)
            .map_err(|e| S3Error::Internal(format!("encode meta: {e}")))?;
        fs::write(&path, json)
            .await
            .map_err(|e| S3Error::Internal(format!("write meta: {e}")))
    }

    /// Load an object's raw on-disk metadata sidecar, reconstructing it from
    /// `stat` if the sidecar is missing.
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    /// - `key`: object key.
    ///
    /// # Returns
    /// [`StoredMeta`] on success, or [`S3Error::NoSuchKey`] if the payload does
    /// not exist.
    async fn read_stored(&self, bucket: &str, key: &str) -> Result<StoredMeta, S3Error> {
        let obj_path = self.object_path(bucket, key);
        let stat = match fs::metadata(&obj_path).await {
            Ok(m) if m.is_file() => m,
            _ => return Err(S3Error::NoSuchKey),
        };
        if let Ok(bytes) = fs::read(self.meta_path(bucket, key)).await {
            if let Ok(stored) = serde_json::from_slice::<StoredMeta>(&bytes) {
                return Ok(stored);
            }
        }
        Ok(StoredMeta {
            etag: String::new(),
            size: stat.len(),
            content_type: "application/octet-stream".to_string(),
            user_metadata: BTreeMap::new(),
            last_modified: stat
                .modified()
                .map(|t| OffsetDateTime::from(t).unix_timestamp())
                .unwrap_or_else(|_| now_secs()),
            encrypted: false,
            version_id: None,
        })
    }

    /// Load an object's public metadata.
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    /// - `key`: object key.
    async fn load_meta(&self, bucket: &str, key: &str) -> Result<ObjectMeta, S3Error> {
        let stored = self.read_stored(bucket, key).await?;
        Ok(self.stored_to_meta(key, stored))
    }

    /// Build public [`ObjectMeta`] from a raw [`StoredMeta`].
    ///
    /// # Parameters
    /// - `key`: the object key.
    /// - `stored`: the on-disk metadata.
    fn stored_to_meta(&self, key: &str, stored: StoredMeta) -> ObjectMeta {
        ObjectMeta {
            key: key.to_string(),
            size: stored.size,
            etag: stored.etag,
            last_modified: unix_to_dt(stored.last_modified),
            content_type: stored.content_type,
            user_metadata: stored.user_metadata,
            encrypted: stored.encrypted,
            version_id: stored.version_id,
            audit: None,
        }
    }

    /// Decide whether to encrypt a write given the caller's `encrypt` flag and
    /// the global `encrypt_all` override.
    ///
    /// # Parameters
    /// - `encrypt`: per-call flag (from SSE header or bucket SSE config).
    ///
    /// # Returns
    /// `true` if the object should be encrypted.
    fn should_encrypt(&self, encrypt: bool) -> bool {
        encrypt || self.encrypt_all
    }

    // ── Versioning: paths + history helpers ───────────────────────────────────

    /// Root of the version archive tree (non-current versions + histories).
    fn versions_root(&self) -> PathBuf {
        self.root.join(SYS_DIR).join("versions")
    }

    /// Directory holding a key's archived versions and its history file.
    fn version_dir(&self, bucket: &str, key: &str) -> PathBuf {
        self.versions_root().join(bucket).join(key)
    }

    /// Path to an archived version's payload file.
    fn version_data_path(&self, bucket: &str, key: &str, vid: &str) -> PathBuf {
        self.version_dir(bucket, key).join(format!("{vid}.data"))
    }

    /// Path to an archived version's metadata sidecar.
    fn version_meta_path(&self, bucket: &str, key: &str, vid: &str) -> PathBuf {
        self.version_dir(bucket, key).join(format!("{vid}.json"))
    }

    /// Path to a key's version-history file.
    fn history_path(&self, bucket: &str, key: &str) -> PathBuf {
        self.version_dir(bucket, key).join("kp.history.json")
    }

    /// Resolve a bucket's effective versioning mode from its config.
    async fn versioning_mode(&self, bucket: &str) -> VMode {
        match self.read_bucket_cfg(bucket, "versioning.json").await {
            Some(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
                Ok(v) => match v["status"].as_str().unwrap_or("") {
                    "Enabled" => VMode::Enabled,
                    "Suspended" => VMode::Suspended,
                    _ => VMode::Off,
                },
                Err(_) => VMode::Off,
            },
            None => VMode::Off,
        }
    }

    /// Read a key's version history, or an empty history if none exists.
    async fn read_history(&self, bucket: &str, key: &str) -> VersionHistory {
        match fs::read(self.history_path(bucket, key)).await {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => VersionHistory::default(),
        }
    }

    /// Persist a key's version history.
    async fn write_history(
        &self,
        bucket: &str,
        key: &str,
        hist: &VersionHistory,
    ) -> Result<(), S3Error> {
        let path = self.history_path(bucket, key);
        fs::create_dir_all(path.parent().unwrap())
            .await
            .map_err(|e| S3Error::Internal(format!("mkdir versions: {e}")))?;
        let json = serde_json::to_vec(hist)
            .map_err(|e| S3Error::Internal(format!("encode history: {e}")))?;
        fs::write(&path, json)
            .await
            .map_err(|e| S3Error::Internal(format!("write history: {e}")))
    }

    /// Whether a key already has a version history on disk.
    async fn has_history(&self, bucket: &str, key: &str) -> bool {
        fs::metadata(self.history_path(bucket, key)).await.is_ok()
    }

    /// Seed a one-entry `"null"` history from a pre-existing (legacy or
    /// non-versioned) canonical object, so it can be addressed as a version once
    /// the bucket becomes versioned. No-op if a history already exists or no
    /// canonical object is present.
    async fn seed_legacy_history(&self, bucket: &str, key: &str) -> Result<(), S3Error> {
        if self.has_history(bucket, key).await {
            return Ok(());
        }
        let stored = match self.read_stored(bucket, key).await {
            Ok(s) => s,
            Err(_) => return Ok(()), // no canonical object — nothing to seed
        };
        let hist = VersionHistory {
            versions: vec![VersionEntry {
                version_id: "null".to_string(),
                delete_marker: false,
                last_modified: stored.last_modified,
                etag: stored.etag,
                size: stored.size,
            }],
        };
        self.write_history(bucket, key, &hist).await
    }

    /// Move the current canonical object (and its meta) into the version archive
    /// under `vid`. Preserves the invariant when a newer version takes over the
    /// canonical slot.
    async fn demote_canonical_to_archive(
        &self,
        bucket: &str,
        key: &str,
        vid: &str,
    ) -> Result<(), S3Error> {
        let data_dst = self.version_data_path(bucket, key, vid);
        if let Some(parent) = data_dst.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| S3Error::Internal(format!("mkdir archive: {e}")))?;
        }
        fs::rename(self.object_path(bucket, key), &data_dst)
            .await
            .map_err(|e| S3Error::Internal(format!("archive payload: {e}")))?;
        // Meta sidecar is best-effort (reads fall back to stat if missing).
        let _ = fs::rename(
            self.meta_path(bucket, key),
            self.version_meta_path(bucket, key, vid),
        )
        .await;
        Ok(())
    }

    /// Promote an archived version back into the canonical slot (used when the
    /// current version is permanently deleted and a prior version exists).
    async fn promote_archive_to_canonical(
        &self,
        bucket: &str,
        key: &str,
        vid: &str,
    ) -> Result<(), S3Error> {
        let dst = self.object_path(bucket, key);
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| S3Error::Internal(format!("mkdir bucket: {e}")))?;
        }
        fs::rename(self.version_data_path(bucket, key, vid), &dst)
            .await
            .map_err(|e| S3Error::Internal(format!("promote payload: {e}")))?;
        let _ = fs::rename(
            self.version_meta_path(bucket, key, vid),
            self.meta_path(bucket, key),
        )
        .await;
        Ok(())
    }

    /// Remove the canonical object payload + meta (current version discarded).
    async fn discard_canonical(&self, bucket: &str, key: &str) {
        let _ = fs::remove_file(self.object_path(bucket, key)).await;
        let _ = fs::remove_file(self.meta_path(bucket, key)).await;
    }

    /// Remove an archived version's payload + meta.
    async fn remove_archive(&self, bucket: &str, key: &str, vid: &str) {
        let _ = fs::remove_file(self.version_data_path(bucket, key, vid)).await;
        let _ = fs::remove_file(self.version_meta_path(bucket, key, vid)).await;
    }

    /// Prepare the version archive for a new write: seed legacy history, purge
    /// any prior `"null"` version (suspended mode), and demote the current
    /// canonical version into the archive so the canonical slot is free.
    ///
    /// # Returns
    /// `(new_version_id, history_without_new_entry)`. The caller writes the new
    /// canonical payload + meta, then calls [`FsStore::finish_versioned_write`].
    async fn begin_versioned_write(
        &self,
        bucket: &str,
        key: &str,
        mode: VMode,
    ) -> Result<(String, VersionHistory), S3Error> {
        self.seed_legacy_history(bucket, key).await?;
        let mut hist = self.read_history(bucket, key).await;
        let mut canonical_occupied =
            hist.versions.first().map(|v| !v.delete_marker).unwrap_or(false);

        let new_vid = match mode {
            VMode::Enabled => Uuid::new_v4().simple().to_string(),
            VMode::Suspended => "null".to_string(),
            VMode::Off => unreachable!("begin_versioned_write called in Off mode"),
        };

        // Suspended writes replace any existing "null" version.
        if mode == VMode::Suspended {
            if let Some(idx) = hist.versions.iter().position(|v| v.version_id == "null") {
                let is_marker = hist.versions[idx].delete_marker;
                if idx == 0 && canonical_occupied {
                    self.discard_canonical(bucket, key).await;
                    canonical_occupied = false;
                } else if !is_marker {
                    self.remove_archive(bucket, key, "null").await;
                }
                hist.versions.remove(idx);
            }
        }

        // Demote whatever real version still holds the canonical slot.
        if canonical_occupied {
            let cur_vid = hist.versions[0].version_id.clone();
            self.demote_canonical_to_archive(bucket, key, &cur_vid).await?;
        }

        Ok((new_vid, hist))
    }

    /// Record a freshly written canonical version at the head of the history.
    async fn finish_versioned_write(
        &self,
        bucket: &str,
        key: &str,
        mut hist: VersionHistory,
        vid: String,
        etag: String,
        size: u64,
        last_modified: i64,
    ) -> Result<(), S3Error> {
        hist.versions.insert(
            0,
            VersionEntry { version_id: vid, delete_marker: false, last_modified, etag, size },
        );
        self.write_history(bucket, key, &hist).await
    }

    /// Read an archived version's metadata sidecar, reconstructing it from the
    /// archived payload's `stat` if the sidecar is missing.
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    /// - `key`: object key.
    /// - `vid`: the archived version id.
    ///
    /// # Returns
    /// [`StoredMeta`] for the version, or [`S3Error::NoSuchVersion`] if neither
    /// the sidecar nor the payload exists.
    async fn read_version_stored(
        &self,
        bucket: &str,
        key: &str,
        vid: &str,
    ) -> Result<StoredMeta, S3Error> {
        if let Ok(bytes) = fs::read(self.version_meta_path(bucket, key, vid)).await {
            if let Ok(stored) = serde_json::from_slice::<StoredMeta>(&bytes) {
                return Ok(stored);
            }
        }
        let stat = fs::metadata(self.version_data_path(bucket, key, vid))
            .await
            .map_err(|_| S3Error::NoSuchVersion)?;
        Ok(StoredMeta {
            etag: String::new(),
            size: stat.len(),
            content_type: "application/octet-stream".to_string(),
            user_metadata: BTreeMap::new(),
            last_modified: now_secs(),
            encrypted: false,
            version_id: Some(vid.to_string()),
        })
    }
}

/// Convert a Unix timestamp (seconds) into an [`OffsetDateTime`].
fn unix_to_dt(secs: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(secs).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

/// Current wall-clock time as a Unix timestamp (seconds).
fn now_secs() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

#[async_trait]
impl ObjectStore for FsStore {
    /// See [`ObjectStore::create_bucket`].
    async fn create_bucket(&self, bucket: &str) -> Result<(), S3Error> {
        validate_bucket_name(bucket)?;
        let path = self.bucket_path(bucket);
        if fs::metadata(&path).await.is_ok() {
            return Err(S3Error::BucketAlreadyOwnedByYou);
        }
        fs::create_dir_all(&path)
            .await
            .map_err(|e| S3Error::Internal(format!("create bucket: {e}")))
    }

    /// See [`ObjectStore::delete_bucket`].
    async fn delete_bucket(&self, bucket: &str) -> Result<(), S3Error> {
        let path = self.bucket_path(bucket);
        if fs::metadata(&path).await.is_err() {
            return Err(S3Error::NoSuchBucket);
        }
        let walk_path = path.clone();
        let has_objects = tokio::task::spawn_blocking(move || {
            WalkDir::new(&walk_path)
                .into_iter()
                .filter_map(|e| e.ok())
                .any(|e| e.file_type().is_file())
        })
        .await
        .map_err(|e| S3Error::Internal(format!("walk: {e}")))?;
        if has_objects {
            return Err(S3Error::BucketNotEmpty);
        }
        fs::remove_dir_all(&path)
            .await
            .map_err(|e| S3Error::Internal(format!("remove bucket: {e}")))?;
        // Best-effort cleanup of side trees.
        let _ = fs::remove_dir_all(self.meta_root().join(bucket)).await;
        let _ = fs::remove_dir_all(self.multipart_root().join(bucket)).await;
        let _ = fs::remove_dir_all(self.bucket_cfg_dir(bucket)).await;
        let _ = fs::remove_dir_all(self.versions_root().join(bucket)).await;
        Ok(())
    }

    /// See [`ObjectStore::list_buckets`].
    async fn list_buckets(&self) -> Result<Vec<BucketInfo>, S3Error> {
        let mut entries = fs::read_dir(&self.root)
            .await
            .map_err(|e| S3Error::Internal(format!("read root: {e}")))?;
        let mut buckets = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| S3Error::Internal(e.to_string()))?
        {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == SYS_DIR {
                continue;
            }
            let meta = match entry.metadata().await {
                Ok(m) if m.is_dir() => m,
                _ => continue,
            };
            let creation_date = meta
                .created()
                .or_else(|_| meta.modified())
                .map(OffsetDateTime::from)
                .unwrap_or_else(|_| OffsetDateTime::now_utc());
            buckets.push(BucketInfo { name, creation_date });
        }
        buckets.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(buckets)
    }

    /// See [`ObjectStore::head_bucket`].
    async fn head_bucket(&self, bucket: &str) -> Result<(), S3Error> {
        match fs::metadata(self.bucket_path(bucket)).await {
            Ok(m) if m.is_dir() => Ok(()),
            _ => Err(S3Error::NoSuchBucket),
        }
    }

    /// See [`ObjectStore::put_object`].
    async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        body: BodyReader,
        content_type: String,
        user_metadata: BTreeMap<String, String>,
        encrypt: bool,
    ) -> Result<ObjectMeta, S3Error> {
        self.head_bucket(bucket).await?;
        validate_key(key)?;
        let _lock = self.locks.acquire(&format!("{bucket}/{key}")).await;
        let encrypted = self.should_encrypt(encrypt);
        // Fail-closed: mint the DEK before staging anything, so a KMS outage
        // aborts the write instead of storing a 0-byte object and answering 200.
        let body: BodyReader = if encrypted {
            crypto::encrypting_reader(body, self.crypto.clone())
                .await
                .map_err(|e| S3Error::Internal(format!("encrypt object: {e}")))?
        } else {
            body
        };
        let (tmp, etag, stored_size) = self.stream_to_temp(body, !encrypted).await?;
        let size = if encrypted {
            crypto::plaintext_len(stored_size, self.crypto.header_len())
        } else {
            stored_size
        };
        let last_modified = now_secs();
        let mode = self.versioning_mode(bucket).await;

        // For versioned buckets, archive the prior current version (freeing the
        // canonical slot) before moving the new payload into place.
        let (version_id, pending_hist) = if mode == VMode::Off {
            (None, None)
        } else {
            let (vid, hist) = self.begin_versioned_write(bucket, key, mode).await?;
            (Some(vid), Some(hist))
        };

        self.move_into_place(&tmp, &self.object_path(bucket, key)).await?;
        let stored = StoredMeta {
            etag: etag.clone(),
            size,
            content_type: content_type.clone(),
            user_metadata: user_metadata.clone(),
            last_modified,
            encrypted,
            version_id: version_id.clone(),
        };
        self.write_meta(bucket, key, &stored).await?;

        if let (Some(vid), Some(hist)) = (version_id.clone(), pending_hist) {
            self.finish_versioned_write(
                bucket,
                key,
                hist,
                vid,
                etag.clone(),
                size,
                last_modified,
            )
            .await?;
        }

        Ok(ObjectMeta {
            key: key.to_string(),
            size,
            etag,
            last_modified: unix_to_dt(last_modified),
            content_type,
            user_metadata,
            encrypted,
            version_id,
            audit: None,
        })
    }

    /// See [`ObjectStore::get_object`].
    async fn get_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<(ObjectMeta, ObjectBody), S3Error> {
        let stored = self.read_stored(bucket, key).await?;
        let file = File::open(self.object_path(bucket, key))
            .await
            .map_err(|_| S3Error::NoSuchKey)?;
        let body: ObjectBody = if stored.encrypted {
            crypto::decrypting_reader_checked(Box::pin(file), self.crypto.clone())
                .await
                .map_err(|e| S3Error::Internal(format!("decrypt object: {e}")))?
        } else {
            Box::pin(file)
        };
        Ok((self.stored_to_meta(key, stored), body))
    }

    /// See [`ObjectStore::get_object_range`].
    async fn get_object_range(
        &self,
        bucket: &str,
        key: &str,
        start: u64,
        end: Option<u64>,
    ) -> Result<(ObjectMeta, u64, ObjectBody), S3Error> {
        use tokio::io::AsyncSeekExt;
        let stored = self.read_stored(bucket, key).await?;
        let size = stored.size;
        let start = start.min(size);
        let last = end
            .map(|e| e.min(size.saturating_sub(1)))
            .unwrap_or_else(|| size.saturating_sub(1));
        let len = if size == 0 || last < start { 0 } else { last - start + 1 };
        let path = self.object_path(bucket, key);
        let mut file = File::open(&path).await.map_err(|_| S3Error::NoSuchKey)?;

        if !stored.encrypted {
            file.seek(std::io::SeekFrom::Start(start))
                .await
                .map_err(|e| S3Error::Internal(format!("seek: {e}")))?;
            let body: ObjectBody = Box::pin(file.take(len));
            return Ok((self.stored_to_meta(key, stored), len, body));
        }

        // Encrypted: read the header, then decrypt only the covering chunks.
        let ct_size = fs::metadata(&path)
            .await
            .map_err(|e| S3Error::Internal(e.to_string()))?
            .len();
        let mut prefix = [0u8; 8];
        file.read_exact(&mut prefix)
            .await
            .map_err(|e| S3Error::Internal(format!("read header: {e}")))?;
        let wrapped_len = u16::from_be_bytes([prefix[6], prefix[7]]) as usize;
        let header_len = 8 + wrapped_len + 8;
        let mut header = vec![0u8; header_len];
        header[..8].copy_from_slice(&prefix);
        file.read_exact(&mut header[8..])
            .await
            .map_err(|e| S3Error::Internal(format!("read header: {e}")))?;
        let (cipher, _hl) = ObjectCipher::open(&self.crypto, &header)
            .await
            .map_err(|e| S3Error::Internal(e.to_string()))?;

        let chunk = CHUNK_SIZE as u64;
        let first_chunk = start / chunk;
        let last_chunk = last / chunk;
        let mut plain: Vec<u8> = Vec::new();
        for ci in first_chunk..=last_chunk {
            let off = header_len as u64 + ci * CHUNK_BLOCK as u64;
            if off >= ct_size {
                break;
            }
            let block_len = ((ct_size - off) as usize).min(CHUNK_BLOCK);
            file.seek(std::io::SeekFrom::Start(off))
                .await
                .map_err(|e| S3Error::Internal(format!("seek: {e}")))?;
            let mut block = vec![0u8; block_len];
            file.read_exact(&mut block)
                .await
                .map_err(|e| S3Error::Internal(format!("read chunk: {e}")))?;
            let pt = cipher
                .decrypt_chunk(ci as u32, &block)
                .map_err(|e| S3Error::Internal(e.to_string()))?;
            plain.extend_from_slice(&pt);
        }
        let local_start = (start - first_chunk * chunk) as usize;
        let local_end = (local_start + len as usize).min(plain.len());
        let slice = plain.get(local_start..local_end).unwrap_or(&[]).to_vec();
        let body: ObjectBody = Box::pin(std::io::Cursor::new(slice));
        Ok((self.stored_to_meta(key, stored), len, body))
    }

    /// See [`ObjectStore::head_object`].
    async fn head_object(&self, bucket: &str, key: &str) -> Result<ObjectMeta, S3Error> {
        self.load_meta(bucket, key).await
    }

    /// See [`ObjectStore::delete_object`].
    async fn delete_object(&self, bucket: &str, key: &str) -> Result<DeleteOutcome, S3Error> {
        self.head_bucket(bucket).await?;
        let _lock = self.locks.acquire(&format!("{bucket}/{key}")).await;
        let mode = self.versioning_mode(bucket).await;

        // Versioned (enabled/suspended): insert a delete marker, preserving the
        // current version in the archive rather than removing data.
        if mode != VMode::Off {
            self.seed_legacy_history(bucket, key).await?;
            let mut hist = self.read_history(bucket, key).await;

            let marker_vid = match mode {
                VMode::Enabled => Uuid::new_v4().simple().to_string(),
                VMode::Suspended => "null".to_string(),
                VMode::Off => unreachable!(),
            };
            let mut canonical_occupied =
                hist.versions.first().map(|v| !v.delete_marker).unwrap_or(false);

            // Suspended delete replaces any existing "null" version.
            if mode == VMode::Suspended {
                if let Some(idx) = hist.versions.iter().position(|v| v.version_id == "null") {
                    let is_marker = hist.versions[idx].delete_marker;
                    if idx == 0 && canonical_occupied {
                        self.discard_canonical(bucket, key).await;
                        canonical_occupied = false;
                    } else if !is_marker {
                        self.remove_archive(bucket, key, "null").await;
                    }
                    hist.versions.remove(idx);
                }
            }

            // Preserve the current real version in the archive.
            if canonical_occupied {
                let cur_vid = hist.versions[0].version_id.clone();
                self.demote_canonical_to_archive(bucket, key, &cur_vid).await?;
            }

            hist.versions.insert(
                0,
                VersionEntry {
                    version_id: marker_vid.clone(),
                    delete_marker: true,
                    last_modified: now_secs(),
                    etag: String::new(),
                    size: 0,
                },
            );
            self.write_history(bucket, key, &hist).await?;
            return Ok(DeleteOutcome { version_id: Some(marker_vid), delete_marker: true });
        }

        // Non-versioned: permanent delete (legacy behaviour).
        let obj_path = self.object_path(bucket, key);
        let _ = fs::remove_file(&obj_path).await;
        let meta_path = self.meta_path(bucket, key);
        let _ = fs::remove_file(&meta_path).await;
        // Remove all object sidecars (tags, retention, legal hold).
        for suffix in ["tags.json", "retention.json", "legalhold.json"] {
            self.delete_obj_sidecar(bucket, key, suffix).await;
        }
        if let Some(parent) = obj_path.parent() {
            self.prune_empty_dirs(parent.to_path_buf(), &self.bucket_path(bucket)).await;
        }
        if let Some(parent) = meta_path.parent() {
            self.prune_empty_dirs(parent.to_path_buf(), &self.meta_root().join(bucket)).await;
        }
        Ok(DeleteOutcome::default())
    }

    /// See [`ObjectStore::get_object_version`].
    async fn get_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<(ObjectMeta, ObjectBody), S3Error> {
        self.head_bucket(bucket).await?;
        self.seed_legacy_history(bucket, key).await?;
        let hist = self.read_history(bucket, key).await;
        let idx = hist
            .versions
            .iter()
            .position(|v| v.version_id == version_id)
            .ok_or(S3Error::NoSuchVersion)?;
        if hist.versions[idx].delete_marker {
            return Err(S3Error::MethodNotAllowed);
        }
        // versions[0] real ⇒ lives at the canonical path; others in the archive.
        let (data_path, stored) = if idx == 0 {
            (self.object_path(bucket, key), self.read_stored(bucket, key).await?)
        } else {
            let meta = self.read_version_stored(bucket, key, version_id).await?;
            (self.version_data_path(bucket, key, version_id), meta)
        };
        let file = File::open(&data_path).await.map_err(|_| S3Error::NoSuchVersion)?;
        let body: ObjectBody = if stored.encrypted {
            crypto::decrypting_reader_checked(Box::pin(file), self.crypto.clone())
                .await
                .map_err(|e| S3Error::Internal(format!("decrypt object: {e}")))?
        } else {
            Box::pin(file)
        };
        let mut meta = self.stored_to_meta(key, stored);
        meta.version_id = Some(version_id.to_string());
        Ok((meta, body))
    }

    /// See [`ObjectStore::head_object_version`].
    async fn head_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<ObjectMeta, S3Error> {
        self.head_bucket(bucket).await?;
        self.seed_legacy_history(bucket, key).await?;
        let hist = self.read_history(bucket, key).await;
        let idx = hist
            .versions
            .iter()
            .position(|v| v.version_id == version_id)
            .ok_or(S3Error::NoSuchVersion)?;
        if hist.versions[idx].delete_marker {
            return Err(S3Error::MethodNotAllowed);
        }
        let stored = if idx == 0 {
            self.read_stored(bucket, key).await?
        } else {
            self.read_version_stored(bucket, key, version_id).await?
        };
        let mut meta = self.stored_to_meta(key, stored);
        meta.version_id = Some(version_id.to_string());
        Ok(meta)
    }

    /// See [`ObjectStore::delete_object_version`].
    async fn delete_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<DeleteOutcome, S3Error> {
        self.head_bucket(bucket).await?;
        let _lock = self.locks.acquire(&format!("{bucket}/{key}")).await;
        self.seed_legacy_history(bucket, key).await?;
        let mut hist = self.read_history(bucket, key).await;
        let idx = hist
            .versions
            .iter()
            .position(|v| v.version_id == version_id)
            .ok_or(S3Error::NoSuchVersion)?;
        let entry = hist.versions[idx].clone();
        let was_current = idx == 0;

        // Remove the targeted version's payload.
        if !entry.delete_marker {
            if was_current {
                self.discard_canonical(bucket, key).await;
            } else {
                self.remove_archive(bucket, key, version_id).await;
            }
        }
        hist.versions.remove(idx);

        // If we removed the current version, promote the next real version (if
        // any) back into the canonical slot.
        if was_current {
            if let Some(next) = hist.versions.first() {
                if !next.delete_marker {
                    let next_vid = next.version_id.clone();
                    self.promote_archive_to_canonical(bucket, key, &next_vid).await?;
                }
            }
        }

        if hist.versions.is_empty() {
            // No versions left — drop the history and prune empty dirs.
            let _ = fs::remove_file(self.history_path(bucket, key)).await;
            self.prune_empty_dirs(self.version_dir(bucket, key), &self.versions_root())
                .await;
        } else {
            self.write_history(bucket, key, &hist).await?;
        }

        Ok(DeleteOutcome {
            version_id: Some(version_id.to_string()),
            delete_marker: entry.delete_marker,
        })
    }

    /// See [`ObjectStore::copy_object`].
    async fn copy_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        dst_bucket: &str,
        dst_key: &str,
        encrypt: bool,
    ) -> Result<ObjectMeta, S3Error> {
        let src_stored = self.read_stored(src_bucket, src_key).await?;
        self.head_bucket(dst_bucket).await?;
        validate_key(dst_key)?;
        let _lock = self.locks.acquire(&format!("{dst_bucket}/{dst_key}")).await;
        let src_file = File::open(self.object_path(src_bucket, src_key))
            .await
            .map_err(|_| S3Error::NoSuchKey)?;
        // Read source as plaintext (decrypting if needed); fail loudly if the key
        // provider can't unwrap (e.g. KMS outage) rather than copying empty bytes.
        let plain: BodyReader = if src_stored.encrypted {
            crypto::decrypting_reader_checked(Box::pin(src_file), self.crypto.clone())
                .await
                .map_err(|e| S3Error::Internal(format!("decrypt source: {e}")))?
        } else {
            Box::pin(src_file)
        };
        let encrypted = self.should_encrypt(encrypt);
        // Fail-closed, mirroring the `decrypting_reader_checked` above: a copy
        // must not silently produce an empty destination on a KMS outage.
        let to_write: BodyReader = if encrypted {
            crypto::encrypting_reader(plain, self.crypto.clone())
                .await
                .map_err(|e| S3Error::Internal(format!("encrypt object: {e}")))?
        } else {
            plain
        };
        let (tmp, etag, stored_size) = self.stream_to_temp(to_write, !encrypted).await?;
        let size = if encrypted {
            crypto::plaintext_len(stored_size, self.crypto.header_len())
        } else {
            stored_size
        };
        let last_modified = now_secs();
        let mode = self.versioning_mode(dst_bucket).await;
        let (version_id, pending_hist) = if mode == VMode::Off {
            (None, None)
        } else {
            let (vid, hist) = self.begin_versioned_write(dst_bucket, dst_key, mode).await?;
            (Some(vid), Some(hist))
        };

        self.move_into_place(&tmp, &self.object_path(dst_bucket, dst_key)).await?;
        let stored = StoredMeta {
            etag: etag.clone(),
            size,
            content_type: src_stored.content_type.clone(),
            user_metadata: src_stored.user_metadata.clone(),
            last_modified,
            encrypted,
            version_id: version_id.clone(),
        };
        self.write_meta(dst_bucket, dst_key, &stored).await?;

        if let (Some(vid), Some(hist)) = (version_id.clone(), pending_hist) {
            self.finish_versioned_write(
                dst_bucket,
                dst_key,
                hist,
                vid,
                etag.clone(),
                size,
                last_modified,
            )
            .await?;
        }

        Ok(ObjectMeta {
            key: dst_key.to_string(),
            size,
            etag,
            last_modified: unix_to_dt(last_modified),
            content_type: src_stored.content_type,
            user_metadata: src_stored.user_metadata,
            encrypted,
            version_id,
            audit: None,
        })
    }

    /// See [`ObjectStore::list_objects_v2`].
    async fn list_objects_v2(
        &self,
        bucket: &str,
        prefix: &str,
        delimiter: Option<&str>,
        continuation_token: Option<&str>,
        start_after: Option<&str>,
        max_keys: usize,
    ) -> Result<Listing, S3Error> {
        self.head_bucket(bucket).await?;
        let bucket_path = self.bucket_path(bucket);
        let mut keys = tokio::task::spawn_blocking(move || {
            let mut keys = Vec::new();
            for entry in WalkDir::new(&bucket_path).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    if let Ok(rel) = entry.path().strip_prefix(&bucket_path) {
                        let rel = rel.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
                        // Translate a directory-marker sentinel back into its
                        // `<dir>/` key; surface other files as their own key.
                        if rel == DIR_MARKER {
                            continue; // marker at the bucket root has no key
                        } else if let Some(dir) = rel.strip_suffix(&format!("/{DIR_MARKER}")) {
                            keys.push(format!("{dir}/"));
                        } else {
                            keys.push(rel);
                        }
                    }
                }
            }
            keys
        })
        .await
        .map_err(|e| S3Error::Internal(format!("walk: {e}")))?;

        keys.retain(|k| k.starts_with(prefix));
        keys.sort();

        let mut common: BTreeSet<String> = BTreeSet::new();
        let mut chosen: Vec<String> = Vec::new();
        let mut count = 0usize;
        let mut truncated = false;
        let mut next_token = None;

        for key in keys {
            if let Some(t) = continuation_token {
                if key.as_str() < t { continue; }
            }
            if let Some(a) = start_after {
                if key.as_str() <= a { continue; }
            }
            if let Some(delim) = delimiter.filter(|d| !d.is_empty()) {
                let rest = &key[prefix.len()..];
                if let Some(idx) = rest.find(delim) {
                    let cp = format!("{}{}{}", prefix, &rest[..idx], delim);
                    if !common.contains(&cp) {
                        if count >= max_keys {
                            truncated = true;
                            next_token = Some(key);
                            break;
                        }
                        common.insert(cp);
                        count += 1;
                    }
                    continue;
                }
            }
            if count >= max_keys {
                truncated = true;
                next_token = Some(key);
                break;
            }
            chosen.push(key);
            count += 1;
        }

        let mut objects = Vec::with_capacity(chosen.len());
        for key in chosen {
            objects.push(self.load_meta(bucket, &key).await?);
        }
        Ok(Listing {
            objects,
            common_prefixes: common.into_iter().collect(),
            is_truncated: truncated,
            next_continuation_token: next_token,
        })
    }

    /// See [`ObjectStore::list_object_versions`].
    async fn list_object_versions(
        &self,
        bucket: &str,
        prefix: &str,
        delimiter: Option<&str>,
        key_marker: Option<&str>,
        version_id_marker: Option<&str>,
        max_keys: usize,
    ) -> Result<VersionListing, S3Error> {
        self.head_bucket(bucket).await?;

        // 1. Gather all versioned keys (those with a history file) by walking the
        //    archive tree, plus all legacy/non-versioned keys from the canonical
        //    tree (emitted as a single "null" current version).
        let versions_bucket = self.versions_root().join(bucket);
        let bucket_path = self.bucket_path(bucket);
        let vb = versions_bucket.clone();
        let bp = bucket_path.clone();
        let (versioned_keys, canonical_keys) = tokio::task::spawn_blocking(move || {
            let mut vkeys = Vec::new();
            for entry in WalkDir::new(&vb).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() && entry.file_name() == "kp.history.json" {
                    if let Some(dir) = entry.path().parent() {
                        if let Ok(rel) = dir.strip_prefix(&vb) {
                            vkeys.push(
                                rel.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"),
                            );
                        }
                    }
                }
            }
            let mut ckeys = Vec::new();
            for entry in WalkDir::new(&bp).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    if let Ok(rel) = entry.path().strip_prefix(&bp) {
                        let rel = rel.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
                        if rel == DIR_MARKER {
                            continue;
                        } else if let Some(dir) = rel.strip_suffix(&format!("/{DIR_MARKER}")) {
                            ckeys.push(format!("{dir}/"));
                        } else {
                            ckeys.push(rel);
                        }
                    }
                }
            }
            (vkeys, ckeys)
        })
        .await
        .map_err(|e| S3Error::Internal(format!("walk versions: {e}")))?;

        let versioned_set: BTreeSet<String> = versioned_keys.iter().cloned().collect();

        // Build a sorted, de-duplicated key set respecting the prefix filter.
        let mut all_keys: BTreeSet<String> = BTreeSet::new();
        for k in &versioned_keys {
            if k.starts_with(prefix) {
                all_keys.insert(k.clone());
            }
        }
        for k in &canonical_keys {
            if k.starts_with(prefix) && !versioned_set.contains(k) {
                all_keys.insert(k.clone());
            }
        }

        // 2. Expand each key into its version entries, applying delimiter rollup
        //    and (key, version) pagination, capped at max_keys.
        let mut out: Vec<ObjectVersion> = Vec::new();
        let mut common: BTreeSet<String> = BTreeSet::new();
        let mut truncated = false;
        let mut next_key_marker = None;
        let mut next_version_id_marker = None;
        let mut started = key_marker.is_none();

        'outer: for key in all_keys {
            // Resume after the (key_marker, version_id_marker) pair.
            if !started {
                if Some(key.as_str()) == key_marker && version_id_marker.is_none() {
                    started = true;
                    continue;
                }
                if key.as_str() > key_marker.unwrap_or("") {
                    started = true;
                }
            }
            if !started {
                continue;
            }

            // Delimiter rollup into common prefixes.
            if let Some(delim) = delimiter.filter(|d| !d.is_empty()) {
                let rest = &key[prefix.len()..];
                if let Some(idx) = rest.find(delim) {
                    let cp = format!("{}{}{}", prefix, &rest[..idx], delim);
                    if !common.contains(&cp) {
                        if out.len() + common.len() >= max_keys {
                            truncated = true;
                            next_key_marker = Some(key);
                            break;
                        }
                        common.insert(cp);
                    }
                    continue;
                }
            }

            // Resolve the key's version entries.
            let entries: Vec<ObjectVersion> = if versioned_set.contains(&key) {
                let hist = self.read_history(bucket, &key).await;
                hist.versions
                    .iter()
                    .enumerate()
                    .map(|(i, v)| ObjectVersion {
                        key: key.clone(),
                        version_id: v.version_id.clone(),
                        is_latest: i == 0,
                        last_modified: unix_to_dt(v.last_modified),
                        etag: v.etag.clone(),
                        size: v.size,
                        is_delete_marker: v.delete_marker,
                        audit: None,
                    })
                    .collect()
            } else {
                // Legacy/non-versioned object: one "null" current version.
                let meta = self.load_meta(bucket, &key).await?;
                vec![ObjectVersion {
                    key: key.clone(),
                    version_id: "null".to_string(),
                    is_latest: true,
                    last_modified: meta.last_modified,
                    etag: meta.etag,
                    size: meta.size,
                    is_delete_marker: false,
                    audit: None,
                }]
            };

            let mut resume = version_id_marker.is_some() && Some(key.as_str()) == key_marker;
            for ev in entries {
                if resume {
                    // Skip up to and including the version_id_marker for this key.
                    if Some(ev.version_id.as_str()) == version_id_marker {
                        resume = false;
                    }
                    continue;
                }
                if out.len() + common.len() >= max_keys {
                    truncated = true;
                    next_key_marker = Some(ev.key.clone());
                    next_version_id_marker = Some(ev.version_id.clone());
                    break 'outer;
                }
                out.push(ev);
            }
        }

        Ok(VersionListing {
            versions: out,
            common_prefixes: common.into_iter().collect(),
            is_truncated: truncated,
            next_key_marker,
            next_version_id_marker,
        })
    }

    /// See [`ObjectStore::create_multipart`].
    async fn create_multipart(
        &self,
        bucket: &str,
        key: &str,
        content_type: String,
        user_metadata: BTreeMap<String, String>,
        encrypt: bool,
    ) -> Result<String, S3Error> {
        self.head_bucket(bucket).await?;
        validate_key(key)?;
        let upload_id = Uuid::new_v4().simple().to_string();
        let dir = self.upload_dir(bucket, &upload_id);
        fs::create_dir_all(&dir)
            .await
            .map_err(|e| S3Error::Internal(format!("mkdir upload: {e}")))?;
        let manifest = UploadManifest {
            key: key.to_string(),
            content_type,
            user_metadata,
            created: now_secs(),
            encrypt: self.should_encrypt(encrypt),
        };
        let json = serde_json::to_vec(&manifest)
            .map_err(|e| S3Error::Internal(format!("encode manifest: {e}")))?;
        fs::write(dir.join("manifest.json"), json)
            .await
            .map_err(|e| S3Error::Internal(format!("write manifest: {e}")))?;
        Ok(upload_id)
    }

    /// See [`ObjectStore::upload_part`].
    async fn upload_part(
        &self,
        bucket: &str,
        _key: &str,
        upload_id: &str,
        part_number: u32,
        body: BodyReader,
    ) -> Result<String, S3Error> {
        let dir = self.upload_dir(bucket, upload_id);
        if fs::metadata(dir.join("manifest.json")).await.is_err() {
            return Err(S3Error::NoSuchUpload);
        }
        // Parts are staged plaintext and their MD5 ETag is meaningful S3 (clients verify
        // it; it feeds the `md5(concat(part-md5s))-N` final ETag), so compute it.
        let (tmp, etag, size) = self.stream_to_temp(body, true).await?;
        self.move_into_place(&tmp, &dir.join(format!("part.{part_number}")))
            .await?;
        let part_meta = PartMeta { etag: etag.clone(), size, created: now_secs() };
        let json = serde_json::to_vec(&part_meta)
            .map_err(|e| S3Error::Internal(format!("encode part meta: {e}")))?;
        fs::write(dir.join(format!("part.{part_number}.json")), json)
            .await
            .map_err(|e| S3Error::Internal(format!("write part meta: {e}")))?;
        Ok(etag)
    }

    /// See [`ObjectStore::complete_multipart`].
    async fn complete_multipart(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: Vec<CompletedPart>,
    ) -> Result<ObjectMeta, S3Error> {
        let dir = self.upload_dir(bucket, upload_id);
        let manifest_bytes = fs::read(dir.join("manifest.json"))
            .await
            .map_err(|_| S3Error::NoSuchUpload)?;
        let manifest: UploadManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| S3Error::Internal(format!("decode manifest: {e}")))?;
        let _lock = self.locks.acquire(&format!("{bucket}/{key}")).await;

        // Assemble parts into a single temp file.
        let tmp = self.tmp_dir().join(Uuid::new_v4().simple().to_string());
        let mut out = File::create(&tmp)
            .await
            .map_err(|e| S3Error::Internal(format!("create assembly: {e}")))?;
        let mut concat_md5: Vec<u8> = Vec::with_capacity(parts.len() * 16);
        let mut total_size: u64 = 0;

        for part in &parts {
            let part_meta_bytes =
                fs::read(dir.join(format!("part.{}.json", part.part_number)))
                    .await
                    .map_err(|_| S3Error::InvalidPart)?;
            let part_meta: PartMeta = serde_json::from_slice(&part_meta_bytes)
                .map_err(|e| S3Error::Internal(format!("decode part meta: {e}")))?;
            if part.etag.trim_matches('"') != part_meta.etag {
                return Err(S3Error::InvalidPart);
            }
            let raw = hex::decode(&part_meta.etag)
                .map_err(|e| S3Error::Internal(format!("bad part etag: {e}")))?;
            concat_md5.extend_from_slice(&raw);
            total_size += part_meta.size;

            let mut part_file =
                File::open(dir.join(format!("part.{}", part.part_number)))
                    .await
                    .map_err(|_| S3Error::InvalidPart)?;
            tokio::io::copy(&mut part_file, &mut out)
                .await
                .map_err(|e| S3Error::Internal(format!("assemble part: {e}")))?;
        }
        out.flush()
            .await
            .map_err(|e| S3Error::Internal(format!("flush assembly: {e}")))?;
        drop(out);

        let etag = format!("{}-{}", hex::encode(Md5::digest(&concat_md5)), parts.len());

        // Build the final encrypted (or plain) payload in a temp file first, so
        // we can archive any prior version before taking over the canonical slot.
        let final_tmp = if manifest.encrypt {
            let plain_file = File::open(&tmp)
                .await
                .map_err(|e| S3Error::Internal(format!("reopen assembly: {e}")))?;
            // Fail-closed: abort the completion if the DEK cannot be minted, before
            // the canonical slot is touched; the staged parts survive for a retry.
            let enc_reader = crypto::encrypting_reader(Box::pin(plain_file), self.crypto.clone())
                .await
                .map_err(|e| S3Error::Internal(format!("encrypt object: {e}")))?;
            // ETag here is discarded (the multipart `…-N` ETag is computed separately);
            // the bytes are ciphertext — skip the MD5.
            let (enc_tmp, _etag, _size) = self.stream_to_temp(enc_reader, false).await?;
            let _ = fs::remove_file(&tmp).await;
            enc_tmp
        } else {
            tmp
        };
        let encrypted = manifest.encrypt;

        let last_modified = now_secs();
        let mode = self.versioning_mode(bucket).await;
        let (version_id, pending_hist) = if mode == VMode::Off {
            (None, None)
        } else {
            let (vid, hist) = self.begin_versioned_write(bucket, key, mode).await?;
            (Some(vid), Some(hist))
        };

        self.move_into_place(&final_tmp, &self.object_path(bucket, key)).await?;
        let stored = StoredMeta {
            etag: etag.clone(),
            size: total_size,
            content_type: manifest.content_type.clone(),
            user_metadata: manifest.user_metadata.clone(),
            last_modified,
            encrypted,
            version_id: version_id.clone(),
        };
        self.write_meta(bucket, key, &stored).await?;
        let _ = fs::remove_dir_all(&dir).await;

        if let (Some(vid), Some(hist)) = (version_id.clone(), pending_hist) {
            self.finish_versioned_write(
                bucket,
                key,
                hist,
                vid,
                etag.clone(),
                total_size,
                last_modified,
            )
            .await?;
        }

        Ok(ObjectMeta {
            key: key.to_string(),
            size: total_size,
            etag,
            last_modified: unix_to_dt(last_modified),
            content_type: manifest.content_type,
            user_metadata: manifest.user_metadata,
            encrypted,
            version_id,
            audit: None,
        })
    }

    /// See [`ObjectStore::abort_multipart`].
    async fn abort_multipart(
        &self,
        bucket: &str,
        _key: &str,
        upload_id: &str,
    ) -> Result<(), S3Error> {
        let dir = self.upload_dir(bucket, upload_id);
        if fs::metadata(&dir).await.is_err() {
            return Err(S3Error::NoSuchUpload);
        }
        fs::remove_dir_all(&dir)
            .await
            .map_err(|e| S3Error::Internal(format!("abort: {e}")))
    }

    /// See [`ObjectStore::list_parts`].
    async fn list_parts(
        &self,
        bucket: &str,
        _key: &str,
        upload_id: &str,
    ) -> Result<Vec<PartInfo>, S3Error> {
        let dir = self.upload_dir(bucket, upload_id);
        let mut entries = match fs::read_dir(&dir).await {
            Ok(e) => e,
            Err(_) => return Err(S3Error::NoSuchUpload),
        };
        let mut parts = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| S3Error::Internal(e.to_string()))?
        {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(rest) = name.strip_prefix("part.") {
                if let Some(num) = rest.strip_suffix(".json") {
                    if let Ok(part_number) = num.parse::<u32>() {
                        let bytes = fs::read(entry.path())
                            .await
                            .map_err(|e| S3Error::Internal(e.to_string()))?;
                        if let Ok(pm) = serde_json::from_slice::<PartMeta>(&bytes) {
                            parts.push(PartInfo {
                                part_number,
                                etag: pm.etag,
                                size: pm.size,
                                last_modified: unix_to_dt(pm.created),
                            });
                        }
                    }
                }
            }
        }
        parts.sort_by_key(|p| p.part_number);
        Ok(parts)
    }

    // ── Per-bucket metadata methods ───────────────────────────────────────────

    /// See [`ObjectStore::get_bucket_encryption`].
    async fn get_bucket_encryption(&self, bucket: &str) -> Result<Option<String>, S3Error> {
        self.head_bucket(bucket).await?;
        Ok(self
            .read_bucket_cfg(bucket, "sse.json")
            .await
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v["type"].as_str().map(String::from)))
    }

    /// See [`ObjectStore::set_bucket_encryption`].
    async fn set_bucket_encryption(&self, bucket: &str, sse_type: &str) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        let data = serde_json::json!({ "type": sse_type }).to_string();
        self.write_bucket_cfg(bucket, "sse.json", data.as_bytes()).await
    }

    /// See [`ObjectStore::delete_bucket_encryption`].
    async fn delete_bucket_encryption(&self, bucket: &str) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        self.delete_bucket_cfg(bucket, "sse.json").await;
        Ok(())
    }

    /// See [`ObjectStore::get_bucket_policy`].
    async fn get_bucket_policy(&self, bucket: &str) -> Result<Option<String>, S3Error> {
        self.head_bucket(bucket).await?;
        Ok(self
            .read_bucket_cfg(bucket, "policy.json")
            .await
            .and_then(|b| String::from_utf8(b).ok()))
    }

    /// See [`ObjectStore::set_bucket_policy`].
    async fn set_bucket_policy(&self, bucket: &str, policy: String) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        self.write_bucket_cfg(bucket, "policy.json", policy.as_bytes()).await
    }

    /// See [`ObjectStore::delete_bucket_policy`].
    async fn delete_bucket_policy(&self, bucket: &str) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        self.delete_bucket_cfg(bucket, "policy.json").await;
        Ok(())
    }

    /// See [`ObjectStore::get_bucket_tags`].
    async fn get_bucket_tags(
        &self,
        bucket: &str,
    ) -> Result<Option<BTreeMap<String, String>>, S3Error> {
        self.head_bucket(bucket).await?;
        Ok(self
            .read_bucket_cfg(bucket, "tags.json")
            .await
            .and_then(|b| serde_json::from_slice(&b).ok()))
    }

    /// See [`ObjectStore::set_bucket_tags`].
    async fn set_bucket_tags(
        &self,
        bucket: &str,
        tags: BTreeMap<String, String>,
    ) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        let data = serde_json::to_vec(&tags)
            .map_err(|e| S3Error::Internal(format!("encode tags: {e}")))?;
        self.write_bucket_cfg(bucket, "tags.json", &data).await
    }

    /// See [`ObjectStore::delete_bucket_tags`].
    async fn delete_bucket_tags(&self, bucket: &str) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        self.delete_bucket_cfg(bucket, "tags.json").await;
        Ok(())
    }

    /// See [`ObjectStore::get_bucket_versioning`].
    async fn get_bucket_versioning(&self, bucket: &str) -> Result<String, S3Error> {
        self.head_bucket(bucket).await?;
        Ok(self
            .read_bucket_cfg(bucket, "versioning.json")
            .await
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v["status"].as_str().map(String::from))
            .unwrap_or_default())
    }

    /// See [`ObjectStore::set_bucket_versioning`].
    async fn set_bucket_versioning(&self, bucket: &str, status: &str) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        let data = serde_json::json!({ "status": status }).to_string();
        self.write_bucket_cfg(bucket, "versioning.json", data.as_bytes()).await
    }

    /// See [`ObjectStore::get_bucket_lifecycle`].
    async fn get_bucket_lifecycle(&self, bucket: &str) -> Result<Option<String>, S3Error> {
        self.head_bucket(bucket).await?;
        Ok(self
            .read_bucket_cfg(bucket, "lifecycle.json")
            .await
            .and_then(|b| String::from_utf8(b).ok()))
    }

    /// See [`ObjectStore::set_bucket_lifecycle`].
    async fn set_bucket_lifecycle(&self, bucket: &str, xml: String) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        self.write_bucket_cfg(bucket, "lifecycle.json", xml.as_bytes()).await
    }

    /// See [`ObjectStore::delete_bucket_lifecycle`].
    async fn delete_bucket_lifecycle(&self, bucket: &str) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        self.delete_bucket_cfg(bucket, "lifecycle.json").await;
        Ok(())
    }

    // ── Per-object metadata methods ───────────────────────────────────────────

    /// See [`ObjectStore::get_object_tags`].
    async fn get_object_tags(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<BTreeMap<String, String>>, S3Error> {
        // Verify object exists.
        self.head_object(bucket, key).await?;
        Ok(self
            .read_obj_sidecar(bucket, key, "tags.json")
            .await
            .and_then(|b| serde_json::from_slice(&b).ok()))
    }

    /// See [`ObjectStore::set_object_tags`].
    async fn set_object_tags(
        &self,
        bucket: &str,
        key: &str,
        tags: BTreeMap<String, String>,
    ) -> Result<(), S3Error> {
        self.head_object(bucket, key).await?;
        let data = serde_json::to_vec(&tags)
            .map_err(|e| S3Error::Internal(format!("encode object tags: {e}")))?;
        self.write_obj_sidecar(bucket, key, "tags.json", &data).await
    }

    /// See [`ObjectStore::delete_object_tags`].
    async fn delete_object_tags(&self, bucket: &str, key: &str) -> Result<(), S3Error> {
        self.head_object(bucket, key).await?;
        self.delete_obj_sidecar(bucket, key, "tags.json").await;
        Ok(())
    }

    /// See [`ObjectStore::get_object_retention`].
    async fn get_object_retention(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<String>, S3Error> {
        self.head_object(bucket, key).await?;
        Ok(self
            .read_obj_sidecar(bucket, key, "retention.json")
            .await
            .and_then(|b| String::from_utf8(b).ok()))
    }

    /// See [`ObjectStore::set_object_retention`].
    async fn set_object_retention(
        &self,
        bucket: &str,
        key: &str,
        data: String,
    ) -> Result<(), S3Error> {
        self.head_object(bucket, key).await?;
        self.write_obj_sidecar(bucket, key, "retention.json", data.as_bytes()).await
    }

    /// See [`ObjectStore::get_object_legal_hold`].
    async fn get_object_legal_hold(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<String>, S3Error> {
        self.head_object(bucket, key).await?;
        Ok(self
            .read_obj_sidecar(bucket, key, "legalhold.json")
            .await
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v["status"].as_str().map(String::from)))
    }

    /// See [`ObjectStore::set_object_legal_hold`].
    async fn set_object_legal_hold(
        &self,
        bucket: &str,
        key: &str,
        status: &str,
    ) -> Result<(), S3Error> {
        self.head_object(bucket, key).await?;
        let data = serde_json::json!({ "status": status }).to_string();
        self.write_obj_sidecar(bucket, key, "legalhold.json", data.as_bytes()).await
    }

    /// See [`ObjectStore::backend_info`]. The FS backend is a single transparent
    /// mirror: one drive, no erasure redundancy.
    async fn backend_info(&self) -> crate::storage::BackendInfo {
        let writable = fs::metadata(&self.root).await.is_ok();
        crate::storage::BackendInfo {
            backend_type: "FS".to_string(),
            data_shards: 0,
            parity_shards: 0,
            drives: vec![crate::storage::DriveStatus {
                path: self.root.display().to_string(),
                state: if writable { "ok" } else { "offline" }.to_string(),
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::MasterKey;

    fn plain_ctx() -> CryptoContext {
        CryptoContext::new_aes(MasterKey::generate())
    }

    /// A provider that boots fine but cannot mint a DEK — a KMS that went away
    /// after startup (an unreachable Vault, or one that re-sealed when the
    /// custody USB was pulled).
    struct DeadProvider;

    #[async_trait::async_trait]
    impl crate::crypto::KeyProvider for DeadProvider {
        fn kind(&self) -> &'static str {
            "dead"
        }
        async fn new_wrapped_dek(
            &self,
        ) -> Result<(crate::crypto::Dek, crate::crypto::WrappedDek), crate::crypto::KeyError> {
            Err(crate::crypto::KeyError::Unavailable("KMS unreachable (test)".into()))
        }
        async fn unwrap_dek(
            &self,
            _wrapped: &crate::crypto::WrappedDek,
        ) -> Result<crate::crypto::Dek, crate::crypto::KeyError> {
            Err(crate::crypto::KeyError::Unavailable("KMS unreachable (test)".into()))
        }
        fn wrapped_dek_len(&self) -> usize {
            32
        }
        fn posture(&self) -> crate::crypto::KeyPosture {
            crate::crypto::KeyPosture {
                kind: "dead",
                unattended_boot: true,
                key_on_host: false,
                protects: "nothing (test double)",
                does_not_protect: "anything (test double)",
            }
        }
    }

    /// A key-provider outage must **fail the write**, not silently commit a
    /// 0-byte object while answering `200 OK`.
    ///
    /// This is the regression guard for the fail-open bug: minting the DEK lazily
    /// inside the streaming task made a KMS failure look like a clean end-of-body,
    /// so the object was stored empty and the client was told it had succeeded —
    /// destroying any previous version of that key.
    #[tokio::test]
    async fn kms_outage_fails_the_write_and_commits_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = CryptoContext::new(std::sync::Arc::new(DeadProvider));
        let s = FsStore::new(tmp.path().to_path_buf(), ctx, true).await.unwrap();
        s.create_bucket("buck").await.unwrap();

        // A previously-good object, written while the "KMS" still worked, would
        // live here; the point is that the failed write must not replace it.
        let res = s
            .put_object(
                "buck",
                "nota.md",
                reader(b"contenido importante"),
                "text/markdown".into(),
                BTreeMap::new(),
                true,
            )
            .await;

        assert!(res.is_err(), "a KMS outage must fail the PUT, got {res:?}");

        // Nothing may be left behind: no 0-byte object, no half-written entry.
        let listing = s.list_objects_v2("buck", "", None, None, None, 100).await.unwrap();
        assert!(
            listing.objects.is_empty(),
            "a failed write must commit nothing, found {:?}",
            listing.objects
        );
    }

    /// Create a fresh temp-dir-backed store for a single test (encryption off).
    ///
    /// # Returns
    /// The store and the owning `TempDir` (kept alive for the test's duration).
    async fn store() -> (FsStore, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store =
            FsStore::new(tmp.path().to_path_buf(), plain_ctx(), false).await.unwrap();
        (store, tmp)
    }

    /// Create a temp-dir store with the global encryption override (`encrypt_all=true`).
    ///
    /// # Returns
    /// The store (with a random AES master key) and the owning `TempDir`.
    async fn encrypted_store() -> (FsStore, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store =
            FsStore::new(tmp.path().to_path_buf(), plain_ctx(), true).await.unwrap();
        (store, tmp)
    }

    /// Wrap a byte slice as a streaming [`BodyReader`].
    fn reader(data: &[u8]) -> BodyReader {
        Box::pin(std::io::Cursor::new(data.to_vec()))
    }

    /// Read an [`ObjectBody`] fully into a vector.
    async fn drain(mut body: ObjectBody) -> Vec<u8> {
        let mut out = Vec::new();
        body.read_to_end(&mut out).await.unwrap();
        out
    }

    /// Directory-marker objects (keys ending in `/`, created by s3fs `mkdir`)
    /// round-trip and surface as `<dir>/` keys without leaking the sentinel.
    #[tokio::test]
    async fn directory_marker_objects() {
        let (s, _t) = store().await;
        s.create_bucket("buck").await.unwrap();
        // Create a directory marker and a nested object under it.
        let meta = s
            .put_object("buck", "photos/", reader(b""), "application/x-directory".into(), BTreeMap::new(), false)
            .await
            .unwrap();
        assert_eq!(meta.size, 0);
        s.put_object("buck", "photos/cat.jpg", reader(b"jpeg"), "image/jpeg".into(), BTreeMap::new(), false)
            .await
            .unwrap();

        // The marker is HEAD-able as `photos/` and readable as an empty object.
        let head = s.head_object("buck", "photos/").await.unwrap();
        assert_eq!(head.size, 0);

        // A flat list exposes `photos/` (the marker) and the nested key, but
        // never the on-disk sentinel filename.
        let flat = s.list_objects_v2("buck", "", None, None, None, 1000).await.unwrap();
        let keys: Vec<&str> = flat.objects.iter().map(|o| o.key.as_str()).collect();
        assert!(keys.contains(&"photos/"), "keys={keys:?}");
        assert!(keys.contains(&"photos/cat.jpg"), "keys={keys:?}");
        assert!(!keys.iter().any(|k| k.contains(DIR_MARKER)), "sentinel leaked: {keys:?}");

        // With a delimiter, `photos/` rolls up into a common prefix.
        let rolled = s.list_objects_v2("buck", "", Some("/"), None, None, 1000).await.unwrap();
        assert!(rolled.common_prefixes.contains(&"photos/".to_string()));

        // Deleting the marker removes it.
        s.delete_object("buck", "photos/").await.unwrap();
        assert!(matches!(s.head_object("buck", "photos/").await, Err(S3Error::NoSuchKey)));
    }

    /// Bucket create/head/list/delete lifecycle and duplicate/missing errors.
    #[tokio::test]
    async fn bucket_lifecycle() {
        let (s, _t) = store().await;
        assert!(matches!(s.head_bucket("missing").await, Err(S3Error::NoSuchBucket)));
        s.create_bucket("buck").await.unwrap();
        s.head_bucket("buck").await.unwrap();
        let buckets = s.list_buckets().await.unwrap();
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].name, "buck");
        assert!(matches!(
            s.create_bucket("buck").await,
            Err(S3Error::BucketAlreadyOwnedByYou)
        ));
        s.delete_bucket("buck").await.unwrap();
        assert!(matches!(s.delete_bucket("buck").await, Err(S3Error::NoSuchBucket)));
    }

    /// Invalid bucket names are rejected.
    #[tokio::test]
    async fn invalid_bucket_name() {
        let (s, _t) = store().await;
        assert!(matches!(s.create_bucket("ab").await, Err(S3Error::InvalidBucketName)));
        assert!(matches!(s.create_bucket("UPPER").await, Err(S3Error::InvalidBucketName)));
    }

    /// PUT then GET/HEAD returns identical bytes, an MD5 ETag and metadata.
    #[tokio::test]
    async fn put_get_head_roundtrip() {
        let (s, _t) = store().await;
        s.create_bucket("buck").await.unwrap();
        let data = b"hello world";
        let meta = s
            .put_object("buck", "hello.txt", reader(data), "text/plain".into(), BTreeMap::new(), false)
            .await
            .unwrap();
        assert_eq!(meta.size, data.len() as u64);
        assert_eq!(meta.etag, hex::encode(Md5::digest(data)));

        let (gmeta, body) = s.get_object("buck", "hello.txt").await.unwrap();
        assert_eq!(gmeta.etag, meta.etag);
        assert_eq!(drain(body).await, data);

        let head = s.head_object("buck", "hello.txt").await.unwrap();
        assert_eq!(head.size, data.len() as u64);
        assert_eq!(head.content_type, "text/plain");
    }

    /// PUT to a non-existent bucket fails; GET of a missing key fails.
    #[tokio::test]
    async fn missing_bucket_and_key() {
        let (s, _t) = store().await;
        assert!(matches!(
            s.put_object("nobucket", "k", reader(b"x"), "".into(), BTreeMap::new(), false).await,
            Err(S3Error::NoSuchBucket)
        ));
        s.create_bucket("buck").await.unwrap();
        assert!(matches!(s.get_object("buck", "missing").await, Err(S3Error::NoSuchKey)));
    }

    /// Delete is idempotent and prunes empty dirs so the bucket becomes empty.
    #[tokio::test]
    async fn delete_prunes_and_bucket_empties() {
        let (s, _t) = store().await;
        s.create_bucket("buck").await.unwrap();
        s.put_object("buck", "a/b/c.txt", reader(b"hi"), "".into(), BTreeMap::new(), false)
            .await
            .unwrap();
        assert!(matches!(s.delete_bucket("buck").await, Err(S3Error::BucketNotEmpty)));
        s.delete_object("buck", "a/b/c.txt").await.unwrap();
        s.delete_object("buck", "a/b/c.txt").await.unwrap();
        s.delete_bucket("buck").await.unwrap();
    }

    /// Path-traversal keys are rejected.
    #[tokio::test]
    async fn invalid_key_rejected() {
        let (s, _t) = store().await;
        s.create_bucket("buck").await.unwrap();
        assert!(matches!(
            s.put_object("buck", "../escape", reader(b"x"), "".into(), BTreeMap::new(), false).await,
            Err(S3Error::InvalidArgument(_))
        ));
    }

    /// Listing with a delimiter rolls keys into common prefixes.
    #[tokio::test]
    async fn list_with_delimiter_and_prefix() {
        let (s, _t) = store().await;
        s.create_bucket("buck").await.unwrap();
        for k in ["a/1", "a/2", "b/1", "top"] {
            s.put_object("buck", k, reader(b"x"), "".into(), BTreeMap::new(), false)
                .await
                .unwrap();
        }
        let l =
            s.list_objects_v2("buck", "", Some("/"), None, None, 1000).await.unwrap();
        assert!(l.common_prefixes.contains(&"a/".to_string()));
        assert!(l.common_prefixes.contains(&"b/".to_string()));
        assert_eq!(l.objects.iter().filter(|o| o.key == "top").count(), 1);

        let l2 =
            s.list_objects_v2("buck", "a/", None, None, None, 1000).await.unwrap();
        let keys: Vec<_> = l2.objects.iter().map(|o| o.key.clone()).collect();
        assert_eq!(keys, vec!["a/1".to_string(), "a/2".to_string()]);
    }

    /// A byte-range read returns exactly the requested slice.
    #[tokio::test]
    async fn range_read() {
        let (s, _t) = store().await;
        s.create_bucket("buck").await.unwrap();
        let data: Vec<u8> = (0..100u8).collect();
        s.put_object("buck", "nums", reader(&data), "".into(), BTreeMap::new(), false)
            .await
            .unwrap();
        let (_m, len, body) =
            s.get_object_range("buck", "nums", 10, Some(19)).await.unwrap();
        assert_eq!(len, 10);
        assert_eq!(drain(body).await, &data[10..=19]);
    }

    /// Server-side copy reproduces the source payload at the destination.
    #[tokio::test]
    async fn copy_object_works() {
        let (s, _t) = store().await;
        s.create_bucket("buck").await.unwrap();
        s.put_object("buck", "src", reader(b"payload"), "text/plain".into(), BTreeMap::new(), false)
            .await
            .unwrap();
        s.copy_object("buck", "src", "buck", "dst", false).await.unwrap();
        let (_m, body) = s.get_object("buck", "dst").await.unwrap();
        assert_eq!(drain(body).await, b"payload");
    }

    /// Concurrent writes to the same key are serialized by the per-object lock,
    /// so a versioned bucket ends with exactly one version per write (no
    /// interleaving corrupts the history or loses a version).
    #[tokio::test]
    async fn concurrent_puts_same_key_are_serialized() {
        use std::sync::Arc;
        let (s, _t) = store().await;
        s.create_bucket("buck").await.unwrap();
        s.set_bucket_versioning("buck", "Enabled").await.unwrap();
        let s = Arc::new(s);

        let mut tasks = Vec::new();
        for i in 0..8u8 {
            let s = s.clone();
            tasks.push(tokio::spawn(async move {
                s.put_object("buck", "k", reader(&[i; 4]), "application/octet-stream".into(), BTreeMap::new(), false)
                    .await
            }));
        }
        for t in tasks {
            t.await.unwrap().expect("each concurrent put succeeds");
        }

        // Exactly one version per write — none lost or duplicated by interleaving.
        let listing = s.list_object_versions("buck", "", None, None, None, 1000).await.unwrap();
        let count = listing.versions.iter().filter(|v| v.key == "k").count();
        assert_eq!(count, 8, "8 concurrent puts → 8 versions");
        // The current object is intact and matches one of the writers.
        let (_m, body) = s.get_object("buck", "k").await.unwrap();
        let bytes = drain(body).await;
        assert_eq!(bytes.len(), 4);
        assert!(bytes.iter().all(|&b| b == bytes[0]) && bytes[0] < 8, "current object is one writer's value");
    }

    /// Full multipart flow: parts assemble in order, size and `-N` ETag are set.
    #[tokio::test]
    async fn multipart_flow() {
        let (s, _t) = store().await;
        s.create_bucket("buck").await.unwrap();
        let uid = s
            .create_multipart("buck", "big", "application/octet-stream".into(), BTreeMap::new(), false)
            .await
            .unwrap();
        let p1 = vec![1u8; 1000];
        let p2 = vec![2u8; 500];
        let e1 = s.upload_part("buck", "big", &uid, 1, reader(&p1)).await.unwrap();
        let e2 = s.upload_part("buck", "big", &uid, 2, reader(&p2)).await.unwrap();
        let parts =
            vec![
                CompletedPart { part_number: 1, etag: e1 },
                CompletedPart { part_number: 2, etag: e2 },
            ];
        let meta = s.complete_multipart("buck", "big", &uid, parts).await.unwrap();
        assert!(meta.etag.ends_with("-2"), "etag = {}", meta.etag);
        assert_eq!(meta.size, 1500);

        let (_m, body) = s.get_object("buck", "big").await.unwrap();
        let mut expected = p1.clone();
        expected.extend_from_slice(&p2);
        assert_eq!(drain(body).await, expected);
    }

    /// Aborting a multipart upload removes it; a second abort fails.
    #[tokio::test]
    async fn multipart_abort() {
        let (s, _t) = store().await;
        s.create_bucket("buck").await.unwrap();
        let uid =
            s.create_multipart("buck", "big", "".into(), BTreeMap::new(), false).await.unwrap();
        s.upload_part("buck", "big", &uid, 1, reader(b"data")).await.unwrap();
        s.abort_multipart("buck", "big", &uid).await.unwrap();
        assert!(matches!(
            s.abort_multipart("buck", "big", &uid).await,
            Err(S3Error::NoSuchUpload)
        ));
    }

    /// Completing with a wrong part ETag is rejected.
    #[tokio::test]
    async fn multipart_bad_part_etag() {
        let (s, _t) = store().await;
        s.create_bucket("buck").await.unwrap();
        let uid =
            s.create_multipart("buck", "big", "".into(), BTreeMap::new(), false).await.unwrap();
        s.upload_part("buck", "big", &uid, 1, reader(b"data")).await.unwrap();
        let parts = vec![CompletedPart { part_number: 1, etag: "deadbeef".into() }];
        assert!(matches!(
            s.complete_multipart("buck", "big", &uid, parts).await,
            Err(S3Error::InvalidPart)
        ));
    }

    /// With encrypt_all=true: get returns plaintext, on-disk is KPE1 ciphertext.
    #[tokio::test]
    async fn encrypted_roundtrip_and_on_disk_ciphertext() {
        let (s, t) = encrypted_store().await;
        s.create_bucket("buck").await.unwrap();
        let data: Vec<u8> = (0..(CHUNK_SIZE + 500)).map(|i| (i % 251) as u8).collect();
        let meta = s
            .put_object("buck", "secret.bin", reader(&data), "application/octet-stream".into(), BTreeMap::new(), false)
            .await
            .unwrap();
        assert_eq!(meta.size, data.len() as u64);
        assert!(meta.encrypted);

        let on_disk = std::fs::read(t.path().join("buck").join("secret.bin")).unwrap();
        assert_eq!(&on_disk[0..4], b"KPE\x01");
        assert!(on_disk.len() > data.len());

        let (gmeta, body) = s.get_object("buck", "secret.bin").await.unwrap();
        assert_eq!(gmeta.size, data.len() as u64);
        assert_eq!(drain(body).await, data);
        assert_eq!(s.head_object("buck", "secret.bin").await.unwrap().size, data.len() as u64);
    }

    /// Encrypted Range reads return the correct slice across a chunk boundary.
    #[tokio::test]
    async fn encrypted_range_read() {
        let (s, _t) = encrypted_store().await;
        s.create_bucket("buck").await.unwrap();
        let data: Vec<u8> = (0..(CHUNK_SIZE * 2 + 50)).map(|i| (i % 251) as u8).collect();
        s.put_object("buck", "r", reader(&data), "".into(), BTreeMap::new(), false)
            .await
            .unwrap();
        let (_m, len, body) = s
            .get_object_range("buck", "r", CHUNK_SIZE as u64 - 5, Some(CHUNK_SIZE as u64 + 9))
            .await
            .unwrap();
        assert_eq!(len, 15);
        assert_eq!(drain(body).await, &data[CHUNK_SIZE - 5..=CHUNK_SIZE + 9]);
    }

    /// Encrypted multipart upload assembles and reads back correctly.
    #[tokio::test]
    async fn encrypted_multipart_roundtrip() {
        let (s, t) = encrypted_store().await;
        s.create_bucket("buck").await.unwrap();
        let uid =
            s.create_multipart("buck", "big", "".into(), BTreeMap::new(), false).await.unwrap();
        let p1 = vec![1u8; 1000];
        let p2 = vec![2u8; 500];
        let e1 = s.upload_part("buck", "big", &uid, 1, reader(&p1)).await.unwrap();
        let e2 = s.upload_part("buck", "big", &uid, 2, reader(&p2)).await.unwrap();
        let meta = s
            .complete_multipart(
                "buck",
                "big",
                &uid,
                vec![
                    CompletedPart { part_number: 1, etag: e1 },
                    CompletedPart { part_number: 2, etag: e2 },
                ],
            )
            .await
            .unwrap();
        assert_eq!(meta.size, 1500);
        assert!(meta.encrypted);

        let on_disk = std::fs::read(t.path().join("buck").join("big")).unwrap();
        assert_eq!(&on_disk[0..4], b"KPE\x01");

        let (_m, body) = s.get_object("buck", "big").await.unwrap();
        let mut expected = p1.clone();
        expected.extend_from_slice(&p2);
        assert_eq!(drain(body).await, expected);
    }

    /// Per-object encrypt flag works independently of encrypt_all.
    #[tokio::test]
    async fn per_object_encryption() {
        let (s, _t) = store().await; // encrypt_all=false
        s.create_bucket("buck").await.unwrap();
        let data = b"secret";
        let meta = s
            .put_object("buck", "obj", reader(data), "".into(), BTreeMap::new(), true)
            .await
            .unwrap();
        assert!(meta.encrypted);
        let (_, body) = s.get_object("buck", "obj").await.unwrap();
        assert_eq!(drain(body).await, data);
    }

    /// Bucket tagging: set, get, delete roundtrip.
    #[tokio::test]
    async fn bucket_tagging() {
        let (s, _t) = store().await;
        s.create_bucket("buck").await.unwrap();
        assert!(s.get_bucket_tags("buck").await.unwrap().is_none());
        let tags: BTreeMap<_, _> = [("env".into(), "prod".into())].into();
        s.set_bucket_tags("buck", tags.clone()).await.unwrap();
        assert_eq!(s.get_bucket_tags("buck").await.unwrap(), Some(tags));
        s.delete_bucket_tags("buck").await.unwrap();
        assert!(s.get_bucket_tags("buck").await.unwrap().is_none());
    }

    /// Object tagging: set, get, delete roundtrip.
    #[tokio::test]
    async fn object_tagging() {
        let (s, _t) = store().await;
        s.create_bucket("buck").await.unwrap();
        s.put_object("buck", "k", reader(b"v"), "".into(), BTreeMap::new(), false)
            .await
            .unwrap();
        assert!(s.get_object_tags("buck", "k").await.unwrap().is_none());
        let tags: BTreeMap<_, _> = [("color".into(), "blue".into())].into();
        s.set_object_tags("buck", "k", tags.clone()).await.unwrap();
        assert_eq!(s.get_object_tags("buck", "k").await.unwrap(), Some(tags));
        s.delete_object_tags("buck", "k").await.unwrap();
        assert!(s.get_object_tags("buck", "k").await.unwrap().is_none());
    }

    /// Versioning status is stored and returned correctly.
    #[tokio::test]
    async fn bucket_versioning() {
        let (s, _t) = store().await;
        s.create_bucket("buck").await.unwrap();
        assert_eq!(s.get_bucket_versioning("buck").await.unwrap(), "");
        s.set_bucket_versioning("buck", "Enabled").await.unwrap();
        assert_eq!(s.get_bucket_versioning("buck").await.unwrap(), "Enabled");
        s.set_bucket_versioning("buck", "Suspended").await.unwrap();
        assert_eq!(s.get_bucket_versioning("buck").await.unwrap(), "Suspended");
    }
}
