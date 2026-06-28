//! `ErasureStore` — an [`ObjectStore`] backed by Reed-Solomon erasure coding
//! across a set of local drive directories (see `docs/ERASURE_CODING_DESIGN.md`).
//!
//! Each object is stored as `<drive_j>/<bucket>/<key>/{kp.meta, kp.part}`. The
//! payload (optionally KPE1-encrypted first) is sharded block by block; drive
//! `j` holds shard `j` of every block in its `kp.part`. `kp.meta` (replicated on
//! every drive) records the erasure parameters and a BLAKE3 checksum per
//! (drive, block) for bitrot detection. A read reconstructs from any `K`
//! intact shards.
//!
//! Phase 1 scope: bucket lifecycle, put/get/range/head/delete/list/copy, and
//! the per-bucket / per-object config sidecars. Multipart and versioning return
//! [`S3Error::NotImplemented`] for now (phase 2).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::codec::{checksum, Codec};
use super::drive::{Drive, LocalDrive};
use crate::audit;
use crate::crypto::{self, CryptoContext};
use crate::error::S3Error;
use crate::storage::{
    opaque_etag, validate_bucket_name, validate_key, BackendInfo, BodyReader, BucketInfo,
    CompletedPart, DeleteOutcome, DriveStatus, HealReport, Listing, ObjectBody, ObjectMeta,
    ObjectStore, ObjectVersion, PartInfo, VersionAudit, VersionListing,
};

/// Reserved per-drive system directory (config sidecars).
const SYS_DIR: &str = ".kerplace.sys";
/// Metadata filename inside each object directory.
const XL_META: &str = "kp.meta";
/// Shard payload filename inside each object directory.
const PART: &str = "kp.part";

// ── Relative-path helpers (relative to a drive root; passed to the `Drive`
//    seam). They encode the on-disk layout independent of where a drive lives. ─

/// A bucket's directory: `<bucket>`.
fn r_bucket(bucket: &str) -> PathBuf {
    PathBuf::from(bucket)
}
/// An object's directory: `<bucket>/<key>`.
fn r_object(bucket: &str, key: &str) -> PathBuf {
    Path::new(bucket).join(key)
}
/// An object version's directory: current (`vid = None`) ⇒ `<bucket>/<key>`,
/// archived (`vid = Some(v)`) ⇒ `<bucket>/<key>/.v/<v>`.
fn r_obj_v(bucket: &str, key: &str, vid: Option<&str>) -> PathBuf {
    let base = r_object(bucket, key);
    match vid {
        Some(v) => base.join(".v").join(v),
        None => base,
    }
}
/// A per-bucket config sidecar (drive 0): `.kerplace.sys/buckets/<bucket>/<file>`.
fn r_bucket_cfg(bucket: &str, file: &str) -> PathBuf {
    Path::new(SYS_DIR).join("buckets").join(bucket).join(file)
}
/// A per-object sidecar (tags/retention/legalhold) inside the object dir.
fn r_obj_sidecar(bucket: &str, key: &str, file: &str) -> PathBuf {
    r_object(bucket, key).join(file)
}
/// An object's version history file (drive 0): `<bucket>/<key>/.v/kp.history.json`.
fn r_history(bucket: &str, key: &str) -> PathBuf {
    r_object(bucket, key).join(".v").join("kp.history.json")
}
/// A multipart upload's staging directory (drive 0): `.kerplace.sys/multipart/<id>`.
fn r_upload(upload_id: &str) -> PathBuf {
    Path::new(SYS_DIR).join("multipart").join(upload_id)
}

/// On-disk per-object metadata (`xl.meta`), replicated on every drive.
#[derive(Debug, Serialize, Deserialize)]
struct XlMeta {
    version: u32,
    data: usize,
    parity: usize,
    block_size: usize,
    /// Total stored bytes (post-encryption) across all blocks.
    stored_size: u64,
    /// Logical (plaintext) size shown to clients.
    size: u64,
    etag: String,
    content_type: String,
    #[serde(default)]
    user_metadata: BTreeMap<String, String>,
    #[serde(default)]
    encrypted: bool,
    last_modified: i64,
    /// Audit: access key (user) that wrote this version, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    /// Audit: client IP this version was written from, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    src_ip: Option<String>,
    /// `checksums[drive][block]` — BLAKE3 of each shard, for bitrot detection.
    checksums: Vec<Vec<String>>,
}

/// Manifest for an in-progress multipart upload (staged on drive 0).
#[derive(Debug, Serialize, Deserialize)]
struct UploadManifest {
    bucket: String,
    key: String,
    content_type: String,
    #[serde(default)]
    user_metadata: BTreeMap<String, String>,
    created: i64,
    #[serde(default)]
    encrypt: bool,
}

/// Metadata for a single staged part.
#[derive(Debug, Serialize, Deserialize)]
struct PartMeta {
    etag: String,
    size: u64,
    created: i64,
}

/// A bucket's effective versioning mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VMode {
    Off,
    Enabled,
    Suspended,
}

/// One entry in a key's version history (newest-first).
#[derive(Debug, Serialize, Deserialize, Clone)]
struct VEntry {
    version_id: String,
    #[serde(default)]
    delete_marker: bool,
    last_modified: i64,
    #[serde(default)]
    etag: String,
    #[serde(default)]
    size: u64,
    /// Audit: access key (user) that wrote this version, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    /// Audit: client IP this version was written from, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    src_ip: Option<String>,
}

/// On-disk version history for a key. Invariant: `versions[0]` real ⇒ it is the
/// current version (at `<key>/{xl.meta,part.1}`); archived versions live under
/// `<key>/.v/<vid>/`.
#[derive(Debug, Serialize, Deserialize, Default)]
struct VHistory {
    versions: Vec<VEntry>,
    /// Monotonic write counter, replicated to every drive. On read the copy with
    /// the highest epoch wins, so a drive that missed a write (was down) can't
    /// serve a stale history once it returns.
    #[serde(default)]
    epoch: u64,
}

/// An erasure-coded object store over `N` shard slots (the [`Drive`] seam).
/// One **pool** — a single fixed-width erasure set: its `N` shard-slot drives
/// (in shard-index order) plus the Reed-Solomon codec and block size derived
/// from its parity. A cluster is a list of pools (server-pools model — see
/// `docs/DYNAMIC_MEMBERSHIP_DESIGN.md`); today there is exactly one, so this is
/// behaviour-preserving groundwork for online membership changes.
struct Pool {
    drives: Vec<Arc<dyn Drive>>,
    codec: Codec,
    block_size: usize,
}

pub struct ErasureStore {
    /// The cluster's pools. Phase 4c-m1: always exactly one.
    pools: Vec<Pool>,
    crypto: CryptoContext,
    encrypt_all: bool,
    /// Per-object locking (local always; distributed quorum when configured).
    locks: Arc<crate::cluster::lock::LockSet>,
}

impl ErasureStore {
    /// Create a store over `drives` with `parity` parity shards.
    ///
    /// # Parameters
    /// - `drives`: drive directories; `N = drives.len()` (≥ 2).
    /// - `crypto`: crypto context (for at-rest encryption).
    /// - `encrypt_all`: global encrypt override.
    /// - `parity`: parity shards `M` (`1 ≤ M < N`); `K = N - M`.
    /// - `block_size`: erasure block size in bytes.
    ///
    /// # Returns
    /// A ready [`ErasureStore`], or [`S3Error::Internal`] on a bad config / I/O.
    pub async fn new(
        drives: Vec<PathBuf>,
        crypto: CryptoContext,
        encrypt_all: bool,
        parity: usize,
        block_size: usize,
    ) -> Result<Self, S3Error> {
        let mut drive_objs: Vec<Arc<dyn Drive>> = Vec::with_capacity(drives.len());
        for d in drives {
            tokio::fs::create_dir_all(&d)
                .await
                .map_err(|e| S3Error::Internal(format!("erasure mkdir {d:?}: {e}")))?;
            drive_objs.push(Arc::new(LocalDrive::new(d)));
        }
        Self::with_drives(drive_objs, crypto, encrypt_all, parity, block_size)
    }

    /// Build a store over pre-constructed [`Drive`]s — the distributed entry
    /// point (a mix of [`LocalDrive`] for this node + `RemoteDrive` for the
    /// others). Unlike [`ErasureStore::new`] it creates no local directories.
    ///
    /// # Parameters
    /// - `drives`: the `N` shard slots (≥ 2), in shard-index order.
    /// - `crypto`: crypto context (for at-rest encryption).
    /// - `encrypt_all`: global encrypt override.
    /// - `parity`: parity shards `M` (`1 ≤ M < N`); `K = N - M`.
    /// - `block_size`: erasure block size in bytes.
    ///
    /// # Returns
    /// A ready [`ErasureStore`], or [`S3Error::Internal`] on a bad config.
    pub fn with_drives(
        drives: Vec<Arc<dyn Drive>>,
        crypto: CryptoContext,
        encrypt_all: bool,
        parity: usize,
        block_size: usize,
    ) -> Result<Self, S3Error> {
        let n = drives.len();
        if n < 2 || parity == 0 || parity >= n {
            return Err(S3Error::Internal(format!(
                "erasure: need ≥2 drives and 1 ≤ parity < drives (got {n} drives, parity {parity})"
            )));
        }
        let codec = Codec::new(n - parity, parity)
            .map_err(|e| S3Error::Internal(format!("erasure codec: {e}")))?;
        Ok(ErasureStore {
            pools: vec![Pool { drives, codec, block_size }],
            crypto,
            encrypt_all,
            locks: Arc::new(crate::cluster::lock::LockSet::local_only()),
        })
    }

    /// The pool that owns object `<bucket>/<key>`. Phase 4c-m1: always the sole
    /// pool; m3 makes this place/locate across multiple pools.
    ///
    /// # Returns
    /// A reference to the single [`Pool`].
    fn pool(&self) -> &Pool {
        &self.pools[0]
    }

    /// Replace the lock manager (e.g. to enable distributed quorum locks across
    /// the cluster's drive nodes). Local locking is on by default.
    ///
    /// # Parameters
    /// - `locks`: the [`LockSet`](crate::cluster::lock::LockSet) to use.
    ///
    /// # Returns
    /// `self`, for builder-style chaining.
    pub fn with_locks(mut self, locks: Arc<crate::cluster::lock::LockSet>) -> Self {
        self.locks = locks;
        self
    }

    // ── Absolute-path helpers (diagnostics / tests only; real I/O goes through
    //    the `Drive` seam with the `r_*` relative helpers below). ──────────────
    fn bucket_dir(&self, d: usize, bucket: &str) -> PathBuf {
        self.pool().drives[d].local_root().expect("local drive").join(r_bucket(bucket))
    }
    fn object_dir(&self, d: usize, bucket: &str, key: &str) -> PathBuf {
        self.pool().drives[d].local_root().expect("local drive").join(r_object(bucket, key))
    }
    fn obj_dir_v(&self, d: usize, bucket: &str, key: &str, vid: Option<&str>) -> PathBuf {
        self.pool().drives[d].local_root().expect("local drive").join(r_obj_v(bucket, key, vid))
    }

    fn should_encrypt(&self, encrypt: bool) -> bool {
        encrypt || self.encrypt_all
    }

    // ── Replicated metadata helpers (every drive, so no single drive is a SPOF
    //    for history / config / listing). ───────────────────────────────────────

    /// Read a metadata file from the first drive that has it.
    async fn meta_read_any(&self, rel: &Path) -> Option<Vec<u8>> {
        for d in 0..self.pool().drives.len() {
            if let Ok(b) = self.pool().drives[d].read(rel).await {
                return Some(b);
            }
        }
        None
    }

    /// Replicate a metadata file to every reachable drive (creating parents).
    /// Succeeds as long as at least one drive accepted it.
    async fn meta_write_all(&self, rel: &Path, data: &[u8]) -> Result<(), S3Error> {
        let mut ok = 0usize;
        for d in 0..self.pool().drives.len() {
            if let Some(p) = rel.parent() {
                let _ = self.pool().drives[d].create_dir_all(p).await;
            }
            if self.pool().drives[d].write(rel, data).await.is_ok() {
                ok += 1;
            }
        }
        if ok == 0 {
            return Err(S3Error::Internal(format!("metadata write: no drive reachable ({rel:?})")));
        }
        Ok(())
    }

    /// Remove a metadata file from every drive.
    async fn meta_del_all(&self, rel: &Path) {
        for d in 0..self.pool().drives.len() {
            let _ = self.pool().drives[d].remove_file(rel).await;
        }
    }

    /// Walk a bucket on **every** reachable drive and union the entries
    /// (deduped by path) — so a drive that missed some writes can't hide keys
    /// from a listing.
    async fn walk_union(&self, bucket: &str) -> Vec<crate::erasure::drive::WalkEntry> {
        let mut seen: BTreeSet<(PathBuf, bool)> = BTreeSet::new();
        let mut out = Vec::new();
        for d in 0..self.pool().drives.len() {
            if let Ok(entries) = self.pool().drives[d].walk(&r_bucket(bucket)).await {
                for e in entries {
                    if seen.insert((e.rel.clone(), e.is_file)) {
                        out.push(e);
                    }
                }
            }
        }
        out
    }

    /// Whether any drive holds `rel`.
    async fn meta_stat_any(&self, rel: &Path) -> bool {
        for d in 0..self.pool().drives.len() {
            if self.pool().drives[d].stat(rel).await.is_ok() {
                return true;
            }
        }
        false
    }

    /// Index of the first reachable (online) drive, used to stage multipart
    /// uploads off whichever node is up rather than always drive 0.
    async fn first_online_drive(&self) -> Option<usize> {
        for d in 0..self.pool().drives.len() {
            if self.pool().drives[d].online().await {
                return Some(d);
            }
        }
        None
    }

    /// The drive index a multipart upload is staged on, encoded as the first two
    /// hex chars of its id (falls back to 0 for safety).
    fn upload_drive(&self, upload_id: &str) -> usize {
        upload_id
            .get(..2)
            .and_then(|s| usize::from_str_radix(s, 16).ok())
            .filter(|i| *i < self.pool().drives.len())
            .unwrap_or(0)
    }

    // Config sidecars (replicated across drives).
    async fn read_cfg(&self, rel: PathBuf) -> Option<Vec<u8>> {
        self.meta_read_any(&rel).await
    }
    async fn write_cfg(&self, rel: PathBuf, data: &[u8]) -> Result<(), S3Error> {
        self.meta_write_all(&rel, data).await
    }
    async fn del_cfg(&self, rel: PathBuf) {
        self.meta_del_all(&rel).await;
    }

    /// Read an object's `xl.meta` from the first drive that has a valid copy.
    async fn read_xl(&self, bucket: &str, key: &str) -> Result<XlMeta, S3Error> {
        self.read_xl_v(bucket, key, None).await
    }

    async fn read_xl_v(&self, bucket: &str, key: &str, vid: Option<&str>) -> Result<XlMeta, S3Error> {
        let rel = r_obj_v(bucket, key, vid).join(XL_META);
        for d in 0..self.pool().drives.len() {
            if let Ok(bytes) = self.pool().drives[d].read(&rel).await {
                if let Ok(meta) = serde_json::from_slice::<XlMeta>(&bytes) {
                    return Ok(meta);
                }
            }
        }
        Err(S3Error::NoSuchKey)
    }

    fn meta_to_object(&self, key: &str, m: &XlMeta) -> ObjectMeta {
        let audit = VersionAudit { author: m.owner.clone(), source_ip: m.src_ip.clone() };
        ObjectMeta {
            key: key.to_string(),
            size: m.size,
            etag: m.etag.clone(),
            last_modified: OffsetDateTime::from_unix_timestamp(m.last_modified)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH),
            content_type: m.content_type.clone(),
            user_metadata: m.user_metadata.clone(),
            encrypted: m.encrypted,
            version_id: None,
            audit: audit.is_some().then_some(audit),
        }
    }

    /// A streaming reader of an object version's (still-encrypted-if-applicable)
    /// bytes — reconstructed block by block, O(block_size) memory.
    fn streaming_body(&self, bucket: &str, key: &str, vid: Option<&str>, m: &XlMeta) -> Result<BodyReader, S3Error> {
        let codec = Codec::new(m.data, m.parity).map_err(|e| S3Error::Internal(format!("erasure codec: {e}")))?;
        let drives = self.pool().drives.clone();
        let rel_dir = r_obj_v(bucket, key, vid);
        let (wr, rd) = tokio::io::duplex(m.block_size.max(64 * 1024) + 64);
        tokio::spawn(reconstruct_into(
            wr,
            drives,
            rel_dir,
            codec,
            m.block_size,
            m.stored_size as usize,
            m.checksums.clone(),
        ));
        Ok(Box::pin(rd))
    }

    /// Shard `src` (already encrypted iff `encrypted`) across all drives and
    /// write `xl.meta`. Shared by `put_object` and `complete_multipart`.
    ///
    /// `etag_override` lets multipart supply the `md5(concat(part-md5s))-N` ETag
    /// instead of the computed payload MD5.
    async fn write_sharded(
        &self,
        bucket: &str,
        key: &str,
        mut src: BodyReader,
        content_type: String,
        user_metadata: BTreeMap<String, String>,
        encrypted: bool,
        etag_override: Option<String>,
    ) -> Result<ObjectMeta, S3Error> {
        let n = self.pool().drives.len();
        let quorum = self.pool().codec.data() + 1; // a write needs >= K+1 shards (data + 1)
        let rel_dir = r_object(bucket, key);
        let tmp_rel = rel_dir.join(format!("{PART}.tmp"));
        let part_rel = rel_dir.join(PART);
        let meta_rel = rel_dir.join(XL_META);

        // Prepare a writer per drive. A drive that can't be prepared (e.g. a node
        // that is down) is marked offline and skipped: as long as a write quorum
        // survives, the object is still readable, and `heal` restores the missing
        // shards to that drive once it returns.
        let mut ok = vec![true; n];
        let mut writers: Vec<Option<crate::erasure::drive::DriveWriter>> = Vec::with_capacity(n);
        for d in 0..n {
            if self.pool().drives[d].create_dir_all(&rel_dir).await.is_err() {
                ok[d] = false;
                writers.push(None);
                continue;
            }
            match self.pool().drives[d].create(&tmp_rel).await {
                Ok(w) => writers.push(Some(w)),
                Err(_) => {
                    ok[d] = false;
                    writers.push(None);
                }
            }
        }

        // The S3 ETag is `md5(stored bytes)` only for an unencrypted single PUT. For an
        // encrypted object the stored bytes are ciphertext under a fresh random DEK/nonce
        // (the ETag is already opaque + non-deterministic, like AWS SSE), and for a
        // multipart assembly the ETag is supplied via `etag_override` — in both cases the
        // MD5 is pure waste, and it was the #1 on-CPU cost of a PUT (flamegraph ~32%). So
        // only run the hash when its result is actually the ETag.
        let need_md5 = etag_override.is_none() && !encrypted;
        let mut checksums: Vec<Vec<String>> = vec![Vec::new(); n];
        let mut hasher = Md5::new();
        let mut stored_size: u64 = 0;
        let mut block = vec![0u8; self.pool().block_size];
        let mut wrote_any = false;
        loop {
            let got = read_block(&mut src, &mut block).await.map_err(|e| S3Error::Internal(format!("read body: {e}")))?;
            if got == 0 && wrote_any {
                break;
            }
            wrote_any = true;
            if need_md5 {
                hasher.update(&block[..got]);
            }
            stored_size += got as u64;
            let shards = self.pool().codec.encode_block(&block[..got]).map_err(|e| S3Error::Internal(format!("erasure encode: {e}")))?;
            for d in 0..n {
                // Record the checksum for EVERY drive (reads/heal need all N, even
                // for a shard we could not place); only write to live drives.
                checksums[d].push(checksum(&shards[d]));
                if let Some(w) = writers[d].as_mut() {
                    if w.write_all(&shards[d]).await.is_err() {
                        ok[d] = false;
                        writers[d] = None;
                    }
                }
            }
            if got < self.pool().block_size {
                break;
            }
        }
        // Finalise each live writer (for a RemoteWriter, shutdown sends the PUT).
        for d in 0..n {
            if let Some(mut w) = writers[d].take() {
                if w.shutdown().await.is_err() {
                    ok[d] = false;
                }
            }
        }
        // Publish the shard (tmp -> part.1) on each still-healthy drive.
        for d in 0..n {
            if ok[d] && self.pool().drives[d].rename(&tmp_rel, &part_rel).await.is_err() {
                ok[d] = false;
            }
        }

        let etag = match etag_override {
            Some(e) => e,
            None if need_md5 => hex::encode(hasher.finalize()),
            None => opaque_etag(), // encrypted single PUT — opaque, no MD5 computed
        };
        let size = if encrypted {
            crypto::plaintext_len(stored_size, self.crypto.header_len())
        } else {
            stored_size
        };
        let last_modified = now_secs();
        // Stamp the audit trail (who/where) captured from the request context.
        let audit_ctx = audit::current();
        let meta = XlMeta {
            version: 1,
            data: self.pool().codec.data(),
            parity: self.pool().codec.parity(),
            block_size: self.pool().block_size,
            stored_size,
            size,
            etag: etag.clone(),
            content_type: content_type.clone(),
            user_metadata: user_metadata.clone(),
            encrypted,
            last_modified,
            owner: audit_ctx.access_key.clone(),
            src_ip: audit_ctx.remote_ip.clone(),
            checksums,
        };
        let json = serde_json::to_vec(&meta).map_err(|e| S3Error::Internal(format!("encode xl.meta: {e}")))?;
        for d in 0..n {
            if ok[d] && self.pool().drives[d].write(&meta_rel, &json).await.is_err() {
                ok[d] = false;
            }
        }

        // Write quorum: succeed iff >= K+1 shards were fully written. Below that,
        // roll the partial write back and fail (the object would have no
        // redundancy, or be unreadable).
        let written = ok.iter().filter(|x| **x).count();
        if written < quorum {
            for d in 0..n {
                let _ = self.pool().drives[d].remove_dir_all(&rel_dir).await;
            }
            return Err(S3Error::Internal(format!(
                "write quorum not met: {written}/{n} shards written (need {quorum})"
            )));
        }

        let audit = VersionAudit { author: audit_ctx.access_key, source_ip: audit_ctx.remote_ip };
        Ok(ObjectMeta {
            key: key.to_string(),
            size,
            etag,
            last_modified: OffsetDateTime::from_unix_timestamp(last_modified).unwrap_or(OffsetDateTime::UNIX_EPOCH),
            content_type,
            user_metadata,
            encrypted,
            version_id: None,
            audit: audit.is_some().then_some(audit),
        })
    }

    /// Stream a body to the drive-0 relative path `dest`, returning its hex MD5
    /// and byte count.
    async fn stream_to_part(&self, drive: usize, mut body: BodyReader, dest: &Path) -> Result<(String, u64), S3Error> {
        let mut file = self.pool().drives[drive].create(dest).await.map_err(|e| S3Error::Internal(format!("create part: {e}")))?;
        let mut hasher = Md5::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let n = body.read(&mut buf).await.map_err(|e| S3Error::Internal(format!("read part: {e}")))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n]).await.map_err(|e| S3Error::Internal(format!("write part: {e}")))?;
            total += n as u64;
        }
        file.shutdown().await.map_err(|e| S3Error::Internal(format!("finish part: {e}")))?;
        Ok((hex::encode(hasher.finalize()), total))
    }

    // ── Versioning helpers (mirror FsStore, over per-drive object dirs) ────────

    async fn vmode(&self, bucket: &str) -> VMode {
        match self.get_bucket_versioning(bucket).await.unwrap_or_default().as_str() {
            "Enabled" => VMode::Enabled,
            "Suspended" => VMode::Suspended,
            _ => VMode::Off,
        }
    }

    /// Read the key's history, picking the highest-epoch copy across drives.
    async fn read_history(&self, bucket: &str, key: &str) -> VHistory {
        let rel = r_history(bucket, key);
        let mut best: Option<VHistory> = None;
        for d in 0..self.pool().drives.len() {
            if let Ok(b) = self.pool().drives[d].read(&rel).await {
                if let Ok(h) = serde_json::from_slice::<VHistory>(&b) {
                    if best.as_ref().map(|x| h.epoch > x.epoch).unwrap_or(true) {
                        best = Some(h);
                    }
                }
            }
        }
        best.unwrap_or_default()
    }

    /// Replicate the key's history to every drive, bumping its epoch so a stale
    /// copy on a previously-down drive loses the next read.
    async fn write_history(&self, bucket: &str, key: &str, mut h: VHistory) -> Result<(), S3Error> {
        h.epoch += 1;
        let json = serde_json::to_vec(&h).map_err(|e| S3Error::Internal(format!("encode history: {e}")))?;
        self.meta_write_all(&r_history(bucket, key), &json).await
    }

    async fn has_history(&self, bucket: &str, key: &str) -> bool {
        self.meta_stat_any(&r_history(bucket, key)).await
    }

    /// Seed a one-entry `"null"` history from a pre-existing current object.
    async fn seed_legacy_history(&self, bucket: &str, key: &str) -> Result<(), S3Error> {
        if self.has_history(bucket, key).await {
            return Ok(());
        }
        if let Ok(m) = self.read_xl(bucket, key).await {
            let h = VHistory {
                versions: vec![VEntry {
                    version_id: "null".into(),
                    delete_marker: false,
                    last_modified: m.last_modified,
                    etag: m.etag,
                    size: m.size,
                    owner: m.owner,
                    src_ip: m.src_ip,
                }],
                epoch: 0,
            };
            self.write_history(bucket, key, h).await?;
        }
        Ok(())
    }

    /// Move the current version (xl.meta + part.1 on every drive) into `.v/<vid>`.
    async fn demote_current(&self, bucket: &str, key: &str, vid: &str) -> Result<(), S3Error> {
        let arch = r_obj_v(bucket, key, Some(vid));
        let cur = r_object(bucket, key);
        for d in 0..self.pool().drives.len() {
            // Best-effort per drive: a down node simply doesn't archive its shard
            // (write quorum + heal cover it).
            let _ = self.pool().drives[d].create_dir_all(&arch).await;
            let _ = self.pool().drives[d].rename(&cur.join(XL_META), &arch.join(XL_META)).await;
            let _ = self.pool().drives[d].rename(&cur.join(PART), &arch.join(PART)).await;
        }
        Ok(())
    }

    /// Promote an archived version back to the current slot on every drive.
    async fn promote_archive(&self, bucket: &str, key: &str, vid: &str) -> Result<(), S3Error> {
        let arch = r_obj_v(bucket, key, Some(vid));
        let cur = r_object(bucket, key);
        for d in 0..self.pool().drives.len() {
            let _ = self.pool().drives[d].rename(&arch.join(XL_META), &cur.join(XL_META)).await;
            let _ = self.pool().drives[d].rename(&arch.join(PART), &cur.join(PART)).await;
            let _ = self.pool().drives[d].remove_dir(&arch).await;
        }
        Ok(())
    }

    /// Remove the current version's payload + meta on every drive.
    async fn discard_current(&self, bucket: &str, key: &str) {
        let cur = r_object(bucket, key);
        for d in 0..self.pool().drives.len() {
            let _ = self.pool().drives[d].remove_file(&cur.join(XL_META)).await;
            let _ = self.pool().drives[d].remove_file(&cur.join(PART)).await;
        }
    }

    /// Remove an archived version on every drive.
    async fn remove_archive(&self, bucket: &str, key: &str, vid: &str) {
        let arch = r_obj_v(bucket, key, Some(vid));
        for d in 0..self.pool().drives.len() {
            let _ = self.pool().drives[d].remove_dir_all(&arch).await;
        }
    }

    /// Prepare for a new versioned write: seed legacy history, purge a prior
    /// `"null"` (suspended), and demote the current version into the archive.
    /// Returns the new version id and the history (without the new entry).
    async fn begin_versioned_write(&self, bucket: &str, key: &str, mode: VMode) -> Result<(String, VHistory), S3Error> {
        self.seed_legacy_history(bucket, key).await?;
        let mut hist = self.read_history(bucket, key).await;
        let mut canonical_occupied = hist.versions.first().map(|v| !v.delete_marker).unwrap_or(false);

        let new_vid = match mode {
            VMode::Enabled => uuid::Uuid::new_v4().simple().to_string(),
            VMode::Suspended => "null".to_string(),
            VMode::Off => unreachable!(),
        };

        if mode == VMode::Suspended {
            if let Some(idx) = hist.versions.iter().position(|v| v.version_id == "null") {
                let is_marker = hist.versions[idx].delete_marker;
                if idx == 0 && canonical_occupied {
                    self.discard_current(bucket, key).await;
                    canonical_occupied = false;
                } else if !is_marker {
                    self.remove_archive(bucket, key, "null").await;
                }
                hist.versions.remove(idx);
            }
        }

        if canonical_occupied {
            let cur_vid = hist.versions[0].version_id.clone();
            self.demote_current(bucket, key, &cur_vid).await?;
        }
        Ok((new_vid, hist))
    }

    async fn finish_versioned_write(&self, bucket: &str, key: &str, mut hist: VHistory, vid: String, etag: String, size: u64, last_modified: i64) -> Result<(), S3Error> {
        let a = audit::current();
        hist.versions.insert(0, VEntry { version_id: vid, delete_marker: false, last_modified, etag, size, owner: a.access_key, src_ip: a.remote_ip });
        self.write_history(bucket, key, hist).await
    }

    // ── Heal (phase 3) ─────────────────────────────────────────────────────────

    /// Enumerate every stored object version in a bucket as `(key, version_id)`
    /// pairs — the current version (`None`) plus each archived one under
    /// `.v/<vid>`. Scans the **union** across all drives so an object whose
    /// directory was lost on one drive is still discovered (and healable) via
    /// the others. Identified by an `xl.meta` or `part.1` file, so a partial
    /// loss on either is still found.
    ///
    /// # Parameters
    /// - `bucket`: the bucket to scan.
    ///
    /// # Returns
    /// The set of object versions present on at least one drive.
    async fn collect_object_dirs(
        &self,
        bucket: &str,
    ) -> Result<BTreeSet<(String, Option<String>)>, S3Error> {
        let mut set: BTreeSet<(String, Option<String>)> = BTreeSet::new();
        for d in 0..self.pool().drives.len() {
            // `walk` yields paths relative to the bucket dir (e.g. `key/xl.meta`
            // or `key/.v/<vid>/part.1`).
            let entries = self.pool().drives[d].walk(&r_bucket(bucket)).await.unwrap_or_default();
            for e in entries {
                if !e.is_file {
                    continue;
                }
                let name = e.rel.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
                if name != XL_META && name != PART {
                    continue;
                }
                let parent = match e.rel.parent() {
                    Some(p) => p,
                    None => continue,
                };
                let comps: Vec<String> = parent
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().to_string())
                    .collect();
                if comps.is_empty() {
                    continue;
                }
                if let Some(pos) = comps.iter().position(|c| c == ".v") {
                    if pos + 1 < comps.len() && pos > 0 {
                        set.insert((comps[..pos].join("/"), Some(comps[pos + 1].clone())));
                    }
                } else {
                    set.insert((comps.join("/"), None));
                }
            }
        }
        Ok(set)
    }

    /// Inspect (and optionally repair) one object version's shards.
    ///
    /// Every (drive, block) shard is verified against its BLAKE3 checksum in
    /// `xl.meta`. Drives whose shard stream is missing/corrupt, or whose
    /// `xl.meta` is absent, are rebuilt by reconstructing each block from a
    /// quorum (`≥ K` good shards) and re-encoding the missing shards — restoring
    /// full redundancy. Healthy objects and `dry_run` scans write nothing.
    ///
    /// # Parameters
    /// - `bucket`, `key`, `vid`: the object version (`vid = None` ⇒ current).
    /// - `dry_run`: detect only, do not write repairs.
    ///
    /// # Returns
    /// A [`HealOutcome`] for the object version.
    async fn heal_object(
        &self,
        bucket: &str,
        key: &str,
        vid: Option<&str>,
        dry_run: bool,
    ) -> Result<HealOutcome, S3Error> {
        let n = self.pool().drives.len();
        let meta = match self.read_xl_v(bucket, key, vid).await {
            Ok(m) => m,
            Err(_) => return Ok(HealOutcome::Unrecoverable),
        };
        let codec = Codec::new(meta.data, meta.parity)
            .map_err(|e| S3Error::Internal(format!("heal codec: {e}")))?;
        let k = meta.data;
        let bsz = meta.block_size.max(1);
        let stored = meta.stored_size as usize;
        let nblocks = if stored == 0 { 1 } else { stored.div_ceil(bsz) };
        let rel_dir = r_obj_v(bucket, key, vid);
        let part_rel = rel_dir.join(PART);
        let meta_rel = rel_dir.join(XL_META);
        let block_len = |b: usize| -> usize {
            if stored == 0 {
                0
            } else if b == nblocks - 1 {
                stored - b * bsz
            } else {
                bsz
            }
        };

        let mut bad_part = vec![false; n];
        let mut bad_meta = vec![false; n];
        for d in 0..n {
            let ok = self.pool().drives[d].read(&meta_rel)
                .await
                .ok()
                .and_then(|b| serde_json::from_slice::<XlMeta>(&b).ok())
                .is_some();
            bad_meta[d] = !ok;
        }

        // Pass 1 — detection: verify every (drive, block) shard checksum via
        // positioned reads (a missing/short part fails the read ⇒ bad drive).
        let mut min_good = usize::MAX;
        let mut offset: u64 = 0;
        for b in 0..nblocks {
            let slen = codec.shard_len(block_len(b));
            let mut good = 0;
            for d in 0..n {
                let ok = match self.pool().drives[d].read_at(&part_rel, offset, slen).await {
                    Ok(buf) => meta.checksums.get(d).and_then(|c| c.get(b)) == Some(&checksum(&buf)),
                    Err(_) => false,
                };
                if ok {
                    good += 1;
                } else {
                    bad_part[d] = true;
                }
            }
            min_good = min_good.min(good);
            offset += slen as u64;
        }

        let need_part = bad_part.iter().any(|x| *x);
        let need_meta = bad_meta.iter().any(|x| *x);
        if !need_part && !need_meta {
            return Ok(HealOutcome::Healthy);
        }
        if need_part && min_good < k {
            return Ok(HealOutcome::Unrecoverable);
        }
        let rewritten = (0..n).filter(|&d| bad_part[d] || bad_meta[d]).count();
        if dry_run {
            return Ok(HealOutcome::Healed { shards: rewritten });
        }

        let meta_bytes =
            serde_json::to_vec(&meta).map_err(|e| S3Error::Internal(format!("heal meta: {e}")))?;

        // Pass 2 — rebuild: reconstruct each block and re-encode the bad shards.
        if need_part {
            let tmp_rel = rel_dir.join(format!("{PART}.heal.tmp"));
            let mut out: Vec<Option<crate::erasure::drive::DriveWriter>> = (0..n).map(|_| None).collect();
            for d in 0..n {
                if bad_part[d] {
                    self.pool().drives[d].create_dir_all(&rel_dir)
                        .await
                        .map_err(|e| S3Error::Internal(format!("heal mkdir: {e}")))?;
                    let f = self.pool().drives[d].create(&tmp_rel)
                        .await
                        .map_err(|e| S3Error::Internal(format!("heal create: {e}")))?;
                    out[d] = Some(f);
                }
            }
            let mut offset: u64 = 0;
            for b in 0..nblocks {
                let blen = block_len(b);
                let slen = codec.shard_len(blen);
                let mut shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(n);
                for d in 0..n {
                    let mut shard = None;
                    if !bad_part[d] {
                        if let Ok(buf) = self.pool().drives[d].read_at(&part_rel, offset, slen).await {
                            if meta.checksums.get(d).and_then(|c| c.get(b)) == Some(&checksum(&buf)) {
                                shard = Some(buf);
                            }
                        }
                    }
                    shards.push(shard);
                }
                let block = codec
                    .reconstruct_block(&mut shards, blen)
                    .map_err(|_| S3Error::Internal("heal: block unrecoverable".into()))?;
                let reshards = codec
                    .encode_block(&block)
                    .map_err(|e| S3Error::Internal(format!("heal encode: {e}")))?;
                for d in 0..n {
                    if let Some(f) = out[d].as_mut() {
                        f.write_all(&reshards[d])
                            .await
                            .map_err(|e| S3Error::Internal(format!("heal write: {e}")))?;
                    }
                }
                offset += slen as u64;
            }
            for d in 0..n {
                if let Some(mut f) = out[d].take() {
                    f.shutdown().await.map_err(|e| S3Error::Internal(format!("heal finish: {e}")))?;
                    drop(f);
                    self.pool().drives[d].rename(&tmp_rel, &part_rel)
                        .await
                        .map_err(|e| S3Error::Internal(format!("heal rename: {e}")))?;
                }
            }
        }

        // Rewrite xl.meta wherever it was missing or the part was rebuilt.
        for d in 0..n {
            if bad_meta[d] || bad_part[d] {
                self.pool().drives[d].create_dir_all(&rel_dir)
                    .await
                    .map_err(|e| S3Error::Internal(format!("heal mkdir meta: {e}")))?;
                self.pool().drives[d].write(&meta_rel, &meta_bytes)
                    .await
                    .map_err(|e| S3Error::Internal(format!("heal write meta: {e}")))?;
            }
        }
        Ok(HealOutcome::Healed { shards: rewritten })
    }
}

/// Result of healing a single object version.
enum HealOutcome {
    /// All shards present and verified — nothing to do.
    Healthy,
    /// Degraded but repaired (or repairable, when `dry_run`); `shards` drives
    /// were (or would be) rewritten.
    Healed { shards: usize },
    /// Fewer than `K` good shards on some block — cannot reconstruct.
    Unrecoverable,
}

/// Reconstruct an object block by block, writing each block to `wr`. Runs in a
/// spawned task feeding a duplex stream, so reads stay O(block_size) in memory
/// instead of buffering the whole object. On an unrecoverable block it stops
/// (the reader sees a short read / EOF).
async fn reconstruct_into(
    mut wr: tokio::io::DuplexStream,
    drives: Vec<Arc<dyn Drive>>,
    rel_dir: PathBuf,
    codec: Codec,
    block_size: usize,
    stored: usize,
    checksums: Vec<Vec<String>>,
) {
    let n = drives.len();
    let nblocks = if stored == 0 { 1 } else { stored.div_ceil(block_size) };
    let part_rel = rel_dir.join(PART);
    let mut offset: u64 = 0;
    for b in 0..nblocks {
        let block_len = if stored == 0 {
            0
        } else if b == nblocks - 1 {
            stored - b * block_size
        } else {
            block_size
        };
        let slen = codec.shard_len(block_len);
        let mut shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(n);
        for d in 0..n {
            let mut shard = None;
            if let Ok(buf) = drives[d].read_at(&part_rel, offset, slen).await {
                if checksums.get(d).and_then(|c| c.get(b)) == Some(&checksum(&buf)) {
                    shard = Some(buf);
                }
            }
            shards.push(shard);
        }
        match codec.reconstruct_block(&mut shards, block_len) {
            Ok(block) => {
                if wr.write_all(&block).await.is_err() {
                    return; // reader dropped
                }
            }
            Err(_) => return, // unrecoverable beyond parity
        }
        offset += slen as u64;
    }
}

/// Skip `n` bytes from a reader, discarding them in chunks.
async fn skip_bytes(r: &mut BodyReader, mut n: u64) -> std::io::Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    while n > 0 {
        let want = (n as usize).min(buf.len());
        let got = r.read(&mut buf[..want]).await?;
        if got == 0 {
            break;
        }
        n -= got as u64;
    }
    Ok(())
}

/// Read up to `buf.len()` bytes, looping until the buffer is full or EOF.
async fn read_block(r: &mut BodyReader, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = r.read(&mut buf[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

fn now_secs() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

#[async_trait]
impl ObjectStore for ErasureStore {
    async fn create_bucket(&self, bucket: &str) -> Result<(), S3Error> {
        validate_bucket_name(bucket)?;
        if self.meta_stat_any(&r_bucket(bucket)).await {
            return Err(S3Error::BucketAlreadyOwnedByYou);
        }
        // Create the bucket dir on every reachable drive (so listing/head work
        // from any of them); a down node gets it on its next write / heal.
        let mut created = 0usize;
        for d in 0..self.pool().drives.len() {
            if self.pool().drives[d].create_dir_all(&r_bucket(bucket)).await.is_ok() {
                created += 1;
            }
        }
        if created == 0 {
            return Err(S3Error::Internal("create bucket: no drive reachable".into()));
        }
        Ok(())
    }

    async fn delete_bucket(&self, bucket: &str) -> Result<(), S3Error> {
        if !self.meta_stat_any(&r_bucket(bucket)).await {
            return Err(S3Error::NoSuchBucket);
        }
        // Empty check: any object directory (one holding xl.meta) on drive 0.
        let listing = self.list_objects_v2(bucket, "", None, None, None, 1).await?;
        if !listing.objects.is_empty() {
            return Err(S3Error::BucketNotEmpty);
        }
        let cfg_dir = Path::new(SYS_DIR).join("buckets").join(bucket);
        for d in 0..self.pool().drives.len() {
            let _ = self.pool().drives[d].remove_dir_all(&r_bucket(bucket)).await;
            let _ = self.pool().drives[d].remove_dir_all(&cfg_dir).await;
        }
        Ok(())
    }

    async fn list_buckets(&self) -> Result<Vec<BucketInfo>, S3Error> {
        // Bucket dirs are replicated to every drive — list from the first that
        // answers, so no single drive is required.
        let mut entries = None;
        for d in 0..self.pool().drives.len() {
            if let Ok(e) = self.pool().drives[d].read_dir(Path::new("")).await {
                entries = Some(e);
                break;
            }
        }
        let entries = entries.ok_or_else(|| S3Error::Internal("list buckets: no drive reachable".into()))?;
        let mut buckets = Vec::new();
        for entry in entries {
            if entry.name == SYS_DIR || !entry.is_dir {
                continue;
            }
            let creation_date = entry
                .created
                .map(OffsetDateTime::from)
                .unwrap_or_else(OffsetDateTime::now_utc);
            buckets.push(BucketInfo { name: entry.name, creation_date });
        }
        buckets.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(buckets)
    }

    async fn head_bucket(&self, bucket: &str) -> Result<(), S3Error> {
        for d in 0..self.pool().drives.len() {
            if matches!(self.pool().drives[d].stat(&r_bucket(bucket)).await, Ok(s) if s.is_dir) {
                return Ok(());
            }
        }
        Err(S3Error::NoSuchBucket)
    }

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
        let lock = self.locks.acquire(&format!("{bucket}/{key}")).await;
        // Hold the lock and run the write under its fencing context, so each
        // remote shard write carries the per-node token (a superseded gateway
        // is rejected by the node). `lock` stays alive for the whole section.
        crate::cluster::lock::with_fence(lock.fence_ctx(), async move {
            let encrypted = self.should_encrypt(encrypt);
            let src: BodyReader = if encrypted {
                crypto::encrypting_reader(body, self.crypto.clone())
            } else {
                body
            };
            let mode = self.vmode(bucket).await;
            // For versioned buckets, archive the prior current version first.
            let (version_id, pending) = if mode == VMode::Off {
                (None, None)
            } else {
                let (vid, hist) = self.begin_versioned_write(bucket, key, mode).await?;
                (Some(vid), Some(hist))
            };
            let mut meta = self.write_sharded(bucket, key, src, content_type, user_metadata, encrypted, None).await?;
            if let (Some(vid), Some(hist)) = (version_id.clone(), pending) {
                self.finish_versioned_write(bucket, key, hist, vid.clone(), meta.etag.clone(), meta.size, meta.last_modified.unix_timestamp()).await?;
                meta.version_id = Some(vid);
            }
            Ok(meta)
        })
        .await
    }

    async fn get_object(&self, bucket: &str, key: &str) -> Result<(ObjectMeta, ObjectBody), S3Error> {
        let m = self.read_xl(bucket, key).await?;
        let raw = self.streaming_body(bucket, key, None, &m)?;
        let body: ObjectBody = if m.encrypted {
            crypto::decrypting_reader_checked(raw, self.crypto.clone())
                .await
                .map_err(|e| S3Error::Internal(format!("decrypt object: {e}")))?
        } else {
            raw
        };
        Ok((self.meta_to_object(key, &m), body))
    }

    async fn get_object_range(
        &self,
        bucket: &str,
        key: &str,
        start: u64,
        end: Option<u64>,
    ) -> Result<(ObjectMeta, u64, ObjectBody), S3Error> {
        // Stream the object, discard up to `start`, then take `len` bytes —
        // O(len) memory rather than buffering the whole object.
        let (meta, mut body) = self.get_object(bucket, key).await?;
        let size = meta.size;
        let start = start.min(size);
        let last = end.map(|e| e.min(size.saturating_sub(1))).unwrap_or_else(|| size.saturating_sub(1));
        let len = if size == 0 || last < start { 0 } else { last - start + 1 };
        skip_bytes(&mut body, start).await.map_err(|e| S3Error::Internal(e.to_string()))?;
        let mut slice = vec![0u8; len as usize];
        body.read_exact(&mut slice).await.map_err(|e| S3Error::Internal(format!("range read: {e}")))?;
        Ok((meta, len, Box::pin(std::io::Cursor::new(slice))))
    }

    async fn head_object(&self, bucket: &str, key: &str) -> Result<ObjectMeta, S3Error> {
        let m = self.read_xl(bucket, key).await?;
        Ok(self.meta_to_object(key, &m))
    }

    async fn delete_object(&self, bucket: &str, key: &str) -> Result<DeleteOutcome, S3Error> {
        self.head_bucket(bucket).await?;
        let lock = self.locks.acquire(&format!("{bucket}/{key}")).await;
        crate::cluster::lock::with_fence(lock.fence_ctx(), async move {
            let mode = self.vmode(bucket).await;

            if mode != VMode::Off {
                // Insert a delete marker, preserving the current version in the archive.
                self.seed_legacy_history(bucket, key).await?;
                let mut hist = self.read_history(bucket, key).await;
                let marker_vid = match mode {
                    VMode::Enabled => uuid::Uuid::new_v4().simple().to_string(),
                    VMode::Suspended => "null".to_string(),
                    VMode::Off => unreachable!(),
                };
                let mut canonical_occupied = hist.versions.first().map(|v| !v.delete_marker).unwrap_or(false);
                if mode == VMode::Suspended {
                    if let Some(idx) = hist.versions.iter().position(|v| v.version_id == "null") {
                        let is_marker = hist.versions[idx].delete_marker;
                        if idx == 0 && canonical_occupied {
                            self.discard_current(bucket, key).await;
                            canonical_occupied = false;
                        } else if !is_marker {
                            self.remove_archive(bucket, key, "null").await;
                        }
                        hist.versions.remove(idx);
                    }
                }
                if canonical_occupied {
                    let cur_vid = hist.versions[0].version_id.clone();
                    self.demote_current(bucket, key, &cur_vid).await?;
                }
                let a = audit::current();
                hist.versions.insert(0, VEntry { version_id: marker_vid.clone(), delete_marker: true, last_modified: now_secs(), etag: String::new(), size: 0, owner: a.access_key, src_ip: a.remote_ip });
                self.write_history(bucket, key, hist).await?;
                return Ok(DeleteOutcome { version_id: Some(marker_vid), delete_marker: true });
            }

            // Non-versioned: permanent delete.
            let rel = r_object(bucket, key);
            let parent = rel.parent().map(|p| p.to_path_buf());
            for d in 0..self.pool().drives.len() {
                let _ = self.pool().drives[d].remove_dir_all(&rel).await;
                if let Some(p) = &parent {
                    prune_empty(&self.pool().drives[d], p.clone(), &r_bucket(bucket)).await;
                }
            }
            Ok(DeleteOutcome::default())
        })
        .await
    }

    async fn copy_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        dst_bucket: &str,
        dst_key: &str,
        encrypt: bool,
    ) -> Result<ObjectMeta, S3Error> {
        let (src_meta, mut body) = self.get_object(src_bucket, src_key).await?;
        let mut bytes = Vec::new();
        body.read_to_end(&mut bytes).await.map_err(|e| S3Error::Internal(e.to_string()))?;
        self.put_object(
            dst_bucket,
            dst_key,
            Box::pin(std::io::Cursor::new(bytes)),
            src_meta.content_type,
            src_meta.user_metadata,
            encrypt,
        )
        .await
    }

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
        // Keys = directories containing an xl.meta (opaque: hand-dropped files ignored).
        // Union the walk across drives so a drive that missed writes can't hide
        // keys; `walk` yields paths relative to the bucket dir (e.g. `key/xl.meta`).
        let entries = self.walk_union(bucket).await;
        let mut keys = Vec::new();
        for e in entries {
            if e.is_file && e.rel.file_name() == Some(std::ffi::OsStr::new(XL_META)) {
                if let Some(dir) = e.rel.parent() {
                    let rel = dir.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
                    // Skip archived versions (under <key>/.v/<vid>/xl.meta).
                    if !rel.split('/').any(|c| c == ".v") {
                        keys.push(rel);
                    }
                }
            }
        }

        keys.retain(|k| k.starts_with(prefix) && !k.is_empty());
        keys.sort();

        let mut common: BTreeSet<String> = BTreeSet::new();
        let mut chosen: Vec<String> = Vec::new();
        let mut count = 0usize;
        let mut truncated = false;
        let mut next_token = None;
        for key in keys {
            if let Some(t) = continuation_token {
                if key.as_str() < t {
                    continue;
                }
            }
            if let Some(a) = start_after {
                if key.as_str() <= a {
                    continue;
                }
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
            if let Ok(m) = self.read_xl(bucket, &key).await {
                objects.push(self.meta_to_object(&key, &m));
            }
        }
        Ok(Listing {
            objects,
            common_prefixes: common.into_iter().collect(),
            is_truncated: truncated,
            next_continuation_token: next_token,
        })
    }

    async fn list_object_versions(
        &self,
        bucket: &str,
        prefix: &str,
        delimiter: Option<&str>,
        _key_marker: Option<&str>,
        _version_id_marker: Option<&str>,
        max_keys: usize,
    ) -> Result<VersionListing, S3Error> {
        self.head_bucket(bucket).await?;
        // Keys with a current xl.meta (not under .v) and keys with a kp.history.json.
        // Union across drives so no single drive is required; `walk` yields paths
        // relative to the bucket dir.
        let entries = self.walk_union(bucket).await;
        let mut versioned: BTreeSet<String> = BTreeSet::new();
        let mut current: BTreeSet<String> = BTreeSet::new();
        for e in entries {
            if !e.is_file {
                continue;
            }
            let name = e.rel.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
            let parent = match e.rel.parent() {
                Some(p) => p,
                None => continue,
            };
            if name == XL_META {
                let rel = parent.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
                if !rel.is_empty() && !rel.split('/').any(|c| c == ".v") {
                    current.insert(rel);
                }
            } else if name == "kp.history.json" {
                if let Some(kdir) = parent.parent() {
                    let rel = kdir.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
                    if !rel.is_empty() {
                        versioned.insert(rel);
                    }
                }
            }
        }

        let mut all: BTreeSet<String> = BTreeSet::new();
        for k in &versioned {
            if k.starts_with(prefix) {
                all.insert(k.clone());
            }
        }
        for k in &current {
            if k.starts_with(prefix) && !versioned.contains(k) {
                all.insert(k.clone());
            }
        }

        let mut out: Vec<ObjectVersion> = Vec::new();
        let mut common: BTreeSet<String> = BTreeSet::new();
        let mut truncated = false;
        'outer: for key in all {
            if let Some(delim) = delimiter.filter(|d| !d.is_empty()) {
                let rest = &key[prefix.len()..];
                if let Some(idx) = rest.find(delim) {
                    let cp = format!("{}{}{}", prefix, &rest[..idx], delim);
                    if !common.contains(&cp) {
                        if out.len() + common.len() >= max_keys {
                            truncated = true;
                            break;
                        }
                        common.insert(cp);
                    }
                    continue;
                }
            }
            let entries: Vec<ObjectVersion> = if versioned.contains(&key) {
                self.read_history(bucket, &key)
                    .await
                    .versions
                    .iter()
                    .enumerate()
                    .map(|(i, v)| {
                        let audit = VersionAudit { author: v.owner.clone(), source_ip: v.src_ip.clone() };
                        ObjectVersion {
                            key: key.clone(),
                            version_id: v.version_id.clone(),
                            is_latest: i == 0,
                            last_modified: OffsetDateTime::from_unix_timestamp(v.last_modified).unwrap_or(OffsetDateTime::UNIX_EPOCH),
                            etag: v.etag.clone(),
                            size: v.size,
                            is_delete_marker: v.delete_marker,
                            audit: audit.is_some().then_some(audit),
                        }
                    })
                    .collect()
            } else if let Ok(m) = self.read_xl(bucket, &key).await {
                let audit = VersionAudit { author: m.owner.clone(), source_ip: m.src_ip.clone() };
                vec![ObjectVersion {
                    key: key.clone(),
                    version_id: "null".to_string(),
                    is_latest: true,
                    last_modified: OffsetDateTime::from_unix_timestamp(m.last_modified).unwrap_or(OffsetDateTime::UNIX_EPOCH),
                    etag: m.etag,
                    size: m.size,
                    is_delete_marker: false,
                    audit: audit.is_some().then_some(audit),
                }]
            } else {
                vec![]
            };
            for ev in entries {
                if out.len() + common.len() >= max_keys {
                    truncated = true;
                    break 'outer;
                }
                out.push(ev);
            }
        }

        Ok(VersionListing {
            versions: out,
            common_prefixes: common.into_iter().collect(),
            is_truncated: truncated,
            next_key_marker: None,
            next_version_id_marker: None,
        })
    }

    // ── Versioned reads / multipart: phase 2 ──────────────────────────────────
    async fn get_object_version(&self, bucket: &str, key: &str, version_id: &str) -> Result<(ObjectMeta, ObjectBody), S3Error> {
        self.head_bucket(bucket).await?;
        self.seed_legacy_history(bucket, key).await?;
        let hist = self.read_history(bucket, key).await;
        let idx = hist.versions.iter().position(|v| v.version_id == version_id).ok_or(S3Error::NoSuchVersion)?;
        if hist.versions[idx].delete_marker {
            return Err(S3Error::MethodNotAllowed);
        }
        let vopt = if idx == 0 { None } else { Some(version_id) };
        let m = self.read_xl_v(bucket, key, vopt).await?;
        let raw = self.streaming_body(bucket, key, vopt, &m)?;
        let body: ObjectBody = if m.encrypted {
            crypto::decrypting_reader_checked(raw, self.crypto.clone())
                .await
                .map_err(|e| S3Error::Internal(format!("decrypt object: {e}")))?
        } else {
            raw
        };
        let mut meta = self.meta_to_object(key, &m);
        meta.version_id = Some(version_id.to_string());
        Ok((meta, body))
    }
    async fn head_object_version(&self, bucket: &str, key: &str, version_id: &str) -> Result<ObjectMeta, S3Error> {
        self.head_bucket(bucket).await?;
        self.seed_legacy_history(bucket, key).await?;
        let hist = self.read_history(bucket, key).await;
        let idx = hist.versions.iter().position(|v| v.version_id == version_id).ok_or(S3Error::NoSuchVersion)?;
        if hist.versions[idx].delete_marker {
            return Err(S3Error::MethodNotAllowed);
        }
        let vopt = if idx == 0 { None } else { Some(version_id) };
        let m = self.read_xl_v(bucket, key, vopt).await?;
        let mut meta = self.meta_to_object(key, &m);
        meta.version_id = Some(version_id.to_string());
        Ok(meta)
    }
    async fn delete_object_version(&self, bucket: &str, key: &str, version_id: &str) -> Result<DeleteOutcome, S3Error> {
        self.head_bucket(bucket).await?;
        let lock = self.locks.acquire(&format!("{bucket}/{key}")).await;
        crate::cluster::lock::with_fence(lock.fence_ctx(), async move {
            self.seed_legacy_history(bucket, key).await?;
            let mut hist = self.read_history(bucket, key).await;
            let idx = hist.versions.iter().position(|v| v.version_id == version_id).ok_or(S3Error::NoSuchVersion)?;
            let entry = hist.versions[idx].clone();
            let was_current = idx == 0;
            if !entry.delete_marker {
                if was_current {
                    self.discard_current(bucket, key).await;
                } else {
                    self.remove_archive(bucket, key, version_id).await;
                }
            }
            hist.versions.remove(idx);
            if was_current {
                if let Some(next) = hist.versions.first() {
                    if !next.delete_marker {
                        let nv = next.version_id.clone();
                        self.promote_archive(bucket, key, &nv).await?;
                    }
                }
            }
            if hist.versions.is_empty() {
                let rel = r_object(bucket, key);
                let parent = rel.parent().map(|p| p.to_path_buf());
                for d in 0..self.pool().drives.len() {
                    let _ = self.pool().drives[d].remove_dir_all(&rel).await;
                    if let Some(p) = &parent {
                        prune_empty(&self.pool().drives[d], p.clone(), &r_bucket(bucket)).await;
                    }
                }
            } else {
                self.write_history(bucket, key, hist).await?;
            }
            Ok(DeleteOutcome { version_id: Some(version_id.to_string()), delete_marker: entry.delete_marker })
        })
        .await
    }
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
        // Stage on the first reachable drive (not always drive 0), encoding its
        // index in the upload id so the other ops find the staging drive.
        let stage = self
            .first_online_drive()
            .await
            .ok_or_else(|| S3Error::Internal("multipart: no drive reachable".into()))?;
        let upload_id = format!("{stage:02x}{}", uuid::Uuid::new_v4().simple());
        let dir = r_upload(&upload_id);
        self.pool().drives[stage].create_dir_all(&dir).await.map_err(|e| S3Error::Internal(format!("mkdir upload: {e}")))?;
        let manifest = UploadManifest {
            bucket: bucket.to_string(),
            key: key.to_string(),
            content_type,
            user_metadata,
            created: now_secs(),
            encrypt: self.should_encrypt(encrypt),
        };
        let json = serde_json::to_vec(&manifest).map_err(|e| S3Error::Internal(format!("encode manifest: {e}")))?;
        self.pool().drives[stage].write(&dir.join("manifest.json"), &json).await.map_err(|e| S3Error::Internal(format!("write manifest: {e}")))?;
        Ok(upload_id)
    }

    async fn upload_part(
        &self,
        _bucket: &str,
        _key: &str,
        upload_id: &str,
        part_number: u32,
        body: BodyReader,
    ) -> Result<String, S3Error> {
        let sd = self.upload_drive(upload_id);
        let dir = r_upload(upload_id);
        if self.pool().drives[sd].stat(&dir.join("manifest.json")).await.is_err() {
            return Err(S3Error::NoSuchUpload);
        }
        // Parts are staged as plaintext; the final object is encrypted+sharded on complete.
        let (etag, size) = self.stream_to_part(sd, body, &dir.join(format!("part.{part_number}"))).await?;
        let pm = PartMeta { etag: etag.clone(), size, created: now_secs() };
        let json = serde_json::to_vec(&pm).map_err(|e| S3Error::Internal(format!("encode part meta: {e}")))?;
        self.pool().drives[sd].write(&dir.join(format!("part.{part_number}.json")), &json)
            .await
            .map_err(|e| S3Error::Internal(format!("write part meta: {e}")))?;
        Ok(etag)
    }

    async fn complete_multipart(
        &self,
        _bucket: &str,
        _key: &str,
        upload_id: &str,
        parts: Vec<CompletedPart>,
    ) -> Result<ObjectMeta, S3Error> {
        let sd = self.upload_drive(upload_id);
        let dir = r_upload(upload_id);
        let manifest_bytes = self.pool().drives[sd].read(&dir.join("manifest.json")).await.map_err(|_| S3Error::NoSuchUpload)?;
        let manifest: UploadManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|e| S3Error::Internal(format!("decode manifest: {e}")))?;
        let lock = self.locks.acquire(&format!("{}/{}", manifest.bucket, manifest.key)).await;
        crate::cluster::lock::with_fence(lock.fence_ctx(), async move {
            // Verify each requested part, assemble the plaintext into a temp file,
            // and compute the multipart ETag from the part MD5s.
            let assembly = dir.join("assembly.tmp");
            let mut out = self.pool().drives[sd].create(&assembly).await.map_err(|e| S3Error::Internal(format!("create assembly: {e}")))?;
            let mut concat_md5: Vec<u8> = Vec::with_capacity(parts.len() * 16);
            for part in &parts {
                let pm_bytes = self.pool().drives[sd].read(&dir.join(format!("part.{}.json", part.part_number))).await.map_err(|_| S3Error::InvalidPart)?;
                let pm: PartMeta = serde_json::from_slice(&pm_bytes).map_err(|e| S3Error::Internal(format!("decode part meta: {e}")))?;
                if part.etag.trim_matches('"') != pm.etag {
                    return Err(S3Error::InvalidPart);
                }
                concat_md5.extend_from_slice(&hex::decode(&pm.etag).map_err(|e| S3Error::Internal(format!("bad part etag: {e}")))?);
                let mut pf = self.pool().drives[sd].open(&dir.join(format!("part.{}", part.part_number))).await.map_err(|_| S3Error::InvalidPart)?;
                tokio::io::copy(&mut pf, &mut out).await.map_err(|e| S3Error::Internal(format!("assemble part: {e}")))?;
            }
            out.shutdown().await.map_err(|e| S3Error::Internal(format!("finish assembly: {e}")))?;
            drop(out);

            let etag = format!("{}-{}", hex::encode(Md5::digest(&concat_md5)), parts.len());
            let encrypted = manifest.encrypt;
            let plain = self.pool().drives[sd].open(&assembly).await.map_err(|e| S3Error::Internal(format!("reopen assembly: {e}")))?;
            let src: BodyReader = if encrypted {
                crypto::encrypting_reader(Box::pin(plain), self.crypto.clone())
            } else {
                Box::pin(plain)
            };
            let meta = self
                .write_sharded(&manifest.bucket, &manifest.key, src, manifest.content_type, manifest.user_metadata, encrypted, Some(etag))
                .await?;
            let _ = self.pool().drives[sd].remove_dir_all(&dir).await;
            Ok(meta)
        })
        .await
    }

    async fn abort_multipart(&self, _b: &str, _k: &str, upload_id: &str) -> Result<(), S3Error> {
        let sd = self.upload_drive(upload_id);
        let dir = r_upload(upload_id);
        if self.pool().drives[sd].stat(&dir).await.is_err() {
            return Err(S3Error::NoSuchUpload);
        }
        self.pool().drives[sd].remove_dir_all(&dir).await.map_err(|e| S3Error::Internal(format!("abort: {e}")))
    }

    async fn list_parts(&self, _b: &str, _k: &str, upload_id: &str) -> Result<Vec<PartInfo>, S3Error> {
        let sd = self.upload_drive(upload_id);
        let dir = r_upload(upload_id);
        let entries = match self.pool().drives[sd].read_dir(&dir).await {
            Ok(e) => e,
            Err(_) => return Err(S3Error::NoSuchUpload),
        };
        let mut parts = Vec::new();
        for entry in entries {
            let name = entry.name;
            if let Some(rest) = name.strip_prefix("part.") {
                if let Some(num) = rest.strip_suffix(".json") {
                    if let Ok(part_number) = num.parse::<u32>() {
                        if let Ok(pm) = serde_json::from_slice::<PartMeta>(&self.pool().drives[sd].read(&dir.join(&name)).await.unwrap_or_default()) {
                            parts.push(PartInfo {
                                part_number,
                                etag: pm.etag,
                                size: pm.size,
                                last_modified: OffsetDateTime::from_unix_timestamp(pm.created).unwrap_or(OffsetDateTime::UNIX_EPOCH),
                            });
                        }
                    }
                }
            }
        }
        parts.sort_by_key(|p| p.part_number);
        Ok(parts)
    }

    // ── Per-bucket config (sidecars on drive 0) ───────────────────────────────
    async fn get_bucket_encryption(&self, bucket: &str) -> Result<Option<String>, S3Error> {
        Ok(self
            .read_cfg(r_bucket_cfg(bucket, "sse.json"))
            .await
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v["sse"].as_str().map(String::from)))
    }
    async fn set_bucket_encryption(&self, bucket: &str, sse_type: &str) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        let data = serde_json::json!({ "sse": sse_type }).to_string();
        self.write_cfg(r_bucket_cfg(bucket, "sse.json"), data.as_bytes()).await
    }
    async fn delete_bucket_encryption(&self, bucket: &str) -> Result<(), S3Error> {
        self.del_cfg(r_bucket_cfg(bucket, "sse.json")).await;
        Ok(())
    }
    async fn get_bucket_policy(&self, bucket: &str) -> Result<Option<String>, S3Error> {
        Ok(self.read_cfg(r_bucket_cfg(bucket, "policy.json")).await.and_then(|b| String::from_utf8(b).ok()))
    }
    async fn set_bucket_policy(&self, bucket: &str, policy: String) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        self.write_cfg(r_bucket_cfg(bucket, "policy.json"), policy.as_bytes()).await
    }
    async fn delete_bucket_policy(&self, bucket: &str) -> Result<(), S3Error> {
        self.del_cfg(r_bucket_cfg(bucket, "policy.json")).await;
        Ok(())
    }
    async fn get_bucket_tags(&self, bucket: &str) -> Result<Option<BTreeMap<String, String>>, S3Error> {
        Ok(self.read_cfg(r_bucket_cfg(bucket, "tags.json")).await.and_then(|b| serde_json::from_slice(&b).ok()))
    }
    async fn set_bucket_tags(&self, bucket: &str, tags: BTreeMap<String, String>) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        let json = serde_json::to_vec(&tags).map_err(|e| S3Error::Internal(e.to_string()))?;
        self.write_cfg(r_bucket_cfg(bucket, "tags.json"), &json).await
    }
    async fn delete_bucket_tags(&self, bucket: &str) -> Result<(), S3Error> {
        self.del_cfg(r_bucket_cfg(bucket, "tags.json")).await;
        Ok(())
    }
    async fn get_bucket_versioning(&self, bucket: &str) -> Result<String, S3Error> {
        // Fail-safe: read every drive and return the MOST protective status, so a
        // stale drive that missed an "enable versioning" write can never make us
        // treat the bucket as non-versioned (which would overwrite live versions).
        let rel = r_bucket_cfg(bucket, "versioning.json");
        let rank = |s: &str| -> u8 {
            match s {
                "Enabled" => 2,
                "Suspended" => 1,
                _ => 0,
            }
        };
        let mut best = String::new();
        for d in 0..self.pool().drives.len() {
            if let Ok(b) = self.pool().drives[d].read(&rel).await {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&b) {
                    if let Some(status) = v["status"].as_str() {
                        if rank(status) > rank(&best) {
                            best = status.to_string();
                        }
                    }
                }
            }
        }
        Ok(best)
    }
    async fn set_bucket_versioning(&self, bucket: &str, status: &str) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        let data = serde_json::json!({ "status": status }).to_string();
        self.write_cfg(r_bucket_cfg(bucket, "versioning.json"), data.as_bytes()).await
    }
    async fn get_bucket_lifecycle(&self, bucket: &str) -> Result<Option<String>, S3Error> {
        Ok(self.read_cfg(r_bucket_cfg(bucket, "lifecycle.xml")).await.and_then(|b| String::from_utf8(b).ok()))
    }
    async fn set_bucket_lifecycle(&self, bucket: &str, xml: String) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        self.write_cfg(r_bucket_cfg(bucket, "lifecycle.xml"), xml.as_bytes()).await
    }
    async fn delete_bucket_lifecycle(&self, bucket: &str) -> Result<(), S3Error> {
        self.del_cfg(r_bucket_cfg(bucket, "lifecycle.xml")).await;
        Ok(())
    }

    // ── Per-object metadata (sidecars in the object dir on drive 0) ────────────
    async fn get_object_tags(&self, bucket: &str, key: &str) -> Result<Option<BTreeMap<String, String>>, S3Error> {
        self.head_object(bucket, key).await?;
        Ok(self.read_cfg(r_obj_sidecar(bucket, key, "tags.json")).await.and_then(|b| serde_json::from_slice(&b).ok()))
    }
    async fn set_object_tags(&self, bucket: &str, key: &str, tags: BTreeMap<String, String>) -> Result<(), S3Error> {
        self.head_object(bucket, key).await?;
        let json = serde_json::to_vec(&tags).map_err(|e| S3Error::Internal(e.to_string()))?;
        self.write_cfg(r_obj_sidecar(bucket, key, "tags.json"), &json).await
    }
    async fn delete_object_tags(&self, bucket: &str, key: &str) -> Result<(), S3Error> {
        self.head_object(bucket, key).await?;
        self.del_cfg(r_obj_sidecar(bucket, key, "tags.json")).await;
        Ok(())
    }
    async fn get_object_retention(&self, bucket: &str, key: &str) -> Result<Option<String>, S3Error> {
        self.head_object(bucket, key).await?;
        Ok(self.read_cfg(r_obj_sidecar(bucket, key, "retention.json")).await.and_then(|b| String::from_utf8(b).ok()))
    }
    async fn set_object_retention(&self, bucket: &str, key: &str, data: String) -> Result<(), S3Error> {
        self.head_object(bucket, key).await?;
        self.write_cfg(r_obj_sidecar(bucket, key, "retention.json"), data.as_bytes()).await
    }
    async fn get_object_legal_hold(&self, bucket: &str, key: &str) -> Result<Option<String>, S3Error> {
        self.head_object(bucket, key).await?;
        Ok(self
            .read_cfg(r_obj_sidecar(bucket, key, "legalhold.json"))
            .await
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v["status"].as_str().map(String::from)))
    }
    async fn set_object_legal_hold(&self, bucket: &str, key: &str, status: &str) -> Result<(), S3Error> {
        self.head_object(bucket, key).await?;
        let data = serde_json::json!({ "status": status }).to_string();
        self.write_cfg(r_obj_sidecar(bucket, key, "legalhold.json"), data.as_bytes()).await
    }

    async fn backend_info(&self) -> BackendInfo {
        let mut drives = Vec::with_capacity(self.pool().drives.len());
        for d in &self.pool().drives {
            // A drive is "ok" if it is reachable; a removed or unmounted drive
            // surfaces as "offline" (reads still reconstruct from survivors).
            let state = if d.online().await { "ok" } else { "offline" };
            drives.push(DriveStatus { path: d.id(), state: state.to_string() });
        }
        BackendInfo {
            backend_type: "Erasure".to_string(),
            data_shards: self.pool().codec.data(),
            parity_shards: self.pool().codec.parity(),
            drives,
        }
    }

    async fn heal(&self, bucket: Option<&str>, dry_run: bool) -> Result<HealReport, S3Error> {
        let mut report = HealReport { dry_run, ..Default::default() };
        let buckets: Vec<String> = match bucket {
            Some(b) => {
                self.head_bucket(b).await?;
                vec![b.to_string()]
            }
            None => self.list_buckets().await?.into_iter().map(|b| b.name).collect(),
        };
        for b in buckets {
            for (key, vid) in self.collect_object_dirs(&b).await? {
                report.objects_scanned += 1;
                match self.heal_object(&b, &key, vid.as_deref(), dry_run).await? {
                    HealOutcome::Healthy => {}
                    HealOutcome::Healed { shards } => {
                        report.objects_healed += 1;
                        report.shards_rewritten += shards as u64;
                    }
                    HealOutcome::Unrecoverable => report.objects_unrecoverable += 1,
                }
            }
        }
        Ok(report)
    }
}

/// Remove now-empty directories on `drive`, upward from `rel` until `stop`
/// (exclusive). Paths are relative to the drive root.
async fn prune_empty(drive: &Arc<dyn Drive>, mut rel: PathBuf, stop: &Path) {
    while rel != stop && rel.starts_with(stop) {
        if drive.remove_dir(&rel).await.is_err() {
            break;
        }
        match rel.parent() {
            Some(p) => rel = p.to_path_buf(),
            None => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CryptoContext, MasterKey};
    use tokio::fs;

    /// Build a 4-drive store (K=2, M=2) with a small block size to force
    /// multi-block objects, optionally with post-quantum encryption.
    async fn store(encrypted: bool) -> (ErasureStore, Vec<tempfile::TempDir>) {
        let dirs: Vec<tempfile::TempDir> = (0..4).map(|_| tempfile::tempdir().unwrap()).collect();
        let drives: Vec<PathBuf> = dirs.iter().map(|d| d.path().to_path_buf()).collect();
        let crypto = if encrypted {
            CryptoContext::new_pq(MasterKey::generate(), crate::crypto::PqKeypair::generate())
        } else {
            CryptoContext::new_aes(MasterKey::generate())
        };
        let s = ErasureStore::new(drives, crypto, encrypted, 2, 4096).await.unwrap();
        (s, dirs)
    }

    async fn read_all(mut body: ObjectBody) -> Vec<u8> {
        let mut v = Vec::new();
        body.read_to_end(&mut v).await.unwrap();
        v
    }

    fn rdr(data: &[u8]) -> BodyReader {
        Box::pin(std::io::Cursor::new(data.to_vec()))
    }

    /// put/get round-trips; the object survives losing M=2 drives and bitrot.
    #[tokio::test]
    async fn durability_survives_two_drive_losses_and_bitrot() {
        let (s, _dirs) = store(false).await;
        s.create_bucket("buck").await.unwrap();
        // 10 KiB → spans multiple 4 KiB blocks.
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let meta = s.put_object("buck", "obj", rdr(&data), "application/octet-stream".into(), BTreeMap::new(), false).await.unwrap();
        assert_eq!(meta.size, 10_000);

        // Baseline read.
        let (_, body) = s.get_object("buck", "obj").await.unwrap();
        assert_eq!(read_all(body).await, data);

        // Drive 0 lost entirely (remove its part.1).
        fs::remove_file(s.object_dir(0, "buck", "obj").join(PART)).await.unwrap();
        // Drive 1 suffers bitrot (corrupt some bytes of its part.1).
        let p1 = s.object_dir(1, "buck", "obj").join(PART);
        let mut bytes = fs::read(&p1).await.unwrap();
        for b in bytes.iter_mut().take(64) { *b ^= 0xFF; }
        fs::write(&p1, &bytes).await.unwrap();

        // Two drives down (= parity) → still reconstructs exactly.
        let (_, body) = s.get_object("buck", "obj").await.unwrap();
        assert_eq!(read_all(body).await, data, "must reconstruct from K survivors");

        // A third loss exceeds parity → unrecoverable: the streamed body
        // truncates rather than returning the original data.
        fs::remove_file(s.object_dir(2, "buck", "obj").join(PART)).await.unwrap();
        let (_, body) = s.get_object("buck", "obj").await.unwrap();
        assert_ne!(read_all(body).await, data, "beyond parity must not yield original data");
    }

    /// Encrypted objects are sharded as KPE1 ciphertext and round-trip; the
    /// on-disk shards never contain the plaintext.
    #[tokio::test]
    async fn encrypted_roundtrip_shards_are_ciphertext() {
        let (s, _dirs) = store(true).await;
        s.create_bucket("buck").await.unwrap();
        let data = b"top secret payload that must not appear on disk".to_vec();
        s.put_object("buck", "secret", rdr(&data), "text/plain".into(), BTreeMap::new(), true).await.unwrap();

        let (m, body) = s.get_object("buck", "secret").await.unwrap();
        assert!(m.encrypted);
        assert_eq!(read_all(body).await, data);

        // No shard on any drive contains the plaintext.
        for d in 0..4 {
            let shard = fs::read(s.object_dir(d, "buck", "secret").join(PART)).await.unwrap();
            assert!(!shard.windows(9).any(|w| w == b"top secre"), "plaintext leaked on drive {d}");
        }
    }

    /// ETag policy (the MD5-skip optimization): an **unencrypted** object keeps the
    /// real `md5(bytes)` ETag (plain-S3), while an **encrypted** object gets an opaque
    /// 32-hex ETag that is NOT the plaintext MD5 (the costly MD5 pass is skipped, like
    /// AWS SSE). Both still round-trip and report a stable ETag across GET/HEAD.
    #[tokio::test]
    async fn etag_is_md5_when_plain_and_opaque_when_encrypted() {
        use md5::{Digest, Md5};
        let data = b"the quick brown fox jumps over the lazy dog".to_vec();
        let plain_md5 = hex::encode(Md5::digest(&data));

        // Unencrypted: ETag == md5(plaintext).
        let (s, _d) = store(false).await;
        s.create_bucket("buck").await.unwrap();
        let pm = s.put_object("buck", "k", rdr(&data), "text/plain".into(), BTreeMap::new(), false).await.unwrap();
        assert_eq!(pm.etag, plain_md5, "plain object must keep the real MD5 ETag");

        // Encrypted: opaque 32-hex ETag, NOT the plaintext MD5, stable across GET/HEAD.
        let (se, _de) = store(true).await;
        se.create_bucket("buck").await.unwrap();
        let em = se.put_object("buck", "k", rdr(&data), "text/plain".into(), BTreeMap::new(), true).await.unwrap();
        assert_eq!(em.etag.len(), 32, "opaque ETag is 32 chars (MD5-shaped)");
        assert!(em.etag.chars().all(|c| c.is_ascii_hexdigit()), "opaque ETag is hex");
        assert_ne!(em.etag, plain_md5, "encrypted object must NOT expose the plaintext MD5");
        let (gm, body) = se.get_object("buck", "k").await.unwrap();
        assert_eq!(gm.etag, em.etag, "ETag stable across GET");
        assert_eq!(read_all(body).await, data, "encrypted object still round-trips");
        assert_eq!(se.head_object("buck", "k").await.unwrap().etag, em.etag, "ETag stable across HEAD");
    }

    /// Range reads, listing, and delete behave correctly.
    #[tokio::test]
    async fn range_list_delete() {
        let (s, _dirs) = store(false).await;
        s.create_bucket("buck").await.unwrap();
        let data: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        s.put_object("buck", "a/x", rdr(&data), "application/octet-stream".into(), BTreeMap::new(), false).await.unwrap();
        s.put_object("buck", "a/y", rdr(b"yy"), "application/octet-stream".into(), BTreeMap::new(), false).await.unwrap();

        // Range [1000, 1009].
        let (_, len, body) = s.get_object_range("buck", "a/x", 1000, Some(1009)).await.unwrap();
        assert_eq!(len, 10);
        assert_eq!(read_all(body).await, data[1000..=1009]);

        // Listing with delimiter rolls a/ into a common prefix.
        let listing = s.list_objects_v2("buck", "", Some("/"), None, None, 1000).await.unwrap();
        assert!(listing.common_prefixes.contains(&"a/".to_string()));
        let flat = s.list_objects_v2("buck", "a/", None, None, None, 1000).await.unwrap();
        assert_eq!(flat.objects.len(), 2);

        // Delete removes it everywhere.
        s.delete_object("buck", "a/x").await.unwrap();
        assert!(matches!(s.head_object("buck", "a/x").await, Err(S3Error::NoSuchKey)));
        for d in 0..4 {
            assert!(fs::metadata(s.object_dir(d, "buck", "a/x")).await.is_err());
        }
    }

    /// Multipart upload assembles parts, erasure-codes the final object, and
    /// the result survives a drive loss. Covers plain + encrypted.
    #[tokio::test]
    async fn multipart_roundtrip_and_durability() {
        for encrypted in [false, true] {
            let (s, _dirs) = store(encrypted).await;
            s.create_bucket("buck").await.unwrap();
            let upload = s
                .create_multipart("buck", "big", "application/octet-stream".into(), BTreeMap::new(), encrypted)
                .await
                .unwrap();

            let p1 = vec![7u8; 6000];
            let p2 = vec![9u8; 3000];
            let e1 = s.upload_part("buck", "big", &upload, 1, rdr(&p1)).await.unwrap();
            let e2 = s.upload_part("buck", "big", &upload, 2, rdr(&p2)).await.unwrap();

            // list_parts reflects both staged parts.
            let parts = s.list_parts("buck", "big", &upload).await.unwrap();
            assert_eq!(parts.len(), 2);
            assert_eq!(parts[0].size, 6000);

            let meta = s
                .complete_multipart(
                    "buck",
                    "big",
                    &upload,
                    vec![
                        CompletedPart { part_number: 1, etag: e1 },
                        CompletedPart { part_number: 2, etag: e2 },
                    ],
                )
                .await
                .unwrap();
            assert!(meta.etag.ends_with("-2"), "multipart etag: {}", meta.etag);
            assert_eq!(meta.size, 9000);

            // Assembled object reads back as p1 || p2.
            let mut expected = p1.clone();
            expected.extend_from_slice(&p2);
            let (_, body) = s.get_object("buck", "big").await.unwrap();
            assert_eq!(read_all(body).await, expected);

            // Survives losing one drive (reconstruct).
            fs::remove_file(s.object_dir(0, "buck", "big").join(PART)).await.unwrap();
            let (_, body) = s.get_object("buck", "big").await.unwrap();
            assert_eq!(read_all(body).await, expected, "encrypted={encrypted}");
        }
    }

    /// Full versioning lifecycle on the erasure backend: multiple versions,
    /// version reads survive a drive loss, delete markers, and promotion.
    #[tokio::test]
    async fn versioning_lifecycle_and_durability() {
        let (s, _dirs) = store(false).await;
        s.create_bucket("vbk").await.unwrap();
        s.set_bucket_versioning("vbk", "Enabled").await.unwrap();

        let m1 = s.put_object("vbk", "obj", rdr(b"version-one"), "text/plain".into(), BTreeMap::new(), false).await.unwrap();
        let m2 = s.put_object("vbk", "obj", rdr(b"version-two-longer"), "text/plain".into(), BTreeMap::new(), false).await.unwrap();
        let v1 = m1.version_id.unwrap();
        let v2 = m2.version_id.unwrap();
        assert_ne!(v1, v2);

        // Current = latest; each version readable by id.
        let (_, b) = s.get_object("vbk", "obj").await.unwrap();
        assert_eq!(read_all(b).await, b"version-two-longer");
        let (_, b) = s.get_object_version("vbk", "obj", &v1).await.unwrap();
        assert_eq!(read_all(b).await, b"version-one");

        // An archived version survives a drive loss (reconstruct from .v/<v1>).
        fs::remove_file(s.obj_dir_v(0, "vbk", "obj", Some(&v1)).join(PART)).await.unwrap();
        let (_, b) = s.get_object_version("vbk", "obj", &v1).await.unwrap();
        assert_eq!(read_all(b).await, b"version-one");

        // ListObjectVersions shows both with latest flag.
        let lv = s.list_object_versions("vbk", "", None, None, None, 1000).await.unwrap();
        assert_eq!(lv.versions.len(), 2);
        assert!(lv.versions.iter().any(|v| v.version_id == v1 && !v.is_latest));
        assert!(lv.versions.iter().any(|v| v.version_id == v2 && v.is_latest));

        // Delete (no vid) → delete marker; current read 404s.
        let out = s.delete_object("vbk", "obj").await.unwrap();
        assert!(out.delete_marker);
        assert!(matches!(s.head_object("vbk", "obj").await, Err(S3Error::NoSuchKey)));
        // ...but old versions remain.
        let (_, b) = s.get_object_version("vbk", "obj", &v2).await.unwrap();
        assert_eq!(read_all(b).await, b"version-two-longer");

        // Remove the delete marker → latest real version is promoted back.
        let marker = out.version_id.unwrap();
        s.delete_object_version("vbk", "obj", &marker).await.unwrap();
        let (_, b) = s.get_object("vbk", "obj").await.unwrap();
        assert_eq!(read_all(b).await, b"version-two-longer");

        // Permanently delete current (v2) → v1 promoted.
        s.delete_object_version("vbk", "obj", &v2).await.unwrap();
        let (_, b) = s.get_object("vbk", "obj").await.unwrap();
        assert_eq!(read_all(b).await, b"version-one");

        // The key does not leak archived versions into the flat listing.
        let flat = s.list_objects_v2("vbk", "", None, None, None, 1000).await.unwrap();
        assert_eq!(flat.objects.len(), 1);
        assert_eq!(flat.objects[0].key, "obj");
    }

    /// Aborting a multipart upload discards its staging.
    #[tokio::test]
    async fn multipart_abort() {
        let (s, _dirs) = store(false).await;
        s.create_bucket("buck").await.unwrap();
        let upload = s.create_multipart("buck", "x", "application/octet-stream".into(), BTreeMap::new(), false).await.unwrap();
        s.upload_part("buck", "x", &upload, 1, rdr(b"data")).await.unwrap();
        s.abort_multipart("buck", "x", &upload).await.unwrap();
        assert!(matches!(s.list_parts("buck", "x", &upload).await, Err(S3Error::NoSuchUpload)));
    }

    /// A hand-dropped file (no xl.meta) is NOT treated as an object — the
    /// backend is opaque, unlike the FS mirror backend.
    #[tokio::test]
    async fn opaque_ignores_hand_dropped_files() {
        let (s, _dirs) = store(false).await;
        s.create_bucket("buck").await.unwrap();
        fs::write(s.bucket_dir(0, "buck").join("stray.txt"), b"not an object").await.unwrap();
        let listing = s.list_objects_v2("buck", "", None, None, None, 1000).await.unwrap();
        assert!(listing.objects.is_empty(), "stray file must not appear as an object");
        assert!(matches!(s.head_object("buck", "stray.txt").await, Err(S3Error::NoSuchKey)));
    }

    /// Heal rewrites a wiped drive and a bitrot-corrupted drive back to full
    /// redundancy: after healing, the object survives a *fresh* loss of two
    /// other drives — which it could not before, having been degraded.
    #[tokio::test]
    async fn heal_restores_full_redundancy() {
        let (s, _dirs) = store(false).await;
        s.create_bucket("buck").await.unwrap();
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        s.put_object("buck", "obj", rdr(&data), "application/octet-stream".into(), BTreeMap::new(), false).await.unwrap();

        // Degrade: drive 0 loses its whole object dir; drive 1 suffers bitrot.
        fs::remove_dir_all(s.object_dir(0, "buck", "obj")).await.unwrap();
        let p1 = s.object_dir(1, "buck", "obj").join(PART);
        let mut bytes = fs::read(&p1).await.unwrap();
        for b in bytes.iter_mut().take(64) { *b ^= 0xFF; }
        fs::write(&p1, &bytes).await.unwrap();

        // A dry run detects the damage but writes nothing.
        let dry = s.heal(Some("buck"), true).await.unwrap();
        assert_eq!(dry.objects_scanned, 1);
        assert_eq!(dry.objects_healed, 1);
        assert_eq!(dry.shards_rewritten, 2, "both bad drives reported");
        assert!(dry.dry_run);
        assert!(!s.object_dir(0, "buck", "obj").join(PART).exists(), "dry run must not write");

        // Real heal rewrites the two bad drives.
        let rep = s.heal(Some("buck"), false).await.unwrap();
        assert_eq!(rep.objects_healed, 1);
        assert_eq!(rep.shards_rewritten, 2);
        assert!(s.object_dir(0, "buck", "obj").join(PART).exists(), "drive 0 part rebuilt");
        assert!(s.object_dir(0, "buck", "obj").join(XL_META).exists(), "drive 0 meta rebuilt");

        // The rebuilt shards verify (a clean read with no drives down).
        let (_, body) = s.get_object("buck", "obj").await.unwrap();
        assert_eq!(read_all(body).await, data);

        // The object is now fully healthy: a second heal finds nothing to do.
        let again = s.heal(Some("buck"), false).await.unwrap();
        assert_eq!(again.objects_healed, 0, "already-healthy object is left alone");

        // Now drop TWO *different* drives: only survivable because redundancy
        // was restored. (Before healing, drives 0+1 were already gone.)
        fs::remove_file(s.object_dir(2, "buck", "obj").join(PART)).await.unwrap();
        fs::remove_file(s.object_dir(3, "buck", "obj").join(PART)).await.unwrap();
        let (_, body) = s.get_object("buck", "obj").await.unwrap();
        assert_eq!(read_all(body).await, data, "healed object survives a fresh 2-drive loss");
    }

    /// Beyond-parity damage is reported as unrecoverable, not silently "healed".
    #[tokio::test]
    async fn heal_reports_unrecoverable() {
        let (s, _dirs) = store(false).await;
        s.create_bucket("buck").await.unwrap();
        let data: Vec<u8> = (0..6000u32).map(|i| i as u8).collect();
        s.put_object("buck", "obj", rdr(&data), "application/octet-stream".into(), BTreeMap::new(), false).await.unwrap();
        // Lose 3 of 4 drives (> M=2) → cannot reconstruct.
        for d in 0..3 {
            fs::remove_dir_all(s.object_dir(d, "buck", "obj")).await.unwrap();
        }
        let rep = s.heal(Some("buck"), false).await.unwrap();
        assert_eq!(rep.objects_unrecoverable, 1);
        assert_eq!(rep.objects_healed, 0);
    }

    /// Audit trail: a versioned write inside an audit scope records WHO (access
    /// key) + WHERE (IP), surfaced on the version history and on object metadata.
    #[tokio::test]
    async fn audit_records_who_and_where() {
        let (s, _dirs) = store(false).await;
        s.create_bucket("buck").await.unwrap();
        s.set_bucket_versioning("buck", "Enabled").await.unwrap();

        // Write v1 as alice@10.0.0.1, v2 as bob@10.0.0.2.
        let ctx_a = crate::audit::AuditContext { access_key: Some("alice".into()), remote_ip: Some("10.0.0.1".into()) };
        crate::audit::scope(ctx_a, s.put_object("buck", "k", rdr(b"one"), "text/plain".into(), BTreeMap::new(), false)).await.unwrap();
        let ctx_b = crate::audit::AuditContext { access_key: Some("bob".into()), remote_ip: Some("10.0.0.2".into()) };
        crate::audit::scope(ctx_b, s.put_object("buck", "k", rdr(b"two"), "text/plain".into(), BTreeMap::new(), false)).await.unwrap();

        // Current object metadata carries bob's audit.
        let head = s.head_object("buck", "k").await.unwrap();
        let a = head.audit.expect("current version has audit");
        assert_eq!(a.author.as_deref(), Some("bob"));
        assert_eq!(a.source_ip.as_deref(), Some("10.0.0.2"));

        // Version history surfaces per-version authorship (newest first).
        let listing = s.list_object_versions("buck", "", None, None, None, 1000).await.unwrap();
        let authors: Vec<Option<String>> = listing
            .versions
            .iter()
            .map(|v| v.audit.as_ref().and_then(|a| a.author.clone()))
            .collect();
        assert_eq!(authors, vec![Some("bob".into()), Some("alice".into())]);
        let ips: Vec<Option<String>> = listing
            .versions
            .iter()
            .map(|v| v.audit.as_ref().and_then(|a| a.source_ip.clone()))
            .collect();
        assert_eq!(ips, vec![Some("10.0.0.2".into()), Some("10.0.0.1".into())]);
    }

    /// `backend_info` reports the erasure profile and one entry per drive.
    #[tokio::test]
    async fn backend_info_reports_drives() {
        let (s, _dirs) = store(false).await;
        let info = s.backend_info().await;
        assert_eq!(info.backend_type, "Erasure");
        assert_eq!(info.data_shards, 2);
        assert_eq!(info.parity_shards, 2);
        assert_eq!(info.drives.len(), 4);
        assert!(info.drives.iter().all(|d| d.state == "ok"));
    }

    /// A [`Drive`] that simulates a permanently down node — every op fails.
    struct FailingDrive;
    fn down() -> std::io::Error {
        std::io::Error::other("node down")
    }
    #[async_trait]
    impl Drive for FailingDrive {
        fn id(&self) -> String {
            "failing".into()
        }
        fn local_root(&self) -> Option<PathBuf> {
            None
        }
        async fn online(&self) -> bool {
            false
        }
        async fn read(&self, _: &Path) -> std::io::Result<Vec<u8>> {
            Err(down())
        }
        async fn write(&self, _: &Path, _: &[u8]) -> std::io::Result<()> {
            Err(down())
        }
        async fn open(&self, _: &Path) -> std::io::Result<crate::erasure::drive::DriveReader> {
            Err(down())
        }
        async fn create(&self, _: &Path) -> std::io::Result<crate::erasure::drive::DriveWriter> {
            Err(down())
        }
        async fn read_at(&self, _: &Path, _: u64, _: usize) -> std::io::Result<Vec<u8>> {
            Err(down())
        }
        async fn rename(&self, _: &Path, _: &Path) -> std::io::Result<()> {
            Err(down())
        }
        async fn remove_file(&self, _: &Path) -> std::io::Result<()> {
            Err(down())
        }
        async fn remove_dir(&self, _: &Path) -> std::io::Result<()> {
            Err(down())
        }
        async fn remove_dir_all(&self, _: &Path) -> std::io::Result<()> {
            Err(down())
        }
        async fn create_dir_all(&self, _: &Path) -> std::io::Result<()> {
            Err(down())
        }
        async fn stat(&self, _: &Path) -> std::io::Result<crate::erasure::drive::DriveStat> {
            Err(down())
        }
        async fn read_dir(&self, _: &Path) -> std::io::Result<Vec<crate::erasure::drive::DirEntry>> {
            Err(down())
        }
        async fn walk(&self, _: &Path) -> std::io::Result<Vec<crate::erasure::drive::WalkEntry>> {
            Err(down())
        }
    }

    /// Build a 4-shard store from `local_dirs` LocalDrives + `failing` down
    /// nodes (`local + failing == 4`), parity 2 (K=2 ⇒ write quorum 3).
    async fn store_with_failing(local: usize, failing: usize) -> (ErasureStore, Vec<tempfile::TempDir>) {
        let dirs: Vec<tempfile::TempDir> = (0..local).map(|_| tempfile::tempdir().unwrap()).collect();
        let mut drives: Vec<Arc<dyn Drive>> = Vec::new();
        for d in &dirs {
            drives.push(Arc::new(LocalDrive::new(d.path().to_path_buf())));
        }
        for _ in 0..failing {
            drives.push(Arc::new(FailingDrive));
        }
        let store = ErasureStore::with_drives(
            drives,
            CryptoContext::new_aes(MasterKey::generate()),
            false,
            2,
            4096,
        )
        .unwrap();
        (store, dirs)
    }

    /// Write quorum: a PUT with one node down (3 of 4) still succeeds, and the
    /// object reconstructs from the surviving shards.
    #[tokio::test]
    async fn put_tolerates_one_node_down() {
        let (s, _dirs) = store_with_failing(3, 1).await;
        s.create_bucket("buck").await.unwrap();
        let data: Vec<u8> = (0..9000u32).map(|i| (i % 251) as u8).collect();
        s.put_object("buck", "obj", rdr(&data), "application/octet-stream".into(), BTreeMap::new(), false)
            .await
            .expect("put should meet quorum with 3/4 drives");
        let (_, body) = s.get_object("buck", "obj").await.unwrap();
        assert_eq!(read_all(body).await, data, "reconstructs from the 3 written shards");
    }

    /// Write quorum: a PUT with two nodes down (only 2 of 4, < K+1=3) is rejected
    /// and leaves no object behind.
    #[tokio::test]
    async fn put_rejected_below_write_quorum() {
        let (s, _dirs) = store_with_failing(2, 2).await;
        s.create_bucket("buck").await.unwrap();
        let data: Vec<u8> = (0..9000u32).map(|i| (i % 251) as u8).collect();
        let res = s
            .put_object("buck", "obj", rdr(&data), "application/octet-stream".into(), BTreeMap::new(), false)
            .await;
        assert!(res.is_err(), "2/4 shards is below write quorum (need 3)");
        assert!(matches!(s.head_object("buck", "obj").await, Err(S3Error::NoSuchKey)), "partial write rolled back");
    }

    /// Metadata (bucket existence, listing, config, version history) no longer
    /// depends on drive 0: with drive 0 down, all of it still works via the
    /// surviving drives.
    #[tokio::test]
    async fn metadata_survives_drive_0_down() {
        // Shard slot 0 is a down node; slots 1..3 are live local drives.
        let dirs: Vec<tempfile::TempDir> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
        let mut drives: Vec<Arc<dyn Drive>> = vec![Arc::new(FailingDrive)];
        for d in &dirs {
            drives.push(Arc::new(LocalDrive::new(d.path().to_path_buf())));
        }
        let s = ErasureStore::with_drives(
            drives,
            CryptoContext::new_aes(MasterKey::generate()),
            false,
            2, // K=2, write quorum 3 (the 3 live drives)
            4096,
        )
        .unwrap();

        // Bucket lifecycle works without drive 0.
        s.create_bucket("buck").await.unwrap();
        s.head_bucket("buck").await.unwrap();
        assert!(s.list_buckets().await.unwrap().iter().any(|b| b.name == "buck"));

        // Replicated config: versioning read back from the live drives.
        s.set_bucket_versioning("buck", "Enabled").await.unwrap();
        assert_eq!(s.get_bucket_versioning("buck").await.unwrap(), "Enabled");

        // Two versions → history + listing work across drives (no drive 0).
        s.put_object("buck", "k", rdr(b"v1"), "text/plain".into(), BTreeMap::new(), false).await.unwrap();
        s.put_object("buck", "k", rdr(b"v2"), "text/plain".into(), BTreeMap::new(), false).await.unwrap();

        let listing = s.list_objects_v2("buck", "", None, None, None, 100).await.unwrap();
        assert!(listing.objects.iter().any(|o| o.key == "k"), "object listed");
        let vers = s.list_object_versions("buck", "", None, None, None, 100).await.unwrap();
        assert_eq!(vers.versions.iter().filter(|v| v.key == "k").count(), 2, "both versions visible");

        let (_, body) = s.get_object("buck", "k").await.unwrap();
        assert_eq!(read_all(body).await, b"v2", "current version reads back");
    }
}
