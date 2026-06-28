//! Storage abstraction.
//!
//! [`ObjectStore`] is the single seam between the S3/HTTP layer and the
//! bytes-on-disk layer. v0.1 ships one implementation ([`fs::FsStore`]);
//! future backends implement the same trait without any change to the HTTP
//! handlers.

pub mod fs;

use std::collections::BTreeMap;
use std::pin::Pin;

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio::io::AsyncRead;

use crate::error::S3Error;

/// A streaming, owned reader for an object/part payload.
pub type BodyReader = Pin<Box<dyn AsyncRead + Send>>;

/// Synthesize an opaque, non-MD5 ETag for an encrypted object (32 hex chars, the
/// same shape as an MD5 so clients that store/echo or hex-decode it keep working).
///
/// KerPlace stores ciphertext, and each PUT uses a fresh random DEK/nonce, so the
/// ETag of an encrypted object is **already** non-deterministic and not the plaintext
/// MD5 — exactly like an AWS SSE object's ETag. Computing `md5(ciphertext)` for it was
/// the single biggest on-CPU cost of a PUT (the flamegraph's ~32%) for no observable
/// benefit, so the encrypt path returns this instead and skips the hash entirely.
///
/// # Returns
/// A fresh random 32-hex-character ETag value (unquoted).
pub fn opaque_etag() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// A streaming, owned reader returned when fetching an object's bytes.
pub type ObjectBody = Pin<Box<dyn AsyncRead + Send>>;

/// Audit trail recorded for a version write — a KerPlace differentiator over
/// stock S3. Captures *who* wrote a version and from *where*; the *when* is the
/// enclosing record's `last_modified`. `None` on backends/objects that have no
/// audit record (e.g. the legacy `fs` mirror, or objects written before the
/// feature existed).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VersionAudit {
    /// Access key (user) that authored the write, when known.
    pub author: Option<String>,
    /// Client IP the write originated from, when known.
    pub source_ip: Option<String>,
}

impl VersionAudit {
    /// Whether this audit record carries any information worth surfacing.
    ///
    /// # Returns
    /// `true` if at least one field is populated.
    pub fn is_some(&self) -> bool {
        self.author.is_some() || self.source_ip.is_some()
    }
}

/// Health of a single backend drive, reported by [`ObjectStore::backend_info`].
#[derive(Debug, Clone)]
pub struct DriveStatus {
    /// Filesystem path (or endpoint) backing this drive.
    pub path: String,
    /// `"ok"` when the drive is present and writable, else `"offline"`.
    pub state: String,
}

/// Backend topology + health, surfaced by `mc admin info` and the console.
#[derive(Debug, Clone)]
pub struct BackendInfo {
    /// Backend kind: `"FS"` (single mirror) or `"Erasure"`.
    pub backend_type: String,
    /// Data shards `K` per object (0 for the FS backend).
    pub data_shards: usize,
    /// Parity shards `M` per object (0 for the FS backend).
    pub parity_shards: usize,
    /// One entry per backing drive.
    pub drives: Vec<DriveStatus>,
}

/// Outcome of a heal scan ([`ObjectStore::heal`]).
#[derive(Debug, Clone, Default)]
pub struct HealReport {
    /// Object versions inspected.
    pub objects_scanned: u64,
    /// Object versions that were degraded and successfully rewritten to full
    /// redundancy (or *would* be, when `dry_run`).
    pub objects_healed: u64,
    /// Total per-drive shard streams rewritten across all healed objects.
    pub shards_rewritten: u64,
    /// Object versions found degraded beyond recovery (fewer than `K` good
    /// shards) — reported, not repaired.
    pub objects_unrecoverable: u64,
    /// Whether this was a dry run (detect only, no writes).
    pub dry_run: bool,
}

/// Summary information about a bucket.
#[derive(Debug, Clone)]
pub struct BucketInfo {
    /// Bucket name.
    pub name: String,
    /// Time the bucket directory was created.
    pub creation_date: OffsetDateTime,
}

/// Metadata describing a stored object (or the result of storing one).
#[derive(Debug, Clone)]
pub struct ObjectMeta {
    /// Object key (path within the bucket, `/`-separated).
    pub key: String,
    /// Size of the object payload in bytes (logical / plaintext size).
    pub size: u64,
    /// Entity tag. For single PUT this is the hex MD5; for multipart it is
    /// `hex(md5(concat(part_md5...)))-<part_count>`. Always quoted on the wire.
    pub etag: String,
    /// Last modification time.
    pub last_modified: OffsetDateTime,
    /// MIME type stored alongside the object.
    pub content_type: String,
    /// User metadata (the `x-amz-meta-*` headers), keys without the prefix.
    pub user_metadata: BTreeMap<String, String>,
    /// Whether the payload on disk is encrypted (KerPlace `KPE1` container). Used
    /// by HTTP handlers to set `x-amz-server-side-encryption: AES256`.
    pub encrypted: bool,
    /// Version id of this object, when the bucket has versioning configured.
    /// `None` for objects in non-versioned buckets; `Some("null")` for objects
    /// written while versioning was suspended.
    pub version_id: Option<String>,
    /// Audit trail (who/where) for this object/version, when recorded.
    pub audit: Option<VersionAudit>,
}

/// Outcome of a delete operation, carrying versioning side effects.
#[derive(Debug, Clone, Default)]
pub struct DeleteOutcome {
    /// Version id created (a delete marker) or removed by this delete. `None`
    /// for a plain delete in a non-versioned bucket.
    pub version_id: Option<String>,
    /// `true` when this delete created (or removed) a delete marker.
    pub delete_marker: bool,
}

/// One entry in a `ListObjectVersions` result — a version or a delete marker.
#[derive(Debug, Clone)]
pub struct ObjectVersion {
    /// Object key.
    pub key: String,
    /// Version id (`"null"` for objects written without active versioning).
    pub version_id: String,
    /// Whether this is the current (latest) version of the key.
    pub is_latest: bool,
    /// Last modification time.
    pub last_modified: OffsetDateTime,
    /// Entity tag (empty for delete markers).
    pub etag: String,
    /// Logical size in bytes (0 for delete markers).
    pub size: u64,
    /// Whether this entry is a delete marker rather than a real version.
    pub is_delete_marker: bool,
    /// Audit trail (who/where) for this version write, when recorded.
    pub audit: Option<VersionAudit>,
}

/// A page of a `ListObjectVersions` result.
#[derive(Debug, Clone, Default)]
pub struct VersionListing {
    /// Versions and delete markers, ordered by key then newest-first.
    pub versions: Vec<ObjectVersion>,
    /// Common prefixes rolled up by the delimiter.
    pub common_prefixes: Vec<String>,
    /// Whether more results exist beyond this page.
    pub is_truncated: bool,
    /// Continuation key marker for the next page, when truncated.
    pub next_key_marker: Option<String>,
    /// Continuation version-id marker for the next page, when truncated.
    pub next_version_id_marker: Option<String>,
}

/// One page of a `ListObjectsV2` result.
#[derive(Debug, Clone, Default)]
pub struct Listing {
    /// Objects in this page, ordered by key.
    pub objects: Vec<ObjectMeta>,
    /// Common prefixes (the "directories") rolled up by the delimiter.
    pub common_prefixes: Vec<String>,
    /// Whether more results exist beyond this page.
    pub is_truncated: bool,
    /// Opaque token to fetch the next page, when truncated.
    pub next_continuation_token: Option<String>,
}

/// Information about a single uploaded part of a multipart upload.
#[derive(Debug, Clone)]
pub struct PartInfo {
    /// 1-based part number.
    pub part_number: u32,
    /// Hex MD5 of the part payload (quoted ETag on the wire).
    pub etag: String,
    /// Size of the part in bytes.
    pub size: u64,
    /// Time the part was uploaded.
    pub last_modified: OffsetDateTime,
}

/// A part referenced by the client when completing a multipart upload.
#[derive(Debug, Clone)]
pub struct CompletedPart {
    /// 1-based part number.
    pub part_number: u32,
    /// ETag the client expects this part to have (verified on completion).
    pub etag: String,
}

/// Backend-agnostic object storage operations backing the S3 API.
///
/// All methods are async and fallible with [`S3Error`]. Implementations must
/// be `Send + Sync` so a single instance can be shared across all requests.
#[async_trait]
pub trait ObjectStore: Send + Sync + 'static {
    /// Create a new bucket.
    ///
    /// # Parameters
    /// - `bucket`: the bucket name to create.
    ///
    /// # Returns
    /// `Ok(())` on success, [`S3Error::BucketAlreadyOwnedByYou`] if it already
    /// exists, or [`S3Error::InvalidBucketName`] if the name is invalid.
    async fn create_bucket(&self, bucket: &str) -> Result<(), S3Error>;

    /// Delete an empty bucket.
    ///
    /// # Parameters
    /// - `bucket`: the bucket name to delete.
    ///
    /// # Returns
    /// `Ok(())` on success, [`S3Error::NoSuchBucket`] if missing, or
    /// [`S3Error::BucketNotEmpty`] if it still contains objects.
    async fn delete_bucket(&self, bucket: &str) -> Result<(), S3Error>;

    /// List all buckets.
    ///
    /// # Returns
    /// A vector of [`BucketInfo`] ordered by name.
    async fn list_buckets(&self) -> Result<Vec<BucketInfo>, S3Error>;

    /// Check that a bucket exists.
    ///
    /// # Parameters
    /// - `bucket`: the bucket name to test.
    ///
    /// # Returns
    /// `Ok(())` if present, otherwise [`S3Error::NoSuchBucket`].
    async fn head_bucket(&self, bucket: &str) -> Result<(), S3Error>;

    /// Store an object, streaming its body to the backend.
    ///
    /// # Parameters
    /// - `bucket`: destination bucket (must exist).
    /// - `key`: destination object key.
    /// - `body`: streaming reader of the (already de-chunked) payload.
    /// - `content_type`: MIME type to persist.
    /// - `user_metadata`: `x-amz-meta-*` values (prefix stripped).
    /// - `encrypt`: encrypt the object at rest (requires a master key configured).
    ///
    /// # Returns
    /// [`ObjectMeta`] describing the stored object (including its ETag).
    async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        body: BodyReader,
        content_type: String,
        user_metadata: BTreeMap<String, String>,
        encrypt: bool,
    ) -> Result<ObjectMeta, S3Error>;

    /// Fetch an object's metadata and a streaming reader of its bytes.
    ///
    /// # Parameters
    /// - `bucket`: source bucket.
    /// - `key`: object key.
    ///
    /// # Returns
    /// A tuple of [`ObjectMeta`] and an [`ObjectBody`] reader.
    async fn get_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<(ObjectMeta, ObjectBody), S3Error>;

    /// Fetch a contiguous byte range of an object (HTTP `Range` requests).
    ///
    /// # Parameters
    /// - `bucket`: source bucket.
    /// - `key`: object key.
    /// - `start`: zero-based inclusive start offset (clamped to object size).
    /// - `end`: zero-based inclusive end offset; `None` means end of object.
    ///
    /// # Returns
    /// A tuple of [`ObjectMeta`], the number of bytes in the returned range,
    /// and an [`ObjectBody`] reader positioned at `start`.
    async fn get_object_range(
        &self,
        bucket: &str,
        key: &str,
        start: u64,
        end: Option<u64>,
    ) -> Result<(ObjectMeta, u64, ObjectBody), S3Error>;

    /// Fetch only an object's metadata (no body).
    ///
    /// # Parameters
    /// - `bucket`: source bucket.
    /// - `key`: object key.
    ///
    /// # Returns
    /// [`ObjectMeta`], or [`S3Error::NoSuchKey`] / [`S3Error::NoSuchBucket`].
    async fn head_object(&self, bucket: &str, key: &str) -> Result<ObjectMeta, S3Error>;

    /// Delete an object. Idempotent: deleting a missing key succeeds.
    ///
    /// In a versioning-enabled (or suspended) bucket this inserts a delete
    /// marker rather than removing data, and the returned [`DeleteOutcome`]
    /// carries the new marker's version id.
    ///
    /// # Parameters
    /// - `bucket`: source bucket (must exist).
    /// - `key`: object key to remove.
    ///
    /// # Returns
    /// A [`DeleteOutcome`] describing any versioning side effect.
    async fn delete_object(&self, bucket: &str, key: &str) -> Result<DeleteOutcome, S3Error>;

    /// Fetch a specific version's metadata and a streaming reader of its bytes.
    ///
    /// # Parameters
    /// - `bucket`: source bucket.
    /// - `key`: object key.
    /// - `version_id`: the version to read.
    ///
    /// # Returns
    /// A tuple of [`ObjectMeta`] and an [`ObjectBody`], or [`S3Error::NoSuchKey`]
    /// / [`S3Error::NoSuchVersion`] / [`S3Error::MethodNotAllowed`] (delete marker).
    async fn get_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<(ObjectMeta, ObjectBody), S3Error>;

    /// Fetch only a specific version's metadata (no body).
    ///
    /// # Parameters
    /// - `bucket`: source bucket.
    /// - `key`: object key.
    /// - `version_id`: the version to stat.
    async fn head_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<ObjectMeta, S3Error>;

    /// Permanently delete a single version (or delete marker) of an object.
    ///
    /// When the current version is removed, the next-newest version is promoted
    /// back to the canonical (live) location.
    ///
    /// # Parameters
    /// - `bucket`: source bucket.
    /// - `key`: object key.
    /// - `version_id`: the version to remove.
    ///
    /// # Returns
    /// A [`DeleteOutcome`] recording the removed version id and whether it was a
    /// delete marker.
    async fn delete_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<DeleteOutcome, S3Error>;

    /// List all object versions and delete markers in a bucket
    /// (the `ListObjectVersions` operation).
    ///
    /// # Parameters
    /// - `bucket`: bucket to list.
    /// - `prefix`: only return keys starting with this prefix.
    /// - `delimiter`: roll keys sharing a prefix up to this delimiter.
    /// - `key_marker`: return keys after this one (pagination).
    /// - `version_id_marker`: with `key_marker`, the version to resume after.
    /// - `max_keys`: maximum number of entries to return.
    ///
    /// # Returns
    /// A [`VersionListing`] page.
    async fn list_object_versions(
        &self,
        bucket: &str,
        prefix: &str,
        delimiter: Option<&str>,
        key_marker: Option<&str>,
        version_id_marker: Option<&str>,
        max_keys: usize,
    ) -> Result<VersionListing, S3Error>;

    /// Server-side copy of an object.
    ///
    /// # Parameters
    /// - `src_bucket`: source bucket.
    /// - `src_key`: source object key.
    /// - `dst_bucket`: destination bucket.
    /// - `dst_key`: destination object key.
    /// - `encrypt`: encrypt the destination object at rest.
    ///
    /// # Returns
    /// [`ObjectMeta`] of the newly written destination object.
    async fn copy_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        dst_bucket: &str,
        dst_key: &str,
        encrypt: bool,
    ) -> Result<ObjectMeta, S3Error>;

    /// List objects in a bucket (the `ListObjectsV2` operation).
    ///
    /// # Parameters
    /// - `bucket`: bucket to list.
    /// - `prefix`: only return keys starting with this prefix.
    /// - `delimiter`: roll keys sharing a prefix up to this delimiter into
    ///   common prefixes (typically `/`).
    /// - `continuation_token`: opaque page token from a prior response.
    /// - `start_after`: return keys strictly greater than this value.
    /// - `max_keys`: maximum number of keys to return.
    ///
    /// # Returns
    /// A [`Listing`] page.
    async fn list_objects_v2(
        &self,
        bucket: &str,
        prefix: &str,
        delimiter: Option<&str>,
        continuation_token: Option<&str>,
        start_after: Option<&str>,
        max_keys: usize,
    ) -> Result<Listing, S3Error>;

    /// Begin a multipart upload.
    ///
    /// # Parameters
    /// - `bucket`: destination bucket (must exist).
    /// - `key`: destination object key.
    /// - `content_type`: MIME type to persist on completion.
    /// - `user_metadata`: `x-amz-meta-*` values to persist on completion.
    /// - `encrypt`: whether to encrypt the final assembled object.
    ///
    /// # Returns
    /// A newly generated upload id.
    async fn create_multipart(
        &self,
        bucket: &str,
        key: &str,
        content_type: String,
        user_metadata: BTreeMap<String, String>,
        encrypt: bool,
    ) -> Result<String, S3Error>;

    /// Upload one part of an in-progress multipart upload.
    ///
    /// # Parameters
    /// - `bucket`: destination bucket.
    /// - `key`: destination object key.
    /// - `upload_id`: id returned by [`ObjectStore::create_multipart`].
    /// - `part_number`: 1-based part number (parts may arrive out of order).
    /// - `body`: streaming reader of the part payload.
    ///
    /// # Returns
    /// The part's ETag (hex MD5).
    async fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: u32,
        body: BodyReader,
    ) -> Result<String, S3Error>;

    /// Finalize a multipart upload, concatenating its parts in order.
    ///
    /// # Parameters
    /// - `bucket`: destination bucket.
    /// - `key`: destination object key.
    /// - `upload_id`: the upload to complete.
    /// - `parts`: the parts (with expected ETags) in assembly order.
    ///
    /// # Returns
    /// [`ObjectMeta`] of the assembled object (with the multipart ETag), or
    /// [`S3Error::InvalidPart`] if a part is missing or its ETag mismatches.
    async fn complete_multipart(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: Vec<CompletedPart>,
    ) -> Result<ObjectMeta, S3Error>;

    /// Abort a multipart upload, discarding any staged parts.
    ///
    /// # Parameters
    /// - `bucket`: destination bucket.
    /// - `key`: destination object key.
    /// - `upload_id`: the upload to abort.
    ///
    /// # Returns
    /// `Ok(())` on success, or [`S3Error::NoSuchUpload`] if unknown.
    async fn abort_multipart(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<(), S3Error>;

    /// List the parts already uploaded for a multipart upload.
    ///
    /// # Parameters
    /// - `bucket`: destination bucket.
    /// - `key`: destination object key.
    /// - `upload_id`: the upload to inspect.
    ///
    /// # Returns
    /// A vector of [`PartInfo`] ordered by part number.
    async fn list_parts(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<Vec<PartInfo>, S3Error>;

    // ── Per-bucket metadata ───────────────────────────────────────────────────

    /// Get the SSE algorithm configured as default for the bucket.
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    ///
    /// # Returns
    /// `Some("AES256")` (or another algorithm string) if SSE is configured,
    /// `None` if not.
    async fn get_bucket_encryption(&self, bucket: &str) -> Result<Option<String>, S3Error>;

    /// Set the default SSE algorithm for the bucket.
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    /// - `sse_type`: algorithm string (`"AES256"`).
    async fn set_bucket_encryption(&self, bucket: &str, sse_type: &str) -> Result<(), S3Error>;

    /// Remove the default SSE configuration for the bucket.
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    async fn delete_bucket_encryption(&self, bucket: &str) -> Result<(), S3Error>;

    /// Retrieve the raw JSON bucket policy (`None` if not set).
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    async fn get_bucket_policy(&self, bucket: &str) -> Result<Option<String>, S3Error>;

    /// Store a raw JSON bucket policy.
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    /// - `policy`: raw JSON policy document.
    async fn set_bucket_policy(&self, bucket: &str, policy: String) -> Result<(), S3Error>;

    /// Remove the bucket policy.
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    async fn delete_bucket_policy(&self, bucket: &str) -> Result<(), S3Error>;

    /// Retrieve the tag set for a bucket (`None` if not set).
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    async fn get_bucket_tags(
        &self,
        bucket: &str,
    ) -> Result<Option<BTreeMap<String, String>>, S3Error>;

    /// Store the tag set for a bucket (replaces any existing tags).
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    /// - `tags`: map of tag key → value.
    async fn set_bucket_tags(
        &self,
        bucket: &str,
        tags: BTreeMap<String, String>,
    ) -> Result<(), S3Error>;

    /// Remove the tag set for a bucket.
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    async fn delete_bucket_tags(&self, bucket: &str) -> Result<(), S3Error>;

    /// Retrieve the versioning status (`""`, `"Enabled"`, or `"Suspended"`).
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    async fn get_bucket_versioning(&self, bucket: &str) -> Result<String, S3Error>;

    /// Set the versioning status for a bucket.
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    /// - `status`: `"Enabled"` or `"Suspended"`.
    async fn set_bucket_versioning(&self, bucket: &str, status: &str) -> Result<(), S3Error>;

    /// Retrieve the lifecycle configuration for a bucket (raw XML `None` if absent).
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    async fn get_bucket_lifecycle(&self, bucket: &str) -> Result<Option<String>, S3Error>;

    /// Store the lifecycle configuration for a bucket as raw XML.
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    /// - `xml`: serialized `LifecycleConfiguration` XML document.
    async fn set_bucket_lifecycle(&self, bucket: &str, xml: String) -> Result<(), S3Error>;

    /// Remove the lifecycle configuration for a bucket.
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    async fn delete_bucket_lifecycle(&self, bucket: &str) -> Result<(), S3Error>;

    // ── Per-object metadata ───────────────────────────────────────────────────

    /// Retrieve the tag set for an object (`None` if not set).
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    /// - `key`: object key.
    async fn get_object_tags(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<BTreeMap<String, String>>, S3Error>;

    /// Store the tag set for an object (replaces any existing tags).
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    /// - `key`: object key.
    /// - `tags`: map of tag key → value.
    async fn set_object_tags(
        &self,
        bucket: &str,
        key: &str,
        tags: BTreeMap<String, String>,
    ) -> Result<(), S3Error>;

    /// Remove the tag set for an object.
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    /// - `key`: object key.
    async fn delete_object_tags(&self, bucket: &str, key: &str) -> Result<(), S3Error>;

    /// Get per-object retention (raw JSON, `None` if absent).
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    /// - `key`: object key.
    async fn get_object_retention(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<String>, S3Error>;

    /// Set per-object retention (raw JSON).
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    /// - `key`: object key.
    /// - `data`: serialized retention JSON.
    async fn set_object_retention(
        &self,
        bucket: &str,
        key: &str,
        data: String,
    ) -> Result<(), S3Error>;

    /// Get per-object legal hold (`"ON"` or `"OFF"`, `None` if not set).
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    /// - `key`: object key.
    async fn get_object_legal_hold(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<String>, S3Error>;

    /// Set per-object legal hold (`"ON"` or `"OFF"`).
    ///
    /// # Parameters
    /// - `bucket`: bucket name.
    /// - `key`: object key.
    /// - `status`: `"ON"` or `"OFF"`.
    async fn set_object_legal_hold(
        &self,
        bucket: &str,
        key: &str,
        status: &str,
    ) -> Result<(), S3Error>;

    // ── Backend health & self-healing ─────────────────────────────────────────

    /// Report the backend's topology and per-drive health.
    ///
    /// The default describes a generic single-drive backend with no redundancy;
    /// redundant backends override it with real drive states and `(K, M)`.
    ///
    /// # Returns
    /// A [`BackendInfo`] for `mc admin info` / the console.
    async fn backend_info(&self) -> BackendInfo {
        BackendInfo {
            backend_type: "FS".to_string(),
            data_shards: 0,
            parity_shards: 0,
            drives: vec![DriveStatus { path: String::new(), state: "ok".to_string() }],
        }
    }

    /// Scan for and repair degraded objects (missing/corrupt shards).
    ///
    /// The default is a no-op (single-mirror backends have nothing to heal):
    /// every scan reports zero work. Redundant backends override it to rewrite
    /// reconstructable shards back to full redundancy.
    ///
    /// # Parameters
    /// - `bucket`: restrict the scan to one bucket, or `None` for all buckets.
    /// - `dry_run`: when `true`, detect and report but do not write repairs.
    ///
    /// # Returns
    /// A [`HealReport`] summarising what was scanned and repaired.
    async fn heal(&self, _bucket: Option<&str>, dry_run: bool) -> Result<HealReport, S3Error> {
        Ok(HealReport { dry_run, ..Default::default() })
    }
}

/// Validate an S3 bucket name against the standard naming rules.
///
/// # Parameters
/// - `name`: the candidate bucket name.
///
/// # Returns
/// `Ok(())` if valid, otherwise [`S3Error::InvalidBucketName`]. Names must be
/// 3–63 chars, lowercase alphanumeric / `.` / `-`, start and end
/// alphanumeric, and must not be formatted as an IPv4 address.
pub fn validate_bucket_name(name: &str) -> Result<(), S3Error> {
    let len = name.len();
    if !(3..=63).contains(&len) {
        return Err(S3Error::InvalidBucketName);
    }
    let bytes = name.as_bytes();
    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_alnum(bytes[0]) || !is_alnum(bytes[len - 1]) {
        return Err(S3Error::InvalidBucketName);
    }
    if !name
        .bytes()
        .all(|b| is_alnum(b) || b == b'-' || b == b'.')
    {
        return Err(S3Error::InvalidBucketName);
    }
    if name.contains("..") {
        return Err(S3Error::InvalidBucketName);
    }
    // Reject IPv4-looking names, as AWS does.
    if name.split('.').count() == 4 && name.split('.').all(|p| p.parse::<u8>().is_ok()) {
        return Err(S3Error::InvalidBucketName);
    }
    Ok(())
}

/// Validate an object key, primarily to prevent path traversal on filesystem
/// backends.
///
/// # Parameters
/// - `key`: the candidate object key.
///
/// # Returns
/// `Ok(())` if safe, otherwise [`S3Error::InvalidArgument`]. Rejects empty
/// keys, leading `/`, `..`/`.` path segments and backslashes.
pub fn validate_key(key: &str) -> Result<(), S3Error> {
    if key.is_empty() {
        return Err(S3Error::InvalidArgument("object key is empty".into()));
    }
    if key.starts_with('/') || key.contains('\\') {
        return Err(S3Error::InvalidArgument("invalid object key".into()));
    }
    if key.split('/').any(|seg| seg == ".." || seg == ".") {
        return Err(S3Error::InvalidArgument("invalid object key".into()));
    }
    Ok(())
}
