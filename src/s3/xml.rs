//! Serde models for the S3 XML wire format (responses and request bodies).
//!
//! Response types are serialized with [`to_xml`]; request bodies
//! ([`CompleteMultipartUpload`], [`Delete`]) are parsed with [`from_xml`].

use serde::{Deserialize, Serialize};

/// The XML namespace every S3 response document declares.
pub const S3_NS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// Serialize a value as an S3 XML document with the standard declaration.
///
/// # Parameters
/// - `root`: the root element name (e.g. `"ListBucketResult"`).
/// - `value`: the serde-serializable body.
///
/// # Returns
/// A `String` containing the XML declaration followed by the serialized body.
/// On serialization failure, returns just the XML declaration.
pub fn to_xml<T: Serialize>(root: &str, value: &T) -> String {
    match quick_xml::se::to_string_with_root(root, value) {
        Ok(body) => format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>{body}"),
        Err(_) => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>".to_string(),
    }
}

/// Parse an S3 XML request body into a typed value.
///
/// # Parameters
/// - `xml`: the raw request body as a UTF-8 string.
///
/// # Returns
/// `Ok(T)` on success, or `Err(String)` describing the parse failure.
pub fn from_xml<T: for<'de> Deserialize<'de>>(xml: &str) -> Result<T, String> {
    quick_xml::de::from_str(xml).map_err(|e| e.to_string())
}

/// Bucket owner identity block (we expose a single static owner in v0.1).
#[derive(Debug, Serialize)]
pub struct Owner {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "DisplayName")]
    pub display_name: String,
}

/// One bucket entry inside [`ListAllMyBucketsResult`].
#[derive(Debug, Serialize)]
pub struct Bucket {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "CreationDate")]
    pub creation_date: String,
}

/// Wrapper holding the repeated `<Bucket>` elements.
#[derive(Debug, Serialize)]
pub struct Buckets {
    #[serde(rename = "Bucket", default)]
    pub bucket: Vec<Bucket>,
}

/// Root document for `ListBuckets` (`GET /`).
#[derive(Debug, Serialize)]
pub struct ListAllMyBucketsResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "Owner")]
    pub owner: Owner,
    #[serde(rename = "Buckets")]
    pub buckets: Buckets,
}

/// One object entry inside [`ListBucketResult`].
#[derive(Debug, Serialize)]
pub struct Contents {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "LastModified")]
    pub last_modified: String,
    #[serde(rename = "ETag")]
    pub etag: String,
    #[serde(rename = "Size")]
    pub size: u64,
    #[serde(rename = "StorageClass")]
    pub storage_class: String,
}

/// One common-prefix entry inside [`ListBucketResult`].
#[derive(Debug, Serialize)]
pub struct CommonPrefix {
    #[serde(rename = "Prefix")]
    pub prefix: String,
}

/// Root document for `ListObjectsV2` (`GET /{bucket}?list-type=2`).
#[derive(Debug, Serialize)]
pub struct ListBucketResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Prefix")]
    pub prefix: String,
    #[serde(rename = "KeyCount")]
    pub key_count: usize,
    #[serde(rename = "MaxKeys")]
    pub max_keys: usize,
    #[serde(rename = "Delimiter", skip_serializing_if = "Option::is_none")]
    pub delimiter: Option<String>,
    #[serde(rename = "EncodingType", skip_serializing_if = "Option::is_none")]
    pub encoding_type: Option<String>,
    #[serde(rename = "IsTruncated")]
    pub is_truncated: bool,
    #[serde(
        rename = "NextContinuationToken",
        skip_serializing_if = "Option::is_none"
    )]
    pub next_continuation_token: Option<String>,
    #[serde(rename = "Contents", default)]
    pub contents: Vec<Contents>,
    #[serde(rename = "CommonPrefixes", default)]
    pub common_prefixes: Vec<CommonPrefix>,
}

/// One `<Version>` entry inside [`ListVersionsResult`].
#[derive(Debug, Serialize)]
pub struct VersionXml {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "VersionId")]
    pub version_id: String,
    #[serde(rename = "IsLatest")]
    pub is_latest: bool,
    #[serde(rename = "LastModified")]
    pub last_modified: String,
    #[serde(rename = "ETag")]
    pub etag: String,
    #[serde(rename = "Size")]
    pub size: u64,
    #[serde(rename = "StorageClass")]
    pub storage_class: String,
    /// Standard S3 `<Owner>` — KerPlace populates it with the access key that
    /// authored the version (the audit "who"); omitted when unknown.
    #[serde(rename = "Owner", skip_serializing_if = "Option::is_none")]
    pub owner: Option<Owner>,
}

/// One `<DeleteMarker>` entry inside [`ListVersionsResult`].
#[derive(Debug, Serialize)]
pub struct DeleteMarkerXml {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "VersionId")]
    pub version_id: String,
    #[serde(rename = "IsLatest")]
    pub is_latest: bool,
    #[serde(rename = "LastModified")]
    pub last_modified: String,
}

/// Root document for `ListObjectVersions` (`GET /{bucket}?versions`).
#[derive(Debug, Serialize)]
pub struct ListVersionsResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Prefix")]
    pub prefix: String,
    #[serde(rename = "KeyMarker")]
    pub key_marker: String,
    #[serde(rename = "VersionIdMarker")]
    pub version_id_marker: String,
    #[serde(rename = "MaxKeys")]
    pub max_keys: usize,
    #[serde(rename = "Delimiter", skip_serializing_if = "Option::is_none")]
    pub delimiter: Option<String>,
    #[serde(rename = "IsTruncated")]
    pub is_truncated: bool,
    #[serde(rename = "NextKeyMarker", skip_serializing_if = "Option::is_none")]
    pub next_key_marker: Option<String>,
    #[serde(rename = "NextVersionIdMarker", skip_serializing_if = "Option::is_none")]
    pub next_version_id_marker: Option<String>,
    #[serde(rename = "Version", default)]
    pub version: Vec<VersionXml>,
    #[serde(rename = "DeleteMarker", default)]
    pub delete_marker: Vec<DeleteMarkerXml>,
    #[serde(rename = "CommonPrefixes", default)]
    pub common_prefixes: Vec<CommonPrefix>,
}

/// Root document returned by `CreateMultipartUpload`.
#[derive(Debug, Serialize)]
pub struct InitiateMultipartUploadResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "UploadId")]
    pub upload_id: String,
}

/// Root document returned by `CompleteMultipartUpload`.
#[derive(Debug, Serialize)]
pub struct CompleteMultipartUploadResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "Location")]
    pub location: String,
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "ETag")]
    pub etag: String,
}

/// One part entry inside [`ListPartsResult`].
#[derive(Debug, Serialize)]
pub struct PartXml {
    #[serde(rename = "PartNumber")]
    pub part_number: u32,
    #[serde(rename = "LastModified")]
    pub last_modified: String,
    #[serde(rename = "ETag")]
    pub etag: String,
    #[serde(rename = "Size")]
    pub size: u64,
}

/// Root document returned by `ListParts`.
#[derive(Debug, Serialize)]
pub struct ListPartsResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "UploadId")]
    pub upload_id: String,
    #[serde(rename = "Part", default)]
    pub part: Vec<PartXml>,
}

/// Root document returned by `CopyObject`.
#[derive(Debug, Serialize)]
pub struct CopyObjectResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "LastModified")]
    pub last_modified: String,
    #[serde(rename = "ETag")]
    pub etag: String,
}

/// One deleted-object entry inside [`DeleteResult`].
#[derive(Debug, Serialize)]
pub struct Deleted {
    #[serde(rename = "Key")]
    pub key: String,
}

/// One error entry inside [`DeleteResult`].
#[derive(Debug, Serialize)]
pub struct DeleteError {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "Message")]
    pub message: String,
}

/// Root document returned by the batch `DeleteObjects` (`POST /{bucket}?delete`).
#[derive(Debug, Serialize)]
pub struct DeleteResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "Deleted", default)]
    pub deleted: Vec<Deleted>,
    #[serde(rename = "Error", default)]
    pub errors: Vec<DeleteError>,
}

/// One part reference inside a [`CompleteMultipartUpload`] request body.
#[derive(Debug, Deserialize)]
pub struct CompletePart {
    #[serde(rename = "PartNumber")]
    pub part_number: u32,
    #[serde(rename = "ETag")]
    pub etag: String,
}

/// Request body of `CompleteMultipartUpload`.
#[derive(Debug, Deserialize)]
pub struct CompleteMultipartUpload {
    #[serde(rename = "Part", default)]
    pub parts: Vec<CompletePart>,
}

/// One object reference inside a [`Delete`] request body.
#[derive(Debug, Deserialize)]
pub struct ObjectIdentifier {
    #[serde(rename = "Key")]
    pub key: String,
}

/// Request body of the batch `DeleteObjects` operation.
#[derive(Debug, Deserialize)]
pub struct Delete {
    #[serde(rename = "Object", default)]
    pub objects: Vec<ObjectIdentifier>,
    #[serde(rename = "Quiet", default)]
    pub quiet: bool,
}

// ── SSE (Server-Side Encryption) ─────────────────────────────────────────────

/// Default SSE algorithm inside a rule.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SseDefault {
    #[serde(rename = "SSEAlgorithm")]
    pub sse_algorithm: String,
}

/// One encryption rule.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SseRule {
    #[serde(rename = "ApplyServerSideEncryptionByDefault", default)]
    pub default: SseDefault,
    #[serde(rename = "BucketKeyEnabled", skip_serializing_if = "Option::is_none")]
    pub bucket_key_enabled: Option<bool>,
}

/// Root of `PutBucketEncryption` / `GetBucketEncryption` XML body.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServerSideEncryptionConfiguration {
    #[serde(rename = "Rule")]
    pub rule: SseRule,
}

// ── Tagging ───────────────────────────────────────────────────────────────────

/// One tag key-value pair.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Tag {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "Value")]
    pub value: String,
}

/// Wrapper around repeated `<Tag>` elements.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct TagSet {
    #[serde(rename = "Tag", default)]
    pub tags: Vec<Tag>,
}

/// Root of `PutBucketTagging` / `PutObjectTagging` / `GetBucketTagging` /
/// `GetObjectTagging` XML body.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Tagging {
    #[serde(rename = "TagSet", default)]
    pub tag_set: TagSet,
}

// ── Versioning ────────────────────────────────────────────────────────────────

/// Root of `PutBucketVersioning` / `GetBucketVersioning` XML body.
///
/// `Status` is `"Enabled"` or `"Suspended"`. Missing means versioning was
/// never configured.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct VersioningConfiguration {
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

// ── Object lock / retention ───────────────────────────────────────────────────

/// Root of `PutBucketObjectLockConfiguration` request / `GetObjectLockConfiguration`.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ObjectLockConfiguration {
    #[serde(rename = "ObjectLockEnabled", skip_serializing_if = "Option::is_none")]
    pub object_lock_enabled: Option<String>,
    #[serde(rename = "Rule", skip_serializing_if = "Option::is_none")]
    pub rule: Option<ObjectLockRule>,
}

/// Default retention rule inside an object-lock configuration.
#[derive(Debug, Serialize, Deserialize)]
pub struct ObjectLockRule {
    #[serde(rename = "DefaultRetention")]
    pub default_retention: DefaultRetention,
}

/// Default retention period.
#[derive(Debug, Serialize, Deserialize)]
pub struct DefaultRetention {
    #[serde(rename = "Mode")]
    pub mode: String,
    #[serde(rename = "Days", skip_serializing_if = "Option::is_none")]
    pub days: Option<u64>,
    #[serde(rename = "Years", skip_serializing_if = "Option::is_none")]
    pub years: Option<u64>,
}

/// Per-object retention config (`PUT/GET /{bucket}/{key}?retention`).
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ObjectRetention {
    #[serde(rename = "Mode", skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(rename = "RetainUntilDate", skip_serializing_if = "Option::is_none")]
    pub retain_until_date: Option<String>,
}

/// Per-object legal hold (`PUT/GET /{bucket}/{key}?legal-hold`).
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct LegalHold {
    #[serde(rename = "Status")]
    pub status: String,
}

// ── Lifecycle / ILM ───────────────────────────────────────────────────────────

/// Root of `PutBucketLifecycleConfiguration` XML body.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct LifecycleConfiguration {
    #[serde(rename = "Rule", default)]
    pub rules: Vec<LifecycleRule>,
}

/// One lifecycle rule.
#[derive(Debug, Serialize, Deserialize)]
pub struct LifecycleRule {
    #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "Filter", skip_serializing_if = "Option::is_none")]
    pub filter: Option<LifecycleFilter>,
    #[serde(rename = "Expiration", skip_serializing_if = "Option::is_none")]
    pub expiration: Option<LifecycleExpiration>,
    #[serde(rename = "NoncurrentVersionExpiration", skip_serializing_if = "Option::is_none")]
    pub noncurrent_version_expiration: Option<NoncurrentVersionExpiration>,
}

/// Filter section of a lifecycle rule.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct LifecycleFilter {
    #[serde(rename = "Prefix", skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

/// Expiration action in a lifecycle rule.
#[derive(Debug, Serialize, Deserialize)]
pub struct LifecycleExpiration {
    #[serde(rename = "Days", skip_serializing_if = "Option::is_none")]
    pub days: Option<u64>,
    #[serde(rename = "Date", skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
}

/// Noncurrent version expiration action.
#[derive(Debug, Serialize, Deserialize)]
pub struct NoncurrentVersionExpiration {
    #[serde(rename = "NoncurrentDays")]
    pub noncurrent_days: u64,
}
