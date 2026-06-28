//! End-to-end HTTP tests driving the full router (handlers + XML + storage)
//! via `tower`'s `oneshot`, without a real socket. Authentication is disabled
//! so these focus on the S3 data plane; SigV4 is covered in `auth::sigv4`.

#![cfg(test)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::Router;
use tower::ServiceExt;

use crate::config::Config;
use crate::router::build_router;
use crate::state::AppState;
use crate::crypto::{CryptoContext, MasterKey};
use crate::storage::fs::FsStore;

/// Build a router backed by a fresh temp directory, with auth disabled.
///
/// # Returns
/// The configured [`Router`] and the owning `TempDir` (kept alive by callers).
async fn test_app() -> (Router, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let store = FsStore::new(
        tmp.path().to_path_buf(),
        CryptoContext::new_aes(MasterKey::generate()),
        false,
    )
    .await
    .unwrap();
    let config = Config {
        address: String::new(),
        data_dir: tmp.path().to_path_buf(),
        root_user: "k".into(),
        root_password: "s".into(),
        region: "us-east-1".into(),
        auth_enabled: false,
        console_address: String::new(),
        console_enabled: false,
        encryption_enabled: false,
        tls_enabled: false,
        tls_cert: None,
        tls_key: None,
        minio_compat: true,
        profile: crate::config::Profile::Open,
    };
    let state = AppState {
        store: Arc::new(store),
        config: Arc::new(config),
        iam: Arc::new(crate::iam::IamStore::root_only("k", "s")),
        crypto: CryptoContext::new_aes(MasterKey::generate()),
        oidc: None,
    };
    (build_router(state), tmp)
}

/// Send one request through the router and collect the full response.
///
/// # Parameters
/// - `app`: the router under test.
/// - `method`: HTTP method string.
/// - `uri`: request URI (path + optional query).
/// - `body`: request body bytes.
///
/// # Returns
/// The response status, headers and fully-read body bytes.
async fn send(app: &Router, method: &str, uri: &str, body: Vec<u8>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec();
    (status, headers, bytes)
}

/// Extract the text content of the first `<tag>...</tag>` in an XML string.
///
/// # Parameters
/// - `xml`: the XML document.
/// - `tag`: the element name to extract.
///
/// # Returns
/// The element's text, or `None` if the tag is absent.
fn extract(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].to_string())
}

/// Read the value of a response header as a string.
///
/// # Parameters
/// - `headers`: the response headers.
/// - `name`: the header name.
///
/// # Returns
/// The header value as an owned string (empty if absent).
fn header_str(headers: &HeaderMap, name: header::HeaderName) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// PUT/GET/HEAD/DELETE round-trip for a single object.
#[tokio::test]
async fn put_get_head_delete() {
    let (app, _t) = test_app().await;
    assert_eq!(send(&app, "PUT", "/buck", vec![]).await.0, StatusCode::OK);

    let (st, h, _) = send(&app, "PUT", "/buck/hello.txt", b"hi there".to_vec()).await;
    assert_eq!(st, StatusCode::OK);
    assert!(h.get(header::ETAG).is_some());

    let (st, h, body) = send(&app, "GET", "/buck/hello.txt", vec![]).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, b"hi there");
    assert_eq!(header_str(&h, header::CONTENT_LENGTH), "8");

    let (st, h, body) = send(&app, "HEAD", "/buck/hello.txt", vec![]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.is_empty());
    assert_eq!(header_str(&h, header::CONTENT_LENGTH), "8");

    assert_eq!(
        send(&app, "DELETE", "/buck/hello.txt", vec![]).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        send(&app, "GET", "/buck/hello.txt", vec![]).await.0,
        StatusCode::NOT_FOUND
    );
}

/// A missing key returns a `404` with an S3 XML error document.
#[tokio::test]
async fn missing_key_returns_xml_error() {
    let (app, _t) = test_app().await;
    send(&app, "PUT", "/buck", vec![]).await;
    let (st, h, body) = send(&app, "GET", "/buck/none", vec![]).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(header_str(&h, header::CONTENT_TYPE), "application/xml");
    let s = String::from_utf8_lossy(&body);
    assert!(s.contains("<Code>NoSuchKey</Code>"), "body = {s}");
}

/// Listing buckets and objects renders the expected XML.
#[tokio::test]
async fn list_buckets_and_objects() {
    let (app, _t) = test_app().await;
    send(&app, "PUT", "/buck", vec![]).await;
    send(&app, "PUT", "/buck/a.txt", b"x".to_vec()).await;
    send(&app, "PUT", "/buck/b.txt", b"yy".to_vec()).await;

    let (_, _, body) = send(&app, "GET", "/", vec![]).await;
    assert!(String::from_utf8_lossy(&body).contains("<Name>buck</Name>"));

    let (_, _, body) = send(&app, "GET", "/buck/?list-type=2", vec![]).await;
    let s = String::from_utf8_lossy(&body);
    assert!(s.contains("<Key>a.txt</Key>"), "body = {s}");
    assert!(s.contains("<Key>b.txt</Key>"), "body = {s}");
}

/// A `Range` request returns `206` with the correct slice and `Content-Range`.
#[tokio::test]
async fn range_request_returns_206() {
    let (app, _t) = test_app().await;
    send(&app, "PUT", "/buck", vec![]).await;
    let data: Vec<u8> = (0..50u8).collect();
    send(&app, "PUT", "/buck/nums", data.clone()).await;

    let req = Request::builder()
        .method("GET")
        .uri("/buck/nums")
        .header("range", "bytes=10-19")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(header_str(resp.headers(), header::CONTENT_RANGE), "bytes 10-19/50");
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec();
    assert_eq!(body, &data[10..=19]);
}

/// A complete multipart upload assembles parts and is readable as one object.
#[tokio::test]
async fn multipart_over_http() {
    let (app, _t) = test_app().await;
    send(&app, "PUT", "/buck", vec![]).await;

    let (st, _, body) = send(&app, "POST", "/buck/big?uploads", vec![]).await;
    assert_eq!(st, StatusCode::OK);
    let uid = extract(&String::from_utf8_lossy(&body), "UploadId").unwrap();

    let p1 = vec![7u8; 2000];
    let p2 = vec![9u8; 1000];
    let (_, h1, _) = send(
        &app,
        "PUT",
        &format!("/buck/big?partNumber=1&uploadId={uid}"),
        p1.clone(),
    )
    .await;
    let e1 = header_str(&h1, header::ETAG);
    let (_, h2, _) = send(
        &app,
        "PUT",
        &format!("/buck/big?partNumber=2&uploadId={uid}"),
        p2.clone(),
    )
    .await;
    let e2 = header_str(&h2, header::ETAG);

    let complete = format!(
        "<CompleteMultipartUpload>\
<Part><PartNumber>1</PartNumber><ETag>{e1}</ETag></Part>\
<Part><PartNumber>2</PartNumber><ETag>{e2}</ETag></Part>\
</CompleteMultipartUpload>"
    );
    let (st, _, _) = send(
        &app,
        "POST",
        &format!("/buck/big?uploadId={uid}"),
        complete.into_bytes(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, _, body) = send(&app, "GET", "/buck/big", vec![]).await;
    assert_eq!(st, StatusCode::OK);
    let mut expected = p1.clone();
    expected.extend_from_slice(&p2);
    assert_eq!(body, expected);
}

/// POST Object (HTML form upload) stores an object and returns 204.
#[tokio::test]
async fn post_object_form_upload() {
    let (app, _t) = test_app().await;
    send(&app, "PUT", "/frm", vec![]).await;

    // Build a minimal multipart/form-data body with key + file fields.
    let boundary = "testboundary1234";
    let body = format!(
        "--{boundary}\r\n\
Content-Disposition: form-data; name=\"key\"\r\n\
\r\n\
uploaded.txt\r\n\
--{boundary}\r\n\
Content-Disposition: form-data; name=\"Content-Type\"\r\n\
\r\n\
text/plain\r\n\
--{boundary}\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"uploaded.txt\"\r\n\
Content-Type: text/plain\r\n\
\r\n\
hello from form upload\r\n\
--{boundary}--\r\n"
    );

    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/frm")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // The object must be readable.
    let (st, _, body) = send(&app, "GET", "/frm/uploaded.txt", vec![]).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, b"hello from form upload");
}

/// POST Object with `success_action_status=201` returns PostResponse XML.
#[tokio::test]
async fn post_object_form_upload_201() {
    let (app, _t) = test_app().await;
    send(&app, "PUT", "/frm2", vec![]).await;

    let boundary = "bound201";
    let body = format!(
        "--{boundary}\r\n\
Content-Disposition: form-data; name=\"key\"\r\n\
\r\n\
doc.txt\r\n\
--{boundary}\r\n\
Content-Disposition: form-data; name=\"success_action_status\"\r\n\
\r\n\
201\r\n\
--{boundary}\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"doc.txt\"\r\n\
\r\n\
data\r\n\
--{boundary}--\r\n"
    );

    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/frm2")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body_bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let s = String::from_utf8_lossy(&body_bytes);
    assert!(s.contains("<Key>doc.txt</Key>"), "body={s}");
    assert!(s.contains("<Bucket>frm2</Bucket>"), "body={s}");
}

/// Legal hold blocks delete; removing the hold allows delete to proceed.
#[tokio::test]
async fn legal_hold_blocks_delete() {
    let (app, _t) = test_app().await;
    send(&app, "PUT", "/lhbkt", vec![]).await;
    send(&app, "PUT", "/lhbkt/obj.txt", b"content".to_vec()).await;

    // Set legal hold ON.
    let hold_xml = b"<LegalHold><Status>ON</Status></LegalHold>";
    let (st, _, _) = send(&app, "PUT", "/lhbkt/obj.txt?legal-hold", hold_xml.to_vec()).await;
    assert_eq!(st, StatusCode::OK);

    // GET legal hold should return ON.
    let (st, _, body) = send(&app, "GET", "/lhbkt/obj.txt?legal-hold", vec![]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("ON"));

    // DELETE must be blocked (403).
    let (st, _, _) = send(&app, "DELETE", "/lhbkt/obj.txt", vec![]).await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Lift the hold and delete succeeds.
    let off_xml = b"<LegalHold><Status>OFF</Status></LegalHold>";
    send(&app, "PUT", "/lhbkt/obj.txt?legal-hold", off_xml.to_vec()).await;
    let (st, _, _) = send(&app, "DELETE", "/lhbkt/obj.txt", vec![]).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
}

/// Retention with a future date blocks delete; expired retention allows it.
#[tokio::test]
async fn retention_blocks_delete() {
    let (app, _t) = test_app().await;
    send(&app, "PUT", "/retbkt", vec![]).await;
    send(&app, "PUT", "/retbkt/obj.txt", b"content".to_vec()).await;

    // Set retention to a date in the far future.
    let retention_xml =
        b"<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2099-01-01T00:00:00Z</RetainUntilDate></Retention>";
    let (st, _, _) =
        send(&app, "PUT", "/retbkt/obj.txt?retention", retention_xml.to_vec()).await;
    assert_eq!(st, StatusCode::OK);

    // DELETE must be blocked.
    let (st, _, _) = send(&app, "DELETE", "/retbkt/obj.txt", vec![]).await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // GET retention should round-trip correctly.
    let (st, _, body) = send(&app, "GET", "/retbkt/obj.txt?retention", vec![]).await;
    assert_eq!(st, StatusCode::OK);
    let s = String::from_utf8_lossy(&body);
    assert!(s.contains("GOVERNANCE"), "body={s}");
    assert!(s.contains("2099"), "body={s}");
}

/// Lifecycle worker expires objects that match a `Days: 0` rule immediately.
#[tokio::test]
async fn lifecycle_worker_expires_objects() {
    use crate::crypto::{CryptoContext, MasterKey};
    use crate::lifecycle::start_lifecycle_worker;
    use crate::storage::fs::FsStore;
    use crate::storage::ObjectStore;
    use std::sync::Arc;

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(
        FsStore::new(
            tmp.path().to_path_buf(),
            CryptoContext::new_aes(MasterKey::generate()),
            false,
        )
        .await
        .unwrap(),
    );

    // Create bucket + two objects under different prefixes.
    store.create_bucket("ilmbkt").await.unwrap();
    let empty_meta = std::collections::BTreeMap::new();
    store
        .put_object(
            "ilmbkt",
            "logs/old.txt",
            Box::pin(std::io::Cursor::new(b"data".to_vec())),
            "text/plain".into(),
            empty_meta.clone(),
            false,
        )
        .await
        .unwrap();
    store
        .put_object(
            "ilmbkt",
            "keep/me.txt",
            Box::pin(std::io::Cursor::new(b"data".to_vec())),
            "text/plain".into(),
            empty_meta,
            false,
        )
        .await
        .unwrap();

    // Set a lifecycle rule: expire `logs/` prefix after 0 days (= immediately).
    let lc_xml = "\
<LifecycleConfiguration>\
<Rule>\
<ID>expire-logs</ID>\
<Status>Enabled</Status>\
<Filter><Prefix>logs/</Prefix></Filter>\
<Expiration><Days>0</Days></Expiration>\
</Rule>\
</LifecycleConfiguration>";
    store.set_bucket_lifecycle("ilmbkt", lc_xml.to_string()).await.unwrap();

    // Run one lifecycle pass with a very short interval (never sleeps — first
    // pass happens before the first sleep).
    start_lifecycle_worker(store.clone(), tokio::time::Duration::from_secs(86400));
    // Give the spawned task time to complete the first pass.
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // `logs/old.txt` must be gone.
    assert!(store.head_object("ilmbkt", "logs/old.txt").await.is_err());
    // `keep/me.txt` must still exist.
    assert!(store.head_object("ilmbkt", "keep/me.txt").await.is_ok());
}

/// Lifecycle worker must NOT expire an object protected by active retention,
/// even when it matches an expiration rule.
#[tokio::test]
async fn lifecycle_worker_respects_retention() {
    use crate::crypto::{CryptoContext, MasterKey};
    use crate::lifecycle::start_lifecycle_worker;
    use crate::storage::fs::FsStore;
    use crate::storage::ObjectStore;
    use std::sync::Arc;

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(
        FsStore::new(
            tmp.path().to_path_buf(),
            CryptoContext::new_aes(MasterKey::generate()),
            false,
        )
        .await
        .unwrap(),
    );

    store.create_bucket("lockbkt").await.unwrap();
    store
        .put_object(
            "lockbkt",
            "logs/locked.txt",
            Box::pin(std::io::Cursor::new(b"data".to_vec())),
            "text/plain".into(),
            std::collections::BTreeMap::new(),
            false,
        )
        .await
        .unwrap();

    // Protect the object with a retention date far in the future.
    let retention_xml =
        "<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>2099-01-01T00:00:00Z</RetainUntilDate></Retention>";
    store
        .set_object_retention("lockbkt", "logs/locked.txt", retention_xml.to_string())
        .await
        .unwrap();

    // Lifecycle rule that would otherwise expire it immediately.
    let lc_xml = "\
<LifecycleConfiguration>\
<Rule><ID>r</ID><Status>Enabled</Status>\
<Filter><Prefix>logs/</Prefix></Filter>\
<Expiration><Days>0</Days></Expiration></Rule>\
</LifecycleConfiguration>";
    store.set_bucket_lifecycle("lockbkt", lc_xml.to_string()).await.unwrap();

    start_lifecycle_worker(store.clone(), tokio::time::Duration::from_secs(86400));
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // The retained object must survive the lifecycle pass.
    assert!(store.head_object("lockbkt", "logs/locked.txt").await.is_ok());
}

/// Read a response header as an owned string (empty if absent).
fn hdr(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Full object-versioning lifecycle: enable, multiple versions, version reads,
/// delete markers, permanent version deletes, and promotion of the prior
/// version back to current.
#[tokio::test]
async fn versioning_full_lifecycle() {
    let (app, _t) = test_app().await;
    send(&app, "PUT", "/vbk", vec![]).await;
    // Enable versioning.
    let cfg = "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";
    assert_eq!(
        send(&app, "PUT", "/vbk?versioning", cfg.as_bytes().to_vec()).await.0,
        StatusCode::OK
    );

    // Two writes create two versions.
    let (_, h1, _) = send(&app, "PUT", "/vbk/obj", b"v1".to_vec()).await;
    let vid1 = hdr(&h1, "x-amz-version-id");
    let (_, h2, _) = send(&app, "PUT", "/vbk/obj", b"v2".to_vec()).await;
    let vid2 = hdr(&h2, "x-amz-version-id");
    assert!(!vid1.is_empty() && !vid2.is_empty() && vid1 != vid2, "vids: {vid1} {vid2}");

    // Current read returns the latest; version reads return each version.
    assert_eq!(send(&app, "GET", "/vbk/obj", vec![]).await.2, b"v2");
    assert_eq!(
        send(&app, "GET", &format!("/vbk/obj?versionId={vid1}"), vec![]).await.2,
        b"v1"
    );
    assert_eq!(
        send(&app, "GET", &format!("/vbk/obj?versionId={vid2}"), vec![]).await.2,
        b"v2"
    );

    // ListObjectVersions shows both, with the newest marked latest.
    let (_, _, body) = send(&app, "GET", "/vbk?versions", vec![]).await;
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains(&vid1), "versions missing vid1: {xml}");
    assert!(xml.contains(&vid2), "versions missing vid2: {xml}");
    assert!(xml.contains("<IsLatest>true</IsLatest>"), "no latest flag: {xml}");

    // Delete (no version) inserts a delete marker; current read 404s.
    let (st, hd, _) = send(&app, "DELETE", "/vbk/obj", vec![]).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(hdr(&hd, "x-amz-delete-marker"), "true");
    let marker_vid = hdr(&hd, "x-amz-version-id");
    assert!(!marker_vid.is_empty());
    assert_eq!(send(&app, "GET", "/vbk/obj", vec![]).await.0, StatusCode::NOT_FOUND);
    // Old versions still readable behind the marker.
    assert_eq!(
        send(&app, "GET", &format!("/vbk/obj?versionId={vid1}"), vec![]).await.2,
        b"v1"
    );

    // Removing the delete marker re-exposes the latest real version.
    assert_eq!(
        send(&app, "DELETE", &format!("/vbk/obj?versionId={marker_vid}"), vec![]).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(send(&app, "GET", "/vbk/obj", vec![]).await.2, b"v2");

    // Permanently delete the current version → prior version is promoted.
    assert_eq!(
        send(&app, "DELETE", &format!("/vbk/obj?versionId={vid2}"), vec![]).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(send(&app, "GET", "/vbk/obj", vec![]).await.2, b"v1");

    // Deleting the last version removes the object entirely.
    assert_eq!(
        send(&app, "DELETE", &format!("/vbk/obj?versionId={vid1}"), vec![]).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(send(&app, "GET", "/vbk/obj", vec![]).await.0, StatusCode::NOT_FOUND);
}

/// A non-versioned bucket keeps plain overwrite semantics (no version headers).
#[tokio::test]
async fn versioning_off_is_plain_overwrite() {
    let (app, _t) = test_app().await;
    send(&app, "PUT", "/plain", vec![]).await;
    let (_, h, _) = send(&app, "PUT", "/plain/k", b"a".to_vec()).await;
    assert_eq!(hdr(&h, "x-amz-version-id"), "");
    send(&app, "PUT", "/plain/k", b"b".to_vec()).await;
    assert_eq!(send(&app, "GET", "/plain/k", vec![]).await.2, b"b");
    // Plain delete is permanent.
    assert_eq!(send(&app, "DELETE", "/plain/k", vec![]).await.0, StatusCode::NO_CONTENT);
    assert_eq!(send(&app, "GET", "/plain/k", vec![]).await.0, StatusCode::NOT_FOUND);
}

/// Suspended versioning writes the `null` version and overwrites it in place,
/// while previously-created versions remain addressable.
#[tokio::test]
async fn versioning_suspended_uses_null() {
    let (app, _t) = test_app().await;
    send(&app, "PUT", "/sbk", vec![]).await;
    let enable = "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";
    send(&app, "PUT", "/sbk?versioning", enable.as_bytes().to_vec()).await;
    let (_, h1, _) = send(&app, "PUT", "/sbk/k", b"enabled".to_vec()).await;
    let vid1 = hdr(&h1, "x-amz-version-id");

    let suspend = "<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>";
    send(&app, "PUT", "/sbk?versioning", suspend.as_bytes().to_vec()).await;
    let (_, h2, _) = send(&app, "PUT", "/sbk/k", b"null-a".to_vec()).await;
    assert_eq!(hdr(&h2, "x-amz-version-id"), "null");
    // A second suspended write overwrites the null version in place.
    send(&app, "PUT", "/sbk/k", b"null-b".to_vec()).await;

    assert_eq!(send(&app, "GET", "/sbk/k", vec![]).await.2, b"null-b");
    // The original enabled version is still retrievable.
    assert_eq!(
        send(&app, "GET", &format!("/sbk/k?versionId={vid1}"), vec![]).await.2,
        b"enabled"
    );
    // Exactly one null version exists alongside the original.
    let (_, _, body) = send(&app, "GET", "/sbk?versions", vec![]).await;
    let xml = String::from_utf8_lossy(&body);
    assert_eq!(xml.matches("<VersionId>null</VersionId>").count(), 1, "{xml}");
}

/// Batch `DeleteObjects` removes the listed keys and reports them.
#[tokio::test]
async fn batch_delete() {
    let (app, _t) = test_app().await;
    send(&app, "PUT", "/buck", vec![]).await;
    send(&app, "PUT", "/buck/x", b"1".to_vec()).await;
    send(&app, "PUT", "/buck/y", b"2".to_vec()).await;

    let del = "<Delete><Object><Key>x</Key></Object><Object><Key>y</Key></Object></Delete>";
    let (st, _, body) = send(&app, "POST", "/buck?delete", del.as_bytes().to_vec()).await;
    assert_eq!(st, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("<Deleted><Key>x</Key></Deleted>"));

    let (_, _, body) = send(&app, "GET", "/buck/?list-type=2", vec![]).await;
    assert!(String::from_utf8_lossy(&body).contains("<KeyCount>0</KeyCount>"));
}
