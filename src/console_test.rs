//! Integration tests for the web-console JSON API, driving the console router
//! end-to-end (login → bucket settings → versioning → users) via `oneshot`.

#![cfg(test)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::Router;
use tower::ServiceExt;

use crate::config::Config;
use crate::console;
use crate::crypto::{CryptoContext, MasterKey};
use crate::iam::IamStore;
use crate::state::AppState;
use crate::storage::fs::FsStore;

/// Build the console router backed by a fresh temp dir, with root `k`/`s` and no
/// OIDC configured.
///
/// # Returns
/// The console [`Router`] and the owning `TempDir`.
async fn console_app() -> (Router, tempfile::TempDir) {
    build_app(None).await
}

/// Build the console router with an optional OIDC client wired in.
///
/// # Parameters
/// - `oidc`: the external identity provider, or `None` to disable SSO.
///
/// # Returns
/// The console [`Router`] and the owning `TempDir`.
async fn build_app(oidc: Option<Arc<crate::auth::oidc::Oidc>>) -> (Router, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let store = FsStore::new(
        tmp.path().to_path_buf(),
        CryptoContext::new_aes(MasterKey::generate()),
        false,
    )
    .await
    .unwrap();
    let config = Config {
        address: "127.0.0.1:9000".into(),
        data_dir: tmp.path().to_path_buf(),
        root_user: "k".into(),
        root_password: "s".into(),
        region: "us-east-1".into(),
        auth_enabled: true,
        console_address: String::new(),
        console_enabled: true,
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
        iam: Arc::new(IamStore::root_only("k", "s")),
        crypto: CryptoContext::new_aes(MasterKey::generate()),
        oidc,
    };
    (console::build_router(state), tmp)
}

/// Send a JSON request through the console router and return status + body text.
async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> (StatusCode, String) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let req = builder
        .body(body.map(|b| Body::from(b.to_string())).unwrap_or(Body::empty()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Login yields a token; the console manages bucket settings and users with it.
#[tokio::test]
async fn console_settings_and_users_flow() {
    let (app, _t) = console_app().await;

    // Unauthenticated access is rejected.
    assert_eq!(send(&app, "GET", "/api/buckets", None, None).await.0, StatusCode::UNAUTHORIZED);

    // Login as root → token.
    let (st, body) = send(
        &app,
        "POST",
        "/api/login",
        None,
        Some(r#"{"accessKey":"k","secretKey":"s"}"#),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let token = body
        .split("\"token\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap()
        .to_string();

    // Info exposes capability flags.
    let (_, info) = send(&app, "GET", "/api/info", Some(&token), None).await;
    assert!(info.contains("\"postQuantum\":true"), "info={info}");

    // Storage surfaces the at-rest key-custody posture honestly (K1).
    let (st, storage) = send(&app, "GET", "/api/storage", Some(&token), None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(storage.contains("\"keyProvider\":\"file\""), "storage={storage}");
    assert!(storage.contains("\"doesNotProtect\""), "posture must be honest: {storage}");

    // Create a bucket, enable versioning + encryption, read them back.
    assert_eq!(
        send(&app, "POST", "/api/buckets", Some(&token), Some(r#"{"name":"cbk"}"#)).await.0,
        StatusCode::OK
    );
    assert_eq!(
        send(&app, "PUT", "/api/buckets/cbk/versioning", Some(&token), Some(r#"{"status":"Enabled"}"#))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        send(&app, "PUT", "/api/buckets/cbk/encryption", Some(&token), Some(r#"{"enabled":true}"#))
            .await
            .0,
        StatusCode::OK
    );
    let (_, settings) = send(&app, "GET", "/api/buckets/cbk/settings", Some(&token), None).await;
    assert!(settings.contains("\"versioning\":\"Enabled\""), "settings={settings}");
    assert!(settings.contains("\"encryption\":\"AES256\""), "settings={settings}");

    // Add a user, list it, disable it.
    assert_eq!(
        send(
            &app,
            "POST",
            "/api/users",
            Some(&token),
            Some(r#"{"accessKey":"u1","secretKey":"u1secret","policy":"readonly"}"#),
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, users) = send(&app, "GET", "/api/users", Some(&token), None).await;
    assert!(users.contains("\"accessKey\":\"u1\""), "users={users}");
    assert!(users.contains("\"policy\":\"readonly\""), "users={users}");
    assert_eq!(
        send(&app, "POST", "/api/users/u1/status", Some(&token), Some(r#"{"enabled":false}"#)).await.0,
        StatusCode::OK
    );
    let (_, users2) = send(&app, "GET", "/api/users", Some(&token), None).await;
    assert!(users2.contains("\"accessKey\":\"u1\",\"enabled\":false") || users2.contains("\"enabled\":false"));
}

/// Regression: a console upload to a bucket with per-bucket SSE must be
/// encrypted at rest (the on-disk payload is a `KPE1` container), not stored
/// in plaintext just because the global `KP_ENCRYPT` flag is off.
#[tokio::test]
async fn console_upload_honours_bucket_sse() {
    let (app, tmp) = console_app().await;

    let (_, body) = send(&app, "POST", "/api/login", None, Some(r#"{"accessKey":"k","secretKey":"s"}"#)).await;
    let token = body.split("\"token\":\"").nth(1).and_then(|s| s.split('"').next()).unwrap().to_string();

    // Create an encrypted bucket and upload an object through the console.
    send(&app, "POST", "/api/buckets", Some(&token), Some(r#"{"name":"encbk"}"#)).await;
    assert_eq!(
        send(&app, "PUT", "/api/buckets/encbk/encryption", Some(&token), Some(r#"{"enabled":true}"#)).await.0,
        StatusCode::OK
    );
    assert_eq!(
        send(&app, "PUT", "/api/buckets/encbk/objects/secret.txt", Some(&token), Some("PLAINTEXT-SECRET")).await.0,
        StatusCode::OK
    );

    // The on-disk payload must be a KPE1 ciphertext container, not the plaintext.
    let raw = std::fs::read(tmp.path().join("encbk").join("secret.txt")).unwrap();
    assert_eq!(&raw[..4], b"KPE\x01", "console upload to SSE bucket was not encrypted at rest");
    assert!(!raw.windows(9).any(|w| w == b"PLAINTEXT"), "plaintext leaked to disk");
}

// ── OIDC console SSO (D1) — full callback flow against an in-process fake IdP ──

use crate::auth::oidc::testsupport;

/// GET a URL and return the status + the `Location` header (for redirects).
async fn get_loc(app: &Router, uri: &str, token: Option<&str>) -> (StatusCode, String) {
    let mut b = Request::builder().method("GET").uri(uri);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    let resp = app.clone().oneshot(b.body(Body::empty()).unwrap()).await.unwrap();
    let status = resp.status();
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    (status, loc)
}

/// Extract a (percent-decoded) query parameter from a URL.
fn query_param(url: &str, key: &str) -> String {
    let q = url.split_once('?').map(|x| x.1).unwrap_or("");
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return percent_encoding::percent_decode_str(v).decode_utf8_lossy().into_owned();
            }
        }
    }
    String::new()
}

/// Percent-encode a value for placing into a URL query.
fn enc(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

/// Drive `/api/oidc/login` and return the `(state, nonce)` it minted.
async fn start_login(app: &Router) -> (String, String) {
    let (st, loc) = get_loc(app, "/api/oidc/login", None).await;
    assert_eq!(st, StatusCode::TEMPORARY_REDIRECT, "login should redirect to the IdP");
    (query_param(&loc, "state"), query_param(&loc, "nonce"))
}

/// The whole console SSO flow: login → callback (fake IdP token exchange +
/// validation) → a working console session; and a non-admin user is rejected.
#[tokio::test]
async fn oidc_console_login_full_flow() {
    let oidc = std::sync::Arc::new(testsupport::fake_oidc().await);
    let (app, _t) = build_app(Some(oidc)).await;

    // The login screen can discover that SSO is on.
    let (st, body) = send(&app, "GET", "/api/oidc/enabled", None, None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("\"enabled\":true"), "enabled probe: {body}");

    // Admin user: login → callback issues a session token via the URL fragment.
    let (state, nonce) = start_login(&app).await;
    // Convention: the fake token endpoint treats the `code` as the nonce to embed.
    let cb = format!("/api/oidc/callback?code={}&state={}", enc(&nonce), enc(&state));
    let (st, loc) = get_loc(&app, &cb, None).await;
    assert_eq!(st, StatusCode::TEMPORARY_REDIRECT, "callback should redirect to the SPA");
    assert!(loc.starts_with("/#token="), "session token must come back in the fragment: {loc}");
    let session = loc.trim_start_matches("/#token=").to_string();
    assert!(!session.is_empty());

    // The issued session token authenticates a real (auth-gated) console request.
    let (st, _) = send(&app, "GET", "/api/buckets", Some(&session), None).await;
    assert_eq!(st, StatusCode::OK, "the OIDC-issued session must be accepted");

    // Non-admin user (`:readonly` makes the fake mint a no-groups token) is denied
    // the (admin-only) console.
    let (state2, nonce2) = start_login(&app).await;
    let cb2 = format!(
        "/api/oidc/callback?code={}&state={}",
        enc(&format!("{nonce2}:readonly")),
        enc(&state2)
    );
    let (st, _) = get_loc(&app, &cb2, None).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "a non-admin SSO user must not get console access");
}

/// The callback rejects malformed/forged requests before touching the IdP.
#[tokio::test]
async fn oidc_console_callback_rejects_bad_requests() {
    let oidc = std::sync::Arc::new(testsupport::fake_oidc().await);
    let (app, _t) = build_app(Some(oidc)).await;

    // An IdP-reported error.
    let (st, _) = get_loc(&app, "/api/oidc/callback?error=access_denied", None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // Missing code/state.
    let (st, _) = get_loc(&app, "/api/oidc/callback", None).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // A forged state (bad HMAC) is rejected without any token exchange.
    let (st, _) = get_loc(&app, "/api/oidc/callback?code=x&state=forged.deadbeef", None).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

/// With OIDC disabled, the SSO endpoints are inert.
#[tokio::test]
async fn oidc_disabled_endpoints_are_inert() {
    let (app, _t) = console_app().await; // oidc: None
    let (_, body) = send(&app, "GET", "/api/oidc/enabled", None, None).await;
    assert!(body.contains("\"enabled\":false"), "enabled probe: {body}");
    let (st, _) = get_loc(&app, "/api/oidc/login", None).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = get_loc(&app, "/api/oidc/callback?code=x&state=y", None).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}
