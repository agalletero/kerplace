//! Console SSO login via OIDC (D1, authorization-code flow).
//!
//! `GET /api/oidc/login` redirects the browser to the IdP; the IdP redirects back
//! to `GET /api/oidc/callback`, which exchanges the code, validates the ID token,
//! and — for a user in the console admin group — issues a normal console session
//! token (handed to the SPA via the URL fragment, which servers never see).
//!
//! CSRF/replay protection is **stateless**: the login `nonce` is HMAC-signed with
//! the console secret into the OAuth `state`, so the callback can trust the
//! IdP-echoed `state` and bind the token's `nonce` without any server-side store.

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;

use super::auth::{issue_token, now_secs};
use crate::iam::Policy;
use crate::state::AppState;

type HmacSha256 = Hmac<Sha256>;

/// Bind a login `nonce` into a signed OAuth `state` (`"<nonce>.<hmac>"`).
///
/// # Parameters
/// - `secret`: the console signing secret (root password).
/// - `nonce`: the per-login random nonce.
///
/// # Returns
/// The signed state string to send to the IdP.
fn sign_state(secret: &str, nonce: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    mac.update(nonce.as_bytes());
    format!("{nonce}.{}", hex::encode(mac.finalize().into_bytes()))
}

/// Verify an IdP-echoed `state` and recover the nonce it carries.
///
/// # Parameters
/// - `secret`: the console signing secret.
/// - `state`: the `state` returned by the IdP.
///
/// # Returns
/// `Some(nonce)` if the signature is valid, else `None`.
fn verify_state(secret: &str, state: &str) -> Option<String> {
    let (nonce, _sig) = state.split_once('.')?;
    if sign_state(secret, nonce) == state {
        Some(nonce.to_string())
    } else {
        None
    }
}

/// `GET /api/oidc/enabled` — public probe so the (logged-out) login screen can
/// reveal the "Sign in with SSO" button only when OIDC is configured.
///
/// # Parameters
/// - `st`: app state.
///
/// # Returns
/// `{ "enabled": bool }`.
pub async fn enabled(State(st): State<AppState>) -> Response {
    axum::Json(serde_json::json!({ "enabled": st.oidc.is_some() })).into_response()
}

/// `GET /api/oidc/login` — redirect to the IdP authorize endpoint.
///
/// # Parameters
/// - `st`: app state (the OIDC client + console secret).
///
/// # Returns
/// A `307` redirect to the IdP, or `404` if OIDC is disabled.
pub async fn login(State(st): State<AppState>) -> Response {
    let Some(oidc) = st.oidc.as_ref() else {
        return (StatusCode::NOT_FOUND, "OIDC is not enabled").into_response();
    };
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    let nonce = hex::encode(buf);
    let state = sign_state(&st.config.root_password, &nonce);
    Redirect::temporary(&oidc.authorize_url(&state, &nonce)).into_response()
}

/// `GET /api/oidc/callback?code=&state=` — validate and start a console session.
///
/// # Parameters
/// - `st`: app state.
/// - `q`: query parameters (`code`, `state`, or an IdP `error`).
///
/// # Returns
/// A redirect to the console with the session token in the URL fragment, or an
/// error status (`400` bad state, `401` invalid token, `403` not an admin,
/// `502` IdP error).
pub async fn callback(State(st): State<AppState>, Query(q): Query<HashMap<String, String>>) -> Response {
    let Some(oidc) = st.oidc.as_ref() else {
        return (StatusCode::NOT_FOUND, "OIDC is not enabled").into_response();
    };
    if let Some(err) = q.get("error") {
        return (StatusCode::UNAUTHORIZED, format!("IdP returned error: {err}")).into_response();
    }
    let (Some(code), Some(state)) = (q.get("code"), q.get("state")) else {
        return (StatusCode::BAD_REQUEST, "missing code/state").into_response();
    };
    let Some(nonce) = verify_state(&st.config.root_password, state) else {
        return (StatusCode::BAD_REQUEST, "invalid OAuth state").into_response();
    };
    let id_token = match oidc.exchange_code(code).await {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("OIDC token exchange failed: {e}")).into_response(),
    };
    let claims = match oidc.validate(&id_token, Some(&nonce)) {
        Ok(c) => c,
        Err(e) => return (StatusCode::UNAUTHORIZED, format!("OIDC token rejected: {e}")).into_response(),
    };
    // The console is an admin tool: require the mapped admin policy.
    if oidc.policy_for(&claims) != Policy::Admin {
        return (
            StatusCode::FORBIDDEN,
            format!("user `{}` is not in the console admin group", claims.username),
        )
            .into_response();
    }
    let token = issue_token(&st.config.root_password, now_secs());
    // Deliver the session token via the URL fragment: it is not sent in the
    // request line, Referer, or server logs. The SPA reads it on load.
    Redirect::temporary(&format!("/#token={token}")).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A signed state round-trips; tampering or a wrong secret is rejected.
    #[test]
    fn state_signing_roundtrips_and_rejects_tampering() {
        let s = sign_state("sekret", "abc123");
        assert_eq!(verify_state("sekret", &s), Some("abc123".to_string()));
        assert_eq!(verify_state("other", &s), None, "wrong secret must fail");
        assert_eq!(verify_state("sekret", "abc123.deadbeef"), None, "forged sig must fail");
        assert_eq!(verify_state("sekret", "no-dot"), None);
    }
}
