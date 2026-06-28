//! AWS STS `AssumeRoleWithWebIdentity` (D1): exchange a validated OIDC ID token
//! for **temporary S3 credentials**.
//!
//! Served at `POST /` (the AWS STS convention of posting `Action=…` to the service
//! endpoint root) and authenticated by the `WebIdentityToken` itself — there is no
//! SigV4 on this request, since its whole purpose is to *issue* a credential. The
//! returned access/secret pair is an ephemeral [`crate::iam`] credential carrying
//! the policy mapped from the token's groups; `mc`/`aws` then sign normal S3
//! requests with it.

use std::collections::HashMap;

use axum::extract::{Form, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::state::AppState;

/// `POST /` — dispatch by the `Action` form parameter (STS lives at the root).
///
/// # Parameters
/// - `st`: app state (OIDC client + IAM).
/// - `params`: the form-encoded request parameters.
///
/// # Returns
/// The STS XML response, or an STS-style XML error.
pub async fn dispatch(State(st): State<AppState>, Form(params): Form<HashMap<String, String>>) -> Response {
    match params.get("Action").map(|s| s.as_str()) {
        Some("AssumeRoleWithWebIdentity") => assume_role_with_web_identity(st, params).await,
        Some(other) => sts_error(
            StatusCode::BAD_REQUEST,
            "InvalidAction",
            &format!("unsupported STS action `{other}`"),
        ),
        None => sts_error(StatusCode::BAD_REQUEST, "MissingAction", "missing Action parameter"),
    }
}

/// Validate the presented OIDC token and mint temporary credentials.
///
/// # Parameters
/// - `st`: app state.
/// - `params`: form params (`WebIdentityToken`, optional `DurationSeconds`).
///
/// # Returns
/// STS XML with temporary `Credentials`, or an STS error (`403` rejected token,
/// `400` bad params, `501` OIDC disabled).
async fn assume_role_with_web_identity(st: AppState, params: HashMap<String, String>) -> Response {
    let Some(oidc) = st.oidc.as_ref() else {
        return sts_error(
            StatusCode::NOT_IMPLEMENTED,
            "STSNotEnabled",
            "OIDC is not configured (set KP_OIDC_ISSUER)",
        );
    };
    let Some(token) = params.get("WebIdentityToken") else {
        return sts_error(StatusCode::BAD_REQUEST, "InvalidParameterValue", "WebIdentityToken is required");
    };
    let claims = match oidc.validate(token, None) {
        Ok(c) => c,
        Err(e) => return sts_error(StatusCode::FORBIDDEN, "AccessDenied", &format!("token rejected: {e}")),
    };
    let policy = oidc.policy_for(&claims);
    let duration = params
        .get("DurationSeconds")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(3600)
        .clamp(900, 43200);
    let (access_key, secret_key, expiry) = st.iam.issue_temp(policy, duration);
    let session_token = format!("KPSTSTOKEN.{access_key}");
    let exp_iso = OffsetDateTime::from_unix_timestamp(expiry)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_default();

    tracing::info!(
        subject = %claims.subject,
        policy = policy.name(),
        access_key = %access_key,
        "STS issued temporary credentials via OIDC"
    );

    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <SubjectFromWebIdentityToken>{sub}</SubjectFromWebIdentityToken>
    <Credentials>
      <AccessKeyId>{ak}</AccessKeyId>
      <SecretAccessKey>{sk}</SecretAccessKey>
      <SessionToken>{stoken}</SessionToken>
      <Expiration>{exp}</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata><RequestId>kerplace</RequestId></ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>"#,
        sub = xml_escape(&claims.subject),
        ak = access_key,
        sk = secret_key,
        stoken = session_token,
        exp = exp_iso,
    );
    ([(header::CONTENT_TYPE, "application/xml")], body).into_response()
}

/// Build an STS-style XML error response.
fn sts_error(status: StatusCode, code: &str, message: &str) -> Response {
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error><Type>Sender</Type><Code>{code}</Code><Message>{msg}</Message></Error>
  <RequestId>kerplace</RequestId>
</ErrorResponse>"#,
        code = code,
        msg = xml_escape(message),
    );
    (status, [(header::CONTENT_TYPE, "application/xml")], body).into_response()
}

/// Minimal XML text escaping for the few interpolated values.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}
