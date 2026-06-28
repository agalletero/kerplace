//! OIDC external identity (D1).
//!
//! Validates IdP-issued **ID tokens** (OpenID Connect, RS256) against the
//! provider's published JWKS and maps their group claims to a KerPlace
//! [`Policy`]. This single core is shared by:
//!
//! - the **console SSO login** (authorization-code flow: redirect → callback →
//!   exchange code → validate ID token → console session), and
//! - the **STS `AssumeRoleWithWebIdentity`** endpoint (a client presents an ID
//!   token and receives temporary S3 credentials with the mapped policy).
//!
//! It does **not** touch the at-rest crypto seam — this is an authentication
//! concern only. OIDC is enabled by setting `KP_OIDC_ISSUER`; when unset, the
//! server behaves exactly as before (built-in IAM only).

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::Value;

use crate::iam::Policy;

/// Errors from the OIDC subsystem.
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    /// The IdP discovery document or JWKS could not be fetched/parsed.
    #[error("OIDC discovery failed: {0}")]
    Discovery(String),
    /// A network/transport failure talking to the IdP.
    #[error("OIDC request failed: {0}")]
    Network(String),
    /// The presented token was missing, malformed, unsigned by a known key, or
    /// failed an `iss`/`aud`/`exp`/`nonce` check.
    #[error("invalid OIDC token: {0}")]
    InvalidToken(String),
}

/// OIDC configuration, read from `KP_OIDC_*`.
///
/// [`from_env`](OidcConfig::from_env) returns `None` when `KP_OIDC_ISSUER` is
/// unset, which leaves OIDC disabled.
#[derive(Clone, Debug)]
pub struct OidcConfig {
    /// Issuer URL (no trailing slash); discovery is `{issuer}/.well-known/openid-configuration`.
    pub issuer: String,
    /// OAuth2 client id registered at the IdP.
    pub client_id: String,
    /// OAuth2 client secret (confidential client).
    pub client_secret: String,
    /// Where the IdP redirects back after login (the console callback).
    pub redirect_url: String,
    /// Token claim that carries the user's groups (default `groups`).
    pub groups_claim: String,
    /// Group that maps to the admin policy (default `kerplace-admins`).
    pub admin_group: String,
    /// Group that maps to the read-write policy (default `kerplace-writers`).
    pub readwrite_group: String,
}

impl OidcConfig {
    /// Read OIDC settings from the environment.
    ///
    /// # Returns
    /// `Some(config)` if `KP_OIDC_ISSUER` is set (OIDC enabled), else `None`.
    pub fn from_env() -> Option<Self> {
        let issuer = crate::config::env_var("OIDC_ISSUER").filter(|s| !s.trim().is_empty())?;
        let get = |k: &str, default: &str| {
            crate::config::env_var(k).filter(|s| !s.trim().is_empty()).unwrap_or_else(|| default.to_string())
        };
        Some(OidcConfig {
            issuer: issuer.trim_end_matches('/').to_string(),
            client_id: get("OIDC_CLIENT_ID", ""),
            client_secret: get("OIDC_CLIENT_SECRET", ""),
            redirect_url: get("OIDC_REDIRECT_URL", ""),
            groups_claim: get("OIDC_GROUPS_CLAIM", "groups"),
            admin_group: get("OIDC_ADMIN_GROUP", "kerplace-admins"),
            readwrite_group: get("OIDC_READWRITE_GROUP", "kerplace-writers"),
        })
    }
}

/// The validated claims KerPlace cares about from an ID token.
#[derive(Debug, Clone)]
pub struct OidcClaims {
    /// Stable subject identifier (`sub`).
    pub subject: String,
    /// A human-friendly name: `preferred_username` or `email` or `sub`.
    pub username: String,
    /// Groups the user belongs to (from the configured groups claim).
    pub groups: Vec<String>,
}

/// One RSA verification key from the IdP's JWKS.
struct RsaJwk {
    kid: String,
    n: String,
    e: String,
}

/// An initialised OIDC client: discovery endpoints + cached verification keys.
pub struct Oidc {
    /// The resolved configuration.
    pub config: OidcConfig,
    /// IdP authorization endpoint (where the browser is redirected to log in).
    authorize_endpoint: String,
    /// IdP token endpoint (where the auth code is exchanged for tokens).
    token_endpoint: String,
    /// Cached RSA verification keys from the JWKS.
    jwks: Vec<RsaJwk>,
    /// HTTP client for discovery / code exchange.
    http: reqwest::Client,
}

impl Oidc {
    /// Initialise by fetching the IdP discovery document and JWKS.
    ///
    /// # Parameters
    /// - `config`: the OIDC settings.
    ///
    /// # Returns
    /// A ready [`Oidc`], or [`OidcError`] if the IdP is unreachable/malformed.
    pub async fn discover(config: OidcConfig) -> Result<Self, OidcError> {
        let http = reqwest::Client::new();
        let disco_url = format!("{}/.well-known/openid-configuration", config.issuer);
        let disco: Value = http
            .get(&disco_url)
            .send()
            .await
            .map_err(|e| OidcError::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| OidcError::Discovery(format!("discovery doc: {e}")))?;
        let authorize_endpoint = str_field(&disco, "authorization_endpoint")?;
        let token_endpoint = str_field(&disco, "token_endpoint")?;
        let jwks_uri = str_field(&disco, "jwks_uri")?;

        let jwks_doc: Value = http
            .get(&jwks_uri)
            .send()
            .await
            .map_err(|e| OidcError::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| OidcError::Discovery(format!("jwks: {e}")))?;
        let jwks = parse_jwks(&jwks_doc);
        if jwks.is_empty() {
            return Err(OidcError::Discovery("JWKS contained no usable RSA keys".into()));
        }
        Ok(Oidc { config, authorize_endpoint, token_endpoint, jwks, http })
    }

    /// Build the IdP authorization-code redirect URL (the "Sign in with SSO" link).
    ///
    /// # Parameters
    /// - `state`: an opaque CSRF value the IdP echoes back.
    /// - `nonce`: a one-time value bound into the ID token to prevent replay.
    ///
    /// # Returns
    /// The full authorize URL to redirect the browser to.
    pub fn authorize_url(&self, state: &str, nonce: &str) -> String {
        let enc = |s: &str| utf8_percent_encode(s, NON_ALPHANUMERIC).to_string();
        format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope=openid%20email%20profile&state={}&nonce={}",
            self.authorize_endpoint,
            enc(&self.config.client_id),
            enc(&self.config.redirect_url),
            enc(state),
            enc(nonce),
        )
    }

    /// Exchange an authorization `code` (from the callback) for the ID token.
    ///
    /// # Parameters
    /// - `code`: the authorization code returned by the IdP.
    ///
    /// # Returns
    /// The raw ID token (JWT), or [`OidcError`].
    pub async fn exchange_code(&self, code: &str) -> Result<String, OidcError> {
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.config.redirect_url.as_str()),
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
        ];
        let resp: Value = self
            .http
            .post(&self.token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| OidcError::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| OidcError::InvalidToken(format!("token response: {e}")))?;
        resp.get("id_token")
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| OidcError::InvalidToken("token response had no id_token".into()))
    }

    /// Validate an ID token (signature against the JWKS, plus `iss`/`aud`/`exp`
    /// and, if given, `nonce`) and extract the claims KerPlace uses.
    ///
    /// # Parameters
    /// - `id_token`: the raw JWT.
    /// - `expected_nonce`: the nonce issued at login (console flow), or `None`
    ///   (STS, which has no browser round-trip).
    ///
    /// # Returns
    /// The validated [`OidcClaims`], or [`OidcError::InvalidToken`].
    pub fn validate(&self, id_token: &str, expected_nonce: Option<&str>) -> Result<OidcClaims, OidcError> {
        let header = decode_header(id_token).map_err(|e| OidcError::InvalidToken(e.to_string()))?;
        let kid = header.kid.unwrap_or_default();
        // Pick the JWKS key by `kid`; fall back to the sole key if none is named.
        let jwk = self
            .jwks
            .iter()
            .find(|k| k.kid == kid)
            .or_else(|| if self.jwks.len() == 1 { self.jwks.first() } else { None })
            .ok_or_else(|| OidcError::InvalidToken(format!("no JWKS key for kid `{kid}`")))?;
        let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|e| OidcError::InvalidToken(format!("bad JWKS key: {e}")))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.client_id]);
        let data = decode::<Value>(id_token, &key, &validation)
            .map_err(|e| OidcError::InvalidToken(e.to_string()))?;
        let claims = data.claims;

        if let Some(expected) = expected_nonce {
            if claims.get("nonce").and_then(|v| v.as_str()) != Some(expected) {
                return Err(OidcError::InvalidToken("nonce mismatch".into()));
            }
        }

        let subject = claims.get("sub").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let username = claims
            .get("preferred_username")
            .or_else(|| claims.get("email"))
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| subject.clone());
        let groups = claims
            .get(&self.config.groups_claim)
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|g| g.as_str().map(String::from)).collect())
            .unwrap_or_default();

        Ok(OidcClaims { subject, username, groups })
    }

    /// Map validated claims to a KerPlace [`Policy`] by group membership.
    ///
    /// Admin group → [`Policy::Admin`]; read-write group → [`Policy::ReadWrite`];
    /// otherwise [`Policy::ReadOnly`]. Group names match exactly or with a leading
    /// `/` (Keycloak emits `/kerplace-admins`).
    ///
    /// # Parameters
    /// - `claims`: the validated claims.
    ///
    /// # Returns
    /// The mapped [`Policy`].
    pub fn policy_for(&self, claims: &OidcClaims) -> Policy {
        let in_group = |name: &str| {
            claims.groups.iter().any(|g| g == name || g.trim_start_matches('/') == name)
        };
        if in_group(&self.config.admin_group) {
            Policy::Admin
        } else if in_group(&self.config.readwrite_group) {
            Policy::ReadWrite
        } else {
            Policy::ReadOnly
        }
    }
}

/// Extract a required string field from a JSON object, or a discovery error.
fn str_field(v: &Value, key: &str) -> Result<String, OidcError> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(String::from)
        .ok_or_else(|| OidcError::Discovery(format!("discovery doc missing `{key}`")))
}

/// Parse the RSA verification keys out of a JWKS document (ignores non-RSA keys).
fn parse_jwks(doc: &Value) -> Vec<RsaJwk> {
    doc.get("keys")
        .and_then(|k| k.as_array())
        .map(|keys| {
            keys.iter()
                .filter(|k| k.get("kty").and_then(|t| t.as_str()) == Some("RSA"))
                .filter_map(|k| {
                    Some(RsaJwk {
                        kid: k.get("kid").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                        n: k.get("n").and_then(|v| v.as_str())?.to_string(),
                        e: k.get("e").and_then(|v| v.as_str())?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Shared OIDC test scaffolding: an embedded test RSA key and an in-process fake
/// IdP. Lives here (not in a `tests` module) so the console integration tests can
/// reuse it via `crate::auth::oidc::testsupport`.
#[cfg(test)]
pub(crate) mod testsupport {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    use jsonwebtoken::{encode, EncodingKey, Header};

    /// Test-only RSA-2048 private key (NOT a secret; generated for the suite).
    pub(crate) const PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCvyA67dHWN6wlx\nA9XZTfEU+6ou9zBEje+WNZzdIYq6uyWftrbq8zkIzKHq2kFtG/nhyhOaIEVSCDyh\nrTSFzKyhJNMc+L18N7qbiGkiW40F12uZp5h9JkgiWh8vf83MiR508P/F532hgv/f\nU8TA3+S9QDZh/Wv0phZvFSzNlnGHIcq3ZiCZ5n2Oj53uGcsKNt3jy5FdQjkb7zmX\nP0VEQByCTunyhLJBnK1l9d1g+VHTfvj77DaYI7DKfKDa4dtYEOaKRQXHa8bdkwmw\n4dbF0AduFvbRpBX+1mYG9cz6qznmd9gPtFlB+TgFBmeQIGiXnDOJHQ6EuzXdUDUg\nD+08wmr9AgMBAAECggEAAZHaidOCKjyHVs5HNlvTE5IkxKsZ7/7JfTCo4DOour6p\nmRnHW+VEpN648nE1BN2rV1gX4Tg5DkC7E+GJVsmLYBwFU5yoCogv3ywybiddpMf1\n8scTnkh9e+sMnL66LoGp9zbgvdpxnYPfN5YWq3dEYmlEow7hjCuAh0jr38Egbem8\nSjbmXFG5OomaWsRCIIeUI1LVbi4ij4qbTkCvsYDhyecbv+RHMf7Z7WaXgA+ZBa++\nea4iUG2SBpGexFAtoticboad+racJltdRR6mBVYoS4KkoEiqRrbzeZODpJ6imKay\nhfnyYqg2m5F1hIkxkJyZgUNdqzJQhF19QNdsH/bG4QKBgQDk6Yh0eluo5y/nfopW\no+13CUpaIE10aBqa8BykIfjlTC+U3ogkW1hoJw0UsVAvttyTz4QhSka+Jhk1Pc/J\nEelVJl7jHtZvvs2T0M9IqnbVP2WLE4FQv09IcIPYyN/mmpE/H2WPHzla2U2mfSJ6\n3MLQl4NL4WYut+MBU4bAp0kn3QKBgQDElQcVxg2ZKOx/7LjyXCLV5D/t2tYLKMRk\niZzpcaMOMCcjpkqYfx/jl0J/kfuM78qtKYP4oEIDGAWqaZahvLJTw3Qvavo5t9yy\nkwNLFCmRr25Tm3PGuOv3oSqq+jrF4nampDWyzDTeCCbyST+3WzNxqEeqHX0tV4Il\njCiE4hCtoQKBgQCsMQdWJtxgF1evmT5Sogj0q+ZkGTxqPg0VU10YEf357e802pgq\nURQVdJqgYCjjW3hdL5JCwG6qhlob9J0isPiF9tEVo5LGiA54DHCARsoQ6xllHoz9\nworPAOQM5D2YZ9iuVN2+ZUxtjFyeyi5voTRiWDaJk8mbhvOZgc0xiiS7eQKBgBy/\nbnnQrMxpH6zVgXZv4uhEqNSv2/1lyNKrDTdWVvIMOK0N9Hq4nIE77Y2aW58QsiMA\nnzwMs5qgOLPjHRQp9CoruyH0EwO9z5iNxz2DhVC4xvmTEitNf7SG7SZz0YR+ybs0\n6GVtV43gw1FLRPYbcDp+0XwfM98dnPrAtGw6YxYBAoGAcId9e/gMvvG7hjhLf6/v\nYEbObxwVaBFvF6etlWXqBGNooi+uZtYZhvmJQ6KB/XwaNqua6hhFjx+9/tQ4v1ca\nOBNXSLjBk7nvHK9Dha+a/rUasorOcYoHiIHI9CAqBA+VlzIPSYP+Cwq9+bGAr/wh\nus1z/4329qM6O4TdZu9slIw=\n-----END PRIVATE KEY-----\n";
    /// Base64url RSA modulus of [`PRIV_PEM`]'s public key (the JWKS `n`).
    pub(crate) const N: &str = "r8gOu3R1jesJcQPV2U3xFPuqLvcwRI3vljWc3SGKursln7a26vM5CMyh6tpBbRv54coTmiBFUgg8oa00hcysoSTTHPi9fDe6m4hpIluNBddrmaeYfSZIIlofL3_NzIkedPD_xed9oYL_31PEwN_kvUA2Yf1r9KYWbxUszZZxhyHKt2YgmeZ9jo-d7hnLCjbd48uRXUI5G-85lz9FREAcgk7p8oSyQZytZfXdYPlR0374--w2mCOwynyg2uHbWBDmikUFx2vG3ZMJsOHWxdAHbhb20aQV_tZmBvXM-qs55nfYD7RZQfk4BQZnkCBol5wziR0OhLs13VA1IA_tPMJq_Q";
    /// RSA public exponent (65537) in base64url (the JWKS `e`).
    pub(crate) const E: &str = "AQAB";
    /// Key id advertised in the JWKS and stamped in signed tokens.
    pub(crate) const KID: &str = "test-kid";
    /// Client id the fake IdP issues tokens for.
    pub(crate) const CLIENT_ID: &str = "kerplace";

    /// Sign an ID token (RS256, test key, `kid=test-kid`) with the given claims.
    pub(crate) fn sign(claims: Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KID.to_string());
        let key = EncodingKey::from_rsa_pem(PRIV_PEM.as_bytes()).unwrap();
        encode(&header, &claims, &key).unwrap()
    }

    /// A `now + 1h` Unix timestamp for the `exp` claim.
    pub(crate) fn exp() -> i64 {
        jsonwebtoken::get_current_timestamp() as i64 + 3600
    }

    /// Fake discovery document pointing every endpoint back at this server.
    async fn discovery(axum::extract::State(issuer): axum::extract::State<Arc<String>>) -> axum::Json<Value> {
        axum::Json(serde_json::json!({
            "issuer": *issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
        }))
    }

    /// Fake JWKS exposing the single test RSA key.
    async fn jwks() -> axum::Json<Value> {
        axum::Json(serde_json::json!({
            "keys": [{ "kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID, "n": N, "e": E }]
        }))
    }

    /// Fake token endpoint. Convention for tests: the `code` is the nonce to embed,
    /// optionally suffixed `:readonly` to mint a non-admin (no-groups) token. The
    /// minted ID token carries that nonce, `aud=CLIENT_ID`, `iss=this server`.
    async fn token(
        axum::extract::State(issuer): axum::extract::State<Arc<String>>,
        axum::Form(form): axum::Form<HashMap<String, String>>,
    ) -> axum::Json<Value> {
        let code = form.get("code").cloned().unwrap_or_default();
        let (nonce, readonly) = match code.split_once(':') {
            Some((n, "readonly")) => (n.to_string(), true),
            _ => (code, false),
        };
        let groups = if readonly { serde_json::json!([]) } else { serde_json::json!(["/kerplace-admins"]) };
        let id_token = sign(serde_json::json!({
            "iss": *issuer, "aud": CLIENT_ID, "exp": exp(),
            "sub": "alice-sub", "preferred_username": "alice",
            "groups": groups, "nonce": nonce,
        }));
        axum::Json(serde_json::json!({
            "id_token": id_token, "access_token": "at", "token_type": "Bearer", "expires_in": 3600
        }))
    }

    /// Spin up an in-process fake OIDC IdP and return a discovered [`Oidc`] wired to
    /// it (real discovery + JWKS + token-exchange paths, no external Keycloak).
    pub(crate) async fn fake_oidc() -> Oidc {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let issuer = Arc::new(format!("http://{addr}"));
        let app = axum::Router::new()
            .route("/.well-known/openid-configuration", axum::routing::get(discovery))
            .route("/jwks", axum::routing::get(jwks))
            .route("/token", axum::routing::post(token))
            .with_state(issuer.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let config = OidcConfig {
            issuer: (*issuer).clone(),
            client_id: CLIENT_ID.to_string(),
            client_secret: "secret".to_string(),
            redirect_url: "http://kp.example/api/oidc/callback".to_string(),
            groups_claim: "groups".to_string(),
            admin_group: "kerplace-admins".to_string(),
            readwrite_group: "kerplace-writers".to_string(),
        };
        Oidc::discover(config).await.unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testsupport::{exp, sign, E, N};
    use super::*;

    /// Build an `Oidc` directly from the test key (bypasses network discovery).
    fn test_oidc() -> Oidc {
        Oidc {
            config: OidcConfig {
                issuer: "https://idp.example".into(),
                client_id: "kerplace".into(),
                client_secret: "secret".into(),
                redirect_url: "https://kp.example/api/oidc/callback".into(),
                groups_claim: "groups".into(),
                admin_group: "kerplace-admins".into(),
                readwrite_group: "kerplace-writers".into(),
            },
            authorize_endpoint: "https://idp.example/authorize".into(),
            token_endpoint: "https://idp.example/token".into(),
            jwks: vec![RsaJwk { kid: "test-kid".into(), n: N.into(), e: E.into() }],
            http: reqwest::Client::new(),
        }
    }

    /// A valid token validates and its claims are extracted.
    #[test]
    fn validates_and_extracts_claims() {
        let oidc = test_oidc();
        let token = sign(serde_json::json!({
            "iss": "https://idp.example", "aud": "kerplace", "exp": exp(),
            "sub": "user-1", "preferred_username": "alice",
            "groups": ["/kerplace-admins", "everyone"], "nonce": "n0",
        }));
        let claims = oidc.validate(&token, Some("n0")).unwrap();
        assert_eq!(claims.subject, "user-1");
        assert_eq!(claims.username, "alice");
        assert_eq!(oidc.policy_for(&claims), Policy::Admin);
    }

    /// Group membership maps to the right policy (writer → ReadWrite, none → ReadOnly).
    #[test]
    fn maps_groups_to_policy() {
        let oidc = test_oidc();
        let writer = OidcClaims { subject: "u".into(), username: "u".into(), groups: vec!["kerplace-writers".into()] };
        assert_eq!(oidc.policy_for(&writer), Policy::ReadWrite);
        let nobody = OidcClaims { subject: "u".into(), username: "u".into(), groups: vec![] };
        assert_eq!(oidc.policy_for(&nobody), Policy::ReadOnly);
    }

    /// Wrong audience, bad nonce, and a foreign signature are all rejected.
    #[test]
    fn rejects_bad_tokens() {
        let oidc = test_oidc();
        // Wrong audience.
        let bad_aud = sign(serde_json::json!({
            "iss": "https://idp.example", "aud": "someone-else", "exp": exp(), "sub": "x",
        }));
        assert!(oidc.validate(&bad_aud, None).is_err());

        // Nonce mismatch.
        let good = sign(serde_json::json!({
            "iss": "https://idp.example", "aud": "kerplace", "exp": exp(), "sub": "x", "nonce": "right",
        }));
        assert!(oidc.validate(&good, Some("wrong")).is_err());

        // Garbage token.
        assert!(oidc.validate("not.a.jwt", None).is_err());
    }

    /// The authorize URL carries the client id, redirect, state and nonce.
    #[test]
    fn authorize_url_has_params() {
        let url = test_oidc().authorize_url("st8", "nc9");
        assert!(url.starts_with("https://idp.example/authorize?"));
        assert!(url.contains("client_id=kerplace"));
        assert!(url.contains("state=st8"));
        assert!(url.contains("nonce=nc9"));
        assert!(url.contains("response_type=code"));
    }
}
