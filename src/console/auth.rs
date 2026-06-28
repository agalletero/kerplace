//! Stateless session tokens for the web console.
//!
//! A token is `"<expiry_unix>.<hex(hmac_sha256(root_password, expiry_unix))>"`.
//! It is self-verifying (no server-side session store) and bound to the
//! configured secret, so it stops being valid if the secret changes.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use time::OffsetDateTime;

type HmacSha256 = Hmac<Sha256>;

/// Lifetime of a console session token, in seconds (12 hours).
const TOKEN_TTL_SECONDS: i64 = 12 * 3600;

/// Current Unix time in seconds.
///
/// # Returns
/// Seconds since the Unix epoch (UTC).
pub fn now_secs() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// Compute the hex HMAC-SHA256 of an expiry value under the secret.
///
/// # Parameters
/// - `secret`: the signing secret (the root password).
/// - `expiry`: the token expiry as a Unix timestamp.
///
/// # Returns
/// The lowercase hex MAC.
fn sign(secret: &str, expiry: i64) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    mac.update(expiry.to_string().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Issue a fresh session token valid for [`TOKEN_TTL_SECONDS`].
///
/// # Parameters
/// - `secret`: the signing secret (the root password).
/// - `now`: the current Unix timestamp.
///
/// # Returns
/// A token string of the form `"<expiry>.<signature>"`.
pub fn issue_token(secret: &str, now: i64) -> String {
    let expiry = now + TOKEN_TTL_SECONDS;
    format!("{expiry}.{}", sign(secret, expiry))
}

/// Verify a session token: well-formed, unexpired and correctly signed.
///
/// # Parameters
/// - `secret`: the signing secret (the root password).
/// - `token`: the token to validate.
/// - `now`: the current Unix timestamp.
///
/// # Returns
/// `true` if the token is valid, `false` otherwise.
pub fn verify_token(secret: &str, token: &str, now: i64) -> bool {
    let Some((expiry_str, signature)) = token.split_once('.') else {
        return false;
    };
    let Ok(expiry) = expiry_str.parse::<i64>() else {
        return false;
    };
    if now >= expiry {
        return false;
    }
    sign(secret, expiry) == signature
}
