//! Identity & Access Management: multiple credentials with canned policies.
//!
//! The single root credential (from config) is always present and has the
//! `admin` policy. Additional users are persisted at
//! `.kerplace.sys/iam/users.json` and can be mutated at runtime (add / remove /
//! enable / disable) without restarting the server.
//!
//! Authentication (SigV4) resolves the secret key for an access key via
//! [`IamStore::resolve`]; the auth middleware then enforces the identity's
//! policy against the requested action (read / write / admin).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::Method;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::fs;

use crate::error::S3Error;

/// Prefix marking an access key as a (stateless) STS temporary credential.
const STS_PREFIX: &str = "KPSTS";
/// STS payload length: `policy_id(1) || expiry_be(8) || nonce(8)`.
const STS_PAYLOAD_LEN: usize = 17;
/// Truncated HMAC tag length appended to the STS payload.
const STS_TAG_LEN: usize = 16;

/// Current Unix time in seconds.
fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Full HMAC-SHA256 of `data` under `secret` (32 bytes).
fn hmac_sha256(secret: &str, data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Map a [`Policy`] to its 1-byte STS id (and back).
fn policy_to_id(p: Policy) -> u8 {
    match p {
        Policy::Admin => 1,
        Policy::ReadWrite => 2,
        Policy::ReadOnly => 3,
        Policy::WriteOnly => 4,
    }
}

/// Inverse of [`policy_to_id`]; `None` for an unknown id.
fn policy_from_id(id: u8) -> Option<Policy> {
    match id {
        1 => Some(Policy::Admin),
        2 => Some(Policy::ReadWrite),
        3 => Some(Policy::ReadOnly),
        4 => Some(Policy::WriteOnly),
        _ => None,
    }
}

/// The action class a request maps to, for policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Read-only S3 operations (GET / HEAD / list).
    Read,
    /// Mutating S3 operations (PUT / POST / DELETE).
    Write,
    /// Administrative operations (`/minio/admin/*`, user management).
    Admin,
}

/// A canned access policy, mirroring MinIO's built-in policy names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Full access including administrative endpoints.
    Admin,
    /// All read and write S3 operations (no admin).
    ReadWrite,
    /// Read-only S3 operations.
    ReadOnly,
    /// Write-only S3 operations.
    WriteOnly,
}

impl Policy {
    /// Resolve a policy from its name (MinIO-compatible aliases).
    ///
    /// Unknown names fall back to the safest policy ([`Policy::ReadOnly`]).
    ///
    /// # Parameters
    /// - `name`: the policy name (e.g. `"readwrite"`, `"consoleAdmin"`).
    ///
    /// # Returns
    /// The matching [`Policy`].
    pub fn from_name(name: &str) -> Policy {
        match name.trim().to_ascii_lowercase().as_str() {
            "admin" | "consoleadmin" | "diagnostics" => Policy::Admin,
            "readwrite" | "readwriteadmin" => Policy::ReadWrite,
            "writeonly" => Policy::WriteOnly,
            _ => Policy::ReadOnly,
        }
    }

    /// The canonical name of this policy.
    ///
    /// # Returns
    /// The policy name string.
    pub fn name(&self) -> &'static str {
        match self {
            Policy::Admin => "consoleAdmin",
            Policy::ReadWrite => "readwrite",
            Policy::ReadOnly => "readonly",
            Policy::WriteOnly => "writeonly",
        }
    }

    /// Whether this policy permits the given action.
    ///
    /// # Parameters
    /// - `action`: the action class being requested.
    ///
    /// # Returns
    /// `true` if allowed.
    pub fn allows(&self, action: Action) -> bool {
        match (self, action) {
            (Policy::Admin, _) => true,
            (_, Action::Admin) => false,
            (Policy::ReadWrite, _) => true,
            (Policy::ReadOnly, Action::Read) => true,
            (Policy::WriteOnly, Action::Write) => true,
            _ => false,
        }
    }
}

/// A resolved identity (credential + policy + status).
#[derive(Debug, Clone)]
pub struct Identity {
    /// Access key id.
    pub access_key: String,
    /// Secret access key used to verify SigV4 signatures.
    pub secret_key: String,
    /// Policy name attached to this identity.
    pub policy: String,
    /// Whether the credential is enabled.
    pub enabled: bool,
}

/// On-disk record for a non-root user.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredUser {
    secret_key: String,
    #[serde(default = "default_policy")]
    policy: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

/// Default policy for a deserialized user missing the field.
fn default_policy() -> String {
    "readwrite".to_string()
}

/// Default enabled state for a deserialized user missing the field.
fn default_true() -> bool {
    true
}

/// The persisted users document (`.kerplace.sys/iam/users.json`).
#[derive(Debug, Default, Serialize, Deserialize)]
struct UsersDoc {
    #[serde(default)]
    users: HashMap<String, StoredUser>,
}

/// In-memory identity store backing authentication and authorization.
pub struct IamStore {
    /// Root access key (always admin, never persisted to users.json).
    root_key: String,
    /// Root secret key.
    root_secret: String,
    /// Non-root users, keyed by access key.
    users: RwLock<HashMap<String, StoredUser>>,
    /// Path to the persisted users document.
    path: PathBuf,
}

impl IamStore {
    /// Construct a store containing only the root credential (no persistence).
    /// Test-only helper (production uses [`IamStore::load`]).
    ///
    /// # Parameters
    /// - `root_key`: root access key.
    /// - `root_secret`: root secret key.
    ///
    /// # Returns
    /// A root-only [`IamStore`] with an empty (in-memory) user set.
    #[cfg(test)]
    pub fn root_only(root_key: &str, root_secret: &str) -> Self {
        IamStore {
            root_key: root_key.to_string(),
            root_secret: root_secret.to_string(),
            users: RwLock::new(HashMap::new()),
            path: PathBuf::new(),
        }
    }

    /// Load the store: seed root from config, read persisted users, then apply
    /// any `KP_USERS` env seed (`ak:sk:policy` entries, comma-separated).
    ///
    /// # Parameters
    /// - `iam_dir`: directory holding `users.json`.
    /// - `root_key`: root access key (from config).
    /// - `root_secret`: root secret key (from config).
    /// - `env_seed`: the raw `KP_USERS` value, if set.
    ///
    /// # Returns
    /// A populated [`IamStore`].
    pub async fn load(
        iam_dir: PathBuf,
        root_key: &str,
        root_secret: &str,
        env_seed: Option<String>,
    ) -> Self {
        let path = iam_dir.join("users.json");
        let mut users: HashMap<String, StoredUser> = match fs::read(&path).await {
            Ok(bytes) => serde_json::from_slice::<UsersDoc>(&bytes)
                .map(|d| d.users)
                .unwrap_or_default(),
            Err(_) => HashMap::new(),
        };

        // Apply env seed (does not overwrite users already persisted on disk).
        if let Some(seed) = env_seed {
            for entry in seed.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                let parts: Vec<&str> = entry.split(':').collect();
                if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
                    continue;
                }
                let ak = parts[0].to_string();
                if ak == root_key {
                    continue;
                }
                let policy = parts.get(2).map(|s| s.to_string()).unwrap_or_else(default_policy);
                users.entry(ak).or_insert(StoredUser {
                    secret_key: parts[1].to_string(),
                    policy,
                    enabled: true,
                });
            }
        }

        IamStore {
            root_key: root_key.to_string(),
            root_secret: root_secret.to_string(),
            users: RwLock::new(users),
            path,
        }
    }

    /// Mint a **stateless** STS credential: the policy and expiry are signed into
    /// the access key with the server secret, so any gateway can validate it with
    /// no shared state (it survives restarts and works across multiple gateways).
    ///
    /// Layout: `access_key = "KPSTS" || b64url(policy_id(1) ‖ expiry_be(8) ‖
    /// nonce(8) ‖ hmac16)`; `secret_key = b64url(HMAC(server_secret, access_key))`
    /// (deterministic, so [`resolve`](Self::resolve) recomputes it to verify SigV4).
    /// Nothing is persisted.
    ///
    /// # Parameters
    /// - `policy`: the policy to attach (mapped from the token's groups).
    /// - `ttl_secs`: lifetime in seconds.
    ///
    /// # Returns
    /// `(access_key, secret_key, expiry_unix)`.
    pub fn issue_temp(&self, policy: Policy, ttl_secs: i64) -> (String, String, i64) {
        let expiry = now_unix() + ttl_secs;
        let mut payload = Vec::with_capacity(STS_PAYLOAD_LEN);
        payload.push(policy_to_id(policy));
        payload.extend_from_slice(&expiry.to_be_bytes());
        let mut nonce = [0u8; 8];
        OsRng.fill_bytes(&mut nonce);
        payload.extend_from_slice(&nonce);

        let tag = hmac_sha256(&self.root_secret, &payload);
        let mut blob = payload;
        blob.extend_from_slice(&tag[..STS_TAG_LEN]);
        let access_key = format!("{STS_PREFIX}{}", B64.encode(&blob));
        let secret_key = B64.encode(hmac_sha256(&self.root_secret, access_key.as_bytes()));
        (access_key, secret_key, expiry)
    }

    /// Validate and decode a stateless STS access key into an [`Identity`].
    ///
    /// # Parameters
    /// - `access_key`: the full access key (including the `KPSTS` prefix).
    ///
    /// # Returns
    /// The identity if the signature is valid and the credential is unexpired,
    /// else `None`.
    fn resolve_sts(&self, access_key: &str) -> Option<Identity> {
        let b64 = access_key.strip_prefix(STS_PREFIX)?;
        let blob = B64.decode(b64).ok()?;
        if blob.len() != STS_PAYLOAD_LEN + STS_TAG_LEN {
            return None;
        }
        let (payload, tag) = blob.split_at(STS_PAYLOAD_LEN);
        // Verify the credential was minted by us.
        if hmac_sha256(&self.root_secret, payload)[..STS_TAG_LEN] != *tag {
            return None;
        }
        let policy = policy_from_id(payload[0])?;
        let expiry = i64::from_be_bytes(payload[1..9].try_into().ok()?);
        if expiry <= now_unix() {
            return None; // expired
        }
        Some(Identity {
            access_key: access_key.to_string(),
            secret_key: B64.encode(hmac_sha256(&self.root_secret, access_key.as_bytes())),
            policy: policy.name().to_string(),
            enabled: true,
        })
    }

    /// Resolve an access key to its identity (root, a stored user, or a stateless
    /// STS credential).
    ///
    /// # Parameters
    /// - `access_key`: the access key id presented by the request.
    ///
    /// # Returns
    /// The [`Identity`], or `None` if the access key is unknown/invalid/expired.
    pub fn resolve(&self, access_key: &str) -> Option<Identity> {
        if access_key == self.root_key {
            return Some(Identity {
                access_key: self.root_key.clone(),
                secret_key: self.root_secret.clone(),
                policy: Policy::Admin.name().to_string(),
                enabled: true,
            });
        }
        // Stateless STS credential (self-validating, no shared state).
        if access_key.starts_with(STS_PREFIX) {
            return self.resolve_sts(access_key);
        }
        if let Some(u) = self.users.read().unwrap().get(access_key) {
            return Some(Identity {
                access_key: access_key.to_string(),
                secret_key: u.secret_key.clone(),
                policy: u.policy.clone(),
                enabled: u.enabled,
            });
        }
        None
    }

    /// List all identities (root first, then users sorted by access key).
    ///
    /// # Returns
    /// A vector of [`Identity`] (secrets included; callers must not leak them).
    pub fn list(&self) -> Vec<Identity> {
        let mut out = vec![Identity {
            access_key: self.root_key.clone(),
            secret_key: self.root_secret.clone(),
            policy: Policy::Admin.name().to_string(),
            enabled: true,
        }];
        let users = self.users.read().unwrap();
        let mut keys: Vec<&String> = users.keys().collect();
        keys.sort();
        for k in keys {
            let u = &users[k];
            out.push(Identity {
                access_key: k.clone(),
                secret_key: u.secret_key.clone(),
                policy: u.policy.clone(),
                enabled: u.enabled,
            });
        }
        out
    }

    /// Add or replace a user, then persist.
    ///
    /// # Parameters
    /// - `access_key`: the new user's access key (must not be the root key).
    /// - `secret_key`: the new user's secret key.
    /// - `policy`: the policy name to attach.
    ///
    /// # Returns
    /// `Ok(())`, or [`S3Error::InvalidArgument`] if the key collides with root
    /// or is empty.
    pub async fn add_user(
        &self,
        access_key: &str,
        secret_key: &str,
        policy: &str,
    ) -> Result<(), S3Error> {
        if access_key.is_empty() || secret_key.is_empty() {
            return Err(S3Error::InvalidArgument("empty access/secret key".into()));
        }
        if access_key == self.root_key {
            return Err(S3Error::InvalidArgument("cannot redefine root user".into()));
        }
        {
            let mut users = self.users.write().unwrap();
            users.insert(
                access_key.to_string(),
                StoredUser {
                    secret_key: secret_key.to_string(),
                    policy: policy.to_string(),
                    enabled: true,
                },
            );
        }
        self.persist().await
    }

    /// Remove a user, then persist. Idempotent.
    ///
    /// # Parameters
    /// - `access_key`: the user to remove.
    ///
    /// # Returns
    /// `Ok(())`, or [`S3Error::InvalidArgument`] if targeting the root key.
    pub async fn remove_user(&self, access_key: &str) -> Result<(), S3Error> {
        if access_key == self.root_key {
            return Err(S3Error::InvalidArgument("cannot remove root user".into()));
        }
        {
            let mut users = self.users.write().unwrap();
            users.remove(access_key);
        }
        self.persist().await
    }

    /// Enable or disable a user, then persist.
    ///
    /// # Parameters
    /// - `access_key`: the user to update.
    /// - `enabled`: the new enabled state.
    ///
    /// # Returns
    /// `Ok(())`, or [`S3Error::NoSuchKey`]-style error if the user is unknown.
    pub async fn set_status(&self, access_key: &str, enabled: bool) -> Result<(), S3Error> {
        {
            let mut users = self.users.write().unwrap();
            match users.get_mut(access_key) {
                Some(u) => u.enabled = enabled,
                None => return Err(S3Error::InvalidArgument("no such user".into())),
            }
        }
        self.persist().await
    }

    /// Set (or clear) the canned policy attached to an existing user, then
    /// persist. Used by the madmin policy attach/detach endpoints so a
    /// migration preserves least-privilege instead of defaulting everyone to
    /// `readwrite`.
    ///
    /// # Parameters
    /// - `access_key`: the user to update.
    /// - `policy`: the canned policy name to attach (empty string detaches all,
    ///   leaving the user with no permissions).
    ///
    /// # Returns
    /// `Ok(())`, or [`S3Error::InvalidArgument`] if the user is unknown or is
    /// the root key (whose policy is fixed).
    pub async fn set_policy(&self, access_key: &str, policy: &str) -> Result<(), S3Error> {
        if access_key == self.root_key {
            return Err(S3Error::InvalidArgument("cannot change root policy".into()));
        }
        {
            let mut users = self.users.write().unwrap();
            match users.get_mut(access_key) {
                Some(u) => u.policy = policy.to_string(),
                None => return Err(S3Error::InvalidArgument("no such user".into())),
            }
        }
        self.persist().await
    }

    /// Write the current user set to disk (root is never persisted).
    ///
    /// # Returns
    /// `Ok(())`, or [`S3Error::Internal`] on an I/O or encoding failure. A no-op
    /// when the store has no backing path (root-only / test stores).
    async fn persist(&self) -> Result<(), S3Error> {
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        let doc = {
            let users = self.users.read().unwrap();
            UsersDoc { users: users.clone() }
        };
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| S3Error::Internal(format!("mkdir iam: {e}")))?;
        }
        let json = serde_json::to_vec_pretty(&doc)
            .map_err(|e| S3Error::Internal(format!("encode users: {e}")))?;
        fs::write(&self.path, json)
            .await
            .map_err(|e| S3Error::Internal(format!("write users: {e}")))
    }
}

/// Classify an HTTP request into an [`Action`] for policy evaluation.
///
/// # Parameters
/// - `method`: the HTTP method.
/// - `path`: the request path.
///
/// # Returns
/// [`Action::Admin`] for admin endpoints, otherwise [`Action::Read`] for
/// GET/HEAD and [`Action::Write`] for mutating verbs.
pub fn action_for(method: &Method, path: &str) -> Action {
    if path.starts_with("/kerplace/admin") || path.starts_with("/minio/admin") {
        return Action::Admin;
    }
    match *method {
        Method::GET | Method::HEAD => Action::Read,
        Method::PUT | Method::POST | Method::DELETE | Method::PATCH => Action::Write,
        _ => Action::Read,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The policy matrix allows exactly the intended actions.
    #[test]
    fn policy_allows_matrix() {
        assert!(Policy::Admin.allows(Action::Admin));
        assert!(Policy::Admin.allows(Action::Write));
        assert!(Policy::ReadWrite.allows(Action::Write));
        assert!(Policy::ReadWrite.allows(Action::Read));
        assert!(!Policy::ReadWrite.allows(Action::Admin));
        assert!(Policy::ReadOnly.allows(Action::Read));
        assert!(!Policy::ReadOnly.allows(Action::Write));
        assert!(Policy::WriteOnly.allows(Action::Write));
        assert!(!Policy::WriteOnly.allows(Action::Read));
    }

    /// Policy names round-trip through `from_name`/`name` for the canon set.
    #[test]
    fn policy_name_roundtrip() {
        for p in [Policy::Admin, Policy::ReadWrite, Policy::ReadOnly, Policy::WriteOnly] {
            assert_eq!(Policy::from_name(p.name()), p);
        }
        assert_eq!(Policy::from_name("consoleAdmin"), Policy::Admin);
        assert_eq!(Policy::from_name("unknown"), Policy::ReadOnly);
    }

    /// Root resolves as admin; unknown keys resolve to `None`.
    #[test]
    fn root_resolves_admin() {
        let store = IamStore::root_only("root", "secret");
        let id = store.resolve("root").unwrap();
        assert_eq!(id.secret_key, "secret");
        assert_eq!(id.policy, "consoleAdmin");
        assert!(store.resolve("ghost").is_none());
    }

    /// Add / resolve / remove a user round-trips in memory.
    #[tokio::test]
    async fn add_resolve_remove_user() {
        let store = IamStore::root_only("root", "secret");
        store.add_user("alice", "alicesecret", "readonly").await.unwrap();
        let id = store.resolve("alice").unwrap();
        assert_eq!(id.secret_key, "alicesecret");
        assert_eq!(Policy::from_name(&id.policy), Policy::ReadOnly);
        assert!(store.add_user("root", "x", "admin").await.is_err());
        store.remove_user("alice").await.unwrap();
        assert!(store.resolve("alice").is_none());
    }

    /// `set_policy` re-attaches a canned policy (used by the migration tool to
    /// preserve least-privilege), refuses unknown users and the root key.
    #[tokio::test]
    async fn set_policy_reassigns_and_guards() {
        let store = IamStore::root_only("root", "secret");
        store.add_user("bob", "bobsecret", "readonly").await.unwrap();
        // Promote bob to readwrite, as `mc admin policy attach` would.
        store.set_policy("bob", "readwrite").await.unwrap();
        assert_eq!(Policy::from_name(&store.resolve("bob").unwrap().policy), Policy::ReadWrite);
        // Unknown user and root are rejected.
        assert!(store.set_policy("ghost", "readonly").await.is_err());
        assert!(store.set_policy("root", "readonly").await.is_err());
    }

    /// `action_for` classifies methods and admin paths correctly.
    #[test]
    fn action_classification() {
        assert_eq!(action_for(&Method::GET, "/buck/key"), Action::Read);
        assert_eq!(action_for(&Method::PUT, "/buck/key"), Action::Write);
        assert_eq!(action_for(&Method::DELETE, "/buck/key"), Action::Write);
        // Admin endpoints require admin under both the canonical and compat prefix.
        assert_eq!(action_for(&Method::GET, "/minio/admin/v3/info"), Action::Admin);
        assert_eq!(action_for(&Method::PUT, "/kerplace/admin/v3/add-user"), Action::Admin);
    }

    /// Review #2: STS credentials are stateless — a *different* store instance with
    /// the same root secret resolves a credential the first one issued (survives
    /// restart / works across gateways), with the same derived secret and policy.
    #[test]
    fn sts_credentials_are_stateless() {
        let gw1 = IamStore::root_only("root", "shared-secret");
        let (ak, sk, _exp) = gw1.issue_temp(Policy::ReadWrite, 3600);
        assert!(ak.starts_with("KPSTS"));

        // A separate gateway (fresh store, same root secret) validates it identically.
        let gw2 = IamStore::root_only("root", "shared-secret");
        let id = gw2.resolve(&ak).expect("a peer gateway must resolve the STS credential");
        assert_eq!(id.secret_key, sk, "derived secret must match what the client got");
        assert_eq!(id.policy, "readwrite");
        assert!(id.enabled);
    }

    /// Review #2: forged/tampered/expired/foreign-secret STS credentials are rejected.
    #[test]
    fn sts_credentials_reject_forgery_and_expiry() {
        let iam = IamStore::root_only("root", "shared-secret");

        // A wrong server secret cannot mint creds this store accepts.
        let other = IamStore::root_only("root", "different-secret");
        let (ak, _sk, _) = other.issue_temp(Policy::Admin, 3600);
        assert!(iam.resolve(&ak).is_none(), "foreign-signed cred must be rejected");

        // Tampering with the signed blob breaks the HMAC (or the base64).
        let (good_ak, _, _) = iam.issue_temp(Policy::Admin, 3600);
        let mut bytes = good_ak.into_bytes();
        *bytes.last_mut().unwrap() ^= 0x01;
        let tampered = String::from_utf8_lossy(&bytes).into_owned();
        assert!(iam.resolve(&tampered).is_none(), "tampered cred must be rejected");

        // An already-expired credential is rejected.
        let (expired_ak, _, _) = iam.issue_temp(Policy::ReadOnly, -10);
        assert!(iam.resolve(&expired_ak).is_none(), "expired cred must be rejected");

        // A non-STS garbage key is simply unknown.
        assert!(iam.resolve("KPSTSnot-valid-base64-!!!").is_none());
    }
}
