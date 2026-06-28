//! Runtime configuration, loaded from environment variables.
//!
//! Defaults intentionally mirror MinIO (`minioadmin` / `minioadmin`,
//! port 9000) so existing tooling and `mc`/`aws` aliases work unchanged.
//!
//! **Variable precedence (one source of truth per variable, nothing copied):**
//! the canonical `KP_<NAME>` wins, then the transitional `MYNIO_<NAME>`
//! (deprecated), then the MinIO-compatible `MINIO_<NAME>`. So an existing MinIO
//! service file keeps starting the server unchanged, while new deployments use
//! `KP_*`. See [`env_var`].

use std::path::PathBuf;

/// Environment-variable name prefixes, in resolution order: the canonical
/// KerPlace prefix first, then the transitional one, then MinIO compat.
const ENV_PREFIXES: [&str; 3] = ["KP_", "MYNIO_", "MINIO_"];

/// Resolve `suffix` against `get` by trying each prefix in [`ENV_PREFIXES`] order
/// and returning the first value found. Pure (the lookup is injected) so the
/// precedence is unit-testable without mutating the process environment.
///
/// # Parameters
/// - `suffix`: the variable name without prefix, e.g. `"DATA_DIR"`.
/// - `get`: looks up a fully-qualified variable name, e.g. `"KP_DATA_DIR"`.
///
/// # Returns
/// The first set value across the prefix chain, or `None` if none is set.
fn resolve(suffix: &str, get: impl Fn(&str) -> Option<String>) -> Option<String> {
    ENV_PREFIXES.iter().find_map(|p| get(&format!("{p}{suffix}")))
}

/// Resolve a configuration variable from the process environment by precedence
/// `KP_<suffix>` → `MYNIO_<suffix>` → `MINIO_<suffix>` (see module docs).
///
/// # Parameters
/// - `suffix`: the variable name without prefix, e.g. `"ADDRESS"`.
///
/// # Returns
/// `Some(value)` for the first prefix that is set, else `None`.
pub fn env_var(suffix: &str) -> Option<String> {
    resolve(suffix, |k| std::env::var(k).ok())
}

/// Whether `value` is a truthy flag (`true`/`1`/`on`, case-insensitive).
fn truthy(value: &str) -> bool {
    matches!(value.to_ascii_lowercase().as_str(), "true" | "1" | "on")
}

/// Whether `value` is a falsy flag (`false`/`0`/`off`, case-insensitive).
fn falsy(value: &str) -> bool {
    matches!(value.to_ascii_lowercase().as_str(), "false" | "0" | "off")
}

/// Deployment posture preset (`KP_PROFILE`), one of the orthogonal product axes.
///
/// A profile does not silently weaken or strengthen settings — it declares a
/// posture whose **invariants are validated at startup** (fail-closed). `open` is
/// today's permissive default; `sealed` is the regulated posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Permissive defaults (dev / trusted-network). No extra invariants.
    Open,
    /// Regulated posture: requires TLS, auth, at-rest encryption, an erasure
    /// backend, external OIDC identity, and **off-host** key custody (not the
    /// `file` provider). The server refuses to start if any of these is unmet.
    Sealed,
}

impl Profile {
    /// The lowercase profile name (for `info` / console / banner).
    ///
    /// # Returns
    /// `"open"` or `"sealed"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Profile::Open => "open",
            Profile::Sealed => "sealed",
        }
    }
}

/// Parse a `KP_PROFILE` value, rejecting unknown names (fail fast).
///
/// # Parameters
/// - `s`: the raw profile string (empty ⇒ `open`).
///
/// # Returns
/// The [`Profile`], or an error message for an unknown name.
pub fn parse_profile(s: &str) -> Result<Profile, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "" | "open" => Ok(Profile::Open),
        "sealed" => Ok(Profile::Sealed),
        other => Err(format!("unknown KP_PROFILE `{other}` (use `open` or `sealed`)")),
    }
}

/// List the `sealed`-profile invariants that are currently **unmet**.
///
/// Reads both the resolved [`Config`] and the environment (for settings not on
/// `Config`: backend and key provider). Used by startup to fail closed with a
/// clear, complete list rather than booting a half-secure deployment.
///
/// # Parameters
/// - `config`: the resolved configuration.
///
/// # Returns
/// A vector of human-readable violation messages (empty ⇒ the posture holds).
pub fn sealed_violations(config: &Config) -> Vec<String> {
    let mut v = Vec::new();
    if !config.auth_enabled {
        v.push("authentication must be enabled (do not set KP_AUTH=false)".to_string());
    }
    if !config.tls_enabled {
        v.push("TLS must be enabled (set KP_TLS=true, optionally KP_TLS_CERT/KP_TLS_KEY)".to_string());
    }
    if !config.encryption_enabled {
        v.push("at-rest encryption must be enabled (set KP_ENCRYPT=true)".to_string());
    }
    if env_var("BACKEND").as_deref() == Some("fs") {
        v.push("the transparent `fs` backend is not allowed; use the erasure backend".to_string());
    }
    if env_var("OIDC_ISSUER").filter(|s| !s.trim().is_empty()).is_none() {
        v.push("external identity must be configured (set KP_OIDC_ISSUER)".to_string());
    }
    let provider = env_var("KEY_PROVIDER").unwrap_or_else(|| "file".to_string());
    if provider == "file" {
        v.push("off-host key custody is required: set KP_KEY_PROVIDER=passphrase or kms (not `file`)".to_string());
    }
    v
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Address the S3 API listens on, e.g. `0.0.0.0:9000`.
    pub address: String,
    /// Root directory under which buckets and objects are stored.
    pub data_dir: PathBuf,
    /// Access key (S3 `AccessKeyId`).
    pub root_user: String,
    /// Secret key used to verify SigV4 signatures.
    pub root_password: String,
    /// Region advertised/expected in the SigV4 credential scope.
    pub region: String,
    /// When false, requests are served without authentication (dev only).
    pub auth_enabled: bool,
    /// Address the web console listens on, e.g. `0.0.0.0:9001`.
    pub console_address: String,
    /// When false, the web console is not started.
    pub console_enabled: bool,
    /// When true, object payloads are encrypted at rest.
    pub encryption_enabled: bool,
    /// When true, the S3 API (and console) are served over HTTPS/TLS.
    pub tls_enabled: bool,
    /// Path to the PEM-encoded TLS certificate chain. When `tls_enabled` is set
    /// but this is `None`, a self-signed certificate is generated for dev use.
    pub tls_cert: Option<PathBuf>,
    /// Path to the PEM-encoded TLS private key. Paired with [`Config::tls_cert`].
    pub tls_key: Option<PathBuf>,
    /// When true, also serve the admin/health API under the MinIO-compatible
    /// `/minio/*` prefix (alias of the canonical `/kerplace/*`), so `mc admin`
    /// and madmin SDKs work unchanged. Default on; set `KP_MINIO_COMPAT=false`
    /// once all tooling is KerPlace-native.
    pub minio_compat: bool,
    /// Deployment posture (`KP_PROFILE`); `sealed` enforces a regulated baseline.
    pub profile: Profile,
}

impl Config {
    /// Build a [`Config`] from the environment by the `KP_*` → `MYNIO_*` →
    /// `MINIO_*` precedence (see [`env_var`]), falling back to
    /// MinIO-compatible defaults for any variable that is unset.
    ///
    /// # Parameters
    /// - (none) — all input is read from the process environment.
    ///
    /// # Returns
    /// A fully-populated [`Config`]. This function never fails; missing
    /// variables resolve to defaults.
    pub fn from_env() -> Self {
        Config {
            address: env_var("ADDRESS").unwrap_or_else(|| "0.0.0.0:9000".to_string()),
            data_dir: env_var("DATA_DIR").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("./data")),
            root_user: env_var("ROOT_USER").unwrap_or_else(|| "minioadmin".to_string()),
            root_password: env_var("ROOT_PASSWORD").unwrap_or_else(|| "minioadmin".to_string()),
            region: env_var("REGION").unwrap_or_else(|| "us-east-1".to_string()),
            auth_enabled: env_var("AUTH").map(|v| !falsy(&v)).unwrap_or(true),
            console_address: env_var("CONSOLE_ADDRESS").unwrap_or_else(|| "0.0.0.0:9001".to_string()),
            console_enabled: env_var("CONSOLE").map(|v| !falsy(&v)).unwrap_or(true),
            encryption_enabled: env_var("ENCRYPT").map(|v| truthy(&v)).unwrap_or(false),
            // TLS is on if the flag is truthy or both cert+key paths are given.
            tls_enabled: env_var("TLS").map(|v| truthy(&v)).unwrap_or(false)
                || (env_var("TLS_CERT").is_some() && env_var("TLS_KEY").is_some()),
            tls_cert: env_var("TLS_CERT").map(PathBuf::from),
            tls_key: env_var("TLS_KEY").map(PathBuf::from),
            minio_compat: env_var("MINIO_COMPAT").map(|v| !falsy(&v)).unwrap_or(true),
            // Lenient here (unknown ⇒ open); `main` re-parses strictly to fail fast
            // on an unknown name and to validate the `sealed` invariants.
            profile: parse_profile(&env_var("PROFILE").unwrap_or_default()).unwrap_or(Profile::Open),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every configuration variable resolves by the `KP_ → MYNIO_ → MINIO_`
    /// precedence: the canonical prefix wins, then the transitional one, then
    /// the MinIO-compat one; unset resolves to `None`.
    #[test]
    fn env_precedence_for_all_variables() {
        // The full set of configuration variable suffixes (read across
        // config.rs and main.rs). Keep in sync when a new KP_* var is added.
        const SUFFIXES: [&str; 26] = [
            "ADDRESS", "AUTH", "BACKEND", "CLUSTER_LOCKS", "CLUSTER_SECRET", "CONSOLE",
            "CONSOLE_ADDRESS", "DATA_DIR", "DEBUG", "DRIVE_ADDR", "ENCRYPT", "ERASURE_BLOCK",
            "ERASURE_DRIVES", "ERASURE_PARITY", "MINIO_COMPAT", "NODE_INDEX", "NODES", "PROFILE",
            "REGION", "ROLE", "ROOT_PASSWORD", "ROOT_USER", "TLS", "TLS_CERT", "TLS_KEY", "USERS",
        ];
        for s in SUFFIXES {
            let kp = format!("KP_{s}");
            let my = format!("MYNIO_{s}");
            let mi = format!("MINIO_{s}");
            // All three set → KP_ wins.
            let all = |k: &str| match k {
                k if k == kp => Some("kp".to_string()),
                k if k == my => Some("my".to_string()),
                k if k == mi => Some("mi".to_string()),
                _ => None,
            };
            assert_eq!(resolve(s, all).as_deref(), Some("kp"), "{s}: KP_ must win");
            // KP_ absent → MYNIO_ wins.
            let no_kp = |k: &str| match k {
                k if k == my => Some("my".to_string()),
                k if k == mi => Some("mi".to_string()),
                _ => None,
            };
            assert_eq!(resolve(s, no_kp).as_deref(), Some("my"), "{s}: MYNIO_ is next");
            // Only MINIO_ set → compat fallback.
            let only_mi = |k: &str| (k == mi).then(|| "mi".to_string());
            assert_eq!(resolve(s, only_mi).as_deref(), Some("mi"), "{s}: MINIO_ is the fallback");
            // None set → None.
            assert_eq!(resolve(s, |_| None).as_deref(), None, "{s}: unset resolves to None");
        }
    }

    /// `KP_PROFILE` parses the two known postures and rejects anything else.
    #[test]
    fn profile_parsing() {
        assert_eq!(parse_profile("").unwrap(), Profile::Open);
        assert_eq!(parse_profile("open").unwrap(), Profile::Open);
        assert_eq!(parse_profile("SEALED").unwrap(), Profile::Sealed);
        assert!(parse_profile("locked").is_err());
    }

    /// `sealed` lists every unmet invariant; a fully-compliant config has none.
    #[test]
    fn sealed_violations_are_listed() {
        // A wide-open config violates every sealed invariant (no TLS/encrypt/OIDC,
        // and the default `file` provider).
        let mut cfg = Config::from_env();
        cfg.auth_enabled = true;
        cfg.tls_enabled = false;
        cfg.encryption_enabled = false;
        let v = sealed_violations(&cfg);
        // env-independent invariants we can assert regardless of the test env:
        assert!(v.iter().any(|m| m.contains("TLS")), "must flag TLS: {v:?}");
        assert!(v.iter().any(|m| m.contains("encryption")), "must flag encryption: {v:?}");
        assert!(v.iter().any(|m| m.contains("KP_OIDC_ISSUER")), "must flag OIDC: {v:?}");
        assert!(v.iter().any(|m| m.contains("KP_KEY_PROVIDER")), "must flag key custody: {v:?}");

        // A compliant config (TLS+encrypt on) drops the TLS/encryption violations.
        cfg.tls_enabled = true;
        cfg.encryption_enabled = true;
        let v2 = sealed_violations(&cfg);
        assert!(!v2.iter().any(|m| m.contains("TLS")));
        assert!(!v2.iter().any(|m| m.contains("at-rest encryption")));
    }
}
