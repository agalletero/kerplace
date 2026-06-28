//! Key custody seam: the [`KeyProvider`] trait + the `file` implementation.
//!
//! This is the foundation of KerPlace's custody axis (Block K). It isolates
//! **where the key-encryption key (KEK) that wraps a DEK comes from** behind a
//! single small trait, the same way [`crate::storage::ObjectStore`] isolates
//! storage and [`crate::erasure::drive::Drive`] isolates disk I/O. Every later
//! custody mode (passphrase, KMS, TPM, PKCS#11) becomes an additive impl of this
//! trait — none of them touch the cipher container, the algorithms, or the HTTP
//! layer.
//!
//! ## Envelope invariant
//!
//! On disk a DEK is **always stored wrapped** by the provider's KEK. No code path
//! persists a bare DEK. [`Dek`] is not [`serde::Serialize`] and only exposes its
//! bytes crate-internally to build the AES cipher, so the type system helps keep
//! that invariant. The only persisted form is [`WrappedDek`].
//!
//! ## Note on the wrap API (deviation from the K0 design doc)
//!
//! The design sketched `wrap_dek(&self, dek) -> WrappedDek`. That shape does not
//! fit ML-KEM: the KEM *generates* the DEK as its decapsulation shared secret —
//! there is no operation that wraps an externally chosen DEK without changing the
//! on-disk `KPE\x01` layout (which K0 must preserve). The honest, format-preserving
//! seam is therefore [`KeyProvider::new_wrapped_dek`] (produce a fresh DEK already
//! wrapped) + [`KeyProvider::unwrap_dek`]. Re-wrapping an existing DEK under a new
//! KEK (key rotation) is a later concern (K7) and may require a format bump.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::json;
use zeroize::Zeroize;

use super::{
    generate_dek, unwrap_dek, wrap_dek, MasterKey, PqKeypair, ALG_AES_MASTER, ALG_KMS, ALG_MLKEM,
    MLKEM_CT_LEN, WRAPPED_DEK_LEN_AES,
};

/// Errors produced by a [`KeyProvider`].
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// The provider could not perform an operation because its backing key store
    /// is unreachable (e.g. a KMS round-trip failed). `file` never returns this;
    /// the `kms` provider (K3) will.
    #[allow(dead_code)]
    #[error("key provider unavailable: {0}")]
    Unavailable(String),
    /// Unwrapping a stored DEK failed authentication (wrong key or tampered blob).
    #[error("DEK unwrap failed")]
    Unwrap,
    /// The wrapped-DEK blob is malformed or its `alg` byte is unknown to this provider.
    #[error("malformed wrapped DEK")]
    Format,
    /// `KP_KEY_PROVIDER` named a provider this build does not implement.
    #[error("unknown key provider: {0}")]
    Unknown(String),
}

impl From<KeyError> for super::CryptoError {
    /// Collapse a [`KeyError`] into the coarser container-level [`super::CryptoError`]
    /// used by the streaming readers and [`super::ObjectCipher`].
    ///
    /// # Parameters
    /// - `e`: the key-layer error.
    ///
    /// # Returns
    /// [`super::CryptoError::Decrypt`] for an authentication failure (wrong key),
    /// [`super::CryptoError::Provider`] for an unavailable/misconfigured provider
    /// (e.g. a KMS outage), otherwise [`super::CryptoError::Format`].
    fn from(e: KeyError) -> Self {
        match e {
            KeyError::Unwrap => super::CryptoError::Decrypt,
            KeyError::Format => super::CryptoError::Format,
            other => super::CryptoError::Provider(other.to_string()),
        }
    }
}

/// A 256-bit data-encryption key, zeroized on drop.
///
/// `Dek` is deliberately **not** [`serde::Serialize`] and exposes its raw bytes
/// only crate-internally (to build the AES cipher) — the only persisted form of a
/// key is the wrapped [`WrappedDek`]. This is the type-level half of the envelope
/// invariant (see module docs).
pub struct Dek([u8; 32]);

impl Drop for Dek {
    /// Zeroize the key material when the DEK is dropped, so plaintext key bytes do
    /// not linger in freed memory.
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Dek {
    /// Construct a DEK from raw key material.
    ///
    /// # Parameters
    /// - `bytes`: the 32-byte key (a fresh random DEK, or an ML-KEM shared secret).
    ///
    /// # Returns
    /// A [`Dek`] owning `bytes`; the bytes are zeroized when it drops.
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Dek(bytes)
    }

    /// Borrow the raw key bytes (crate-internal; used to build the AES cipher).
    ///
    /// Kept `pub(crate)` so the bytes cannot escape the crate and so `Dek` never
    /// gains a public, serializable byte accessor.
    ///
    /// # Returns
    /// A reference to the 32-byte key.
    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A DEK in its at-rest wrapped form: an `alg` tag plus the algorithm-specific blob.
///
/// This is the named type for what the `KPE\x01` container has always stored in its
/// header — its byte layout is unchanged, so objects written before the K0 seam
/// keep decrypting.
pub struct WrappedDek {
    /// Wrapping scheme: [`ALG_AES_MASTER`] or [`ALG_MLKEM`] today.
    pub alg: u8,
    /// Algorithm-specific bytes: an AES-GCM wrap, or the ML-KEM ciphertext.
    pub bytes: Vec<u8>,
}

/// A provider's honest threat-model self-report, surfaced in `info`/console/banner.
///
/// Every provider must declare what it does **not** protect — this is the K1
/// honesty requirement and feeds `SECURITY_MODEL.md`.
#[derive(Debug, Clone, Copy)]
pub struct KeyPosture {
    /// Stable provider identifier (e.g. `"file"`).
    pub kind: &'static str,
    /// Can the server start with no human to supply a factor?
    pub unattended_boot: bool,
    /// Does the unwrap factor live on this host (vs. an external HSM/KMS)?
    pub key_on_host: bool,
    /// Short honest phrase: what custody this posture *does* protect against.
    pub protects: &'static str,
    /// Short honest phrase: what it explicitly does *not* protect against.
    pub does_not_protect: &'static str,
}

impl KeyPosture {
    /// Render this posture as the canonical JSON object surfaced by the admin
    /// `info` endpoint and the console `/storage` endpoint (one shape, one place).
    ///
    /// # Returns
    /// A JSON object with the provider kind and its honest protect/does-not-protect
    /// phrasing.
    pub(crate) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "kind": self.kind,
            "unattendedBoot": self.unattended_boot,
            "keyOnHost": self.key_on_host,
            "protects": self.protects,
            "doesNotProtect": self.does_not_protect,
        })
    }
}

/// Owns the KEK and performs envelope operations on per-object DEKs.
///
/// Implementations never expose the KEK to callers. This is the single seam the
/// whole custody axis (Block K) plugs into.
#[async_trait]
pub trait KeyProvider: Send + Sync {
    /// Stable identifier for logs / `info` / console (e.g. `"file"`, `"kms"`).
    fn kind(&self) -> &'static str;

    /// Generate a fresh per-object DEK already wrapped for at-rest storage.
    ///
    /// Returns the live [`Dek`] (used immediately to seal the object) together
    /// with its opaque [`WrappedDek`] (written into the container header). The bare
    /// DEK is never persisted — only the wrapped form is.
    ///
    /// # Returns
    /// `(dek, wrapped)` on success, or a [`KeyError`].
    async fn new_wrapped_dek(&self) -> Result<(Dek, WrappedDek), KeyError>;

    /// Unwrap a stored DEK. Must accept every `alg` this provider has ever written
    /// (backward-decodable: [`ALG_AES_MASTER`] and [`ALG_MLKEM`] today).
    ///
    /// # Parameters
    /// - `wrapped`: the wrapped-DEK blob from a container header.
    ///
    /// # Returns
    /// The recovered [`Dek`], or a [`KeyError`].
    async fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<Dek, KeyError>;

    /// Length in bytes of the wrapped DEK this provider writes for **new** objects.
    ///
    /// Used to compute the container header length without generating a key.
    ///
    /// # Returns
    /// The wrapped-DEK length for newly written objects.
    fn wrapped_dek_len(&self) -> usize;

    /// Threat-model self-report, surfaced in `info`/console/startup banner.
    ///
    /// # Returns
    /// The provider's [`KeyPosture`].
    fn posture(&self) -> KeyPosture;

    /// Liveness/availability check used at startup and by health.
    ///
    /// `file` is always `Ok` (keys are local); a future `kms` round-trips the KMS.
    ///
    /// # Returns
    /// `Ok(())` if the provider can unwrap, or a [`KeyError`].
    async fn check(&self) -> Result<(), KeyError> {
        Ok(())
    }
}

/// The `file` provider: today's behaviour — the KEK is a master key (and optional
/// ML-KEM keypair) read from `.kerplace.sys/` on the local host.
///
/// New objects are wrapped with `ALG_MLKEM` when a PQ keypair is present, else
/// `ALG_AES_MASTER`. Both algorithms are always accepted on unwrap so objects
/// already on disk keep decrypting.
pub struct FileKeyProvider {
    /// Legacy AES-256-GCM master key (KEK for `ALG_AES_MASTER`; always present).
    master: MasterKey,
    /// Optional ML-KEM-1024 keypair; when present, new objects use `ALG_MLKEM`.
    pq: Option<PqKeypair>,
}

impl FileKeyProvider {
    /// Build a `file` provider from the on-host key material.
    ///
    /// # Parameters
    /// - `master`: the AES master key (loaded from `master.key`).
    /// - `pq`: the optional ML-KEM-1024 keypair (loaded from `pq.bin`).
    ///
    /// # Returns
    /// A [`FileKeyProvider`].
    pub fn new(master: MasterKey, pq: Option<PqKeypair>) -> Self {
        FileKeyProvider { master, pq }
    }

    /// Load (or first-time generate) the on-host key material from `sys_dir`:
    /// `master.key` (AES) and `pq.bin` (ML-KEM-1024).
    ///
    /// # Parameters
    /// - `sys_dir`: the `.kerplace.sys/` directory.
    ///
    /// # Returns
    /// A `file` provider, or [`KeyError::Unavailable`] on an I/O / format error.
    fn load(sys_dir: &Path) -> Result<Self, KeyError> {
        let master = MasterKey::load_or_generate(&sys_dir.join("master.key"))
            .map_err(|e| KeyError::Unavailable(format!("master.key: {e}")))?;
        let pq = PqKeypair::load_or_generate(&sys_dir.join("pq.bin"))
            .map_err(|e| KeyError::Unavailable(format!("pq.bin: {e}")))?;
        Ok(FileKeyProvider::new(master, Some(pq)))
    }
}

#[async_trait]
impl KeyProvider for FileKeyProvider {
    fn kind(&self) -> &'static str {
        "file"
    }

    async fn new_wrapped_dek(&self) -> Result<(Dek, WrappedDek), KeyError> {
        if let Some(pq) = &self.pq {
            // Post-quantum: the encapsulation shared secret IS the DEK; the
            // 1568-byte ciphertext is the wrapped form.
            let (ct, ss) = pq.encapsulate();
            Ok((
                Dek::from_bytes(ss),
                WrappedDek { alg: ALG_MLKEM, bytes: ct.to_vec() },
            ))
        } else {
            // Legacy: a fresh random DEK AES-wrapped under the master key.
            let dek = generate_dek();
            let bytes = wrap_dek(&self.master, &dek);
            Ok((Dek::from_bytes(dek), WrappedDek { alg: ALG_AES_MASTER, bytes }))
        }
    }

    async fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<Dek, KeyError> {
        match wrapped.alg {
            ALG_AES_MASTER => unwrap_dek(&self.master, &wrapped.bytes)
                .map(Dek::from_bytes)
                .map_err(|_| KeyError::Unwrap),
            ALG_MLKEM => self
                .pq
                .as_ref()
                .ok_or(KeyError::Format)?
                .decapsulate(&wrapped.bytes)
                .map(Dek::from_bytes)
                .map_err(|_| KeyError::Unwrap),
            _ => Err(KeyError::Format),
        }
    }

    fn wrapped_dek_len(&self) -> usize {
        if self.pq.is_some() {
            MLKEM_CT_LEN
        } else {
            WRAPPED_DEK_LEN_AES
        }
    }

    fn posture(&self) -> KeyPosture {
        KeyPosture {
            kind: "file",
            unattended_boot: true,
            key_on_host: true,
            protects: "media theft: a discarded/stolen disk or a backup that excludes the key dir",
            does_not_protect: "host compromise, or theft of the whole data directory (keys included)",
        }
    }
}

// ── passphrase provider (K2) ──────────────────────────────────────────────────

/// On-disk filename (under `.kerplace.sys/`) for the persisted Argon2id salt.
const PASSPHRASE_SALT_FILE: &str = "passphrase.salt";
/// On-disk filename for the sealed verifier that detects a wrong passphrase.
const PASSPHRASE_CHECK_FILE: &str = "passphrase.check";
/// Argon2id salt length in bytes (persisted; not secret).
const SALT_LEN: usize = 16;
/// 32-byte sentinel sealed under the derived KEK; opening it verifies the passphrase.
const SENTINEL: [u8; 32] = *b"KerPlace.passphrase.verifier.v1!";

/// The set of key providers this build knows how to construct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderKind {
    /// On-host `master.key` + `pq.bin`.
    File,
    /// KEK derived from an operator passphrase (Argon2id); no key stored on disk.
    Passphrase,
    /// KEK held by an external KMS (Vault Transit); wrap/unwrap are network calls.
    Kms,
}

/// Parse a `KP_KEY_PROVIDER` value into a known provider, or fail fast.
///
/// Pure (no env / no I/O) so it is unit-testable.
///
/// # Parameters
/// - `s`: the configured provider name.
///
/// # Returns
/// The [`ProviderKind`], or [`KeyError::Unknown`] for an unimplemented name — so an
/// unknown value fails fast with a clear error rather than silently falling back.
fn parse_provider_kind(s: &str) -> Result<ProviderKind, KeyError> {
    match s {
        "file" => Ok(ProviderKind::File),
        "passphrase" => Ok(ProviderKind::Passphrase),
        "kms" => Ok(ProviderKind::Kms),
        other => Err(KeyError::Unknown(other.to_string())),
    }
}

/// The `passphrase` provider: the KEK is derived from an operator passphrase via
/// **Argon2id** and is **never written to disk**. Only a (non-secret) salt and a
/// sealed verifier are persisted. DEKs are AES-256-GCM-wrapped under the derived
/// KEK (`ALG_AES_MASTER`); AES-256 keeps post-quantum-acceptable symmetric
/// strength, so the ML-KEM path is intentionally not used here.
///
/// Removing the on-host key is the whole point: a full data-directory backup no
/// longer leaks the means to decrypt. The cost is that the server cannot boot
/// unattended without the passphrase being supplied (`KP_KEY_PASSPHRASE`).
pub struct PassphraseKeyProvider {
    /// The Argon2id-derived key-encryption key (zeroized on drop via [`MasterKey`]).
    kek: MasterKey,
}

impl PassphraseKeyProvider {
    /// Derive a 256-bit KEK from `passphrase` + `salt` via Argon2id
    /// (m = 19 MiB, t = 2, p = 1 — an OWASP-balanced configuration).
    ///
    /// # Parameters
    /// - `passphrase`: the operator passphrase bytes.
    /// - `salt`: the persisted Argon2id salt.
    ///
    /// # Returns
    /// The derived [`MasterKey`] (the KEK), or [`KeyError::Unavailable`] on a KDF error.
    fn derive(passphrase: &[u8], salt: &[u8]) -> Result<MasterKey, KeyError> {
        let params = Params::new(19_456, 2, 1, Some(32))
            .map_err(|e| KeyError::Unavailable(format!("argon2 params: {e}")))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; 32];
        argon
            .hash_password_into(passphrase, salt, &mut out)
            .map_err(|e| KeyError::Unavailable(format!("argon2 derive: {e}")))?;
        let kek = MasterKey::from_bytes(out);
        out.zeroize();
        Ok(kek)
    }

    /// Open an existing passphrase store under `sys_dir`, or initialise one on first
    /// run.
    ///
    /// First run: generate a random salt, derive the KEK, seal [`SENTINEL`] under it,
    /// and persist the salt + sealed verifier. Subsequent runs: re-derive the KEK and
    /// require the verifier to open — a wrong passphrase fails fast.
    ///
    /// # Parameters
    /// - `sys_dir`: the `.kerplace.sys/` directory.
    /// - `passphrase`: the operator passphrase bytes (must be non-empty).
    ///
    /// # Returns
    /// The provider, or [`KeyError`] (`Unavailable` for missing passphrase / I/O,
    /// `Unwrap` for a wrong passphrase).
    fn open_or_init(sys_dir: &Path, passphrase: &[u8]) -> Result<Self, KeyError> {
        if passphrase.is_empty() {
            return Err(KeyError::Unavailable(
                "the `passphrase` provider needs a non-empty KP_KEY_PASSPHRASE".to_string(),
            ));
        }
        let salt_path = sys_dir.join(PASSPHRASE_SALT_FILE);
        let check_path = sys_dir.join(PASSPHRASE_CHECK_FILE);

        if let Ok(salt) = std::fs::read(&salt_path) {
            // Existing store: re-derive and verify against the sealed sentinel.
            let kek = Self::derive(passphrase, &salt)?;
            let blob = std::fs::read(&check_path)
                .map_err(|e| KeyError::Unavailable(format!("{PASSPHRASE_CHECK_FILE}: {e}")))?;
            match unwrap_dek(&kek, &blob) {
                Ok(opened) if opened == SENTINEL => Ok(PassphraseKeyProvider { kek }),
                // The verifier did not open: wrong passphrase (or a tampered store).
                _ => Err(KeyError::Unavailable(
                    "incorrect KP_KEY_PASSPHRASE for this data directory".to_string(),
                )),
            }
        } else {
            // First run: generate salt, derive, seal the sentinel, persist both.
            let mut salt = [0u8; SALT_LEN];
            OsRng.fill_bytes(&mut salt);
            let kek = Self::derive(passphrase, &salt)?;
            let blob = wrap_dek(&kek, &SENTINEL);
            std::fs::create_dir_all(sys_dir)
                .map_err(|e| KeyError::Unavailable(format!("sys dir: {e}")))?;
            std::fs::write(&salt_path, salt)
                .map_err(|e| KeyError::Unavailable(format!("{PASSPHRASE_SALT_FILE}: {e}")))?;
            std::fs::write(&check_path, &blob)
                .map_err(|e| KeyError::Unavailable(format!("{PASSPHRASE_CHECK_FILE}: {e}")))?;
            Ok(PassphraseKeyProvider { kek })
        }
    }
}

#[async_trait]
impl KeyProvider for PassphraseKeyProvider {
    fn kind(&self) -> &'static str {
        "passphrase"
    }

    async fn new_wrapped_dek(&self) -> Result<(Dek, WrappedDek), KeyError> {
        let dek = generate_dek();
        let bytes = wrap_dek(&self.kek, &dek);
        Ok((Dek::from_bytes(dek), WrappedDek { alg: ALG_AES_MASTER, bytes }))
    }

    async fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<Dek, KeyError> {
        match wrapped.alg {
            ALG_AES_MASTER => unwrap_dek(&self.kek, &wrapped.bytes)
                .map(Dek::from_bytes)
                .map_err(|_| KeyError::Unwrap),
            // The passphrase provider holds no ML-KEM key; an `ALG_MLKEM` object
            // was written under the `file` provider and cannot be read here.
            ALG_MLKEM => Err(KeyError::Format),
            _ => Err(KeyError::Format),
        }
    }

    fn wrapped_dek_len(&self) -> usize {
        WRAPPED_DEK_LEN_AES
    }

    fn posture(&self) -> KeyPosture {
        KeyPosture {
            kind: "passphrase",
            unattended_boot: false,
            key_on_host: false,
            protects: "media theft AND a full data-directory backup — the key is derived from a passphrase that is never written to disk",
            does_not_protect: "host compromise while the server runs (the derived key is in memory), or disclosure of the passphrase itself",
        }
    }
}

// ── kms provider (K3) ─────────────────────────────────────────────────────────

/// Fallback wrapped-DEK length before the KMS ciphertext length has been measured
/// (a Vault Transit token for a 32-byte DEK is ~96 bytes). [`KmsKeyProvider::check`]
/// runs at startup and replaces this with the real length before any object write.
const KMS_WRAPPED_LEN_HINT: usize = 96;
/// Default unwrap-DEK cache TTL in seconds (`KP_KMS_CACHE_TTL`; `0` disables).
const KMS_CACHE_TTL_DEFAULT: u64 = 300;
/// Hard cap on cached DEK entries, so a long-lived process can't grow unbounded.
const KMS_CACHE_CAP: usize = 4096;

/// One cached unwrapped DEK (zeroized on eviction/drop).
struct CachedDek {
    bytes: [u8; 32],
    expiry: Instant,
}

impl Drop for CachedDek {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// A small TTL+capacity cache mapping a wrapped DEK token → its unwrapped bytes,
/// so repeated reads of the same object don't each round-trip to the KMS.
#[derive(Default)]
struct DekCache {
    map: HashMap<Vec<u8>, CachedDek>,
}

impl DekCache {
    /// Return the cached DEK for `token` if present and unexpired.
    fn get(&self, token: &[u8]) -> Option<[u8; 32]> {
        match self.map.get(token) {
            Some(c) if c.expiry > Instant::now() => Some(c.bytes),
            _ => None,
        }
    }

    /// Insert (or refresh) a DEK, pruning expired entries (and, if still at the
    /// cap, evicting one) to stay bounded.
    fn put(&mut self, token: Vec<u8>, bytes: [u8; 32], ttl: Duration) {
        let now = Instant::now();
        if self.map.len() >= KMS_CACHE_CAP {
            self.map.retain(|_, c| c.expiry > now);
            if self.map.len() >= KMS_CACHE_CAP {
                if let Some(k) = self.map.keys().next().cloned() {
                    self.map.remove(&k);
                }
            }
        }
        self.map.insert(token, CachedDek { bytes, expiry: now + ttl });
    }
}

/// The `kms` provider: the KEK lives in an external KMS (HashiCorp **Vault
/// Transit**), and wrap/unwrap are network round-trips to it — the on-host process
/// never holds the KEK. This is the regulated-deployment posture (it replaces the
/// "MinIO + KES" split with one binary).
///
/// DEKs are minted and sealed by Vault's `transit/datakey` endpoint and unsealed by
/// `transit/decrypt`; the wrapped form (`ALG_KMS`) is the opaque `vault:vN:…` token.
/// Because every unwrap is a call to the KMS, revoking the Transit key or the token
/// instantly cuts decryption — including against an attacker who has the data at
/// rest but not live KMS access.
pub struct KmsKeyProvider {
    /// HTTP client for the Vault API (plain `reqwest`, like the cluster RPC).
    client: reqwest::Client,
    /// Vault base URL, no trailing slash (e.g. `http://127.0.0.1:8200`).
    endpoint: String,
    /// Transit key name (e.g. `kerplace`).
    key: String,
    /// Vault token presented as `X-Vault-Token`.
    token: String,
    /// Cached length of a wrapped DEK for the current key version (measured by
    /// [`check`](Self::check) at startup); used by [`wrapped_dek_len`].
    wrapped_len: AtomicUsize,
    /// Unwrap-DEK cache (read path), so repeated reads skip the KMS round-trip.
    cache: Mutex<DekCache>,
    /// Cache entry lifetime; `0` disables caching (`KP_KMS_CACHE_TTL`).
    cache_ttl: Duration,
}

/// Build the `reqwest` client used for Vault API calls, honouring optional TLS
/// trust settings.
///
/// The default client (`reqwest::Client::new`) trusts only the bundled public
/// webpki roots — so a Vault served with a **private-CA / self-signed**
/// certificate (the normal case for an on-prem KMS) would be rejected. This lets
/// the operator either pin a private CA or, for dev, skip verification entirely.
///
/// # Parameters
/// - `ca_pem`: optional PEM bytes of a CA to additionally trust (`KP_KMS_CA`).
/// - `skip_verify`: when `true`, disable TLS certificate verification altogether
///   (`KP_KMS_TLS_SKIP_VERIFY`; dev only — the caller should warn).
///
/// # Returns
/// A configured [`reqwest::Client`], or [`KeyError::Unavailable`] if the CA PEM
/// is not a valid certificate or the client cannot be built.
fn build_kms_client(ca_pem: Option<&[u8]>, skip_verify: bool) -> Result<reqwest::Client, KeyError> {
    // Fast path: no TLS customisation → the plain default client (also what the
    // tests against an in-process HTTP fake Vault rely on).
    if ca_pem.is_none() && !skip_verify {
        return Ok(reqwest::Client::new());
    }
    let mut builder = reqwest::Client::builder();
    if let Some(pem) = ca_pem {
        let cert = reqwest::Certificate::from_pem(pem).map_err(|e| {
            KeyError::Unavailable(format!("KP_KMS_CA is not a valid PEM certificate: {e}"))
        })?;
        builder = builder.add_root_certificate(cert);
    }
    if skip_verify {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder
        .build()
        .map_err(|e| KeyError::Unavailable(format!("could not build the KMS HTTP client: {e}")))
}

impl KmsKeyProvider {
    /// Construct a provider from explicit settings (used by `from_env` and tests).
    ///
    /// # Parameters
    /// - `endpoint`: Vault base URL (trailing slash trimmed).
    /// - `key`: Transit key name.
    /// - `token`: Vault token.
    ///
    /// # Returns
    /// A [`KmsKeyProvider`] (no network call is made yet — see [`check`](Self::check)).
    pub fn new(endpoint: &str, key: &str, token: &str) -> Self {
        KmsKeyProvider {
            client: reqwest::Client::new(),
            endpoint: endpoint.trim_end_matches('/').to_string(),
            key: key.to_string(),
            token: token.to_string(),
            wrapped_len: AtomicUsize::new(0),
            cache: Mutex::new(DekCache::default()),
            cache_ttl: Duration::from_secs(KMS_CACHE_TTL_DEFAULT),
        }
    }

    /// Build from `KP_KMS_ENDPOINT` / `KP_KMS_KEY` / `KP_KMS_TOKEN`.
    ///
    /// Optional: `KP_KMS_CACHE_TTL` (unwrap-cache seconds), and — for a Vault on
    /// HTTPS with a private CA — `KP_KMS_CA` (PEM path to trust) or
    /// `KP_KMS_TLS_SKIP_VERIFY` (dev only; disables verification).
    ///
    /// # Returns
    /// The provider, or [`KeyError::Unavailable`] if any required setting is
    /// missing or `KP_KMS_CA` cannot be read/parsed.
    fn from_env() -> Result<Self, KeyError> {
        let endpoint = crate::config::env_var("KMS_ENDPOINT")
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| KeyError::Unavailable("set KP_KMS_ENDPOINT (e.g. http://host:8200)".into()))?;
        let key = crate::config::env_var("KMS_KEY")
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| KeyError::Unavailable("set KP_KMS_KEY (the Vault Transit key name)".into()))?;
        let token = crate::config::env_var("KMS_TOKEN")
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| KeyError::Unavailable("set KP_KMS_TOKEN (the Vault token)".into()))?;
        let mut provider = Self::new(&endpoint, &key, &token);
        if let Some(ttl) = crate::config::env_var("KMS_CACHE_TTL").and_then(|v| v.trim().parse::<u64>().ok()) {
            provider.cache_ttl = Duration::from_secs(ttl);
        }
        // Optional TLS trust, for a Vault served over HTTPS with a private CA.
        let ca_pem = match crate::config::env_var("KMS_CA").filter(|s| !s.trim().is_empty()) {
            Some(path) => Some(std::fs::read(&path).map_err(|e| {
                KeyError::Unavailable(format!("cannot read KP_KMS_CA file `{path}`: {e}"))
            })?),
            None => None,
        };
        let skip_verify = crate::config::env_var("KMS_TLS_SKIP_VERIFY")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        if skip_verify {
            tracing::warn!(
                "KP_KMS_TLS_SKIP_VERIFY is set — KMS TLS certificate verification is DISABLED (dev only)"
            );
        }
        if ca_pem.is_some() || skip_verify {
            provider.client = build_kms_client(ca_pem.as_deref(), skip_verify)?;
        }
        Ok(provider)
    }

    /// Look up an unwrapped DEK in the cache (returns `None` when caching is off).
    ///
    /// # Parameters
    /// - `token`: the wrapped-DEK bytes (the `vault:vN:…` token) used as the key.
    ///
    /// # Returns
    /// The cached 32-byte DEK if present and unexpired, else `None`.
    fn cache_get(&self, token: &[u8]) -> Option<[u8; 32]> {
        if self.cache_ttl.is_zero() {
            return None;
        }
        self.cache.lock().unwrap().get(token)
    }

    /// Store an unwrapped DEK in the cache (no-op when caching is off).
    ///
    /// # Parameters
    /// - `token`: the wrapped-DEK bytes.
    /// - `dek`: the unwrapped 32-byte DEK.
    fn cache_put(&self, token: Vec<u8>, dek: [u8; 32]) {
        if self.cache_ttl.is_zero() {
            return;
        }
        self.cache.lock().unwrap().put(token, dek, self.cache_ttl);
    }

    /// POST a JSON body to a Vault API path, returning the parsed JSON response.
    ///
    /// A transport failure (unreachable KMS) maps to [`KeyError::Unavailable`]; a
    /// non-2xx status maps to `on_status(code)` so callers can distinguish a
    /// transient outage from a permanent rejection (e.g. a foreign ciphertext).
    ///
    /// # Parameters
    /// - `path`: Vault API path after `/v1/` (e.g. `transit/decrypt/kerplace`).
    /// - `body`: the JSON request body.
    /// - `on_status`: maps a non-success HTTP status to a [`KeyError`].
    ///
    /// # Returns
    /// The parsed JSON `data` object, or a [`KeyError`].
    async fn post(
        &self,
        path: &str,
        body: serde_json::Value,
        on_status: impl Fn(reqwest::StatusCode) -> KeyError,
    ) -> Result<serde_json::Value, KeyError> {
        let url = format!("{}/v1/{path}", self.endpoint);
        let resp = self
            .client
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| KeyError::Unavailable(format!("KMS request to {path} failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(on_status(resp.status()));
        }
        resp.json()
            .await
            .map_err(|e| KeyError::Unavailable(format!("KMS returned an unreadable body: {e}")))
    }

    /// Decode a base64 `data.plaintext` field into a 32-byte DEK.
    ///
    /// # Parameters
    /// - `v`: the Vault `data` JSON object.
    /// - `on_err`: error to return on a missing/short/invalid field.
    ///
    /// # Returns
    /// The 32-byte DEK, or `on_err`.
    fn dek_from_plaintext(v: &serde_json::Value, on_err: impl Fn() -> KeyError) -> Result<[u8; 32], KeyError> {
        let b64 = v["data"]["plaintext"].as_str().ok_or_else(&on_err)?;
        let mut bytes = B64.decode(b64).map_err(|_| on_err())?;
        if bytes.len() != 32 {
            bytes.zeroize();
            return Err(on_err());
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(dek)
    }
}

#[async_trait]
impl KeyProvider for KmsKeyProvider {
    fn kind(&self) -> &'static str {
        "kms"
    }

    async fn new_wrapped_dek(&self) -> Result<(Dek, WrappedDek), KeyError> {
        // Vault mints a fresh DEK and returns it together with its wrapped form.
        let data = self
            .post(
                &format!("transit/datakey/plaintext/{}", self.key),
                json!({ "bits": 256 }),
                |c| KeyError::Unavailable(format!("KMS datakey returned HTTP {c}")),
            )
            .await?;
        let ct = data["data"]["ciphertext"]
            .as_str()
            .ok_or_else(|| KeyError::Unavailable("KMS datakey: no ciphertext".into()))?;
        let dek = Self::dek_from_plaintext(&data, || {
            KeyError::Unavailable("KMS datakey: bad plaintext".into())
        })?;
        // Remember the wrapped length so header_len() is correct for this key version.
        self.wrapped_len.store(ct.len(), Ordering::Relaxed);
        Ok((Dek::from_bytes(dek), WrappedDek { alg: ALG_KMS, bytes: ct.as_bytes().to_vec() }))
    }

    async fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<Dek, KeyError> {
        match wrapped.alg {
            ALG_KMS => {
                // Read-path cache: skip the KMS round-trip for a token we've already
                // unwrapped (revocation still bites at the TTL boundary / on restart).
                if let Some(bytes) = self.cache_get(&wrapped.bytes) {
                    return Ok(Dek::from_bytes(bytes));
                }
                let ct = std::str::from_utf8(&wrapped.bytes).map_err(|_| KeyError::Format)?;
                // A 4xx from Vault means a foreign/garbage ciphertext (permanent →
                // Unwrap); transport failures already map to Unavailable in `post`.
                let data = self
                    .post(
                        &format!("transit/decrypt/{}", self.key),
                        json!({ "ciphertext": ct }),
                        |c| {
                            if c.is_server_error() {
                                KeyError::Unavailable(format!("KMS decrypt returned HTTP {c}"))
                            } else {
                                KeyError::Unwrap
                            }
                        },
                    )
                    .await?;
                let dek = Self::dek_from_plaintext(&data, || KeyError::Unwrap)?;
                self.cache_put(wrapped.bytes.clone(), dek);
                Ok(Dek::from_bytes(dek))
            }
            // file/passphrase objects carry no KMS token; this provider can't read them.
            _ => Err(KeyError::Format),
        }
    }

    fn wrapped_dek_len(&self) -> usize {
        match self.wrapped_len.load(Ordering::Relaxed) {
            0 => KMS_WRAPPED_LEN_HINT,
            n => n,
        }
    }

    fn posture(&self) -> KeyPosture {
        KeyPosture {
            kind: "kms",
            unattended_boot: true,
            key_on_host: false,
            protects: "media theft, a full data-directory backup, AND data at rest once the KMS revokes the key/token — the unwrap key never touches this host",
            does_not_protect: "a live host compromise that can call the KMS with our token while the server runs, or compromise of the KMS itself",
        }
    }

    async fn check(&self) -> Result<(), KeyError> {
        // Fail closed: prove we can mint AND unwrap a DEK before serving, and cache
        // the wrapped length for header_len(). Any failure aborts startup.
        let (dek, wrapped) = self.new_wrapped_dek().await?;
        let back = self.unwrap_dek(&wrapped).await?;
        if back.expose() != dek.expose() {
            return Err(KeyError::Unavailable(
                "KMS round-trip mismatch (datakey/decrypt disagree)".into(),
            ));
        }
        Ok(())
    }
}

// ── provider construction ─────────────────────────────────────────────────────

/// Build the configured [`KeyProvider`], reading `KP_KEY_PROVIDER` (default `file`).
///
/// Each provider loads its own key material from `sys_dir`: `file` uses
/// `master.key` + `pq.bin`; `passphrase` derives the KEK from `KP_KEY_PASSPHRASE`
/// (Argon2id) and stores no key on disk. Selecting `passphrase` also applies
/// memory hardening (see [`crate::harden`]).
///
/// # Parameters
/// - `sys_dir`: the `.kerplace.sys/` directory.
///
/// # Returns
/// The selected provider, or a [`KeyError`] (`Unknown` for an unimplemented name,
/// `Unavailable`/`Unwrap` for a missing/wrong passphrase or I/O failure).
pub fn provider_from_env(sys_dir: &Path) -> Result<Arc<dyn KeyProvider>, KeyError> {
    let kind_str = crate::config::env_var("KEY_PROVIDER").unwrap_or_else(|| "file".to_string());
    match parse_provider_kind(&kind_str)? {
        ProviderKind::File => Ok(Arc::new(FileKeyProvider::load(sys_dir)?)),
        ProviderKind::Passphrase => {
            let mut pass = crate::config::env_var("KEY_PASSPHRASE").unwrap_or_default();
            let built = PassphraseKeyProvider::open_or_init(sys_dir, pass.as_bytes());
            pass.zeroize(); // don't leave the passphrase in our heap longer than needed
            let provider = Arc::new(built?);
            // Lock the now-resident KEK against swap + disable core dumps.
            crate::harden::lock_memory();
            Ok(provider)
        }
        // The KEK is off-host (in the KMS); reachability is proven by `check()` at
        // startup, so construction here is just settings + an HTTP client.
        ProviderKind::Kms => Ok(Arc::new(KmsKeyProvider::from_env()?)),
    }
}

/// Build the operator honesty warning for an at-rest posture, if one is warranted.
///
/// Returns `Some(message)` when at-rest encryption is on **and** the unwrap key
/// lives on this host (the `file` provider) — so operators understand that the
/// media-theft protection does *not* extend to a backup/thief that captures the
/// whole data directory (keys included). An external-custody provider
/// (`key_on_host = false`) returns `None`.
///
/// # Parameters
/// - `posture`: the active provider's posture.
/// - `encryption_enabled`: whether objects are written encrypted.
///
/// # Returns
/// The warning text, or `None` if no honesty caveat applies.
pub fn custody_warning(posture: &KeyPosture, encryption_enabled: bool) -> Option<String> {
    if encryption_enabled && posture.key_on_host {
        Some(format!(
            "key provider `{}`: the at-rest key lives on this host (under .kerplace.sys/). \
             At-rest encryption protects a stolen disk or a backup that EXCLUDES that \
             directory — it does NOT protect {}. Keep key material backed up separately, or \
             move to an external-custody provider when available.",
            posture.kind, posture.does_not_protect
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `file` provider with a PQ keypair, for tests.
    fn pq_provider() -> FileKeyProvider {
        FileKeyProvider::new(MasterKey::generate(), Some(PqKeypair::generate()))
    }

    /// A `file` provider with only the AES master key, for tests.
    fn aes_provider() -> FileKeyProvider {
        FileKeyProvider::new(MasterKey::generate(), None)
    }

    /// DoD #2: the provider unwraps DEKs wrapped under both `ALG_AES_MASTER` and
    /// `ALG_MLKEM`.
    #[tokio::test]
    async fn unwraps_both_algs() {
        // AES master path.
        let aes = aes_provider();
        let (dek, wrapped) = aes.new_wrapped_dek().await.unwrap();
        assert_eq!(wrapped.alg, ALG_AES_MASTER);
        assert_eq!(aes.unwrap_dek(&wrapped).await.unwrap().expose(), dek.expose());

        // ML-KEM path.
        let pq = pq_provider();
        let (dek, wrapped) = pq.new_wrapped_dek().await.unwrap();
        assert_eq!(wrapped.alg, ALG_MLKEM);
        assert_eq!(pq.unwrap_dek(&wrapped).await.unwrap().expose(), dek.expose());
    }

    /// DoD #4: the persisted (wrapped) form never equals the bare DEK — the DEK is
    /// only ever stored wrapped. (`Dek` is also not `Serialize`; see module docs.)
    #[tokio::test]
    async fn bare_dek_never_persisted() {
        for provider in [aes_provider(), pq_provider()] {
            let (dek, wrapped) = provider.new_wrapped_dek().await.unwrap();
            assert_ne!(
                wrapped.bytes.as_slice(),
                dek.expose().as_slice(),
                "wrapped DEK must not be the bare DEK"
            );
            // ...and it round-trips back to exactly the live DEK.
            assert_eq!(provider.unwrap_dek(&wrapped).await.unwrap().expose(), dek.expose());
        }
    }

    /// DoD #5 (provider half): `file` reports its kind and an honest posture.
    #[test]
    fn provider_kind_and_posture_surfaced() {
        let p = aes_provider();
        assert_eq!(p.kind(), "file");
        let posture = p.posture();
        assert_eq!(posture.kind, "file");
        assert!(posture.unattended_boot);
        assert!(posture.key_on_host);
        assert!(!posture.does_not_protect.is_empty());
    }

    /// K1: the `file` posture warns (only) when at-rest encryption is on; an
    /// off-host posture never warns.
    #[test]
    fn custody_warning_fires_for_on_host_key() {
        let file = aes_provider().posture();
        assert!(custody_warning(&file, true).is_some(), "file + encryption must warn");
        assert!(custody_warning(&file, false).is_none(), "no encryption => no warning");

        // A hypothetical off-host posture (e.g. a future KMS) never warns.
        let offhost = KeyPosture {
            kind: "kms",
            unattended_boot: true,
            key_on_host: false,
            protects: "x",
            does_not_protect: "y",
        };
        assert!(custody_warning(&offhost, true).is_none(), "off-host custody => no warning");
    }

    /// DoD #6: an unimplemented provider name fails fast with a clear error (no panic).
    #[test]
    fn unknown_provider_rejected() {
        let err = match parse_provider_kind("tpm") {
            Err(e) => e,
            Ok(_) => panic!("`tpm` is not implemented and must be rejected"),
        };
        assert!(matches!(err, KeyError::Unknown(ref s) if s == "tpm"));
        // The implemented providers parse.
        assert_eq!(parse_provider_kind("file").unwrap(), ProviderKind::File);
        assert_eq!(parse_provider_kind("passphrase").unwrap(), ProviderKind::Passphrase);
        assert_eq!(parse_provider_kind("kms").unwrap(), ProviderKind::Kms);
    }

    /// K2: the passphrase provider round-trips a DEK, persists no key on disk,
    /// re-opens with the same passphrase, and rejects a wrong one.
    #[tokio::test]
    async fn passphrase_roundtrip_persist_and_wrong_pass() {
        let dir = tempfile::tempdir().unwrap();
        let sys = dir.path();

        // First run initialises salt + verifier; a DEK round-trips.
        let p1 = PassphraseKeyProvider::open_or_init(sys, b"correct horse").unwrap();
        let (dek, wrapped) = p1.new_wrapped_dek().await.unwrap();
        assert_eq!(wrapped.alg, ALG_AES_MASTER);
        assert_eq!(p1.unwrap_dek(&wrapped).await.unwrap().expose(), dek.expose());

        // No raw key is written — only the (non-secret) salt + sealed verifier.
        assert!(sys.join(PASSPHRASE_SALT_FILE).exists());
        assert!(sys.join(PASSPHRASE_CHECK_FILE).exists());
        assert!(!sys.join("master.key").exists(), "passphrase must not write a master key");

        // Re-opening with the same passphrase derives the same KEK (verifier opens),
        // and can unwrap a DEK wrapped by the first instance.
        let p2 = PassphraseKeyProvider::open_or_init(sys, b"correct horse").unwrap();
        assert_eq!(p2.unwrap_dek(&wrapped).await.unwrap().expose(), dek.expose());

        // A wrong passphrase fails fast (the sealed verifier won't open).
        let err = match PassphraseKeyProvider::open_or_init(sys, b"wrong horse") {
            Err(e) => e,
            Ok(_) => panic!("a wrong passphrase must be rejected"),
        };
        assert!(matches!(err, KeyError::Unavailable(ref m) if m.contains("KP_KEY_PASSPHRASE")));

        // An empty passphrase is rejected up front.
        assert!(matches!(
            PassphraseKeyProvider::open_or_init(sys, b""),
            Err(KeyError::Unavailable(_))
        ));
    }

    /// K2: the passphrase posture is honestly off-host and not unattended; it does
    /// NOT trigger the on-host custody warning.
    #[tokio::test]
    async fn passphrase_posture_is_off_host() {
        let dir = tempfile::tempdir().unwrap();
        let p = PassphraseKeyProvider::open_or_init(dir.path(), b"pw").unwrap();
        let posture = p.posture();
        assert_eq!(posture.kind, "passphrase");
        assert!(!posture.key_on_host);
        assert!(!posture.unattended_boot);
        // Off-host custody => no "key lives on this host" warning.
        assert!(custody_warning(&posture, true).is_none());
    }

    // ── kms (K3): an in-process fake of the Vault Transit envelope API ──────────

    /// Fake `transit/datakey/plaintext/{key}`: mint a random DEK and return it with
    /// a `vault:v1:<b64(dek)>` token (the fake embeds the DEK so decrypt can reverse).
    async fn fake_datakey() -> axum::Json<serde_json::Value> {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        axum::Json(json!({ "data": {
            "plaintext": B64.encode(b),
            "ciphertext": format!("vault:v1:{}", B64.encode(b)),
        }}))
    }

    /// Fake `transit/decrypt/{key}`: reverse the fake token, or 400 on a foreign one.
    async fn fake_decrypt(
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        let ct = body["ciphertext"].as_str().unwrap_or("");
        match ct.strip_prefix("vault:v1:").and_then(|b| B64.decode(b).ok()) {
            Some(bytes) => {
                axum::Json(json!({ "data": { "plaintext": B64.encode(bytes) }})).into_response()
            }
            None => (axum::http::StatusCode::BAD_REQUEST, "invalid ciphertext").into_response(),
        }
    }

    /// Start the fake Vault on an ephemeral port; return its base URL.
    async fn fake_vault() -> String {
        let app = axum::Router::new()
            .route("/v1/transit/datakey/plaintext/{key}", axum::routing::post(fake_datakey))
            .route("/v1/transit/decrypt/{key}", axum::routing::post(fake_decrypt));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    /// The KMS HTTP-client builder: no-TLS-opts and skip-verify both build; a
    /// valid private-CA PEM is accepted (`KP_KMS_CA`); garbage PEM fails loudly.
    #[test]
    fn kms_client_honours_ca_and_skip_verify() {
        // No customisation → the plain default client.
        assert!(build_kms_client(None, false).is_ok());
        // Dev skip-verify builds.
        assert!(build_kms_client(None, true).is_ok());
        // A real self-signed CA PEM is pinned without error.
        let key = rcgen::KeyPair::generate().unwrap();
        let pem = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .pem();
        assert!(build_kms_client(Some(pem.as_bytes()), false).is_ok());
        // A non-certificate is rejected with a clear error.
        let bad = build_kms_client(Some(b"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----"), false);
        assert!(matches!(bad, Err(KeyError::Unavailable(_))));
    }

    /// K3: against a (fake) Vault, the kms provider checks out, mints an `ALG_KMS`
    /// wrapped DEK, and unwraps it back to the same key; the wrapped length is cached.
    #[tokio::test]
    async fn kms_roundtrip_against_fake_vault() {
        let url = fake_vault().await;
        let kms = KmsKeyProvider::new(&url, "kerplace", "root");

        // Fail-closed startup check round-trips datakey + decrypt.
        kms.check().await.unwrap();
        assert!(kms.wrapped_dek_len() > 0, "check() should cache the wrapped length");

        let (dek, wrapped) = kms.new_wrapped_dek().await.unwrap();
        assert_eq!(wrapped.alg, ALG_KMS);
        assert!(wrapped.bytes.starts_with(b"vault:v1:"), "wrapped DEK is the Vault token");
        assert_eq!(kms.unwrap_dek(&wrapped).await.unwrap().expose(), dek.expose());
    }

    /// K3: an unreachable KMS makes startup fail closed (`Unavailable`), and a
    /// foreign ciphertext is a permanent `Unwrap` error (4xx), not a transient one.
    #[tokio::test]
    async fn kms_unreachable_and_foreign_ciphertext() {
        // Nothing is listening here → check() must fail closed.
        let dead = KmsKeyProvider::new("http://127.0.0.1:1", "kerplace", "root");
        assert!(matches!(dead.check().await, Err(KeyError::Unavailable(_))));

        // A real (fake) Vault that 400s a foreign token → Unwrap, not Unavailable.
        let url = fake_vault().await;
        let kms = KmsKeyProvider::new(&url, "kerplace", "root");
        let foreign = WrappedDek { alg: ALG_KMS, bytes: b"vault:v1:not-base64!!".to_vec() };
        assert!(matches!(kms.unwrap_dek(&foreign).await, Err(KeyError::Unwrap)));
    }

    /// `transit/decrypt` that counts how many times it is hit (to prove caching).
    async fn fake_decrypt_counting(
        axum::extract::State(count): axum::extract::State<Arc<AtomicUsize>>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        count.fetch_add(1, Ordering::Relaxed);
        let ct = body["ciphertext"].as_str().unwrap_or("");
        match ct.strip_prefix("vault:v1:").and_then(|b| B64.decode(b).ok()) {
            Some(bytes) => axum::Json(json!({ "data": { "plaintext": B64.encode(bytes) }})).into_response(),
            None => (axum::http::StatusCode::BAD_REQUEST, "invalid ciphertext").into_response(),
        }
    }

    /// Fake Vault whose `decrypt` calls are counted via the returned counter.
    async fn fake_vault_counting() -> (String, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        let app = axum::Router::new()
            .route("/v1/transit/datakey/plaintext/{key}", axum::routing::post(fake_datakey))
            .route("/v1/transit/decrypt/{key}", axum::routing::post(fake_decrypt_counting))
            .with_state(count.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), count)
    }

    /// Review #3: the unwrap-DEK cache avoids repeat KMS decrypts for the same token,
    /// and `KP_KMS_CACHE_TTL=0` (cache_ttl=0) disables it.
    #[tokio::test]
    async fn kms_unwrap_cache_avoids_repeat_calls() {
        let (url, decrypts) = fake_vault_counting().await;

        // Default TTL: first unwrap misses (1 decrypt), the second is cache-served.
        let kms = KmsKeyProvider::new(&url, "kerplace", "root");
        let (dek, wrapped) = kms.new_wrapped_dek().await.unwrap();
        let d1 = kms.unwrap_dek(&wrapped).await.unwrap();
        let d2 = kms.unwrap_dek(&wrapped).await.unwrap();
        assert_eq!(decrypts.load(Ordering::Relaxed), 1, "second unwrap must hit the cache");
        assert_eq!(d1.expose(), dek.expose());
        assert_eq!(d2.expose(), dek.expose());

        // Caching disabled: every unwrap round-trips to the KMS.
        let mut kms2 = KmsKeyProvider::new(&url, "kerplace", "root");
        kms2.cache_ttl = Duration::ZERO;
        let (_d, w2) = kms2.new_wrapped_dek().await.unwrap();
        let before = decrypts.load(Ordering::Relaxed);
        kms2.unwrap_dek(&w2).await.unwrap();
        kms2.unwrap_dek(&w2).await.unwrap();
        assert_eq!(decrypts.load(Ordering::Relaxed) - before, 2, "ttl=0 must not cache");
    }
}
