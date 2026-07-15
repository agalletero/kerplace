//! At-rest encryption primitives.
//!
//! This module is the cryptographic core of KerPlace. It provides:
//!
//! - a server [`MasterKey`] (load-or-generate) for legacy AES-256-GCM DEK wrapping,
//! - a [`PqKeypair`] (ML-KEM-1024, load-or-generate) for post-quantum DEK encapsulation,
//! - a [`CryptoContext`] combining both keys,
//! - per-object data keys (DEKs) and their wrapping under either key type,
//! - chunked AEAD encryption of an object payload ([`encrypting_reader`] /
//!   [`decrypting_reader`]).
//!
//! ## On-disk object format
//!
//! ```text
//! magic b"KPE\x01" (4) | version (1) | alg (1) | wrappedDekLen u16 (2)
//!   | wrappedDek (N) | baseNonce (8) | chunk*
//! ```
//!
//! The magic is `K`,`P`,`E`,`0x01` ("KerPlace Encryption v1"). The trailing
//! non-printable byte (`0x01`) marks the payload as binary to text tools (git,
//! grep, editors) and reserves the magic's last byte for future format families.
//!
//! Each chunk encrypts up to [`CHUNK_SIZE`] plaintext bytes with AES-256-GCM
//! under the DEK, using a 12-byte nonce of `baseNonce(8) || counter_be(4)`.
//!
//! The `alg` byte selects the DEK wrapping scheme:
//! - `1` (`ALG_AES_MASTER`): DEK is AES-256-GCM encrypted under the master key.
//! - `2` (`ALG_MLKEM`): wrappedDek is the 1568-byte ML-KEM-1024 ciphertext; the
//!   shared secret (32 bytes) from decapsulation IS the DEK.

mod provider;
// `KeyProvider` is public, so the types in its signature must be nameable by an
// implementor (including test doubles) without reaching into the private module.
#[allow(unused_imports)]
pub use provider::{
    custody_warning, provider_from_env, Dek, FileKeyProvider, KeyError, KeyPosture, KeyProvider,
    WrappedDek,
};

use std::path::Path;
use std::sync::Arc;

use ring::aead::{Aad, LessSafeKey, Nonce as RingNonce, UnboundKey, AES_256_GCM};
use ml_kem::{
    DecapsulationKey, Decapsulate, Encapsulate, EncapsulationKey, Kem, KeyExport, MlKem1024,
};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::storage::BodyReader;

/// Magic bytes identifying a KerPlace-encrypted object (`K`,`P`,`E`,`0x01`).
const MAGIC: &[u8; 4] = b"KPE\x01";
/// Current container format version.
const VERSION: u8 = 1;
/// Algorithm id: DEK wrapped with the AES-256-GCM master key.
pub const ALG_AES_MASTER: u8 = 1;
/// Algorithm id: wrappedDek is the ML-KEM-1024 ciphertext; shared secret = DEK.
pub const ALG_MLKEM: u8 = 2;
/// Algorithm id: wrappedDek is an external KMS ciphertext (e.g. a Vault Transit
/// `vault:vN:…` token); the DEK is wrapped/unwrapped by the KMS, never on host.
pub const ALG_KMS: u8 = 3;
/// Plaintext bytes encrypted per chunk (64 KiB).
pub const CHUNK_SIZE: usize = 64 * 1024;
/// AES-GCM tag length in bytes.
const TAG_LEN: usize = 16;
/// AES-GCM nonce length in bytes.
const NONCE_LEN: usize = 12;
/// Length of the random per-object base nonce (the chunk counter fills the rest).
const BASE_NONCE_LEN: usize = 8;
/// ML-KEM-1024 ciphertext length (1568 bytes) — stored as wrappedDek for ALG_MLKEM.
pub const MLKEM_CT_LEN: usize = 1568;
/// ML-KEM-1024 seed length (64 bytes) used to persist the decapsulation key.
const MLKEM_SEED_LEN: usize = 64;
/// ML-KEM-1024 encapsulation key length (1568 bytes).
const MLKEM_EK_LEN: usize = 1568;

/// Errors produced by the crypto layer.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("malformed encrypted object")]
    Format,
    #[error("decryption/authentication failed")]
    Decrypt,
    /// The key provider could not supply the DEK (e.g. a KMS outage) — distinct
    /// from a malformed object, so the operator-facing error is accurate.
    #[error("key provider error: {0}")]
    Provider(String),
}

/// A 256-bit server master key used to wrap per-object data keys (legacy AES path).
///
/// Also the in-memory form of a `passphrase`-derived KEK. Zeroized on drop so the
/// key bytes do not linger in freed memory.
#[derive(Clone)]
pub struct MasterKey([u8; 32]);

impl Drop for MasterKey {
    /// Zeroize the key bytes when the master key (or a clone) drops.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

impl MasterKey {
    /// Generate a fresh random master key.
    ///
    /// # Returns
    /// A new [`MasterKey`] seeded from the OS RNG.
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        MasterKey(key)
    }

    /// Construct a master key from raw bytes.
    ///
    /// # Parameters
    /// - `bytes`: the 32-byte key material.
    ///
    /// # Returns
    /// A [`MasterKey`] wrapping `bytes`.
    #[allow(dead_code)]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        MasterKey(bytes)
    }

    /// Load the master key from `path` (hex-encoded), generating and persisting
    /// a new one if the file does not exist.
    ///
    /// # Parameters
    /// - `path`: file storing the hex-encoded 32-byte key.
    ///
    /// # Returns
    /// The loaded or newly created [`MasterKey`], or an [`std::io::Error`] on
    /// I/O failure or a malformed key file.
    pub fn load_or_generate(path: &Path) -> std::io::Result<Self> {
        if let Ok(contents) = std::fs::read_to_string(path) {
            let raw = hex::decode(contents.trim())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            if raw.len() != 32 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "master key must be 32 bytes",
                ));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&raw);
            return Ok(MasterKey(key));
        }
        let key = MasterKey::generate();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, hex::encode(key.0))?;
        Ok(key)
    }
}

/// ML-KEM-1024 keypair for post-quantum per-object DEK encapsulation.
///
/// New objects encrypted under this key use `ALG_MLKEM`: the 1568-byte encapsulation
/// ciphertext is stored as the wrapped DEK; the 32-byte shared secret from
/// decapsulation is used directly as the AES-256-GCM data-encryption key.
///
/// Existing `ALG_AES_MASTER` objects remain decryptable alongside PQ-wrapped ones.
#[derive(Clone)]
pub struct PqKeypair {
    /// 64-byte seed for reconstructing the decapsulation key on demand.
    seed: [u8; MLKEM_SEED_LEN],
    /// Cached encapsulation key (public key) — used for encryption.
    ek: EncapsulationKey<MlKem1024>,
}

impl PqKeypair {
    /// Generate a fresh ML-KEM-1024 keypair.
    ///
    /// # Returns
    /// A new [`PqKeypair`] from OS entropy.
    pub fn generate() -> Self {
        let (dk, ek) = MlKem1024::generate_keypair();
        let seed: [u8; MLKEM_SEED_LEN] = dk
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("ML-KEM-1024 seed is 64 bytes");
        PqKeypair { seed, ek }
    }

    /// Load the keypair from `path` (binary: seed64 || encap1568), generating
    /// and persisting a fresh one if absent.
    ///
    /// # Parameters
    /// - `path`: file storing the 1632-byte binary keypair.
    ///
    /// # Returns
    /// The loaded or newly generated [`PqKeypair`], or an [`std::io::Error`].
    pub fn load_or_generate(path: &Path) -> std::io::Result<Self> {
        const TOTAL: usize = MLKEM_SEED_LEN + MLKEM_EK_LEN;
        if let Ok(data) = std::fs::read(path) {
            if data.len() == TOTAL {
                let seed: [u8; MLKEM_SEED_LEN] = data[..MLKEM_SEED_LEN]
                    .try_into()
                    .expect("64 bytes");
                let ek_slice = &data[MLKEM_SEED_LEN..];
                let ek = Self::ek_from_slice(ek_slice)
                    .ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid EK")
                    })?;
                return Ok(PqKeypair { seed, ek });
            }
        }
        let kp = Self::generate();
        let mut data = Vec::with_capacity(TOTAL);
        data.extend_from_slice(&kp.seed);
        data.extend_from_slice(kp.ek.to_bytes().as_slice());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, &data)?;
        Ok(kp)
    }

    /// Construct an [`EncapsulationKey`] from a raw 1568-byte slice, returning `None` on error.
    fn ek_from_slice(bytes: &[u8]) -> Option<EncapsulationKey<MlKem1024>> {
        if bytes.len() != MLKEM_EK_LEN {
            return None;
        }
        // Build a fixed-size array that EncapsulationKey::new accepts.
        // hybrid_array::Array<u8, N> implements TryFrom<&[u8]>.
        let arr: ml_kem::Key<EncapsulationKey<MlKem1024>> = bytes.try_into().ok()?;
        EncapsulationKey::<MlKem1024>::new(&arr).ok()
    }

    /// Reconstruct the ML-KEM-1024 decapsulation key from the stored 64-byte seed.
    ///
    /// # Returns
    /// A fresh [`DecapsulationKey`] derived from the stored seed.
    fn dk(&self) -> DecapsulationKey<MlKem1024> {
        let seed: ml_kem::Seed = self
            .seed
            .as_ref()
            .try_into()
            .expect("64-byte seed is always valid");
        DecapsulationKey::<MlKem1024>::from_seed(seed)
    }

    /// Encapsulate: produce a one-time ciphertext and the shared secret to use as DEK.
    ///
    /// # Returns
    /// `(ciphertext_1568, shared_secret_32)` — store the ciphertext as the wrapped DEK.
    pub fn encapsulate(&self) -> ([u8; MLKEM_CT_LEN], [u8; 32]) {
        let (ct, ss) = self.ek.encapsulate();
        let ct_bytes: [u8; MLKEM_CT_LEN] = ct
            .as_slice()
            .try_into()
            .expect("ML-KEM-1024 CT is 1568 bytes");
        let ss_bytes: [u8; 32] = ss
            .as_slice()
            .try_into()
            .expect("ML-KEM-1024 SS is 32 bytes");
        (ct_bytes, ss_bytes)
    }

    /// Decapsulate: recover the 32-byte shared secret (= DEK) from the ciphertext.
    ///
    /// # Parameters
    /// - `ct`: the 1568-byte ML-KEM-1024 ciphertext stored in the object header.
    ///
    /// # Returns
    /// The 32-byte shared secret, or [`CryptoError::Format`] if `ct` is wrong length.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<[u8; 32], CryptoError> {
        let ss = self
            .dk()
            .decapsulate_slice(ct)
            .map_err(|_| CryptoError::Format)?;
        ss.as_slice().try_into().map_err(|_| CryptoError::Format)
    }
}

/// The server's at-rest crypto handle: a shared [`KeyProvider`] that owns the KEK.
///
/// Object encrypt/decrypt no longer reads key material directly; it asks the
/// provider to mint or unwrap a DEK (the K0 custody seam). Cheaply cloneable —
/// the provider lives behind an `Arc`.
#[derive(Clone)]
pub struct CryptoContext {
    /// The configured key provider (`file` today; `passphrase`/`kms`/… later).
    pub provider: Arc<dyn KeyProvider>,
}

impl CryptoContext {
    /// Build a context around an arbitrary [`KeyProvider`].
    ///
    /// # Parameters
    /// - `provider`: the key provider that owns the KEK.
    pub fn new(provider: Arc<dyn KeyProvider>) -> Self {
        CryptoContext { provider }
    }

    /// Build a context using only the AES master key (no PQ) via the `file` provider.
    ///
    /// # Parameters
    /// - `master`: the AES-256 master key.
    pub fn new_aes(master: MasterKey) -> Self {
        CryptoContext::new(Arc::new(FileKeyProvider::new(master, None)))
    }

    /// Build a post-quantum context via the `file` provider.
    ///
    /// # Parameters
    /// - `master`: the AES-256 master key (kept for backward compat decryption).
    /// - `pq`: the ML-KEM-1024 keypair (new objects use PQ wrapping).
    #[allow(dead_code)] // convenience constructor exercised by the test suite
    pub fn new_pq(master: MasterKey, pq: PqKeypair) -> Self {
        CryptoContext::new(Arc::new(FileKeyProvider::new(master, Some(pq))))
    }

    /// Return the on-disk header length for objects newly encrypted by this context.
    ///
    /// # Returns
    /// Header size in bytes: `8 + wrappedDekLen + BASE_NONCE_LEN`, where the wrapped
    /// DEK length is reported by the active provider.
    pub fn header_len(&self) -> u64 {
        (8 + self.provider.wrapped_dek_len() + BASE_NONCE_LEN) as u64
    }
}

/// Generate a fresh random 256-bit data-encryption key (DEK).
///
/// # Returns
/// 32 random bytes.
pub fn generate_dek() -> [u8; 32] {
    let mut dek = [0u8; 32];
    OsRng.fill_bytes(&mut dek);
    dek
}

/// Wrap (encrypt) a DEK under the master key with AES-256-GCM.
///
/// # Parameters
/// - `master`: the server master key.
/// - `dek`: the 32-byte data key to wrap.
///
/// # Returns
/// `nonce(12) || ciphertext || tag(16)` as an opaque wrapped-key blob.
pub fn wrap_dek(master: &MasterKey, dek: &[u8; 32]) -> Vec<u8> {
    let cipher = Aead256::new(&master.0);
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher.seal(&nonce, b"", dek.as_slice());
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Unwrap (decrypt) a DEK produced by [`wrap_dek`].
///
/// # Parameters
/// - `master`: the server master key.
/// - `wrapped`: the wrapped-key blob.
///
/// # Returns
/// The 32-byte DEK, or [`CryptoError`] if malformed or authentication fails.
pub fn unwrap_dek(master: &MasterKey, wrapped: &[u8]) -> Result<[u8; 32], CryptoError> {
    if wrapped.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::Format);
    }
    let (nonce, ciphertext) = wrapped.split_at(NONCE_LEN);
    let nonce: &[u8; NONCE_LEN] = nonce.try_into().expect("NONCE_LEN bytes");
    let cipher = Aead256::new(&master.0);
    let plaintext = cipher.open(nonce, b"", ciphertext)?;
    if plaintext.len() != 32 {
        return Err(CryptoError::Format);
    }
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&plaintext);
    Ok(dek)
}

/// Build the 12-byte chunk nonce from the base nonce and a chunk counter.
///
/// # Parameters
/// - `base`: the 8-byte per-object base nonce.
/// - `counter`: the zero-based chunk index.
///
/// # Returns
/// `base(8) || counter_be(4)`.
fn chunk_nonce(base: &[u8; BASE_NONCE_LEN], counter: u32) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..BASE_NONCE_LEN].copy_from_slice(base);
    nonce[BASE_NONCE_LEN..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// AES-256-GCM cipher for all object/DEK AEAD, backed by `ring` (assembly,
/// multi-block, VAES/AVX-512 where the CPU supports it).
///
/// This replaces the prior RustCrypto `aes-gcm` 0.10 path on the hot encrypt/decrypt
/// loop (P1.5; ~6× on this HW, see `benches/BASELINE.md`). It is **byte-compatible**:
/// AES-256-GCM is a standard, so for the same key/nonce/AAD/plaintext `ring` emits the
/// exact same `ciphertext || tag` the old path did — the on-disk `KPE1` container is
/// unchanged and objects written by either backend interoperate (proved by
/// `ring_rustcrypto_interop`).
///
/// [`seal`](Aead256::seal) returns `ciphertext || tag(16)` (matching the old
/// `Aead::encrypt`); [`open`](Aead256::open) takes that same layout and returns the
/// recovered plaintext.
struct Aead256 {
    key: LessSafeKey,
}

impl Aead256 {
    /// Build a cipher from a 32-byte AES-256 key.
    ///
    /// # Parameters
    /// - `key`: the 32-byte AES-256 key (DEK or master/KEK).
    ///
    /// # Returns
    /// An [`Aead256`] ready to [`seal`](Aead256::seal)/[`open`](Aead256::open).
    fn new(key: &[u8]) -> Self {
        let unbound = UnboundKey::new(&AES_256_GCM, key).expect("32-byte AES-256 key");
        Aead256 { key: LessSafeKey::new(unbound) }
    }

    /// Seal `plaintext` under `nonce` and `aad`, appending the 16-byte GCM tag.
    ///
    /// # Parameters
    /// - `nonce`: the 12-byte unique-per-key nonce.
    /// - `aad`: associated data to authenticate (empty for object chunks / DEK wrap).
    /// - `plaintext`: the bytes to encrypt.
    ///
    /// # Returns
    /// `ciphertext || tag(16)` — identical bytes to the prior RustCrypto path.
    fn seal(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut in_out = Vec::with_capacity(plaintext.len() + TAG_LEN);
        in_out.extend_from_slice(plaintext);
        self.key
            .seal_in_place_append_tag(
                RingNonce::assume_unique_for_key(*nonce),
                Aad::from(aad),
                &mut in_out,
            )
            .expect("AES-GCM seal never fails for valid input");
        in_out
    }

    /// Open `ciphertext || tag(16)` under `nonce` and `aad`, returning the plaintext.
    ///
    /// # Parameters
    /// - `nonce`: the 12-byte nonce used to seal.
    /// - `aad`: the associated data used to seal.
    /// - `ciphertext`: the `ciphertext || tag(16)` blob.
    ///
    /// # Returns
    /// The plaintext, or [`CryptoError::Decrypt`] on an authentication failure.
    fn open(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut in_out = ciphertext.to_vec();
        // `open_in_place` decrypts in place and returns the plaintext prefix; truncate
        // off the now-stale tag so we return the single `in_out` allocation (no copy).
        let plain_len = self
            .key
            .open_in_place(
                RingNonce::assume_unique_for_key(*nonce),
                Aad::from(aad),
                &mut in_out,
            )
            .map_err(|_| CryptoError::Decrypt)?
            .len();
        in_out.truncate(plain_len);
        Ok(in_out)
    }
}

/// Unwrap the per-object DEK via the context's [`KeyProvider`], given the
/// container header's `alg` byte and `wrappedDek` blob.
///
/// # Parameters
/// - `ctx`: the server crypto context (holds the key provider).
/// - `alg`: the algorithm byte from the container header.
/// - `wrapped`: the wrapped-DEK blob from the container header.
///
/// # Returns
/// The [`Dek`], or a [`CryptoError`] if the algorithm is unknown or unwrap fails.
async fn unwrap_dek_for_alg(ctx: &CryptoContext, alg: u8, wrapped: &[u8]) -> Result<Dek, CryptoError> {
    let w = WrappedDek { alg, bytes: wrapped.to_vec() };
    Ok(ctx.provider.unwrap_dek(&w).await?)
}

/// Encrypt an object payload into the KerPlace container format (buffer mode, for tests).
///
/// # Parameters
/// - `master`: the AES master key (wraps a fresh per-object DEK via ALG_AES_MASTER).
/// - `plaintext`: the object bytes to encrypt.
///
/// # Returns
/// The full encrypted container (header + chunks).
#[allow(dead_code)]
pub fn encrypt_object(master: &MasterKey, plaintext: &[u8]) -> Vec<u8> {
    let dek = generate_dek();
    let wrapped = wrap_dek(master, &dek);
    let mut base_nonce = [0u8; BASE_NONCE_LEN];
    OsRng.fill_bytes(&mut base_nonce);

    let cipher = Aead256::new(&dek);
    let mut out = Vec::with_capacity(plaintext.len() + 64);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(ALG_AES_MASTER);
    out.extend_from_slice(&(wrapped.len() as u16).to_be_bytes());
    out.extend_from_slice(&wrapped);
    out.extend_from_slice(&base_nonce);

    for (i, chunk) in plaintext.chunks(CHUNK_SIZE).enumerate() {
        let nonce = chunk_nonce(&base_nonce, i as u32);
        let ciphertext = cipher.seal(&nonce, b"", chunk);
        out.extend_from_slice(&ciphertext);
    }
    out
}

/// Decrypt a container produced by [`encrypt_object`].
///
/// # Parameters
/// - `master`: the AES master key.
/// - `data`: the full encrypted container.
///
/// # Returns
/// The original plaintext, or [`CryptoError`] if malformed or wrong key.
#[allow(dead_code)]
pub async fn decrypt_object(master: &MasterKey, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let ctx = CryptoContext::new_aes(master.clone());
    decrypt_object_with_ctx(&ctx, data).await
}

/// Decrypt a container with a full crypto context (handles both ALG_AES_MASTER and ALG_MLKEM).
///
/// # Parameters
/// - `ctx`: the server crypto context.
/// - `data`: the full encrypted container.
///
/// # Returns
/// The original plaintext, or [`CryptoError`] if malformed, wrong key, or tampered.
#[allow(dead_code)]
pub async fn decrypt_object_with_ctx(ctx: &CryptoContext, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < 8 || &data[0..4] != MAGIC {
        return Err(CryptoError::Format);
    }
    let alg = data[5];
    let wrapped_len = u16::from_be_bytes([data[6], data[7]]) as usize;
    let mut pos = 8;
    if data.len() < pos + wrapped_len + BASE_NONCE_LEN {
        return Err(CryptoError::Format);
    }
    let wrapped = &data[pos..pos + wrapped_len];
    pos += wrapped_len;
    let mut base_nonce = [0u8; BASE_NONCE_LEN];
    base_nonce.copy_from_slice(&data[pos..pos + BASE_NONCE_LEN]);
    pos += BASE_NONCE_LEN;

    let dek = unwrap_dek_for_alg(ctx, alg, wrapped).await?;
    let cipher = Aead256::new(dek.expose());

    let body = &data[pos..];
    let block = CHUNK_SIZE + TAG_LEN;
    let mut out = Vec::with_capacity(body.len());
    let mut offset = 0;
    let mut counter = 0u32;
    while offset < body.len() {
        let end = (offset + block).min(body.len());
        let nonce = chunk_nonce(&base_nonce, counter);
        let plaintext = cipher.open(&nonce, b"", &body[offset..end])?;
        out.extend_from_slice(&plaintext);
        offset = end;
        counter += 1;
    }
    Ok(out)
}

/// Size of one on-disk ciphertext chunk: plaintext chunk plus its GCM tag.
pub const CHUNK_BLOCK: usize = CHUNK_SIZE + TAG_LEN;

/// Buffer size of the in-process streaming pipe between the AEAD task and the HTTP
/// body, in bytes (~2 MiB ≈ 32 chunks).
///
/// The crypto task and the socket run as separate tasks bridged by a
/// [`tokio::io::duplex`]. With a tiny pipe the *fast* `ring` AEAD fills it in a few
/// microseconds, blocks, and then ping-pongs one chunk at a time with the consumer —
/// a small-buffer producer/consumer pathology that **halved GET throughput** vs the
/// slower RustCrypto path (which paced itself). Sizing the pipe to hold a whole
/// typical object lets the producer run ahead, collapsing the wakeup churn (measured
/// +25% GET at 32×; see `benches/BASELINE.md`).
///
/// Tradeoff: this bounds in-flight buffering per active transfer, so peak memory is
/// ~`STREAM_PIPE_BUF × concurrent streams`. 32× (~2 MiB) is generous for typical
/// object sizes; a smaller value likely captures most of the win at lower peak memory
/// and is a worthwhile follow-up to tune under a high-concurrency load.
const STREAM_PIPE_BUF: usize = 32 * CHUNK_BLOCK;

/// Length of an AES-master-wrapped DEK blob: nonce + key + tag = 60 bytes.
pub const WRAPPED_DEK_LEN_AES: usize = NONCE_LEN + 32 + TAG_LEN;

/// Compute the plaintext length from an on-disk ciphertext length and header length.
///
/// # Parameters
/// - `ciphertext_len`: total stored size of the encrypted container.
/// - `header_len`: length of the container header (magic..base nonce).
///
/// # Returns
/// The original plaintext length in bytes.
pub fn plaintext_len(ciphertext_len: u64, header_len: u64) -> u64 {
    if ciphertext_len <= header_len {
        return 0;
    }
    let body = ciphertext_len - header_len;
    let block = CHUNK_BLOCK as u64;
    let full = body / block;
    let rem = body % block;
    if rem == 0 {
        full * CHUNK_SIZE as u64
    } else {
        full * CHUNK_SIZE as u64 + rem.saturating_sub(TAG_LEN as u64)
    }
}

/// A per-object cipher reconstructed from an encrypted object's header, used to
/// decrypt individual chunks (e.g. for HTTP `Range` reads).
pub struct ObjectCipher {
    cipher: Aead256,
    base_nonce: [u8; BASE_NONCE_LEN],
}

impl ObjectCipher {
    /// Parse an object header and unwrap its DEK using the crypto context.
    ///
    /// Dispatches on the `alg` byte: `ALG_AES_MASTER` uses the master key,
    /// `ALG_MLKEM` uses the PQ keypair's decapsulation key.
    ///
    /// # Parameters
    /// - `ctx`: the server crypto context.
    /// - `header`: at least the full container header bytes.
    ///
    /// # Returns
    /// `(cipher, header_len)` on success, or [`CryptoError`] if malformed.
    pub async fn open(ctx: &CryptoContext, header: &[u8]) -> Result<(Self, usize), CryptoError> {
        if header.len() < 8 || &header[0..4] != MAGIC {
            return Err(CryptoError::Format);
        }
        let alg = header[5];
        let wrapped_len = u16::from_be_bytes([header[6], header[7]]) as usize;
        let header_len = 8 + wrapped_len + BASE_NONCE_LEN;
        if header.len() < header_len {
            return Err(CryptoError::Format);
        }
        let wrapped = &header[8..8 + wrapped_len];
        let mut base_nonce = [0u8; BASE_NONCE_LEN];
        base_nonce.copy_from_slice(&header[8 + wrapped_len..header_len]);
        let dek = unwrap_dek_for_alg(ctx, alg, wrapped).await?;
        Ok((
            ObjectCipher {
                cipher: Aead256::new(dek.expose()),
                base_nonce,
            },
            header_len,
        ))
    }

    /// Decrypt a single ciphertext chunk.
    ///
    /// # Parameters
    /// - `counter`: the zero-based chunk index.
    /// - `block`: the chunk ciphertext (`<= CHUNK_BLOCK` bytes).
    ///
    /// # Returns
    /// The chunk plaintext, or [`CryptoError::Decrypt`] on authentication failure.
    pub fn decrypt_chunk(&self, counter: u32, block: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = chunk_nonce(&self.base_nonce, counter);
        self.cipher.open(&nonce, b"", block)
    }
}

/// Wrap a plaintext reader so it yields the encrypted container stream.
///
/// The per-object DEK is minted **eagerly**, before any reader is handed back, so
/// a key-provider failure (KMS unreachable, sealed Vault) surfaces as a
/// caller-visible error — mirroring [`decrypting_reader_checked`] on the read
/// path. This is load-bearing: minting lazily inside the streaming task meant a
/// failure dropped the writer, the consumer saw a clean EOF indistinguishable
/// from an empty body, and a 0-byte object was committed with `200 OK`.
///
/// When `ctx.pq` is `Some`, uses `ALG_MLKEM` (post-quantum DEK encapsulation).
/// Otherwise falls back to `ALG_AES_MASTER`.
///
/// # Parameters
/// - `plaintext`: the source plaintext reader.
/// - `ctx`: the server crypto context.
///
/// # Returns
/// A reader over the `KPE1` container (header + sealed chunks), or
/// [`CryptoError::Provider`] when the DEK cannot be minted — in which case the
/// caller must fail the write rather than commit anything.
pub async fn encrypting_reader(
    mut plaintext: BodyReader,
    ctx: CryptoContext,
) -> Result<BodyReader, CryptoError> {
    // Mint a fresh DEK already wrapped by the provider's KEK (envelope invariant).
    // This is the only fallible outbound call the encrypt path makes, so doing it
    // here — before the reader exists — is what keeps the write fail-closed.
    let (dek, wrapped) = ctx.provider.new_wrapped_dek().await?;

    let (mut writer, reader) = tokio::io::duplex(STREAM_PIPE_BUF);
    tokio::spawn(async move {
        let mut base_nonce = [0u8; BASE_NONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);
        let cipher = Aead256::new(dek.expose());

        let mut header = Vec::with_capacity(8 + wrapped.bytes.len() + BASE_NONCE_LEN);
        header.extend_from_slice(MAGIC);
        header.push(VERSION);
        header.push(wrapped.alg);
        header.extend_from_slice(&(wrapped.bytes.len() as u16).to_be_bytes());
        header.extend_from_slice(&wrapped.bytes);
        header.extend_from_slice(&base_nonce);
        if writer.write_all(&header).await.is_err() {
            return; // the consumer went away; nobody left to tell
        }

        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut counter = 0u32;
        loop {
            let mut filled = 0;
            while filled < CHUNK_SIZE {
                match plaintext.read(&mut buf[filled..]).await {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    // The source died mid-object. A duplex cannot carry an error
                    // to the reader, so at least make it loud: a truncated object
                    // must never pass for a complete one in silence.
                    Err(e) => {
                        tracing::error!("encrypt: source read failed mid-object: {e}");
                        return;
                    }
                }
            }
            if filled == 0 {
                break;
            }
            let nonce = chunk_nonce(&base_nonce, counter);
            let sealed = cipher.seal(&nonce, b"", &buf[..filled]);
            if writer.write_all(&sealed).await.is_err() {
                return;
            }
            counter += 1;
            if filled < CHUNK_SIZE {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });
    Ok(Box::pin(reader))
}

/// Wrap an encrypted-container reader so it yields the decrypted plaintext.
///
/// Handles both `ALG_AES_MASTER` and `ALG_MLKEM` by inspecting the `alg` byte.
///
/// # Parameters
/// - `ciphertext`: the source `KPE1` container reader.
/// - `ctx`: the server crypto context.
///
/// # Returns
/// A reader over the decrypted plaintext. On any error the stream ends early.
/// Wrap an encrypted-container reader so it yields the decrypted plaintext,
/// **eagerly** parsing the header and unwrapping the DEK before returning — so a
/// failure to obtain the data key (a malformed header, or an unavailable/incorrect
/// key provider, e.g. a KMS outage) surfaces as an `Err` to the caller **instead
/// of** silently yielding a truncated/empty body.
///
/// Use this on the object GET / copy paths: the caller can turn the error into a
/// proper non-200 response rather than streaming an empty 200.
///
/// Handles both `ALG_AES_MASTER` and `ALG_MLKEM` (and `ALG_KMS`) by inspecting the
/// `alg` byte via the context's key provider.
///
/// # Parameters
/// - `ciphertext`: the source `KPE1` container reader.
/// - `ctx`: the server crypto context.
///
/// # Returns
/// A reader over the decrypted plaintext, or a [`CryptoError`] if the DEK could not
/// be obtained. (Chunk-level failures *after* this point still end the stream early
/// — that is inherent to streaming AEAD.)
pub async fn decrypting_reader_checked(
    mut ciphertext: BodyReader,
    ctx: CryptoContext,
) -> Result<BodyReader, CryptoError> {
    let (writer, reader) = tokio::io::duplex(STREAM_PIPE_BUF);
    let (cipher, base_nonce) = open_stream_header(&mut ciphertext, &ctx).await?;
    tokio::spawn(stream_chunks(ciphertext, cipher, base_nonce, writer));
    Ok(Box::pin(reader))
}

/// Read and parse the container header from `ciphertext` and eagerly unwrap the
/// per-object DEK, returning the ready AES cipher and base nonce.
///
/// This is where a key-provider failure (KMS unreachable, wrong key) becomes a
/// caller-visible error, before any plaintext is produced.
///
/// # Parameters
/// - `ciphertext`: the container reader, positioned at the start.
/// - `ctx`: the server crypto context.
///
/// # Returns
/// `(cipher, base_nonce)`, or [`CryptoError`] on a malformed header or unwrap failure.
async fn open_stream_header(
    ciphertext: &mut BodyReader,
    ctx: &CryptoContext,
) -> Result<(Aead256, [u8; BASE_NONCE_LEN]), CryptoError> {
    let mut prefix = [0u8; 8];
    ciphertext.read_exact(&mut prefix).await.map_err(|_| CryptoError::Format)?;
    if &prefix[0..4] != MAGIC {
        return Err(CryptoError::Format);
    }
    let alg = prefix[5];
    let wrapped_len = u16::from_be_bytes([prefix[6], prefix[7]]) as usize;
    let mut rest = vec![0u8; wrapped_len + BASE_NONCE_LEN];
    ciphertext.read_exact(&mut rest).await.map_err(|_| CryptoError::Format)?;
    let dek = unwrap_dek_for_alg(ctx, alg, &rest[..wrapped_len]).await?;
    let mut base_nonce = [0u8; BASE_NONCE_LEN];
    base_nonce.copy_from_slice(&rest[wrapped_len..wrapped_len + BASE_NONCE_LEN]);
    let cipher = Aead256::new(dek.expose());
    Ok((cipher, base_nonce))
}

/// Stream-decrypt the chunk body (after the header) into `writer`. Shared by both
/// [`decrypting_reader`] variants. A chunk read/auth failure ends the stream early.
///
/// # Parameters
/// - `ciphertext`: the reader positioned just past the header.
/// - `cipher`: the opened per-object AES cipher.
/// - `base_nonce`: the per-object base nonce.
/// - `writer`: the duplex half the plaintext is written into.
async fn stream_chunks(
    mut ciphertext: BodyReader,
    cipher: Aead256,
    base_nonce: [u8; BASE_NONCE_LEN],
    mut writer: tokio::io::DuplexStream,
) {
    let mut buf = vec![0u8; CHUNK_BLOCK];
    let mut counter = 0u32;
    loop {
        let mut filled = 0;
        while filled < CHUNK_BLOCK {
            match ciphertext.read(&mut buf[filled..]).await {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(_) => return,
            }
        }
        if filled == 0 {
            break;
        }
        let nonce = chunk_nonce(&base_nonce, counter);
        let plain = match cipher.open(&nonce, b"", &buf[..filled]) {
            Ok(p) => p,
            Err(_) => return,
        };
        if writer.write_all(&plain).await.is_err() {
            return;
        }
        counter += 1;
        if filled < CHUNK_BLOCK {
            break;
        }
    }
    let _ = writer.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrapping then unwrapping a DEK returns the original key.
    #[test]
    fn wrap_unwrap_roundtrip() {
        let master = MasterKey::generate();
        let dek = generate_dek();
        let wrapped = wrap_dek(&master, &dek);
        assert_eq!(unwrap_dek(&master, &wrapped).unwrap(), dek);
    }

    /// **Byte-compatibility proof (P1.5).** The new `ring` AEAD ([`Aead256`]) and the
    /// prior RustCrypto `aes-gcm` 0.10 path produce identical AES-256-GCM bytes, so
    /// objects sealed by either decrypt with the other — i.e. objects already on disk
    /// (sealed by the old code) stay readable, and the `KPE1` container is unchanged.
    #[test]
    fn ring_rustcrypto_interop() {
        use aes_gcm::aead::Aead as _;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        let key = [7u8; 32];
        let nonce = [3u8; NONCE_LEN];
        let plaintext = b"objects on disk must survive the AEAD backend swap";

        let rc = Aes256Gcm::new_from_slice(&key).unwrap();
        let ring = Aead256::new(&key);

        // 1. Same key/nonce/empty-AAD ⇒ identical ciphertext||tag (the on-disk bytes).
        let rc_ct = rc.encrypt(Nonce::from_slice(&nonce), plaintext.as_slice()).unwrap();
        let ring_ct = ring.seal(&nonce, b"", plaintext);
        assert_eq!(rc_ct, ring_ct, "ring and RustCrypto must emit identical bytes");

        // 2. ring opens what RustCrypto sealed (old objects decrypt under the new path).
        assert_eq!(ring.open(&nonce, b"", &rc_ct).unwrap(), plaintext);

        // 3. RustCrypto opens what ring sealed (new objects readable by the standard).
        let back = rc.decrypt(Nonce::from_slice(&nonce), ring_ct.as_slice()).unwrap();
        assert_eq!(back, plaintext);
    }

    /// Unwrapping with a different master key fails authentication.
    #[test]
    fn unwrap_wrong_master_fails() {
        let dek = generate_dek();
        let wrapped = wrap_dek(&MasterKey::generate(), &dek);
        assert!(matches!(
            unwrap_dek(&MasterKey::generate(), &wrapped),
            Err(CryptoError::Decrypt)
        ));
    }

    /// Encrypt/decrypt round-trips for empty, small and multi-chunk payloads.
    #[tokio::test]
    async fn encrypt_decrypt_roundtrip() {
        let master = MasterKey::generate();
        for size in [0usize, 1, 100, CHUNK_SIZE, CHUNK_SIZE * 2 + 123] {
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let sealed = encrypt_object(&master, &plaintext);
            if size > 16 {
                assert_ne!(sealed, plaintext);
            }
            let opened = decrypt_object(&master, &sealed).await.unwrap();
            assert_eq!(opened, plaintext, "roundtrip failed for size {size}");
        }
    }

    /// Decrypting with the wrong master key fails.
    #[tokio::test]
    async fn decrypt_wrong_master_fails() {
        let sealed = encrypt_object(&MasterKey::generate(), b"secret payload");
        assert!(decrypt_object(&MasterKey::generate(), &sealed).await.is_err());
    }

    /// Tampering with any ciphertext byte is detected on decrypt.
    #[tokio::test]
    async fn tamper_is_detected() {
        let master = MasterKey::generate();
        let mut sealed = encrypt_object(&master, b"important contents here");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(matches!(
            decrypt_object(&master, &sealed).await,
            Err(CryptoError::Decrypt)
        ));
    }

    /// A truncated/garbage container is rejected as malformed.
    #[tokio::test]
    async fn malformed_container_rejected() {
        let master = MasterKey::generate();
        assert!(matches!(
            decrypt_object(&master, b"nope").await,
            Err(CryptoError::Format)
        ));
    }

    /// DoD #1 (`envelope_roundtrip_file`): a `file`-provider context seals an object
    /// whose on-disk DEK is wrapped (never bare), and decrypts back identically.
    #[tokio::test]
    async fn envelope_roundtrip_file() {
        let ctx = CryptoContext::new_pq(MasterKey::generate(), PqKeypair::generate());
        let data: Vec<u8> = (0..(CHUNK_SIZE + 321)).map(|i| (i % 251) as u8).collect();

        let src: BodyReader = Box::pin(std::io::Cursor::new(data.clone()));
        let mut sealed = Vec::new();
        encrypting_reader(src, ctx.clone())
            .await
            .unwrap()
            .read_to_end(&mut sealed)
            .await
            .unwrap();

        // Header records the wrapping alg; the wrapped DEK occupies the header but
        // the plaintext does not appear in the container.
        assert_eq!(&sealed[0..4], MAGIC);
        assert_eq!(sealed[5], ALG_MLKEM);
        assert!(!sealed.windows(data.len().min(64)).any(|w| w == &data[..data.len().min(64)]));

        let ct: BodyReader = Box::pin(std::io::Cursor::new(sealed));
        let mut out = Vec::new();
        decrypting_reader_checked(ct, ctx).await.unwrap().read_to_end(&mut out).await.unwrap();
        assert_eq!(out, data);
    }

    /// DoD #3 (`pre_k0_object_still_decrypts`): an object written by the pre-seam
    /// AES-master path ([`encrypt_object`]) decrypts through the `file` provider —
    /// proving the seam is non-destructive for objects already on disk.
    #[tokio::test]
    async fn pre_k0_object_still_decrypts() {
        let master = MasterKey::generate();
        let plaintext = b"object written before the K0 seam".to_vec();
        let sealed = encrypt_object(&master, &plaintext); // ALG_AES_MASTER container

        // Open it via a provider-backed context (as the live read path now does).
        let ctx = CryptoContext::new_aes(master);
        let opened = decrypt_object_with_ctx(&ctx, &sealed).await.unwrap();
        assert_eq!(opened, plaintext);
    }

    /// ML-KEM-1024 keypair generation, encapsulation and decapsulation round-trip.
    #[test]
    fn pq_encap_decap_roundtrip() {
        let kp = PqKeypair::generate();
        let (ct, ss1) = kp.encapsulate();
        let ss2 = kp.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    /// ML-KEM-1024 decapsulation with a wrong ciphertext length fails.
    #[test]
    fn pq_decap_bad_ct_length_fails() {
        let kp = PqKeypair::generate();
        assert!(kp.decapsulate(&[0u8; 10]).is_err());
    }

    /// A CryptoContext with a PQ keypair reports the larger ML-KEM header length.
    #[test]
    fn pq_context_writes_mlkem_alg_byte() {
        let pq_ctx = CryptoContext::new_pq(MasterKey::generate(), PqKeypair::generate());
        let aes_ctx = CryptoContext::new_aes(MasterKey::generate());
        // The PQ header carries the 1568-byte ML-KEM ciphertext as the wrapped DEK.
        assert_eq!(pq_ctx.header_len(), (8 + MLKEM_CT_LEN + BASE_NONCE_LEN) as u64);
        assert!(pq_ctx.header_len() > aes_ctx.header_len());
    }

    /// ObjectCipher works on AES-master containers via CryptoContext.
    #[tokio::test]
    async fn object_cipher_decrypts_one_chunk() {
        let master = MasterKey::generate();
        let data: Vec<u8> = (0..(CHUNK_SIZE * 2 + 10)).map(|i| (i % 251) as u8).collect();
        let sealed = encrypt_object(&master, &data);
        let ctx = CryptoContext::new_aes(master);
        let (cipher, header_len) = ObjectCipher::open(&ctx, &sealed).await.unwrap();
        let offset = header_len + CHUNK_BLOCK;
        let block = &sealed[offset..offset + CHUNK_BLOCK];
        let plain = cipher.decrypt_chunk(1, block).unwrap();
        assert_eq!(plain, &data[CHUNK_SIZE..CHUNK_SIZE * 2]);
    }

    /// The streaming reader/writer round-trip with the PQ context.
    #[tokio::test]
    async fn streaming_roundtrip_and_size() {
        let ctx = CryptoContext::new_pq(MasterKey::generate(), PqKeypair::generate());
        for size in [0usize, 100, CHUNK_SIZE, CHUNK_SIZE * 3 + 7] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let src: BodyReader = Box::pin(std::io::Cursor::new(data.clone()));
            let mut sealed = Vec::new();
            encrypting_reader(src, ctx.clone())
                .await
                .unwrap()
                .read_to_end(&mut sealed)
                .await
                .unwrap();

            let header_len = ctx.header_len();
            assert_eq!(
                plaintext_len(sealed.len() as u64, header_len),
                size as u64,
                "size derivation for {size}"
            );

            let ct: BodyReader = Box::pin(std::io::Cursor::new(sealed));
            let mut out = Vec::new();
            decrypting_reader_checked(ct, ctx.clone())
                .await
                .unwrap()
                .read_to_end(&mut out)
                .await
                .unwrap();
            assert_eq!(out, data, "streaming roundtrip for {size}");
        }
    }
}
