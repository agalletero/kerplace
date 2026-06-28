//! MinIO `madmin` payload encryption, compatible with `mc admin` requests.
//!
//! The `mc` admin client encrypts sensitive request bodies (e.g. the secret key
//! in `add-user`) and expects encrypted responses (e.g. `list-users`) using
//! MinIO's `madmin.EncryptData`/`DecryptData` scheme. Implementing it here lets
//! `mc admin user ...` interoperate with KerPlace's [`crate::iam`] store.
//!
//! Wire format: `salt(32) || aeadId(1) || nonce(8) || sioStream`.
//! - `aeadId`: `0x00` argon2id+AES-256-GCM, `0x01` argon2id+ChaCha20-Poly1305,
//!   `0x02` PBKDF2(SHA-256)+AES-256-GCM.
//! - The body is a `secure-io/sio-go` stream: plaintext split into 16 KiB
//!   packages, each sealed with a 12-byte nonce (`8-byte prefix || u32 LE
//!   sequence`) and 1-byte associated data (`0x00` normal, `0x80` final).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::ChaCha20Poly1305;
use rand::RngCore;

/// AEAD id: Argon2id key derivation + AES-256-GCM.
const ID_ARGON2_AESGCM: u8 = 0x00;
/// AEAD id: Argon2id key derivation + ChaCha20-Poly1305.
const ID_ARGON2_CHACHA: u8 = 0x01;
/// AEAD id: PBKDF2(SHA-256) key derivation + AES-256-GCM.
const ID_PBKDF2_AESGCM: u8 = 0x02;

/// Salt length prepended to every encrypted blob.
const SALT_LEN: usize = 32;
/// Random nonce-prefix length (the sio stream nonce size).
const NONCE_PREFIX_LEN: usize = 8;
/// Plaintext package size used by the sio stream (16 KiB).
const BUF_SIZE: usize = 1 << 14;
/// AEAD tag length (both AES-256-GCM and ChaCha20-Poly1305 use 16 bytes).
const TAG_LEN: usize = 16;
/// PBKDF2 iteration count used by madmin.
const PBKDF2_ROUNDS: u32 = 8192;

/// Errors from madmin payload (de)serialization.
#[derive(Debug)]
pub enum MadminError {
    /// The blob is shorter than the fixed header or otherwise malformed.
    Format,
    /// An unsupported AEAD id byte was encountered.
    UnsupportedCipher(u8),
    /// AEAD authentication failed (wrong secret or tampered data).
    Decrypt,
}

impl std::fmt::Display for MadminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MadminError::Format => write!(f, "malformed madmin payload"),
            MadminError::UnsupportedCipher(id) => write!(f, "unsupported madmin cipher id {id:#x}"),
            MadminError::Decrypt => write!(f, "madmin payload decryption failed"),
        }
    }
}

/// Derive the 32-byte key for a given scheme from the password and salt.
///
/// # Parameters
/// - `id`: the AEAD scheme id.
/// - `password`: the shared secret (the admin's secret key).
/// - `salt`: the 32-byte salt from the blob header.
///
/// # Returns
/// The derived 32-byte key, or [`MadminError::UnsupportedCipher`].
fn derive_key(id: u8, password: &str, salt: &[u8]) -> Result<[u8; 32], MadminError> {
    let mut key = [0u8; 32];
    match id {
        ID_ARGON2_AESGCM | ID_ARGON2_CHACHA => {
            // Argon2id: time=1, memory=64 MiB, parallelism=4, len=32 (madmin params).
            let params = Params::new(64 * 1024, 1, 4, Some(32)).map_err(|_| MadminError::Format)?;
            let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            argon
                .hash_password_into(password.as_bytes(), salt, &mut key)
                .map_err(|_| MadminError::Format)?;
        }
        ID_PBKDF2_AESGCM => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt, PBKDF2_ROUNDS, &mut key);
        }
        other => return Err(MadminError::UnsupportedCipher(other)),
    }
    Ok(key)
}

/// Build the 12-byte AEAD nonce for package `seq` from the 8-byte prefix
/// (`prefix || u32 little-endian seq`).
fn package_nonce(prefix: &[u8], seq: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_LEN..].copy_from_slice(&seq.to_le_bytes());
    nonce
}

/// Compute the per-stream associated-data buffer used by `sio-go`:
/// `[flag] || tag`, where `tag` is the AEAD tag of an empty plaintext sealed
/// under the sequence-0 nonce with the user associated data (`nil` for madmin).
///
/// The constructor consumes sequence number 0 to build this, so the first real
/// data package starts at sequence number 1.
///
/// # Parameters
/// - `id`: AEAD scheme id.
/// - `key`: derived 32-byte key.
/// - `prefix`: the 8-byte nonce prefix.
///
/// # Returns
/// The 16-byte reference tag.
fn reference_tag(id: u8, key: &[u8; 32], prefix: &[u8]) -> Vec<u8> {
    let nonce0 = package_nonce(prefix, 0);
    // Seal an empty plaintext with empty user-AD; the result is just the tag.
    seal_package(id, key, &nonce0, &[], &[])
}

/// Build the 17-byte sio associated data for a package: `[flag] || refTag`.
fn package_aad(flag: u8, ref_tag: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + ref_tag.len());
    aad.push(flag);
    aad.extend_from_slice(ref_tag);
    aad
}

/// Seal one sio package with the selected AEAD.
fn seal_package(id: u8, key: &[u8; 32], nonce: &[u8; 12], pt: &[u8], aad: &[u8]) -> Vec<u8> {
    let payload = Payload { msg: pt, aad };
    match id {
        ID_ARGON2_CHACHA => ChaCha20Poly1305::new(key.into())
            .encrypt(Nonce::from_slice(nonce), payload)
            .expect("AEAD seal never fails"),
        _ => Aes256Gcm::new(key.into())
            .encrypt(Nonce::from_slice(nonce), payload)
            .expect("AEAD seal never fails"),
    }
}

/// Open one sio package with the selected AEAD.
fn open_package(
    id: u8,
    key: &[u8; 32],
    nonce: &[u8; 12],
    ct: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, MadminError> {
    let payload = Payload { msg: ct, aad };
    let res = match id {
        ID_ARGON2_CHACHA => {
            ChaCha20Poly1305::new(key.into()).decrypt(Nonce::from_slice(nonce), payload)
        }
        _ => Aes256Gcm::new(key.into()).decrypt(Nonce::from_slice(nonce), payload),
    };
    res.map_err(|_| MadminError::Decrypt)
}

/// Encrypt `data` with the madmin scheme (Argon2id + AES-256-GCM).
///
/// Produces a blob `mc` can decrypt with the same `password` (the admin secret
/// key). Used for the `list-users` response body.
///
/// # Parameters
/// - `password`: the shared secret (admin's secret key).
/// - `data`: the plaintext to protect.
///
/// # Returns
/// The encrypted blob: `salt || id || nonce || sioStream`.
pub fn encrypt_data(password: &str, data: &[u8]) -> Vec<u8> {
    let id = ID_ARGON2_AESGCM;
    let mut salt = [0u8; SALT_LEN];
    let mut prefix = [0u8; NONCE_PREFIX_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut prefix);
    let key = derive_key(id, password, &salt).expect("argon2 derivation");

    let mut out = Vec::with_capacity(SALT_LEN + 1 + NONCE_PREFIX_LEN + data.len() + TAG_LEN);
    out.extend_from_slice(&salt);
    out.push(id);
    out.extend_from_slice(&prefix);

    // sio-go consumes sequence 0 to derive the reference tag; data packages
    // start at sequence 1 and carry `[flag] || refTag` as associated data.
    let ref_tag = reference_tag(id, &key, &prefix);
    let mut seq: u32 = 1;
    if data.is_empty() {
        let nonce = package_nonce(&prefix, seq);
        out.extend(seal_package(id, &key, &nonce, &[], &package_aad(0x80, &ref_tag)));
        return out;
    }
    let mut chunks = data.chunks(BUF_SIZE).peekable();
    while let Some(chunk) = chunks.next() {
        let is_final = chunks.peek().is_none();
        let aad = package_aad(if is_final { 0x80 } else { 0x00 }, &ref_tag);
        let nonce = package_nonce(&prefix, seq);
        out.extend(seal_package(id, &key, &nonce, chunk, &aad));
        seq += 1;
    }
    out
}

/// Decrypt a madmin-encrypted blob produced by `mc admin` (e.g. `add-user`).
///
/// # Parameters
/// - `password`: the shared secret (admin's secret key).
/// - `blob`: the encrypted blob (`salt || id || nonce || sioStream`).
///
/// # Returns
/// The recovered plaintext, or a [`MadminError`].
pub fn decrypt_data(password: &str, blob: &[u8]) -> Result<Vec<u8>, MadminError> {
    let header = SALT_LEN + 1 + NONCE_PREFIX_LEN;
    if blob.len() < header {
        return Err(MadminError::Format);
    }
    let salt = &blob[..SALT_LEN];
    let id = blob[SALT_LEN];
    let prefix = &blob[SALT_LEN + 1..header];
    let key = derive_key(id, password, salt)?;

    let stream = &blob[header..];
    let ref_tag = reference_tag(id, &key, prefix);
    let max_pkg = BUF_SIZE + TAG_LEN;
    let mut out = Vec::with_capacity(stream.len());
    // Data packages start at sequence 1 (sequence 0 derived the reference tag).
    let mut seq: u32 = 1;
    let mut rest = stream;
    loop {
        let is_final = rest.len() <= max_pkg;
        let take = if is_final { rest.len() } else { max_pkg };
        if take < TAG_LEN {
            return Err(MadminError::Format);
        }
        let aad = package_aad(if is_final { 0x80 } else { 0x00 }, &ref_tag);
        let nonce = package_nonce(prefix, seq);
        out.extend(open_package(id, &key, &nonce, &rest[..take], &aad)?);
        rest = &rest[take..];
        seq += 1;
        if is_final {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A round-trip through our own encrypt/decrypt recovers the plaintext for
    /// short, exactly-one-package, and multi-package inputs.
    #[test]
    fn roundtrip_all_sizes() {
        for len in [0usize, 16, 100, BUF_SIZE - 1, BUF_SIZE, BUF_SIZE + 1, 3 * BUF_SIZE + 7] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let blob = encrypt_data("s3cr3t-key", &data);
            let back = decrypt_data("s3cr3t-key", &blob).unwrap();
            assert_eq!(back, data, "len {len}");
        }
    }

    /// The wrong password fails authentication rather than returning garbage.
    #[test]
    fn wrong_password_fails() {
        let blob = encrypt_data("right", b"{\"status\":\"enabled\"}");
        assert!(matches!(decrypt_data("wrong", &blob), Err(MadminError::Decrypt)));
    }

    /// Cross-check the full stream body against the authoritative Go `sio-go`
    /// vector (fixed salt + nonce prefix), proving byte-exact interop.
    #[test]
    fn matches_go_sio_vector() {
        let salt: [u8; 32] = std::array::from_fn(|i| i as u8);
        let prefix: [u8; 8] = std::array::from_fn(|i| 100 + i as u8);
        let pt = br#"{"secretKey":"davesecret123","status":"enabled"}"#;
        let key = derive_key(ID_ARGON2_AESGCM, "s3cr3t", &salt).unwrap();
        let ref_tag = reference_tag(ID_ARGON2_AESGCM, &key, &prefix);
        let nonce = package_nonce(&prefix, 1);
        let ct = seal_package(ID_ARGON2_AESGCM, &key, &nonce, pt, &package_aad(0x80, &ref_tag));
        let go = "9f674e18e5ffb501157bf00947e9cabaa8a77e6786fe8e123c5bf3eed7ab2de5\
d0d278a9feb0dc4f1237b9fc148646dd9a0c2059dea832d2adf891c948fba722";
        assert_eq!(hex::encode(&ct), go, "stream body must match Go sio-go");
    }

    /// The header layout matches the madmin wire format.
    #[test]
    fn header_layout() {
        let blob = encrypt_data("k", b"hi");
        assert_eq!(blob[SALT_LEN], ID_ARGON2_AESGCM);
        assert!(blob.len() >= SALT_LEN + 1 + NONCE_PREFIX_LEN + 2 + TAG_LEN);
    }
}
