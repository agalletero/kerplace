//! TLS support for the S3 API and web console.
//!
//! Two modes, selected by configuration:
//! - **Provided certificate:** `KP_TLS_CERT` + `KP_TLS_KEY` point at
//!   PEM files (production / bring-your-own-cert).
//! - **Self-signed (dev):** `KP_TLS=true` with no cert paths generates a
//!   self-signed certificate for `localhost`, persists it under
//!   `<data_dir>/.kerplace.sys/` and reuses it on subsequent starts.
//!
//! The rustls `ring` crypto provider is installed once, lazily, before any
//! TLS configuration is built.

use std::path::Path;
use std::sync::Once;

use axum_server::tls_rustls::RustlsConfig;
use tracing::info;

use crate::config::Config;

/// Guards one-time installation of the process-wide rustls crypto provider.
static INSTALL_PROVIDER: Once = Once::new();

/// Install the `ring` rustls crypto provider as the process default.
///
/// rustls 0.23 requires a `CryptoProvider` to be installed before any
/// `ServerConfig` is built. This is idempotent and safe to call repeatedly;
/// only the first call has any effect.
///
/// # Returns
/// `()` — installs the provider as a side effect.
pub(crate) fn install_crypto_provider() {
    INSTALL_PROVIDER.call_once(|| {
        // Ignore the error returned when a provider is somehow already set.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Build the [`RustlsConfig`] for the server from the runtime configuration.
///
/// Uses the provided certificate/key when both paths are set; otherwise loads
/// (or generates and persists) a self-signed certificate under the system
/// directory.
///
/// # Parameters
/// - `config`: the runtime configuration (TLS paths + data dir).
///
/// # Returns
/// `Ok(RustlsConfig)` ready to pass to `axum_server::bind_rustls`, or a boxed
/// error if certificate loading or generation fails.
pub async fn build_rustls_config(
    config: &Config,
) -> Result<RustlsConfig, Box<dyn std::error::Error>> {
    install_crypto_provider();

    if let (Some(cert), Some(key)) = (&config.tls_cert, &config.tls_key) {
        info!(cert = ?cert, key = ?key, "TLS: loading provided certificate");
        return Ok(RustlsConfig::from_pem_file(cert, key).await?);
    }

    // No certificate provided — fall back to a persisted self-signed dev cert.
    let sys_dir = config.data_dir.join(".kerplace.sys");
    let cert_path = sys_dir.join("tls-cert.pem");
    let key_path = sys_dir.join("tls-key.pem");

    if cert_path.exists() && key_path.exists() {
        info!("TLS: reusing self-signed certificate from .kerplace.sys");
        return Ok(RustlsConfig::from_pem_file(&cert_path, &key_path).await?);
    }

    info!("TLS: generating self-signed certificate for localhost (dev)");
    let (cert_pem, key_pem) = generate_self_signed()?;
    tokio::fs::create_dir_all(&sys_dir).await?;
    tokio::fs::write(&cert_path, &cert_pem).await?;
    tokio::fs::write(&key_path, &key_pem).await?;

    Ok(RustlsConfig::from_pem(cert_pem.into_bytes(), key_pem.into_bytes()).await?)
}

/// Generate a self-signed certificate and private key in PEM form.
///
/// The certificate is valid for `localhost`, `127.0.0.1` and `::1` so local
/// `mc`/`aws`/`curl` clients can connect (with certificate verification
/// disabled, as for any self-signed cert).
///
/// # Returns
/// `Ok((cert_pem, key_pem))` as PEM-encoded strings, or an `rcgen` error.
fn generate_self_signed() -> Result<(String, String), Box<dyn std::error::Error>> {
    let san = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    let certified = rcgen::generate_simple_self_signed(san)?;
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();
    Ok((cert_pem, key_pem))
}

/// Convenience predicate: is a path a regular, readable file?
///
/// # Parameters
/// - `path`: the path to test.
///
/// # Returns
/// `true` if the path exists and is a file.
#[allow(dead_code)]
pub fn is_file(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-signed generation yields non-empty PEM blocks for cert and key.
    #[test]
    fn self_signed_pem_is_well_formed() {
        let (cert, key) = generate_self_signed().unwrap();
        assert!(cert.contains("BEGIN CERTIFICATE"), "cert PEM malformed");
        assert!(key.contains("BEGIN PRIVATE KEY"), "key PEM malformed");
    }
}
