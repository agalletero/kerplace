//! Mutual TLS for the internal gateway↔drive RPC (`/_kerplace/drive/v1/*`).
//!
//! Without this, the cluster RPC is authenticated by a shared bearer secret over
//! a trusted overlay (Tailscale, a VPC). `KP_CLUSTER_TLS=true` adds **mutual TLS**:
//! the drive presents a server certificate *and* requires a client certificate
//! from the gateway, both verified against a shared cluster CA — so a leaked
//! bearer secret alone no longer lets an unauthenticated peer join, and the
//! transport is encrypted and mutually authenticated.
//!
//! Each node carries one cert/key (used as the **server** identity when it runs as
//! a drive and as the **client** identity when it acts as a gateway), all issued by
//! the same `KP_CLUSTER_TLS_CA`. This requires real PKI — there is no self-signed
//! dev shortcut, since both ends must chain to the same CA.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};

/// Loaded cluster-mTLS material: the CA (to verify peers) plus this node's own
/// certificate chain and private key (PEM bytes).
#[derive(Clone)]
pub struct ClusterTls {
    /// CA certificate PEM used to verify the *peer* (client or server).
    ca_pem: Vec<u8>,
    /// This node's certificate chain PEM.
    cert_pem: Vec<u8>,
    /// This node's private key PEM.
    key_pem: Vec<u8>,
}

impl ClusterTls {
    /// Load cluster-mTLS material from `KP_CLUSTER_TLS_*` if `KP_CLUSTER_TLS` is on.
    ///
    /// # Returns
    /// - `Ok(None)` when cluster mTLS is disabled,
    /// - `Ok(Some(_))` with the loaded material when enabled and complete,
    /// - `Err(_)` when enabled but a CA/cert/key path is missing or unreadable
    ///   (fail closed — don't silently fall back to plaintext).
    pub fn from_env() -> Result<Option<ClusterTls>, String> {
        let enabled = crate::config::env_var("CLUSTER_TLS").map(|v| v == "true").unwrap_or(false);
        if !enabled {
            return Ok(None);
        }
        let read = |suffix: &str| -> Result<Vec<u8>, String> {
            let path = crate::config::env_var(suffix)
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| format!("KP_CLUSTER_TLS=true requires KP_{suffix}"))?;
            std::fs::read(&path).map_err(|e| format!("KP_{suffix} ({path}): {e}"))
        };
        Ok(Some(ClusterTls {
            ca_pem: read("CLUSTER_TLS_CA")?,
            cert_pem: read("CLUSTER_TLS_CERT")?,
            key_pem: read("CLUSTER_TLS_KEY")?,
        }))
    }

    /// Build from explicit PEM bytes (used by tests).
    ///
    /// # Parameters
    /// - `ca_pem` / `cert_pem` / `key_pem`: PEM-encoded CA, node chain, node key.
    #[cfg(test)]
    pub fn from_pem(ca_pem: Vec<u8>, cert_pem: Vec<u8>, key_pem: Vec<u8>) -> Self {
        ClusterTls { ca_pem, cert_pem, key_pem }
    }

    /// Build the rustls [`ServerConfig`] for a **drive**: present this node's cert
    /// and **require** a client certificate that chains to the cluster CA.
    ///
    /// # Returns
    /// An `Arc<ServerConfig>` enforcing mutual TLS, or an error string.
    pub fn server_config(&self) -> Result<Arc<ServerConfig>, String> {
        crate::tls::install_crypto_provider();
        let roots = self.ca_roots()?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| format!("client verifier: {e}"))?;
        let cfg = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(self.cert_chain()?, self.private_key()?)
            .map_err(|e| format!("server cert: {e}"))?;
        Ok(Arc::new(cfg))
    }

    /// Build the reqwest [`Client`](reqwest::Client) for a **gateway**: present
    /// this node's cert as the client identity and verify the drive's server cert
    /// against the cluster CA (no system roots).
    ///
    /// # Returns
    /// A configured `reqwest::Client`, or an error string.
    pub fn reqwest_client(&self) -> Result<reqwest::Client, String> {
        let mut identity_pem = self.cert_pem.clone();
        identity_pem.extend_from_slice(b"\n");
        identity_pem.extend_from_slice(&self.key_pem);
        let identity = reqwest::Identity::from_pem(&identity_pem)
            .map_err(|e| format!("client identity: {e}"))?;
        let ca = reqwest::Certificate::from_pem(&self.ca_pem).map_err(|e| format!("CA cert: {e}"))?;
        reqwest::Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(ca)
            .identity(identity)
            .build()
            .map_err(|e| format!("cluster TLS client: {e}"))
    }

    /// Parse the CA PEM into a rustls root store.
    fn ca_roots(&self) -> Result<RootCertStore, String> {
        let mut roots = RootCertStore::empty();
        for cert in self.cert_chain_from(&self.ca_pem)? {
            roots.add(cert).map_err(|e| format!("add CA root: {e}"))?;
        }
        if roots.is_empty() {
            return Err("CLUSTER_TLS_CA contained no certificates".into());
        }
        Ok(roots)
    }

    /// Parse this node's certificate chain PEM.
    fn cert_chain(&self) -> Result<Vec<CertificateDer<'static>>, String> {
        let chain = self.cert_chain_from(&self.cert_pem)?;
        if chain.is_empty() {
            return Err("CLUSTER_TLS_CERT contained no certificates".into());
        }
        Ok(chain)
    }

    /// Parse a PEM blob into a certificate chain.
    fn cert_chain_from(&self, pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
        rustls_pemfile::certs(&mut &pem[..])
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("parse certificates: {e}"))
    }

    /// Parse this node's private key PEM (PKCS#8 / SEC1 / PKCS#1).
    fn private_key(&self) -> Result<PrivateKeyDer<'static>, String> {
        rustls_pemfile::private_key(&mut &self.key_pem[..])
            .map_err(|e| format!("parse private key: {e}"))?
            .ok_or_else(|| "CLUSTER_TLS_KEY contained no private key".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed CA plus the material to issue leaf certs from it.
    struct TestCa {
        cert: rcgen::Certificate,
        key: rcgen::KeyPair,
        pem: Vec<u8>,
    }

    /// Generate a throwaway CA for the mTLS tests.
    fn test_ca() -> TestCa {
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let pem = cert.pem().into_bytes();
        TestCa { cert, key, pem }
    }

    /// Issue a leaf cert/key (with SAN `san`) signed by `ca` → `(cert_pem, key_pem)`.
    fn issue(ca: &TestCa, san: &str) -> (Vec<u8>, Vec<u8>) {
        let params = rcgen::CertificateParams::new(vec![san.to_string()]).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &ca.cert, &ca.key).unwrap();
        (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
    }

    /// A drive ServerConfig (mutual TLS) and a gateway client both build from
    /// CA-issued material.
    #[test]
    fn builds_server_and_client_configs() {
        let ca = test_ca();
        let (cert, key) = issue(&ca, "drive-0");
        let tls = ClusterTls::from_pem(ca.pem.clone(), cert, key);
        assert!(tls.server_config().is_ok(), "drive mTLS server config must build");
        assert!(tls.reqwest_client().is_ok(), "gateway mTLS client must build");
    }

    /// Malformed material fails loudly rather than silently dropping mTLS.
    #[test]
    fn rejects_malformed_material() {
        let ca = test_ca();
        let (cert, key) = issue(&ca, "drive-0");
        let bad = ClusterTls::from_pem(
            ca.pem.clone(),
            cert.clone(),
            b"-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n".to_vec(),
        );
        assert!(bad.server_config().is_err(), "garbage key must be rejected");
        let bad_ca = ClusterTls::from_pem(b"".to_vec(), cert, key);
        assert!(bad_ca.server_config().is_err(), "empty CA must be rejected");
    }

    /// End-to-end mutual TLS: a CA-issued gateway client reaches an mTLS drive
    /// server, but a client **without** a certificate is rejected at the handshake.
    #[tokio::test]
    async fn mutual_tls_requires_a_client_cert() {
        let ca = test_ca();
        // Server cert SAN must match the connect host (`localhost`).
        let (srv_cert, srv_key) = issue(&ca, "localhost");
        let (cli_cert, cli_key) = issue(&ca, "gateway-1");

        let server_tls = ClusterTls::from_pem(ca.pem.clone(), srv_cert, srv_key);
        let config = axum_server::tls_rustls::RustlsConfig::from_config(server_tls.server_config().unwrap());

        // A trivial drive-like server that requires a client cert.
        let app: axum::Router = axum::Router::new().route("/ping", axum::routing::get(|| async { "pong" }));
        // Grab an ephemeral port, then bind the rustls server to it.
        let addr = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        tokio::spawn(async move {
            axum_server::bind_rustls(addr, config).serve(app.into_make_service()).await.unwrap();
        });
        // Give the listener a moment to start accepting.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let url = format!("https://localhost:{}/ping", addr.port());

        // ✅ A CA-issued gateway client (with its client cert) is accepted.
        let client = ClusterTls::from_pem(ca.pem.clone(), cli_cert, cli_key).reqwest_client().unwrap();
        let ok = client.get(&url).send().await;
        assert_eq!(ok.unwrap().text().await.unwrap(), "pong");

        // ✗ A client that trusts the CA but presents NO client cert is rejected.
        let anon = reqwest::Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(&ca.pem).unwrap())
            .build()
            .unwrap();
        assert!(anon.get(&url).send().await.is_err(), "a client with no cert must be rejected");
    }
}
