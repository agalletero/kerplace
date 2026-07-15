//! Shared application state injected into every request handler.

use std::sync::Arc;

use crate::config::Config;
use crate::iam::IamStore;
use crate::storage::ObjectStore;

/// Process-wide state, cheaply cloneable (all fields are behind `Arc`).
///
/// A single instance is created at startup and shared across all
/// connections via axum's `State` extractor and the auth middleware.
#[derive(Clone)]
pub struct AppState {
    /// The active storage backend (filesystem in v0.1, pluggable later).
    pub store: Arc<dyn ObjectStore>,
    /// Immutable runtime configuration.
    pub config: Arc<Config>,
    /// Identity & access management store (credentials + policies).
    pub iam: Arc<IamStore>,
    /// At-rest key-custody handle (the active [`crate::crypto::KeyProvider`]),
    /// so handlers like `info` can report the server's custody posture.
    pub crypto: crate::crypto::CryptoContext,
    /// External OIDC identity provider (D1), or `None` when `KP_OIDC_ISSUER` is
    /// unset. Drives console SSO login and STS `AssumeRoleWithWebIdentity`.
    pub oidc: Option<std::sync::Arc<crate::auth::oidc::Oidc>>,
    /// Fine-grained access log sink (`KP_ACCESS_LOG`), or `None` when the
    /// chronological audit trail is off. See [`crate::access_log`].
    pub access_log: Option<Arc<crate::access_log::AccessLogger>>,
}
