//! Per-request audit context (a KerPlace differentiator).
//!
//! The S3/HTTP layer authenticates a request and learns *who* (access key) and
//! *where* (client IP) it came from, but the [`ObjectStore`](crate::storage::ObjectStore)
//! seam is deliberately identity-agnostic so backends stay simple. To record an
//! audit trail on each version write **without** threading identity through
//! every trait method (and every test), the auth middleware publishes a
//! [`AuditContext`] into a task-local for the lifetime of the request; the
//! storage layer reads it at write time via [`current`].
//!
//! This keeps audit recording an additive, opt-in concern: a backend that does
//! not care simply never calls [`current`], and a code path with no middleware
//! (unit tests, internal lifecycle jobs) transparently sees an empty context.

use std::future::Future;

tokio::task_local! {
    /// The authenticated requester's audit context for the current task.
    static AUDIT: AuditContext;
}

/// Who/where information captured for the in-flight request.
///
/// `when` is not stored here — version writes already record their own
/// `last_modified` timestamp, which is the authoritative "when".
#[derive(Debug, Clone, Default)]
pub struct AuditContext {
    /// Access key (user) that authenticated the request, if any. `None` when
    /// auth is disabled or the request was anonymous.
    pub access_key: Option<String>,
    /// Best-effort client IP (peer address, or the first `X-Forwarded-For` hop).
    pub remote_ip: Option<String>,
}

/// Run `fut` with `ctx` installed as the task-local audit context.
///
/// # Parameters
/// - `ctx`: the audit context to make visible to [`current`] for the duration.
/// - `fut`: the future to drive (typically the downstream handler chain).
///
/// # Returns
/// The output of `fut`.
pub async fn scope<F>(ctx: AuditContext, fut: F) -> F::Output
where
    F: Future,
{
    AUDIT.scope(ctx, fut).await
}

/// Read the current task's audit context.
///
/// # Returns
/// The installed [`AuditContext`], or an empty one when called outside any
/// [`scope`] (e.g. in tests or background jobs).
pub fn current() -> AuditContext {
    AUDIT.try_with(|c| c.clone()).unwrap_or_default()
}
