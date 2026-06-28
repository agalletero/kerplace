//! Best-effort process hardening for on-host secret key material.
//!
//! Used by the `passphrase` key provider (K2), whose derived KEK lives in process
//! memory. We make two cheap, honest hardening moves and **degrade gracefully**
//! (log a warning, never abort) if the platform or privileges don't allow them:
//!
//! - **Disable core dumps** (`setrlimit(RLIMIT_CORE, 0)`) so the KEK can't be
//!   written to a core file after a crash.
//! - **Lock current memory against swap** (`mlockall(MCL_CURRENT)`) so the KEK
//!   page can't be paged out to disk. We deliberately do **not** pass
//!   `MCL_FUTURE`: this is a data-plane server that streams large objects, and
//!   locking every future allocation would risk `ENOMEM`/OOM. The KEK is derived
//!   before this runs, so it is part of the locked current set.

/// Apply best-effort memory hardening (disable core dumps + lock current memory).
///
/// Safe to call once at startup, after the secret key material has been derived.
/// Failures are logged at `WARN` and otherwise ignored — hardening is a defence in
/// depth, not a correctness requirement.
#[cfg(unix)]
pub fn lock_memory() {
    // SAFETY: both calls are simple libc syscalls with well-formed arguments; we
    // check every return value and never dereference returned pointers.
    unsafe {
        let rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::setrlimit(libc::RLIMIT_CORE, &rl) != 0 {
            tracing::warn!("could not disable core dumps (setrlimit RLIMIT_CORE)");
        }
        if libc::mlockall(libc::MCL_CURRENT) != 0 {
            tracing::warn!(
                "could not lock memory against swap (mlockall) — needs CAP_IPC_LOCK \
                 or a higher RLIMIT_MEMLOCK; the passphrase-derived key may be swappable"
            );
        } else {
            tracing::info!("memory hardening: core dumps disabled, current memory locked (no swap)");
        }
    }
}

/// No-op on non-Unix platforms.
#[cfg(not(unix))]
pub fn lock_memory() {
    tracing::warn!("memory hardening (mlock/core-dump-off) is not available on this platform");
}
