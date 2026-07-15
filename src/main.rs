//! KerPlace (myNextIO) — an S3-compatible object storage server.
//!
//! Entry point: loads configuration, constructs the storage backend, builds
//! the HTTP router and serves the S3 API.

mod audit;
mod auth;
mod cluster;
mod config;
mod console;
#[cfg(test)]
mod console_test;
mod crypto;
mod erasure;
mod error;
mod handlers;
mod harden;
#[cfg(test)]
mod http_test;
mod iam;
mod lifecycle;
mod madmin;
mod router;
mod s3;
mod state;
mod storage;
mod tls;

use std::sync::Arc;

use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::state::AppState;
use crate::storage::fs::FsStore;

/// Initialize the tracing subscriber from the `RUST_LOG` environment variable,
/// defaulting to `info` level.
///
/// # Returns
/// `()` — installs the global subscriber as a side effect.
fn init_tracing() {
    // Standard `RUST_LOG` wins for power users. Otherwise `KP_DEBUG` is the
    // friendly support knob: tell a user to run `KP_DEBUG=debug ./kerplace` and
    // send the logs.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let directive = match crate::config::env_var("DEBUG") {
            Some(v) => debug_directive(&v),
            None => "info".to_string(),
        };
        EnvFilter::try_new(&directive).unwrap_or_else(|_| EnvFilter::new("info"))
    });
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// Map a `KP_DEBUG` value to a log-level directive: truthy values mean
/// `debug`; a level name (`trace`/`debug`/`info`/`warn`/`error`) or a full
/// `RUST_LOG`-style directive is passed through; empty means `info`.
///
/// # Parameters
/// - `v`: the raw `KP_DEBUG` value.
///
/// # Returns
/// A directive string for [`EnvFilter`].
fn debug_directive(v: &str) -> String {
    match v.trim().to_ascii_lowercase().as_str() {
        "" => "info".to_string(),
        "true" | "1" | "on" | "yes" => "debug".to_string(),
        _ => v.trim().to_string(),
    }
}

/// Parse the command line before doing any work.
///
/// Two invocation styles are supported:
/// - **Env-only** (KerPlace native): `kerplace` with no arguments — everything comes
///   from `KP_*` environment variables.
/// - **MinIO-compatible** (eases migration): `kerplace server --address :9000
///   --console-address :9001 /data` — the `server` word is optional; recognised
///   flags and positional drive paths are translated into the matching `KP_*`
///   variables (read moments later by [`Config::from_env`]). One path → the data
///   dir; several paths → erasure drives.
///
/// `-h`/`--help` and `-v`/`--version` print and exit; an unknown flag exits 2.
///
/// # Returns
/// `()` — sets env vars as a side effect and may terminate via
/// [`std::process::exit`].
fn apply_cli() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return;
    }
    match args[0].as_str() {
        "-h" | "--help" => {
            print!("{}", help_text());
            std::process::exit(0);
        }
        "-v" | "-V" | "--version" => {
            println!("KerPlace {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        _ => {}
    }

    // Server mode (MinIO-compatible). The `server` subcommand is optional.
    let mut i = if args[0] == "server" { 1 } else { 0 };
    let mut paths: Vec<String> = Vec::new();
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print!("{}", help_text());
                std::process::exit(0);
            }
            "--address" => set_env_addr("KP_ADDRESS", take_val(&args, &mut i, "--address")),
            "--console-address" => {
                set_env_addr("KP_CONSOLE_ADDRESS", take_val(&args, &mut i, "--console-address"))
            }
            "--certs-dir" | "-C" => apply_certs_dir(&take_val(&args, &mut i, "--certs-dir")),
            // Accept-and-ignore common MinIO flags so existing commands don't break.
            "--quiet" | "-q" | "--anonymous" | "--json" | "--no-compat" => i += 1,
            other if other.starts_with('-') => {
                eprintln!("kerplace: unrecognised flag '{other}'\nTry 'kerplace --help'.");
                std::process::exit(2);
            }
            _ => {
                paths.push(args[i].clone());
                i += 1;
            }
        }
    }
    match paths.len() {
        0 => {}
        1 => std::env::set_var("KP_DATA_DIR", &paths[0]),
        _ => std::env::set_var("KP_ERASURE_DRIVES", paths.join(",")),
    }
}

/// Consume a flag's value (the next argv token), advancing the cursor past both.
///
/// # Parameters
/// - `args`: the full argument list; `flag`: the flag name (for the error message).
/// - `i`: cursor positioned at the flag; advanced by 2 on return.
///
/// # Returns
/// The flag's value, or exits 2 if it is missing.
fn take_val(args: &[String], i: &mut usize, flag: &str) -> String {
    if *i + 1 >= args.len() {
        eprintln!("kerplace: '{flag}' needs a value");
        std::process::exit(2);
    }
    let v = args[*i + 1].clone();
    *i += 2;
    v
}

/// Set a listen-address env var, expanding MinIO's `:port` form (all interfaces)
/// to `0.0.0.0:port`.
fn set_env_addr(var: &str, addr: String) {
    let normalized = match addr.strip_prefix(':') {
        Some(port) => format!("0.0.0.0:{port}"),
        None => addr,
    };
    std::env::set_var(var, normalized);
}

/// Map MinIO's `--certs-dir DIR` (containing `public.crt` + `private.key`) onto
/// the `KP_TLS*` variables.
fn apply_certs_dir(dir: &str) {
    let p = std::path::Path::new(dir);
    std::env::set_var("KP_TLS", "true");
    std::env::set_var("KP_TLS_CERT", p.join("public.crt"));
    std::env::set_var("KP_TLS_KEY", p.join("private.key"));
}

/// The `--help` text. Configuration is entirely via `KP_*` environment
/// variables (no config file), so help points at the most important ones.
/// Each variable is also read under the transitional `MYNIO_*` and the
/// MinIO-compatible `MINIO_*` prefixes (in that precedence).
///
/// # Returns
/// The formatted help string.
fn help_text() -> String {
    format!(
        "KerPlace {ver} — an S3-compatible object storage server.

USAGE:
    kerplace                                  # configured via KP_* env vars
    kerplace server [FLAGS] [PATH...]         # MinIO-compatible form

    The 'server' word is optional. One PATH = the data dir; several PATHs = the
    erasure drives. Anything not given on the CLI falls back to KP_* env vars.

    e.g.  kerplace server --address :9000 --console-address :9001 /data

FLAGS:
    -h, --help                   Print this help and exit
    -v, --version                Print version and exit
        --address ADDR           S3 API listen address          (e.g. :9000)
        --console-address ADDR   Web console listen address     (e.g. :9001)
        --certs-dir DIR          TLS certs dir (public.crt + private.key)

COMMON ENV VARS — KP_* is canonical; MYNIO_* (deprecated) and MINIO_* are read
as fallback in that order, so an existing MinIO service file keeps working:
    KP_ADDRESS               S3 API listen address          [default 0.0.0.0:9000]
    KP_CONSOLE_ADDRESS       Web console listen address     [default 0.0.0.0:9001]
    KP_DATA_DIR              Where buckets/objects live     [default ./data]
    KP_ROOT_USER             Root access key                [default minioadmin]
    KP_ROOT_PASSWORD         Root secret key                [default minioadmin]
    KP_REGION                SigV4 region                   [default us-east-1]
    KP_BACKEND               erasure (default) | fs
    KP_ENCRYPT               true to encrypt at rest (post-quantum + AES-256)
    KP_TLS                   true to serve over HTTPS
    KP_USERS                 Seed users: ak:sk:policy[:bucket1|bucket2] , comma-separated
                             (4th field scopes the credential to those buckets)
    KP_DEBUG                 log level for support: debug | trace | info | warn | error

DISTRIBUTED (see docs/CLUSTERING.md):
    KP_ROLE                  gateway (default) | drive
    KP_NODES                 shard map  idx=addr,...   (gateway)
    KP_CLUSTER_SECRET        shared bearer secret for the drive RPC

EXAMPLE:
    KP_DATA_DIR=./data ./kerplace
",
        ver = env!("CARGO_PKG_VERSION")
    )
}

/// Process entry point: wire dependencies and serve the S3 API.
///
/// # Returns
/// `Ok(())` on graceful shutdown, or a boxed error if startup (config,
/// storage initialization, socket bind) or serving fails.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    apply_cli();
    init_tracing();
    handlers::admin::mark_start();

    let config = Config::from_env();

    // Resolve the deployment posture (`KP_PROFILE`) strictly: an unknown name is a
    // hard error, and `sealed` must satisfy all its invariants or we refuse to
    // boot (fail-closed) with the complete list of what is missing.
    let profile = crate::config::parse_profile(&crate::config::env_var("PROFILE").unwrap_or_default())?;
    if profile == crate::config::Profile::Sealed {
        let unmet = crate::config::sealed_violations(&config);
        if !unmet.is_empty() {
            return Err(format!(
                "KP_PROFILE=sealed is not satisfied — refusing to start:\n  - {}",
                unmet.join("\n  - ")
            )
            .into());
        }
        tracing::info!("deployment profile `sealed` — regulated invariants satisfied");
    }

    tracing::info!(
        address = %config.address,
        data_dir = ?config.data_dir,
        auth = config.auth_enabled,
        region = %config.region,
        profile = profile.as_str(),
        "starting KerPlace"
    );

    // Drive mode (Phase 4): this node only serves its shard storage over the
    // internal cluster RPC — no S3 API, no crypto (payloads arrive already
    // encrypted+sharded from the gateway). See docs/DISTRIBUTED_DESIGN.md.
    if crate::config::env_var("ROLE").as_deref() == Some("drive") {
        let secret = crate::config::env_var("CLUSTER_SECRET").unwrap_or_default();
        let addr: std::net::SocketAddr = crate::config::env_var("DRIVE_ADDR")
            .unwrap_or_else(|| "0.0.0.0:9100".to_string())
            .parse()?;
        tracing::info!(%addr, data_dir = ?config.data_dir, "starting KerPlace drive node");
        cluster::server::serve_drive(addr, config.data_dir.clone(), secret).await?;
        return Ok(());
    }

    let sys_dir = config.data_dir.join(".kerplace.sys");
    tokio::fs::create_dir_all(&sys_dir).await?;

    // Build the at-rest key provider (the K0 custody seam). `KP_KEY_PROVIDER`
    // selects it (default `file`); each provider loads its own key material from
    // `.kerplace.sys/` — `file` uses master.key + pq.bin, `passphrase` derives the
    // KEK from KP_KEY_PASSPHRASE (Argon2id) and stores no key on disk. An unknown
    // name fails fast.
    let provider = crypto::provider_from_env(&sys_dir).map_err(|e| format!("key provider: {e}"))?;
    // Liveness check: confirm the provider can unwrap before serving (a future KMS
    // provider round-trips here; `file` is a no-op).
    provider
        .check()
        .await
        .map_err(|e| format!("key provider `{}` is not ready: {e}", provider.kind()))?;
    let posture = provider.posture();
    let crypto_ctx = crypto::CryptoContext::new(provider);
    tracing::info!(
        provider = posture.kind,
        unattended_boot = posture.unattended_boot,
        key_on_host = posture.key_on_host,
        "key custody `{}` — protects {}; does NOT protect {}",
        posture.kind,
        posture.protects,
        posture.does_not_protect
    );
    if config.encryption_enabled {
        tracing::info!(provider = posture.kind, "at-rest encryption enabled");
    }
    // Honesty: if the unwrap key lives on this host, say plainly what that does
    // (and does not) protect — the K1 file-provider transparency requirement.
    if let Some(warn) = crypto::custody_warning(&posture, config.encryption_enabled) {
        tracing::warn!("{warn}");
    }

    // Select the storage backend. The default is `erasure` (Reed-Solomon with
    // redundancy + bitrot protection, opaque on-disk format — like modern
    // MinIO). `KP_BACKEND=fs` opts into the transparent single-disk mirror
    // (a "pseudo-NFS" convenience MinIO no longer offers). Both implement
    // ObjectStore, so nothing else changes.
    let store: Arc<dyn storage::ObjectStore> = if crate::config::env_var("BACKEND").as_deref() == Some("fs")
    {
        tracing::info!("filesystem-mirror backend (fs)");
        Arc::new(FsStore::new(config.data_dir.clone(), crypto_ctx.clone(), config.encryption_enabled).await?)
    } else if crate::config::env_var("NODES").map(|v| !v.trim().is_empty()).unwrap_or(false) {
        // Distributed gateway (Phase 4): the N shard slots live on cluster
        // nodes. `NODES` is a comma list of `idx=addr`; this node
        // (`NODE_INDEX`, if it hosts a slot) is a LocalDrive, the others are
        // RemoteDrives over the internal RPC.
        let nodes_env = crate::config::env_var("NODES").unwrap();
        let secret = crate::config::env_var("CLUSTER_SECRET").unwrap_or_default();
        let self_index: Option<usize> =
            crate::config::env_var("NODE_INDEX").and_then(|v| v.parse().ok());
        let mut entries: Vec<(usize, String)> = Vec::new();
        for part in nodes_env.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            let (idx, addr) = part
                .split_once('=')
                .ok_or_else(|| format!("cluster node entry needs idx=addr: {part}"))?;
            let idx: usize = idx.trim().parse().map_err(|_| format!("bad node index: {idx}"))?;
            entries.push((idx, addr.trim().to_string()));
        }
        entries.sort_by_key(|(i, _)| *i);
        // Mutual TLS for the gateway→drive RPC (KP_CLUSTER_TLS=true): build one
        // client cert'd reqwest client and address drives over https.
        let cluster_tls = cluster::mtls::ClusterTls::from_env()?;
        let tls_client = match &cluster_tls {
            Some(t) => Some(t.reqwest_client()?),
            None => None,
        };
        let scheme = if cluster_tls.is_some() { "https" } else { "http" };
        let mut drives: Vec<Arc<dyn erasure::drive::Drive>> = Vec::with_capacity(entries.len());
        for (idx, addr) in &entries {
            if Some(*idx) == self_index {
                tokio::fs::create_dir_all(&config.data_dir).await?;
                drives.push(Arc::new(erasure::drive::LocalDrive::new(config.data_dir.clone())));
            } else {
                let base = if addr.starts_with("http") { addr.clone() } else { format!("{scheme}://{addr}") };
                let remote = match &tls_client {
                    Some(c) => cluster::remote::RemoteDrive::with_client(base, secret.clone(), c.clone()),
                    None => cluster::remote::RemoteDrive::new(base, secret.clone()),
                };
                drives.push(Arc::new(remote));
            }
        }
        let parity = crate::config::env_var("ERASURE_PARITY")
            .and_then(|v| v.parse().ok())
            .unwrap_or(drives.len() / 2);
        let block = crate::config::env_var("ERASURE_BLOCK")
            .and_then(|v| v.parse().ok())
            .unwrap_or(1usize << 20);
        tracing::info!(nodes = drives.len(), parity, block, ?self_index, "distributed erasure gateway");
        let mut store =
            erasure::store::ErasureStore::with_drives(drives, crypto_ctx.clone(), config.encryption_enabled, parity, block)?;
        // Opt-in distributed quorum locks over the remote drive nodes' lock
        // servers (for running several gateways against one cluster). Local
        // per-object locking is always on.
        if crate::config::env_var("CLUSTER_LOCKS").as_deref() == Some("true") {
            let lock_nodes: Vec<cluster::lock::LockClient> = entries
                .iter()
                .filter(|(idx, _)| Some(*idx) != self_index)
                .map(|(_, addr)| {
                    let base = if addr.starts_with("http") { addr.clone() } else { format!("http://{addr}") };
                    cluster::lock::LockClient::new(base, secret.clone())
                })
                .collect();
            if !lock_nodes.is_empty() {
                tracing::info!(lock_nodes = lock_nodes.len(), "distributed quorum locks enabled");
                store = store.with_locks(Arc::new(cluster::lock::LockSet::clustered(lock_nodes)));
            }
        }
        Arc::new(store)
    } else {
        // Erasure (default). Drives come from `ERASURE_DRIVES`, or — for a
        // zero-config single-host start — four sub-drives under the data dir.
        let drives: Vec<std::path::PathBuf> = match crate::config::env_var("ERASURE_DRIVES") {
            Some(v) if !v.trim().is_empty() => v
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(std::path::PathBuf::from)
                .collect(),
            _ => (0..4)
                .map(|i| config.data_dir.join(".erasure").join(format!("disk{i}")))
                .collect(),
        };
        let parity = crate::config::env_var("ERASURE_PARITY")
            .and_then(|v| v.parse().ok())
            .unwrap_or(drives.len() / 2);
        let block = crate::config::env_var("ERASURE_BLOCK")
            .and_then(|v| v.parse().ok())
            .unwrap_or(1usize << 20);
        tracing::info!(drives = drives.len(), parity, block, "erasure-coded backend (default)");
        Arc::new(
            erasure::store::ErasureStore::new(drives, crypto_ctx.clone(), config.encryption_enabled, parity, block).await?,
        )
    };

    // Load the IAM store: root credential from config, plus persisted users and
    // any `USERS` env seed (`accessKey:secretKey:policy`, comma-separated).
    let iam = iam::IamStore::load(
        sys_dir.join("iam"),
        &config.root_user,
        &config.root_password,
        crate::config::env_var("USERS"),
    )
    .await;
    let user_count = iam.list().len();
    tracing::info!(users = user_count, "IAM store loaded (incl. root)");

    // External identity (D1): if KP_OIDC_ISSUER is set, discover the IdP. OIDC is
    // additive (built-in IAM still works), so a discovery failure logs a loud WARN
    // and disables SSO rather than blocking startup.
    let oidc = match crate::auth::oidc::OidcConfig::from_env() {
        Some(cfg) => {
            let issuer = cfg.issuer.clone();
            match crate::auth::oidc::Oidc::discover(cfg).await {
                Ok(o) => {
                    tracing::info!(%issuer, "OIDC external identity enabled (console SSO + STS)");
                    Some(Arc::new(o))
                }
                Err(e) => {
                    tracing::warn!(%issuer, "OIDC configured but discovery failed: {e} — SSO disabled");
                    None
                }
            }
        }
        None => None,
    };

    // Under `sealed`, OIDC must be not just configured but actually reachable — a
    // regulated deployment cannot serve with its identity provider down.
    if profile == crate::config::Profile::Sealed && oidc.is_none() {
        return Err("KP_PROFILE=sealed requires a reachable OIDC IdP, but discovery failed (see the WARN above)".into());
    }

    let state = AppState {
        store,
        config: Arc::new(config.clone()),
        iam: Arc::new(iam),
        crypto: crypto_ctx,
        oidc,
    };

    // Build the TLS configuration once and share it between API and console.
    let tls_config = if config.tls_enabled {
        Some(tls::build_rustls_config(&config).await?)
    } else {
        None
    };
    let scheme = if tls_config.is_some() { "https" } else { "http" };

    // Start the web console on its own port (like MinIO's API/console split).
    if config.console_enabled {
        let console_app = console::build_router(state.clone());
        let console_addr = config.console_address.clone();
        let console_tls = tls_config.clone();
        tokio::spawn(async move {
            let addr: std::net::SocketAddr = match console_addr.parse() {
                Ok(a) => a,
                Err(e) => {
                    tracing::error!("console address {console_addr} invalid: {e}");
                    return;
                }
            };
            tracing::info!("KerPlace console on {scheme}://{console_addr}");
            let result = match console_tls {
                Some(tls) => {
                    axum_server::bind_rustls(addr, tls)
                        .serve(console_app.into_make_service())
                        .await
                }
                None => {
                    axum_server::bind(addr)
                        .serve(console_app.into_make_service())
                        .await
                }
            };
            if let Err(e) = result {
                tracing::error!("console server error: {e}");
            }
        });
    }

    // Start the lifecycle / ILM background worker (hourly scan).
    lifecycle::start_lifecycle_worker(
        state.store.clone(),
        tokio::time::Duration::from_secs(3600),
    );

    let app = router::build_router(state);
    let addr: std::net::SocketAddr = config.address.parse()?;
    tracing::info!("KerPlace listening on {scheme}://{}", config.address);
    // `into_make_service_with_connect_info` exposes the peer `SocketAddr` to the
    // auth middleware so it can record the client IP in the audit trail.
    match tls_config {
        Some(tls) => {
            axum_server::bind_rustls(addr, tls)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await?;
        }
        None => {
            axum_server::bind(addr)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await?;
        }
    }

    Ok(())
}
