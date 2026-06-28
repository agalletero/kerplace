//! Object locking for the erasure backend.
//!
//! KerPlace had no per-object locking, so two writes to the *same* key could
//! interleave (version history + part files). This adds two layers:
//!
//! - [`LocalKeyLocks`] — a per-key async mutex **inside one process**. This
//!   alone makes a single gateway safe (every request funnels through it), which
//!   is the common deployment.
//! - [`DistLock`] — a **quorum** lock across the cluster's drive nodes (each runs
//!   a [`LockTable`] over the RPC), so several gateways writing to the same
//!   cluster coordinate. Opt-in (it costs a round-trip); local locking is always
//!   on. See `docs/DISTRIBUTED_DESIGN.md`.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use reqwest::Client;
use tokio::sync::{Mutex, OwnedMutexGuard};

use super::DRIVE_API;

/// A granted distributed lock plus the per-node **fencing tokens** to present on
/// writes. Each drive node issues its own monotonically increasing token for a
/// resource; a write to that node must carry the node's token, and the node
/// rejects any write whose token is older than the latest it granted. This
/// fences a stalled lock holder (whose lease expired and was re-granted to a
/// successor) out of the data path — the classic distributed-locking hazard.
#[derive(Clone, Default)]
pub struct FenceCtx {
    /// The locked resource (`<bucket>/<key>`).
    pub resource: String,
    /// Node base URL → the fencing token that node granted for this lock.
    pub tokens: HashMap<String, u64>,
}

tokio::task_local! {
    /// The fencing context of the lock the current task holds (if any), read by
    /// [`RemoteDrive`](crate::cluster::remote::RemoteDrive) when it writes.
    static FENCE: FenceCtx;
}

/// Run `fut` with `ctx` installed as the current task's fencing context, so any
/// remote drive write it performs carries the right per-node fencing token.
///
/// # Parameters
/// - `ctx`: the fencing context from the held [`LockGuard`].
/// - `fut`: the critical section to run.
///
/// # Returns
/// The output of `fut`.
pub async fn with_fence<F: Future>(ctx: FenceCtx, fut: F) -> F::Output {
    FENCE.scope(ctx, fut).await
}

/// The fencing `(resource, token)` to present to the drive node at `base`, if a
/// fence scope is active on this task and granted a token for that node.
///
/// # Parameters
/// - `base`: the drive node's base URL.
///
/// # Returns
/// `Some((resource, token))` to attach to the write, else `None`.
pub fn fence_for(base: &str) -> Option<(String, u64)> {
    FENCE
        .try_with(|c| c.tokens.get(base).map(|t| (c.resource.clone(), *t)))
        .ok()
        .flatten()
}

/// Per-key async mutexes within a single process.
#[derive(Default)]
pub struct LocalKeyLocks {
    map: StdMutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl LocalKeyLocks {
    /// Create an empty lock table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquire the exclusive lock for `key`, awaiting any current holder. The
    /// returned guard releases on drop.
    ///
    /// # Parameters
    /// - `key`: the resource (an object's `<bucket>/<key>`).
    ///
    /// # Returns
    /// An owned mutex guard held for the critical section.
    pub async fn acquire(&self, key: &str) -> OwnedMutexGuard<()> {
        let arc = {
            let mut map = self.map.lock().unwrap();
            // Opportunistically drop idle entries so the map can't grow forever
            // (an entry with strong_count 1 has no holder or waiter).
            if map.len() > 1024 {
                map.retain(|_, a| Arc::strong_count(a) > 1);
            }
            map.entry(key.to_string()).or_insert_with(|| Arc::new(Mutex::new(()))).clone()
        };
        arc.lock_owned().await
    }
}

/// One resource's slot in a [`LockTable`]: the current lease plus the highest
/// fencing token ever granted for it (which only increases, even across
/// releases, so a stale holder can always be detected).
struct Slot {
    /// Current holder, or empty when free.
    owner: String,
    /// When the current lease expires.
    expiry: Instant,
    /// Highest fencing token granted so far (monotonic).
    token: u64,
}

/// Server-side lock table held by a drive node — a leased exclusive lock per
/// resource (in memory; a crashed gateway's lock expires with its lease), each
/// grant carrying a monotonic **fencing token** used to reject stale writes.
#[derive(Default)]
pub struct LockTable {
    inner: StdMutex<HashMap<String, Slot>>,
}

impl LockTable {
    /// Create an empty lock table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Grant `resource` to `owner` for `ttl` unless another owner holds an
    /// unexpired lease. A fresh grant bumps the resource's fencing token; a
    /// re-entrant refresh by the live holder keeps its token.
    ///
    /// # Returns
    /// `Some(token)` — the fencing token to present on writes — if granted
    /// (free, expired, or re-entrant for the same owner); `None` if held.
    pub fn acquire(&self, resource: &str, owner: &str, ttl: Duration) -> Option<u64> {
        let mut m = self.inner.lock().unwrap();
        let now = Instant::now();
        // Opportunistic GC of long-idle free slots so the map can't grow without
        // bound. A slot free for far longer than any lease can't fence anything.
        if m.len() > 4096 {
            m.retain(|_, s| !s.owner.is_empty() || s.expiry + LOCK_TTL * 10 > now);
        }
        let slot = m.entry(resource.to_string()).or_insert(Slot {
            owner: String::new(),
            expiry: now,
            token: 0,
        });
        let held_by_other = !slot.owner.is_empty() && slot.expiry > now && slot.owner != owner;
        if held_by_other {
            return None;
        }
        let reentrant = slot.owner == owner && slot.expiry > now;
        if !reentrant {
            slot.token += 1; // a new grant gets a strictly higher fencing token
        }
        slot.owner = owner.to_string();
        slot.expiry = now + ttl;
        Some(slot.token)
    }

    /// Release `resource` if `owner` holds it (the fencing token is retained so
    /// it keeps increasing across future grants).
    ///
    /// # Returns
    /// `true` if a lease owned by `owner` was released.
    pub fn release(&self, resource: &str, owner: &str) -> bool {
        let mut m = self.inner.lock().unwrap();
        match m.get_mut(resource) {
            Some(s) if s.owner == owner => {
                s.owner.clear();
                true
            }
            _ => false,
        }
    }

    /// Whether a write to `resource` carrying `token` is current (not fenced).
    /// A token older than the highest granted means the caller is a stale holder
    /// that has since been superseded — the write must be rejected.
    ///
    /// # Returns
    /// `true` if the write may proceed, `false` if it is fenced out.
    pub fn fence_ok(&self, resource: &str, token: u64) -> bool {
        let m = self.inner.lock().unwrap();
        match m.get(resource) {
            Some(s) => token >= s.token,
            None => true, // never locked here → nothing to fence against
        }
    }
}

/// Lease duration for a distributed lock (refreshed implicitly on each acquire;
/// covers a crashed holder).
const LOCK_TTL: Duration = Duration::from_secs(30);

/// Client to one drive node's [`LockTable`] over the RPC.
pub struct LockClient {
    base: String,
    secret: String,
    http: Client,
}

impl LockClient {
    /// Connect a lock client to the node at `base` with the cluster `secret`.
    pub fn new(base: impl Into<String>, secret: impl Into<String>) -> Self {
        LockClient { base: base.into(), secret: secret.into(), http: Client::new() }
    }

    /// This node's base URL (matches the [`RemoteDrive`](crate::cluster::remote::RemoteDrive) base).
    pub fn base(&self) -> &str {
        &self.base
    }

    /// Attempt to grab `resource` for `owner`.
    ///
    /// # Returns
    /// `Some(token)` with the node's fencing token if granted, else `None`.
    async fn try_acquire(&self, resource: &str, owner: &str) -> Option<u64> {
        let url = format!("{}{}/lock/acquire", self.base, DRIVE_API);
        let resp = self
            .http
            .post(url)
            .query(&[("resource", resource), ("owner", owner), ("ttl_ms", &LOCK_TTL.as_millis().to_string())])
            .bearer_auth(&self.secret)
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        // The body is the granted fencing token (decimal).
        resp.text().await.ok()?.trim().parse::<u64>().ok()
    }

    /// Release `resource` held by `owner` (best-effort).
    async fn release(&self, resource: &str, owner: &str) {
        let url = format!("{}{}/lock/release", self.base, DRIVE_API);
        let _ = self
            .http
            .post(url)
            .query(&[("resource", resource), ("owner", owner)])
            .bearer_auth(&self.secret)
            .send()
            .await;
    }
}

/// A granted quorum lock: the owner id plus each granting node's fencing token.
pub struct Fenced {
    /// Lock owner id, used to release on every node.
    owner: String,
    /// Node base URL → the fencing token that node granted.
    tokens: HashMap<String, u64>,
}

/// A quorum lock over the cluster's drive nodes.
pub struct DistLock {
    nodes: Vec<LockClient>,
    quorum: usize,
}

impl DistLock {
    /// Build a quorum lock over `nodes` (quorum = `⌊N/2⌋ + 1`).
    pub fn new(nodes: Vec<LockClient>) -> Self {
        let quorum = nodes.len() / 2 + 1;
        DistLock { nodes, quorum }
    }

    /// Acquire `resource` on a quorum of nodes, retrying with backoff under
    /// contention. Returns the owner id and per-node fencing tokens on success,
    /// or `None` if a quorum could not be reached within the retry budget
    /// (caller proceeds best-effort under the local lock).
    async fn acquire(&self, resource: &str) -> Option<Fenced> {
        let owner = uuid::Uuid::new_v4().simple().to_string();
        let mut backoff = Duration::from_millis(20);
        for _ in 0..60 {
            let mut tokens = HashMap::new();
            for n in &self.nodes {
                if let Some(tok) = n.try_acquire(resource, &owner).await {
                    tokens.insert(n.base().to_string(), tok);
                }
            }
            if tokens.len() >= self.quorum {
                return Some(Fenced { owner, tokens });
            }
            // Lost the race: drop our partial grants and back off.
            for n in &self.nodes {
                n.release(resource, &owner).await;
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_millis(500));
        }
        None
    }

    /// Release `resource` held by `owner` on every node.
    async fn release(&self, resource: &str, owner: &str) {
        for n in &self.nodes {
            n.release(resource, owner).await;
        }
    }
}

/// The store's lock manager: always-on local locking plus optional distributed
/// quorum locking.
pub struct LockSet {
    local: LocalKeyLocks,
    dist: Option<Arc<DistLock>>,
}

impl LockSet {
    /// Local-only locking (single gateway / single host).
    pub fn local_only() -> Self {
        LockSet { local: LocalKeyLocks::new(), dist: None }
    }

    /// Local locking + a distributed quorum lock over `nodes`.
    pub fn clustered(nodes: Vec<LockClient>) -> Self {
        LockSet { local: LocalKeyLocks::new(), dist: Some(Arc::new(DistLock::new(nodes))) }
    }

    /// Take the exclusive lock for `resource` (local first, then the quorum if
    /// configured). The returned [`LockGuard`] releases on drop.
    pub async fn acquire(&self, resource: &str) -> LockGuard {
        let local = self.local.acquire(resource).await;
        let (dist, tokens) = match &self.dist {
            Some(d) => match d.acquire(resource).await {
                Some(f) => (Some((d.clone(), f.owner)), f.tokens),
                None => (None, HashMap::new()),
            },
            None => (None, HashMap::new()),
        };
        LockGuard { _local: local, resource: resource.to_string(), dist, tokens }
    }
}

/// Holds an object lock for its lifetime; releases (local synchronously, the
/// distributed lease via a spawned best-effort task) on drop.
pub struct LockGuard {
    _local: OwnedMutexGuard<()>,
    resource: String,
    dist: Option<(Arc<DistLock>, String)>,
    tokens: HashMap<String, u64>,
}

impl LockGuard {
    /// The fencing context to install for the critical section (via
    /// [`with_fence`]), so remote drive writes carry the right per-node tokens.
    ///
    /// # Returns
    /// A [`FenceCtx`] for this lock (empty `tokens` when not clustered).
    pub fn fence_ctx(&self) -> FenceCtx {
        FenceCtx { resource: self.resource.clone(), tokens: self.tokens.clone() }
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        if let Some((dist, owner)) = self.dist.take() {
            let resource = std::mem::take(&mut self.resource);
            tokio::spawn(async move {
                dist.release(&resource, &owner).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The local lock is exclusive per key and independent across keys.
    #[tokio::test]
    async fn local_locks_exclusive_per_key() {
        let locks = Arc::new(LocalKeyLocks::new());
        let held = locks.acquire("a/x").await;

        let l2 = locks.clone();
        let waiter = tokio::spawn(async move {
            let _g = l2.acquire("a/x").await;
        });
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(!waiter.is_finished(), "second acquire on the same key must block");

        // A different key is independent and acquires immediately.
        let _other = locks.acquire("a/y").await;

        drop(held);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter unblocks after release")
            .unwrap();
    }

    /// The server-side lease table grants exclusively and is re-entrant per owner.
    #[test]
    fn lock_table_exclusive() {
        let t = LockTable::new();
        assert!(t.acquire("r", "o1", Duration::from_secs(10)).is_some());
        assert!(t.acquire("r", "o2", Duration::from_secs(10)).is_none(), "held by o1");
        assert!(t.acquire("r", "o1", Duration::from_secs(10)).is_some(), "re-entrant for o1");
        assert!(!t.release("r", "o2"), "o2 cannot release o1's lock");
        assert!(t.release("r", "o1"));
        assert!(t.acquire("r", "o2", Duration::from_secs(10)).is_some(), "free after release");
    }

    /// An expired lease is reclaimable by another owner.
    #[tokio::test]
    async fn lock_table_lease_expires() {
        let t = LockTable::new();
        assert!(t.acquire("r", "o1", Duration::from_millis(20)).is_some());
        assert!(t.acquire("r", "o2", Duration::from_millis(20)).is_none());
        tokio::time::sleep(Duration::from_millis(45)).await;
        assert!(t.acquire("r", "o2", Duration::from_secs(10)).is_some(), "expired lease reclaimed by o2");
    }

    /// Fencing tokens increase on each fresh grant, a re-entrant refresh keeps
    /// its token, and a write with a stale token is fenced out.
    #[test]
    fn fencing_tokens_are_monotonic() {
        let t = LockTable::new();
        let t1 = t.acquire("r", "o1", Duration::from_secs(10)).unwrap();
        // Re-entrant refresh by the same owner keeps the same token.
        let t1b = t.acquire("r", "o1", Duration::from_secs(10)).unwrap();
        assert_eq!(t1, t1b, "re-entrant refresh keeps the token");
        assert!(t.fence_ok("r", t1), "current holder's token is valid");

        // o1 releases; o2 takes it and gets a strictly higher token.
        assert!(t.release("r", "o1"));
        let t2 = t.acquire("r", "o2", Duration::from_secs(10)).unwrap();
        assert!(t2 > t1, "a fresh grant gets a higher fencing token");

        // The superseded holder o1 is now fenced out; o2 is current.
        assert!(!t.fence_ok("r", t1), "stale token is fenced");
        assert!(t.fence_ok("r", t2), "current token passes");
        // A never-locked resource has nothing to fence against.
        assert!(t.fence_ok("other", 0));
    }

    /// Distributed acquire/release over a quorum of in-process lock servers,
    /// returning per-node fencing tokens.
    #[tokio::test]
    async fn dist_lock_quorum_round_trip() {
        let secret = "s";
        let mut nodes = Vec::new();
        let mut keep = Vec::new();
        for _ in 0..3 {
            let dir = tempfile::tempdir().unwrap();
            let drive = Arc::new(crate::erasure::drive::LocalDrive::new(dir.path().to_path_buf()));
            let app = crate::cluster::server::drive_router(drive, secret.to_string());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            nodes.push(LockClient::new(format!("http://{addr}"), secret));
            keep.push(dir);
        }
        let dl = DistLock::new(nodes);
        assert_eq!(dl.quorum, 2);
        let f = dl.acquire("buck/obj").await.expect("quorum acquired");
        assert!(f.tokens.len() >= 2, "a token from each granting node");
        assert!(f.tokens.values().all(|&t| t >= 1), "tokens issued");
        dl.release("buck/obj", &f.owner).await;
        assert!(dl.acquire("buck/obj").await.is_some(), "re-acquire after release");
    }

    /// End-to-end over the real RPC: a superseded holder's write carries a stale
    /// fencing token and is rejected by the drive node; the current holder's
    /// write is accepted.
    #[tokio::test]
    async fn fencing_rejects_stale_write_over_rpc() {
        use crate::cluster::remote::RemoteDrive;
        use crate::erasure::drive::{Drive, LocalDrive};
        use std::path::Path;

        let secret = "s";
        let dir = tempfile::tempdir().unwrap();
        let drive = Arc::new(LocalDrive::new(dir.path().to_path_buf()));
        let app = crate::cluster::server::drive_router(drive, secret.to_string());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base = format!("http://{addr}");
        let remote = RemoteDrive::new(&base, secret);
        // Parent dir for the shard write (created outside any fence scope).
        remote.create_dir_all(Path::new("buck/obj")).await.unwrap();

        // owner1 takes the lock (token t1), releases; owner2 supersedes (t2 > t1).
        let lc = LockClient::new(&base, secret);
        let t1 = lc.try_acquire("buck/obj", "owner1").await.unwrap();
        lc.release("buck/obj", "owner1").await;
        let t2 = lc.try_acquire("buck/obj", "owner2").await.unwrap();
        assert!(t2 > t1, "successor gets a higher token");

        let part = Path::new("buck/obj/part.1");
        // The stale holder (t1) is fenced out.
        let stale = FenceCtx { resource: "buck/obj".into(), tokens: HashMap::from([(base.clone(), t1)]) };
        let r = with_fence(stale, remote.write(part, b"stale")).await;
        assert!(r.is_err(), "a write with a stale fencing token must be rejected");

        // The current holder (t2) succeeds.
        let cur = FenceCtx { resource: "buck/obj".into(), tokens: HashMap::from([(base.clone(), t2)]) };
        with_fence(cur, remote.write(part, b"fresh")).await.unwrap();
        assert_eq!(remote.read(part).await.unwrap(), b"fresh");
    }
}
