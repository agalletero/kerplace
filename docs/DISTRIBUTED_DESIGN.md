# Distributed multi-node erasure — design (Phase 4)

> Design for KerPlace's distributed backend: spread an erasure set across **several
> machines** so the loss of a whole node (not just a drive) is survivable.
> Status: **draft / design-first** (no code yet). Builds directly on the
> single-host erasure backend (`docs/ERASURE_CODING_DESIGN.md`, phases 1–3).
> Decisions locked with the user 2026-06-24: **design-first**, and
> **overlay-mesh networking**.

![KerPlace distributed cluster](diagrams/cluster-topology.svg)

## 1. Goals

- **Node-level durability:** with `N` nodes and `M` parity, survive the loss of
  any `M` whole nodes with no data loss (today's per-drive guarantee, lifted to
  whole machines).
- **Reuse the codec & store logic unchanged.** The Reed-Solomon sharding,
  BLAKE3 bitrot checks, versioning, multipart, audit trail and heal from
  phases 1–3 stay exactly as they are. Only *where a shard's bytes live* changes
  (local disk → a remote node), behind a new `Drive` seam.
- **Works across NAT and two clouds.** The four real nodes sit on three
  networks; they must reach each other regardless. We use an **overlay mesh**.
- **S3 API unchanged.** A client talks to any node's `:9000` exactly as today.

### Non-goals (Phase 4)
- Dynamic membership / auto-rebalance on node add-remove (static node list).
- Multiple erasure sets / sharding the *keyspace* across sets (single set).
- Geo-replication / active-active across regions (that's a later objective).

## 2. The cluster (real inventory, 2026-06-24)

| # | Node | Address | OS / specs | Role | Status |
|---|------|---------|-----------|------|--------|
| 0 | Laptop (control) | LAN, behind NAT | dev workstation, x86_64 + Rust toolchain | gateway + drive | ✅ |
| 1 | LAN VM | `user@<vm-lan-ip>` | Linux, ample RAM/disk | drive | ✅ ssh key |
| 2 | Cloud A | `<instance>`, region-a, ext `<public-ip>` | small instance (~2 vCPU / 1 GiB) | drive | ✅ running |
| 3 | Cloud B | `user@<public-ip>` (region-b; key `<your-key>.pem`) | small instance (~2 vCPU / ~1 GiB) | drive | ✅ ssh+pem |

**Caveats to design around:**
- Heterogeneous + tiny: the GCP e2-micro has **1 GiB RAM / 10 G disk**. Block
  size and per-node shard volume in the test must stay small. The laptop VM is
  at **91 % root usage** — point its drive dir at free space or attach storage.
- Asymmetric reachability: only the laptop + VM share a LAN. → overlay mesh (§3).
- This is a **functional** distributed test, not a perf benchmark.

## 3. Network — overlay mesh (decided)

Every node joins one **Tailscale tailnet** (WireGuard under the hood) and gets a
stable `100.x.y.z` address. The cluster is configured purely in terms of these
tailnet IPs, so NAT, dynamic public IPs and per-cloud firewalls are irrelevant.

Why Tailscale over raw WireGuard or public-IP-plus-firewall:
- **No inbound firewall changes** on GCP/AWS and **no router port-forward** for
  the laptop/VM — Tailscale establishes connectivity outbound. Critical for the
  e2-micro and the NAT'd home nodes.
- Stable identity per node; ACLs scope who may reach the storage port.
- Raw WireGuard is the fallback if Tailscale is unacceptable (more manual key /
  endpoint management; same overlay idea).

The internal storage RPC (§6) listens **only** on the tailnet interface and is
additionally authenticated (§6.3) — defence in depth, never exposed publicly.

## 4. Cluster model

- One **erasure set** spans all `N` nodes; each node owns **one shard slot**
  (it may back that slot with one or more local drive dirs, but logically it is
  shard index `i`). For the 4 nodes: `N = 4`, parity `M = 2` ⇒ `K = 2`. Any **2**
  nodes may be lost and every object still reconstructs.
- The existing `distribution` permutation still spreads shard indices across
  slots per object; here a "slot" is a node instead of a local directory.
- `xl.meta` is replicated to **every node** that holds a shard (as today, but the
  write fans out over the network). Reads pick the copy agreed by a quorum.

## 5. Code seam — the `Drive` trait

Today `ErasureStore` holds `drives: Vec<PathBuf>` and performs ~10 distinct
`tokio::fs` operations against them (`read`, `write`, `rename`, `remove_file`,
`remove_dir_all`, `create_dir_all`, `metadata`, `read_dir`, `File::open`,
`File::create`). Phase 4 hoists exactly those behind an async trait:

```rust
#[async_trait]
trait Drive: Send + Sync {
    async fn read(&self, rel: &Path) -> io::Result<Vec<u8>>;
    async fn write(&self, rel: &Path, data: &[u8]) -> io::Result<()>;
    async fn open(&self, rel: &Path) -> io::Result<DriveReader>;   // streaming part.1
    async fn create(&self, rel: &Path) -> io::Result<DriveWriter>; // streaming part.1
    async fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    async fn remove_file(&self, rel: &Path) -> io::Result<()>;
    async fn remove_dir_all(&self, rel: &Path) -> io::Result<()>;
    async fn create_dir_all(&self, rel: &Path) -> io::Result<()>;
    async fn metadata(&self, rel: &Path) -> io::Result<DriveStat>;
    async fn read_dir(&self, rel: &Path) -> io::Result<Vec<DirEntry>>;
    fn id(&self) -> &str;        // for backend_info / heal reports
    async fn online(&self) -> bool;
}
```

- **`LocalDrive(PathBuf)`** — wraps today's `tokio::fs` calls (the local node's
  own shard slot; also the migration path — a single-node erasure store is just
  `N` `LocalDrive`s, behaviour-identical to phase 3).
- **`RemoteDrive { base: Url, secret, http }`** — an RPC client (§6).

`ErasureStore.drives` becomes `Vec<Arc<dyn Drive>>`. **The codec, sharding,
versioning, multipart, audit and heal code is untouched** — it already treats a
drive as an opaque place to put `xl.meta` + `part.1`. `reconstruct_into` and the
heal passes stream through `Drive::open`/`create` instead of `File`.

This refactor (local-only, no network) is **step 4a-0**: land it, prove all 84
tests still pass over `LocalDrive`, *then* add `RemoteDrive`.

## 6. Storage RPC (the "drive server")

### 6.1 One binary, two roles
Every node runs the **same `kerplace` binary**. A node in **drive mode**
(`KP_ROLE=drive`) serves only the internal drive API over the tailnet. A node
in **gateway mode** (default) additionally serves the public S3 API and runs the
`ErasureStore` whose `drives[i]` is a `RemoteDrive` to node `i` (or `LocalDrive`
for itself). Any node can be a gateway; clients may hit any of them.

### 6.2 Wire protocol
A small authenticated **HTTP** API (reuses the axum stack; easy to stream
`part.1`; trivially debuggable) under `/_kerplace/drive/v1`:

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/_kerplace/drive/v1/file?p=<rel>` | read file / stream part.1 (Range ok) |
| PUT | `/_kerplace/drive/v1/file?p=<rel>` | write file / stream part.1 |
| POST | `/_kerplace/drive/v1/rename?from=&to=` | atomic rename |
| DELETE | `/_kerplace/drive/v1/file?p=<rel>&recursive=` | remove file/dir |
| POST | `/_kerplace/drive/v1/mkdir?p=<rel>` | create_dir_all |
| GET | `/_kerplace/drive/v1/stat?p=<rel>` | metadata |
| GET | `/_kerplace/drive/v1/list?p=<rel>` | read_dir |
| GET | `/_kerplace/drive/v1/health` | liveness for `online()` / quorum |

`<rel>` is always `<bucket>/<key>/...` *within this node's drive dir* — the
server joins it under its configured root and rejects traversal (reuse
`validate_key`-style checks). gRPC is a possible later swap; HTTP first.

### 6.3 Auth
`Authorization: Bearer <KP_CLUSTER_SECRET>` (shared cluster secret), checked
by the drive server. The API binds to the tailnet IP only. (mTLS over the
overlay is a hardening option.)

### 6.4 Quorum & consistency
- **Write:** fan out `xl.meta` + `part.1` to all `N` nodes; the operation
  succeeds iff **≥ K+1** acks (data shards + one). Below that → roll back / error.
- **Read:** fetch `xl.meta` from any node; if copies disagree, take the
  **majority**. Reconstruct from the first `K` good `part.1` streams (verifying
  BLAKE3 as today), repairing on the fly.
- A node that is `offline()` is simply a missing shard — handled by the existing
  reconstruction path. Degraded objects are repaired by **heal** (§7).

## 7. Heal & admin across nodes
`heal` (phase 3) already reconstructs from a quorum and rewrites bad shards — it
becomes node-aware for free once `Drive` is the seam: a missing/offline node is
a bad shard; heal rebuilds that node's `part.1` + `xl.meta` via `RemoteDrive`
once it (or a replacement) is back. `backend_info` reports per-node state
(online/offline + tailnet addr) so `mc admin info` shows the cluster.

## 8. Distributed locking
- **4a (start):** a single **lock-coordinator** node grants per-object leases
  (simple, correct for a small static cluster; SPOF acceptable for the test).
- **4b:** quorum locks (MinIO-style Dlock) — acquire a lease on `⌈N/2⌉+1` nodes;
  no SPOF. Needed before calling the cluster production-grade.

## 9. Configuration (new env)

| Var | Meaning |
|---|---|
| `KP_ROLE` | `gateway` (default) or `drive` |
| `KP_NODES` | ordered list `idx=tailnet-addr` of the `N` shard slots, e.g. `0=100.x.0.1:9100,1=100.x.0.2:9100,...` |
| `KP_NODE_INDEX` | which slot **this** machine owns (its drive is `LocalDrive`; others are `RemoteDrive`) |
| `KP_CLUSTER_SECRET` | shared bearer secret for the drive API |
| `KP_DRIVE_ADDR` | bind addr for the internal drive API (tailnet IP : 9100) |
| `KP_DATA_DIR` | this node's local shard-slot directory (as today) |

`KP_ERASURE_PARITY` keeps its meaning (`M`); `N = len(KP_NODES)`.

## 10. Phasing

- **4a-0 — `Drive` seam (local only). ✅ DONE.** `src/erasure/drive.rs`: the
  `Drive` async trait + `LocalDrive` (wraps `tokio::fs`). `ErasureStore` now holds
  `Vec<Arc<dyn Drive>>` and does **all** I/O through the seam with drive-relative
  paths (`r_*` helpers); shard reads use a positioned `read_at` (maps to a future
  HTTP Range). `ErasureStore::new` still takes `Vec<PathBuf>` and wraps them in
  `LocalDrive`, so `main.rs`/tests are unchanged. 84 tests green, rustc 0
  warnings — zero behaviour change.
- **4a-1 — drive server + `RemoteDrive`. ✅ DONE.** `src/cluster/`: `server.rs`
  (a node in `KP_ROLE=drive` exposes its `LocalDrive` over the bearer-gated
  `/_kerplace/drive/v1/*` HTTP API — get/put/`read_at` via Range/mkdir/rename/
  delete/stat/readdir/walk) and `remote.rs` (`RemoteDrive` implements `Drive`
  over that API; `RemoteWriter` buffers and PUTs on `shutdown`). `main.rs` wires
  `KP_ROLE=drive` (drive node) and `KP_NODES`/`KP_NODE_INDEX`/
  `KP_CLUSTER_SECRET` (distributed gateway via `ErasureStore::with_drives`).
  86 tests (2 new: `RemoteDrive` op round-trip + erasure-over-remote durability).
  **Validated live, multi-process:** 2 drive nodes + a gateway, 200 KB object
  put/get over the RPC, shards on the nodes, bearer enforced (401), and a GET
  after killing one node reconstructed the object from the survivor. Payloads
  stream on the local side (`open`/`create`); the remote side buffers per file —
  streaming both directions is a 4b optimisation.
- **4a-2 — N nodes over the network + read-survival + heal. ✅ DONE (live).**
  Ran a **real 4-node cluster** across **three networks**: laptop (gateway +
  shard 0), LAN VM (shard 1), Cloud A / region-a
  (shard 2), Cloud B / region-b (shard 3), **parity 2**.
  - **Connectivity = SSH tunnels, not Tailscale.** The gateway→drive direction is
    one-way (drive nodes never talk to each other), so each node ran its drive
    server on `127.0.0.1:9100` and the gateway reached it through an SSH local-
    forward (`-L 920x:127.0.0.1:9100`). Encrypted, NAT-proof, **zero firewall
    changes, drive ports never exposed.** (Tailscale remains the *production*
    answer — no SSH dependency, true mesh — but is unnecessary for the test.)
  - **Binary:** glibc build for the Ubuntu nodes; a **static musl** build
    (`x86_64-unknown-linux-musl`) for the Debian-12/glibc-2.36 GCP node.
  - **Results:** 300 KB object PUT/GET over the cluster → md5 identical, one
    `part.1`+`xl.meta` shard per node; **killed 2 of 4 whole nodes (GCP+AWS) →
    GET still reconstructed** from laptop+VM; corrupted AWS's shard (bitrot) →
    `POST /kerplace/admin/v3/heal?bucket=` **rebuilt it over the RPC**
    (`shardsRewritten:1`), object still md5-identical.
  - **Gap → 4b:** writes are still strict (all-drives; a node down during a PUT
    fails the write — no write quorum yet). Reads + heal already tolerate loss.
- **4b — write quorum ✅ DONE; distributed locks + streaming remote I/O (todo).**
  - **Write quorum (done):** `write_sharded` no longer fails when a node is down.
    It prepares a writer per drive, skips drives it can't reach (recording the
    BLAKE3 checksum for *every* shard so reads/heal still know all N), and
    succeeds iff **`≥ K+1`** shards were fully written (`tmp.1`→`part.1`+`xl.meta`);
    below that it rolls the partial write back and errors. So a PUT now tolerates
    up to `M-1` nodes down, and `heal` later restores the skipped shards. (Bucket
    creation is likewise best-effort, anchored on drive 0 — the listing/metadata
    drive, still a SPOF, see below.) Tests: `put_tolerates_one_node_down`,
    `put_rejected_below_write_quorum` (a `FailingDrive` double).
  - **Streaming remote I/O (done):** neither side buffers a whole file anymore.
    `RemoteDrive::open` streams the GET response body (`bytes_stream` →
    `StreamReader`); `RemoteWriter` streams the PUT body through a `duplex` pipe
    fed by the caller, with a spawned task whose result `shutdown` awaits (so the
    `tmp`→`part.1` rename only fires once the data is durable). The drive server
    matches: `PUT` streams the request body to disk; full `GET` streams from
    disk (a `Range`/`read_at` slice is still small enough to buffer). Matters for
    the ~1 GiB cloud nodes — a large object never sits wholly in RAM. Test:
    `remote_drive_streams_large_file` (500 KB past the 64 KB duplex buffer).
  - **Object locking (done):** `src/cluster/lock.rs`. Two layers, taken on
    `put`/`delete`/`delete-version`/`complete-multipart` for `<bucket>/<key>`:
    (1) `LocalKeyLocks` — a per-key async mutex **inside the gateway** (makes a
    single gateway race-free, the common case); (2) `DistLock` — an opt-in
    (`KP_CLUSTER_LOCKS=true`) **quorum** lock across the drive nodes (each runs
    a leased `LockTable` over `/_kerplace/drive/v1/lock/{acquire,release}`), so
    multiple gateways against one cluster coordinate. A 30 s lease covers a
    crashed holder; acquire retries with backoff.
  - **Strict fencing (4c, done):** each grant carries a monotonic per-resource
    **fencing token**; a fresh grant bumps it, a re-entrant refresh keeps it, and
    the token only increases (even across releases). The gateway threads each
    node's token to that node's writes (via a task-local read by `RemoteDrive`,
    headers `x-kerplace-fence-{resource,token}`); the drive **rejects** any
    mutating write whose token is older than the latest it granted (`412`). So a
    stalled holder whose lease expired and was superseded can no longer corrupt
    the data path — the classic distributed-locking hazard is closed. Tests:
    `local_locks_exclusive_per_key`, `lock_table_exclusive`,
    `lock_table_lease_expires`, `dist_lock_quorum_round_trip`,
    `fencing_tokens_are_monotonic`, `fencing_rejects_stale_write_over_rpc`.
  - **Drive-0 metadata replication (done):** metadata is no longer pinned to
    drive 0. Config sidecars and `history.json` replicate to **every** drive
    (`meta_write_all` / `meta_read_any`); `history.json` carries a monotonic
    `epoch` so a previously-down drive can't serve a stale copy (read takes the
    max epoch). Bucket existence/`head_bucket` and `list_buckets` answer from any
    drive; `list_objects_v2` / `list_object_versions` **union** the walk across
    drives so a drive that missed writes can't hide keys; `get_bucket_versioning`
    is fail-safe (reads all drives, returns the most protective status, so a
    stale "Off" can't clobber live versions). Multipart staging picks the first
    reachable drive (encoded in the upload id) instead of always drive 0. Test:
    `metadata_survives_drive_0_down`. **This closes 4b.**
- **4c — done: strict lock fencing (above), FsStore locking, Tailscale-for-
  production runbook (`docs/PRODUCTION_TAILSCALE.md` + `cluster-node.sh`). Last
  item: dynamic membership / rebalance — designed in
  [DYNAMIC_MEMBERSHIP_DESIGN.md](DYNAMIC_MEMBERSHIP_DESIGN.md) (server-pools
  model; phased 4c-m1…m4).**

## 11. Test plan (the 4 real nodes)
1. Tailscale on laptop(0) + VM(1) + GCP(2) + AWS(3); confirm mutual `100.x` ping.
2. Deploy the binary (cross-compile `x86_64`; the VM/GCP/AWS are all x86_64) +
   `KP_*` to each; small block size (e2-micro RAM) and small drive dirs.
3. Gateway on the laptop, drives on all four; `mc cp` a file.
4. **Power off / `tailscale down` two nodes** → object still GETs (reconstruct).
5. Bring them back → `POST /kerplace/admin/v3/heal` → full redundancy restored.
6. Audit trail (`x-kerplace-author`/`source-ip`) survives across the cluster.

## 12. Open questions
- Drive API: HTTP (chosen, debuggable) vs gRPC (later perf). → HTTP first.
- `xl.meta` disagreement tie-break with even `N`: majority, else newest
  `last_modified` wins. → document precisely when implementing 4a-2.
- Gateway redundancy: any node can be a gateway, but clients need a stable
  endpoint → a VIP / round-robin DNS over the tailnet, or just pin one for the
  test. → pin laptop(0) for 4a-2; revisit in 4c.
- e2-micro is too small for real data — fine for the functional test; for any
  sustained use, replace node 2 with a larger instance.

## 13. Status / notes before provisioning
- **All 4 nodes reachable:** laptop, LAN VM (ssh key), Cloud A and Cloud B
  (`user@<public-ip>`, via your key). Inventory done.
- **Tiny cloud nodes:** both small instances (~1 GiB RAM, ~10 G disk).
  → use a **small block size** (e.g. ≤ 256 KiB) and small test objects; if a node
  has no Rust → cross-compile `x86_64` and ship the binary (all nodes are x86_64).
- **VM disk:** the LAN VM's root was near-full — point its drive dir at free
  space before loading test data.
- **Tailscale** is not yet installed on any remote node — that's the first
  provisioning step once we move from design to deploy.
- **GCP SSH:** instance is RUNNING; confirm `gcloud compute ssh` / OS Login works
  for deploying (only listing was verified so far).
