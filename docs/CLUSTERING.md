# Clustering & deployment modes

How to run KerPlace — from a zero-config single host to a multi-node cluster whose
shards live on different machines. For the internal design see
[DISTRIBUTED_DESIGN.md](DISTRIBUTED_DESIGN.md).

![KerPlace distributed cluster](diagrams/cluster-topology.svg)

## The three deployment modes

| Mode | When | How |
|---|---|---|
| **Single-host erasure** (default) | one machine, want redundancy + bitrot protection | just run `kerplace` — it auto-creates 4 erasure "drives" under the data dir |
| **Single-host FS mirror** | one machine, want a plain transparent on-disk copy (pseudo-NFS) | `KP_BACKEND=fs` |
| **Distributed cluster** | shards spread across machines, survive whole-node loss | a *gateway* + N *drive nodes* (below) |

All three speak the same S3 API — clients never know the difference.

### 1. Single-host erasure (default)

```bash
KP_DATA_DIR=./data ./kerplace
```

The object is Reed-Solomon sharded into `K` data + `M` parity pieces across `N`
local drives (default `N=4`, `M=2`). Any `M` drives can be lost and every object
still reconstructs; every shard is BLAKE3-checksummed so bitrot is detected and
healed.

![Erasure coding](diagrams/erasure-coding.svg)

Tune it:

```bash
# explicit local drives (ideally separate physical disks) + parity
KP_ERASURE_DRIVES=/mnt/d0,/mnt/d1,/mnt/d2,/mnt/d3,/mnt/d4,/mnt/d5 \
KP_ERASURE_PARITY=2 \
KP_ERASURE_BLOCK=1048576 \
./kerplace
```

> ⚠️ On a single physical disk the redundancy protects against bitrot but not a
> disk failure — for real durability give each drive a separate disk, or go
> distributed.

### 2. Single-host FS mirror (opt-in)

```bash
KP_BACKEND=fs KP_DATA_DIR=./data ./kerplace
```

Each object is one file on disk (transparent, greppable). No redundancy — this
is the "modern NFS" convenience mode, offered on demand.

## Building a distributed cluster

A cluster is **one gateway** (serves the S3 API and runs the erasure logic) plus
**N drive nodes** (each stores one shard slot). The gateway is the only node
that talks to the others; **drive nodes never talk to each other**, which keeps
networking simple.

### Roles & configuration

| Variable | Role | Meaning |
|---|---|---|
| `KP_ROLE=drive` | drive node | serve only the internal shard API (no S3) |
| `KP_DRIVE_ADDR` | drive node | bind address of the drive RPC (default `0.0.0.0:9100`) |
| `KP_DATA_DIR` | drive node | where this node stores its shards |
| `KP_NODES` | gateway | shard map `idx=addr,...` (e.g. `0=local,1=10.0.0.2:9100,2=...`) |
| `KP_NODE_INDEX` | gateway | which shard slot **this** machine hosts locally (optional) |
| `KP_ERASURE_PARITY` | gateway | parity `M` (survive `M` node losses) |
| `KP_CLUSTER_SECRET` | both | shared bearer secret for the drive RPC |
| `KP_CLUSTER_LOCKS` | gateway | `true` → distributed quorum object locks (only needed for **several gateways** on one cluster; local locking is always on) |

### Connectivity: two options

The gateway must reach each drive node's RPC port. Because it's **one-directional**
(gateway → drives), you have two clean choices:

- **SSH tunnels** — quick, encrypted, **no firewall changes, no exposed ports**.
  Each drive binds `127.0.0.1:9100`; the gateway forwards a local port to it:
  ```bash
  ssh -fN -L 9201:127.0.0.1:9100 user@node1     # gateway:9201 → node1
  ```
  Then point the gateway at `127.0.0.1:9201`. Great for a lab / proof.
- **Tailscale (or WireGuard) overlay** — production answer. Every node gets a
  stable `100.x` address; no SSH dependency, true mesh. Bind the drive RPC to the
  tailnet interface and use those IPs in `KP_NODES`. Full hardened runbook
  (ACLs, systemd, security checklist) + the [`cluster-node.sh`](../cluster-node.sh)
  helper: **[PRODUCTION_TAILSCALE.md](PRODUCTION_TAILSCALE.md)**.

Either way the RPC is bearer-authenticated and should never be exposed to the
public internet in the clear.

### Worked example — a 4-node cluster (parity 2)

On **each drive node** (`node1`, `node2`, `node3`):

```bash
KP_ROLE=drive \
KP_DRIVE_ADDR=127.0.0.1:9100 \
KP_DATA_DIR=/var/lib/kerplace \
KP_CLUSTER_SECRET=$SECRET \
./kerplace
```

On the **gateway** (also hosting shard 0 locally), with tunnels
`9201→node1`, `9202→node2`, `9203→node3` open:

```bash
KP_ADDRESS=0.0.0.0:9000 \
KP_DATA_DIR=/var/lib/kerplace \
KP_NODES="0=local,1=127.0.0.1:9201,2=127.0.0.1:9202,3=127.0.0.1:9203" \
KP_NODE_INDEX=0 \
KP_ERASURE_PARITY=2 \
KP_CLUSTER_SECRET=$SECRET \
./kerplace
```

Now use it like any S3 endpoint:

```bash
mc alias set cl http://gateway:9000 minioadmin minioadmin
mc mb cl/data
mc cp ./bigfile cl/data/bigfile        # sharded across all 4 nodes
```

With `parity 2` the cluster **survives losing any 2 of the 4 nodes** on reads,
needs a quorum of `≥ K+1 = 3` nodes to write, and self-heals returned nodes.

> This exact topology was validated live across a laptop + a LAN VM + a GCP
> instance + an AWS instance (3 networks) — see DISTRIBUTED_DESIGN.md §10.
> Cross-OS note: ship a static **musl** build to nodes with an older glibc.

## Operating a cluster

```bash
# cluster + per-drive health (backend type, parity, drive states)
mc admin info cl                              # or: curl .../minio/admin/v3/info

# scan & repair degraded objects (rewrite missing/corrupt shards)
curl -X POST 'http://gateway:9000/kerplace/admin/v3/heal?bucket=data'
curl -X POST 'http://gateway:9000/kerplace/admin/v3/heal?dryRun=true'   # report only
```

| Event | Behaviour |
|---|---|
| read with ≤ `M` nodes down | reconstructs transparently |
| write with a node down | succeeds if ≥ `K+1` shards land; the rest are healed later |
| a returned/replaced node | `heal` rebuilds its missing/corrupt shards over the RPC |
| bitrot on a shard | BLAKE3 mismatch → that shard ignored → reconstructed, then healed |

## Concurrency & locking

Writes to the **same object key** are serialized. A per-key lock inside the
gateway makes the common single-gateway deployment race-free with no extra
network cost. If you run **several gateways** against one cluster, set
`KP_CLUSTER_LOCKS=true` to also take a **quorum lock** across the drive nodes
(each holds a 30 s-leased lock; a crashed gateway's lock expires).

## Current limits

- **Static membership** — the node list is fixed at start (no online add/remove
  or rebalance yet).
- **The gateway is an availability SPOF** — see "Durability vs availability" below.

Quorum locks now do **strict fencing**: each grant carries a monotonic fencing
token and a drive rejects any write from a superseded (stale) holder, so a
stalled gateway can't corrupt the data path.

### Durability vs availability (read this before comparing to MinIO)

These are two different properties, and KerPlace is strong on one but not yet the
other — stating them separately keeps the comparison honest:

- **Durability / data safety — no single node is a hard SPOF.** Metadata (bucket
  existence, listing, version history, config) is replicated to every drive, and
  object data is Reed-Solomon `K+M` sharded, so the cluster **survives losing any
  `M` nodes** with no data loss and reads still reconstruct. ✅
- **Service availability — the gateway is currently a SPOF.** The S3 plane and
  the erasure logic run on a **single gateway**; if it goes down there is no
  service even though every drive node is alive and the data is intact. ⚠️

  Mitigation today: the distributed locks already do **strict fencing**, which is
  exactly what lets several **stateless gateways** run against one cluster behind
  a load balancer / VIP — so an HA front end is mostly a deployment concern, not
  missing machinery. The supported topology, requirements and example are in
  **[MULTI_GATEWAY_HA.md](MULTI_GATEWAY_HA.md)**. True active-active control-plane
  (leader election, lifting the single-writer throughput ceiling) is declared
  **future work**, not implied.

> MinIO spreads the control plane across nodes; KerPlace's gateway-plus-drives shape
> is simpler (and caps write throughput at one gateway). Don't read "no node is a
> SPOF" as a uptime/HA claim — it is a **durability** claim.

The production
overlay deployment is documented in
[PRODUCTION_TAILSCALE.md](PRODUCTION_TAILSCALE.md). The one remaining 4c item is
**dynamic membership / rebalance** (online add/remove of nodes) — see
[DISTRIBUTED_DESIGN.md](DISTRIBUTED_DESIGN.md).
