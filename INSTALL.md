# Installing & configuring KerPlace

> Living document — grown as we go. Covers building, configuring, the storage
> layout, and running KerPlace (single node).

## 1. Prerequisites

- **Build:** a Rust toolchain (stable). `cargo` on `PATH`.
- **Mounting buckets (optional):** `mc` (MinIO client) and `s3fs-fuse` on the host.
- **TLS with `ring`/`rcgen` (built in):** a C compiler + `perl` (already needed by
  the crypto crates). No system OpenSSL required.

## 2. Build

```bash
cargo build --release        # produces ./target/release/kerplace
```

## 3. Configuration — environment variables only

**KerPlace has no config file.** Everything is set through `KP_*` environment
variables (read in `src/config.rs`). Configure it by exporting them before
launch (inline, a sourced `.env`, or a systemd unit — see §6).

| Variable | Default | Meaning |
|---|---|---|
| `KP_ADDRESS` | `0.0.0.0:9000` | S3 API listen address |
| `KP_DATA_DIR` | `./data` | **Storage path** (see §4) |
| `KP_ROOT_USER` | `minioadmin` | Root access key |
| `KP_ROOT_PASSWORD` | `minioadmin` | Root secret key |
| `KP_REGION` | `us-east-1` | SigV4 region |
| `KP_AUTH` | `true` | `false` disables S3 auth (dev only) |
| `KP_CONSOLE` | `true` | `false` disables the web console |
| `KP_CONSOLE_ADDRESS` | `0.0.0.0:9001` | Web console listen address |
| `KP_ENCRYPT` | `false` | `true` = encrypt **all** objects at rest |
| `KP_TLS` | `false` | `true` = HTTPS with a self-signed dev cert |
| `KP_TLS_CERT` / `KP_TLS_KEY` | — | PEM cert/key (enables TLS; overrides self-signed) |
| `KP_USERS` | — | Seed IAM users: `accessKey:secretKey:policy`, comma-separated |

> Per-bucket encryption (recommended over the global `KP_ENCRYPT`) is set at
> runtime with `mc encrypt set` or the console — see WORKING_WITH_IT.md.

### Storage backend
| Variable | Default | Meaning |
|---|---|---|
| `KP_BACKEND` | `erasure` | `erasure` = Reed-Solomon (default); `fs` = single-disk mirror |
| `KP_ERASURE_DRIVES` | 4 sub-drives under the data dir | comma-separated drive dirs (e.g. `/d1,/d2,/d3,/d4`) |
| `KP_ERASURE_PARITY` | `N/2` | parity shards `M` (survives `M` drive losses) |
| `KP_ERASURE_BLOCK` | `1048576` | erasure block size in bytes |

**`erasure` is the default backend** (like modern MinIO, which removed its old
FS mode in 2022). It shards each object across the drives with bitrot detection
— survives up to `M` drive failures and is **opaque** (files dropped into a
drive by hand are ignored). With no `KP_ERASURE_DRIVES` it auto-creates four
sub-drives under `<data_dir>/.erasure/disk{0..3}` (single host).

> **Single physical disk:** sub-drives on one disk give the opaque format +
> intra-disk bitrot reconstruction, but **not** true redundancy (a whole-disk
> failure loses everything). For real redundancy, point `KP_ERASURE_DRIVES`
> at directories on **separate disks**.

**`KP_BACKEND=fs`** opts into the transparent single-disk mirror (objects are
plain files at `<data_dir>/<bucket>/<key>`). It's a convenience for inspection /
easy migration / "pseudo-NFS" use that MinIO no longer offers — and it lets you
serve a pre-existing directory tree as S3. Switching an existing data dir
between `fs` and `erasure` is **not** supported (different on-disk formats).
See `docs/ERASURE_CODING_DESIGN.md`.

## 4. Storage layout (what `KP_DATA_DIR` contains)

```
<KP_DATA_DIR>/
  <bucket>/<key>                  object payloads (plaintext, or MNE1 ciphertext if encrypted)
  .kerplace.sys/
    master.key                    AES master key       ⚠ SECRET
    pq.bin                        ML-KEM-1024 keypair  ⚠ SECRET
    buckets/<bucket>/*.json       per-bucket config (sse, versioning, policy, tags, lifecycle)
    meta/<bucket>/<key>.json      per-object metadata sidecars
    versions/<bucket>/<key>/      non-current versions + delete markers
    multipart/<bucket>/<id>/      in-progress multipart staging
    iam/users.json                IAM users (created at runtime; KP_USERS seed lives in memory)
    tmp/                          temp files for atomic writes
    tls-cert.pem / tls-key.pem    self-signed dev cert (only when KP_TLS=true, no cert provided)
```

### ⚠ Don't modify the backend by hand (FS backend caveat)
The v0.1 **FS backend** stores objects as plain mirror files
(`<data>/<bucket>/<key>`) — like MinIO's deprecated "FS mode". Unlike modern
MinIO (erasure-coded, opaque `xl.meta` format, drives owned exclusively), this
means files dropped into the data dir by hand **do appear** as objects — but
**degraded**: no ETag, generic content-type, no encryption/version tracking (no
metadata sidecar). Treat `KP_DATA_DIR` as **owned by KerPlace**; mutate it only
through the S3 API / console / a mount.

> **Roadmap #4 (erasure coding)** replaces this with a sharded, opaque,
> exclusively-owned backend (Reed-Solomon redundancy + bitrot detection), so the
> backend can no longer be edited from outside.

### ⚠ Protect the keys
`.kerplace.sys/master.key` and `pq.bin` are the at-rest encryption keys. If an
attacker steals the **whole** data dir (data + `.kerplace.sys`) they can decrypt
everything. At-rest encryption protects against theft of the *object data only*
(keys excluded), a backup that excludes `.kerplace.sys`, or raw-disk reads.

- **Never commit `.kerplace.sys/` to git** (it's in `.gitignore`).
- Back it up separately from the bucket data, with stricter access.
- **Roadmap:** external KMS (HashiCorp Vault Transit) to keep the root key off
  the disk entirely.

## 5. First run

```bash
KP_DATA_DIR=/srv/kerplace-data \
KP_ROOT_USER=admin KP_ROOT_PASSWORD=change-me-please \
  ./target/release/kerplace
```

- S3 API → `http://<host>:9000`
- Web console → `http://<host>:9001`

## 6. Running as a service (no config file → use the unit's `Environment=`)

Example systemd unit (`/etc/systemd/system/kerplace.service`):

```ini
[Unit]
Description=KerPlace object storage
After=network.target

[Service]
Environment=KP_DATA_DIR=/srv/kerplace-data
Environment=KP_ROOT_USER=admin
Environment=KP_ROOT_PASSWORD=change-me-please
Environment=KP_TLS=true
ExecStart=/usr/local/bin/kerplace
Restart=on-failure
User=kerplace

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now kerplace
```

## TODO (to document as features land)
- [ ] Optional config file (`kerplace.toml`) as an alternative to env vars.
- [ ] KMS-backed key provider setup.
- [ ] Hardening / production checklist (TLS, firewall, key backup).
