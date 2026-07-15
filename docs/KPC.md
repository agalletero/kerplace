# `kpc` — the KerPlace custody client

## 1. Purpose and definition

`kpc` (*KerPlaceClient*) is a single-binary administration tool for KerPlace
deployments running in **custody mode** — the configuration in which the key that
decrypts the data does not live on the host that stores it, but on an operator's
machine, typically released from a USB device (see
[Off-host key custody](OFFHOST_KMS_CUSTODY.md)).

It exists because that mode introduces a class of operations the S3 protocol
cannot express. A bucket can be listed, an object can be fetched, a user can be
created — all of that is S3, and existing clients handle it well. But *"is the
key store sealed?"*, *"release the key from this USB"*, *"bring the tunnel up"*,
and *"present that bucket as a directory"* are not S3 operations. They have no
verbs in the protocol, no place in its authorization model, and no client that
speaks them. `kpc` is where those operations live.

The design goal is operational rather than functional: an administrator holding
the USB, faced with a sealed system and no other context, should be able to run
`kpc --help` and recover the service. That requirement — legibility under stress
— explains most of the choices described below.

---

## 2. The division of responsibility

KerPlace's tooling divides along a single line: **whether the operation is
expressible in the S3 protocol**. Three layers follow from it.

| Layer | Concern | Tool |
|---|---|---|
| **Data** | buckets, objects, versions, users, policies | `mc`, `aws`, `rclone` — any S3 client |
| **Mount** | presenting a bucket as a local directory | **`kpc mount`** (drives `s3fs`) |
| **Custody** | seal state, USB, passphrase, tunnel, DR | **`kpc`**, exclusively |

The principle is short:

> **`mc` talks to the server. `kpc` talks to the custody.**
> Everything that is not the S3 protocol belongs to `kpc`; everything that is
> belongs to the client the operator already has.

The **mount** layer deserves attention, because it is the reason `kpc` is not
merely a disaster-recovery instrument. Mounting is a daily act — the first thing
an operator does on arrival and the last thing undone on departure — and it is
not an S3 operation. Its presence in the middle layer is what places `kpc` on the
routine path rather than in the emergency drawer.

---

## 3. Coexistence with `mc`

### 3.1 `kpc` does not replace `mc`

This is deliberate and worth stating without qualification: **`kpc` does not
implement the S3 or admin API, and is not intended to.** KerPlace's compatibility
with `mc` — including `mc admin user`, madmin payload encryption, and the
`/minio/admin/v3` prefix — is a deliberate product property, and `kpc` neither
extends nor competes with it. An operator migrating from MinIO keeps every
command they know.

### 3.2 Where each tool applies

| Task | Tool | Why |
|---|---|---|
| List/copy/remove objects, mirror trees | `mc`, `aws`, `rclone` | pure S3 |
| Create users, attach policies, inspect the server | `mc admin` | madmin-compatible |
| Scope a credential to buckets | `mc admin` + the admin API | see [Access control](ACCESS_CONTROL.md) |
| Ask whether the key store is sealed | **`kpc status`** | not an S3 concept |
| Release the key from the USB | **`kpc unseal`** | not an S3 concept |
| Seal immediately (incident response) | **`kpc seal`** | not an S3 concept |
| Bring up the tunnel that carries custody + data | **`kpc enable`** | not an S3 concept |
| Present a bucket as a directory | **`kpc mount`** | filesystem, not protocol |
| Recover the deployment after a disaster | **`kpc`** | `mc` cannot reach a sealed server |

### 3.3 Why `mc` cannot do the custody half

Not from any deficiency of `mc`, but because the custody operations are outside
the protocol it implements. Sealing is an action on a key store the S3 server
does not own; USB presence is a property of the operator's hardware; the tunnel
is transport that must exist *before* any S3 request can be made. An S3 client
cannot, even in principle, address a server whose transport is not yet up — which
is precisely the state `kpc enable` resolves.

The asymmetry is therefore structural: `kpc` needs no S3 vocabulary, and `mc`
cannot acquire a custody vocabulary without ceasing to be an S3 client.

---

## 4. `s3fs` is an implementation, not an alternative

Operators arriving from MinIO frequently mount buckets with `s3fs` directly and
reasonably ask what `kpc mount` adds.

`kpc` does not replace `s3fs` — **it invokes it**. `kpc mount <bucket>` resolves
the instance's endpoint and credentials from configuration, materialises the
credential file `s3fs` requires with correct permissions, and issues the
invocation with the options the deployment needs (`use_path_request_style`, the
endpoint URL, error-level diagnostics). The value is not capability but the
removal of recall: the operator does not have to remember an invocation, and the
mount configuration is declared once, in `kpc.toml`, rather than living in shell
history.

The same relationship holds throughout. `kpc` orchestrates standard tools —
`curl` for the key-store API, `gpg` for the USB material, `systemctl` for units,
`findmnt` for mount state, `s3fs` for FUSE — instead of reimplementing them. The
binary stays small and auditable, and each underlying tool remains inspectable
and replaceable by an operator who needs to work below `kpc`.

---

## 5. Operational lifecycle

The question *"when do I actually need `kpc`?"* is best answered chronologically.

**5.1 Arrival.** The USB is inserted. `kpc watch`, running as a `systemd --user`
agent, detects the transition and invokes `enable`: the tunnel is raised, the key
store is unsealed (the passphrase is prompted), and the configured buckets are
mounted. Equivalently, the operator runs `kpc enable` by hand. **This is not
disaster recovery; this is the ordinary start of a working day.**

**5.2 Work.** The vault is a directory; the buckets are S3 endpoints. `kpc` is
now idle and irrelevant: editors, `mc`, `aws` and `rclone` do the work. This is
the longest phase by wall-clock time, and the reason `kpc` is easily mistaken for
an emergency tool — it is invisible for most of the day.

**5.3 Departure.** `kpc disable` reverses the sequence, or the operator simply
removes the USB: a system-level service (udev plus a presence monitor) unmounts
the filesystems and seals the key store, and `kpc watch` stops the tunnel. From
that moment the host stores ciphertext it cannot read.

**5.4 Disaster.** The server is unreachable, or reachable and sealed. `mc` is of
no use: there is either no transport, or no ability to decrypt. `kpc status`
reports which of the two it is, and `kpc unseal`/`enable` acts on it. **This is
the phase `kpc` was designed for, and the reason its help text is written to be
read by someone who has never used it.**

---

## 6. Command reference

| Command | Effect | Privilege |
|---|---|---|
| `kpc status` | Reports seal state, USB presence, tunnel units and mounts | none |
| `kpc enable [instance]` | Raise tunnel(s) → unseal if sealed → mount buckets | none¹ |
| `kpc disable [instance]` | Unmount buckets → stop tunnel(s) → seal | sudo |
| `kpc unseal` | Decrypt the USB material and release the key to the key store | none |
| `kpc seal` | Seal immediately: unmount buckets, restart the key store | sudo |
| `kpc mount <bucket>` | Mount one bucket over FUSE | none¹ |
| `kpc umount <bucket>` | Unmount one bucket | none¹ |
| `kpc watch` | Agent: bind the USB's presence to enable/disable | none |
| `kpc provision-usb [path]` | Migrate the unseal material onto the USB (script-backed) | sudo |
| `kpc backup [dir]` | Disaster-recovery backup of the key store (script-backed) | sudo |

¹ Assumes the operator may use FUSE and the `systemd --user` session.

`status`, `unseal`, `seal`, `enable`, `disable`, `mount`, `umount` and `watch`
are implemented natively. `provision-usb` and `backup` currently delegate to the
deployment scripts and are to be ported.

---

## 7. Configuration

`kpc` reads, in order: `--config <path>`, `/etc/kerplace/kpc.toml`, then
`~/.config/kerplace/kpc.toml`. Paths must be absolute. The file has three
sections:

- **`[kms]`** — the key store's endpoint (reached over the tunnel), the private
  CA that authenticates it, and the systemd service to restart when sealing.
- **`[usb]`** — the custody device's filesystem label and UUID (the authoritative
  presence signal), and the path of the encrypted unseal material within it.
- **`[[instances]]`** — one entry per KerPlace host: its tunnel unit, S3 endpoint,
  credentials, and the buckets to mount with their mountpoints. A single key store
  may serve several instances.

See [`../kpc/kpc.toml.example`](../kpc/kpc.toml.example) for a complete example.

---

## 8. Design properties

Four properties are load-bearing and should survive refactoring:

1. **Orchestration over reimplementation.** Standard tools are invoked, not
   replaced (§4). An operator can always drop below `kpc` and run them directly —
   which matters most in the situation `kpc` exists for.
2. **Key material never reaches the process table.** The unseal material is
   decrypted into memory and delivered to the key store over its API via standard
   input; it never appears as a command-line argument, and therefore never in
   `ps`.
3. **Terminal-first passphrase entry.** The prompt reads from the controlling
   terminal, falling back to a graphical dialog only when there is none. A
   deployment recovered over SSH — the normal case in a disaster — must not
   depend on a desktop session being present.
4. **Fail-closed by construction.** `kpc` cannot manufacture access it does not
   have: absent USB, absent tunnel or a sealed key store are reported, not worked
   around.

---

## 9. Scope and non-goals

- **`kpc` does not implement S3 or the admin API.** Use `mc`/`aws`/`rclone` (§3).
- **`kpc` does not manage the server's lifecycle** beyond the custody surface; it
  is not an init system or a deployment tool.
- **`kpc` is not required for a non-custody deployment.** A KerPlace instance with
  on-host keys (`KP_KEY_PROVIDER=file`) has nothing for `kpc` to do.
- **`kpc` does not hold keys.** It releases material from a device the operator
  controls; it stores nothing itself.

---

## 10. Note on tiers

`kpc` as described here belongs to the free tier: it operates server-side
encryption and off-host custody, and is published under the same licence as the
server. Should a future client-side-encryption capability be introduced — in
which the client, not the server, performs the cryptography — that capability
would extend `kpc` while not being part of this open component. The distinction
is noted here so the boundary is explicit rather than discovered.

---

## 11. Open item: the `mc` dependency

The division in §3 rests on an assumption: **that a capable, freely available S3
and admin CLI will remain within reach of KerPlace's users.** `kpc` deliberately
declines to duplicate `mc` because duplicating a good tool that users already
have is waste.

That assumption is weakening. As MinIO's tooling moves onto a proprietary
footing, the data/admin layer of the table in §2 may lose its default occupant —
and for the operators KerPlace is built for, "install the proprietary client"
is not an answer.

If that occurs, the layer needs a home, and `kpc` is the natural candidate: it is
already the KerPlace-native binary on the operator's path. **This is recorded as
an open item, not a commitment.** Absorbing a mature CLI's surface is a
substantial undertaking, and undertaking it while `mc` still serves users would
be premature. The decision has a trigger — `mc` ceasing to be dependable for our
users — not a date.

---

## See also

- [Off-host key custody](OFFHOST_KMS_CUSTODY.md) — the deployment model `kpc` operates.
- [Access control](ACCESS_CONTROL.md) — per-bucket authorization (an `mc` concern, not a `kpc` one).
- [Security model](SECURITY_MODEL.md) — the threat model both sit in.
