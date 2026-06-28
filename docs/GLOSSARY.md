# KerPlace glossary

Plain-language definitions of the terms you'll meet in KerPlace's docs — object
storage, the cryptography, and the tools you use to talk to it. Skim it, or jump
to a term. Where a term has a dedicated guide, it's linked.

> New to object storage and just want your files safe? Start with
> **[S3](#s3)**, **[bucket](#bucket)**, **[object](#object)**,
> **[mc](#mc)** and **[alias](#alias)**.

---

## Object storage & the S3 ecosystem

### S3
**Simple Storage Service** — the de-facto standard *API* (a set of HTTP requests)
for storing and retrieving files as **objects** in **buckets**. Originally an
Amazon service, "S3" now means the *protocol*: dozens of tools and libraries speak
it. **KerPlace is S3-compatible**, so anything that talks S3 — `mc`, the AWS CLI,
`rclone`, `s3fs`, application SDKs — works against KerPlace unchanged. You are not
locked into one vendor.

### Bucket
A top-level container for objects, like a drive or a top-level folder. Names are
globally unique within a server and must be 3–63 characters. You create buckets,
set properties on them (versioning, encryption), and put objects inside.

### Object
A single stored item: the file's **bytes** plus its **metadata** (content-type,
size, timestamps, an [ETag](#etag), custom key/value tags). Objects are identified
by a **key** (their name/path within a bucket, e.g. `photos/2026/cat.jpg`). Object
storage has no real directories — the `/` in a key is just part of the name.

### Key (object key)
The name of an object within its bucket. Not to be confused with a *cryptographic*
key (see [KEK](#kek) / [DEK](#dek)).

### ETag
A short tag returned for every object (an "entity tag"). For a plain, unencrypted
upload it is the **MD5 hash** of the bytes, so clients can verify integrity. For an
**encrypted** object KerPlace returns an *opaque* tag instead (the same as Amazon
does for server-side-encrypted objects) — the stored bytes are ciphertext, so their
MD5 would be meaningless. ETags are also used to detect "has this object changed?".

### SSE (server-side encryption)
Encryption performed **by the storage server** as it writes objects to disk, so the
data is never stored in the clear. KerPlace does this by default (see
[PQC](#pqc-post-quantum-cryptography) and `docs/SECURITY_MODEL.md`). Contrast with
*client-side* encryption, where the client encrypts before uploading.

### Versioning
Keeping a history of an object instead of overwriting it. With versioning enabled,
each `PUT` to an existing key creates a new version and the old ones remain
retrievable; deletes leave a "delete marker" you can undo.

---

## Cryptography & key custody

### PQC (post-quantum cryptography)
Encryption designed to stay secure even against a future **quantum computer**, which
would break today's RSA/elliptic-curve key exchange. KerPlace protects the keys that
unlock your data with a post-quantum algorithm so that data captured today cannot be
decrypted later once quantum computers arrive ("harvest now, decrypt later"). Full
explainer: **[`docs/POST_QUANTUM.md`](POST_QUANTUM.md)**.

### ML-KEM (a.k.a. Kyber)
The specific post-quantum algorithm KerPlace uses — **M**odule-**L**attice **K**ey-
**E**ncapsulation **M**echanism, standardized by NIST in 2024 (FIPS 203). It safely
transports a secret key over an untrusted channel. KerPlace uses the strongest
parameter set, **ML-KEM-1024**, to wrap each object's data key.

### AEAD / AES-256-GCM
**AEAD** = Authenticated Encryption with Associated Data: a cipher that both *hides*
the data and *detects tampering*. **AES-256-GCM** is the specific AEAD KerPlace uses
to encrypt the actual object bytes — fast, hardware-accelerated, and the industry
standard. (Post-quantum [ML-KEM](#ml-kem-aka-kyber) protects the *key*; AES-256-GCM
protects the *data*. This pairing is called *hybrid* encryption.)

### DEK (data-encryption key)
A unique, random key generated **per object** to encrypt that object's bytes. The DEK
is never stored in the clear — it is itself encrypted ("wrapped") by a higher-level
key, the [KEK](#kek). This two-level scheme is called **envelope encryption**: cheap
to rotate the top-level key without re-encrypting all the data.

### KEK (key-encryption key)
The higher-level key that **wraps the per-object [DEKs](#dek)**. Whoever controls the
KEK controls access to all the data — so *where the KEK lives* is the heart of
KerPlace's security model. It can live on the server (`file` provider), be derived
from a passphrase at boot (`passphrase` provider), or live in an external
[KMS](#kms) you control (`kms` provider). See `docs/SECURITY_MODEL.md`.

### KMS (key-management service)
A separate, hardened service whose only job is to **hold keys and perform
wrap/unwrap operations** — the keys never leave it. KerPlace can delegate its
[KEK](#kek) to an external KMS (today: HashiCorp [Vault](#vault)), so the storage
host never holds the root key. Revoke access at the KMS and the data instantly goes
dark, even mid-run. This powers the **[off-host custody](OFFHOST_KMS_CUSTODY.md)**
deployment: *your data on their host, your keys on your device.*

### Vault
**HashiCorp Vault** — a popular open-source [KMS](#kms)/secrets manager. KerPlace's
`kms` key provider talks to Vault's *Transit* engine to wrap and unwrap data keys
without ever seeing the root key. Vault also supports **threshold unseal** (it takes
*K-of-N* "unseal shares" to start), which is how you can require *several people* to
be present to bring the service up.

### Envelope encryption
The pattern above: encrypt data with a per-object [DEK](#dek), then encrypt the DEK
with a [KEK](#kek). You store the wrapped DEK next to the data; rotating the KEK is
cheap because the bulk data is never re-encrypted.

### KPE1
KerPlace's on-disk encrypted-object format ("KerPlace Encryption v1") — a small
header (magic bytes, the wrapped DEK, a nonce) followed by the AEAD-encrypted bytes
in chunks. It's an implementation detail; you never handle it directly.

---

## Tools & filesystem access

### mc
The **MinIO Client** — a friendly command-line tool for S3 (`mc cp`, `mc ls`,
`mc mirror`, `mc mb`…). Works against KerPlace unchanged. You first register the
server as an **[alias](#alias)**, then use it like a remote drive.

### alias
A short *nickname* you give a server in a client so you don't retype its URL and
credentials each time. With `mc` you run `mc alias set mykp http://host:9000
ACCESS_KEY SECRET_KEY`, then refer to it as `mykp/bucket/object`. (Other tools call
the same idea a "remote", a "profile", or a "host".)

### FUSE
**Filesystem in Userspace** — a Linux mechanism that lets a program present
something (here: an S3 bucket) as an ordinary **mounted folder**. With a FUSE
adapter you can `cd` into a bucket and `cp`/`ls`/edit files as if they were local,
while reads and writes are translated into S3 calls under the hood. KerPlace ships a
helper (`kerplace.sh`) that mounts buckets this way. See
[`docs/LEGACY_ACCESS.md`](LEGACY_ACCESS.md).

### s3fs
A specific **[FUSE](#fuse)** adapter (`s3fs-fuse`) that mounts an S3 bucket as a
folder. It's what `kerplace.sh` uses under the hood to give you a filesystem view of
a bucket.

### rclone
A versatile command-line tool to **copy and sync** files between many storage
backends (local disk, S3, Google Drive, etc.). It speaks S3, so it works with
KerPlace for backups, migrations and scheduled syncs — and it can also *mount* a
bucket as a folder (`rclone mount`), an alternative to [s3fs](#s3fs).

### AWS CLI (`aws s3`)
Amazon's official command-line tool. Point it at KerPlace with
`aws --endpoint-url http://host:9000 s3 ...` and it works like any S3 endpoint.

### Path-style vs virtual-host-style
Two ways an S3 URL addresses a bucket. **Path-style** puts the bucket in the URL
path (`http://host:9000/bucket/key`); **virtual-host-style** puts it in the hostname
(`http://bucket.host/key`). Self-hosted servers like KerPlace use **path-style**;
some tools need a flag to force it.

---

## KerPlace internals (good to know, rarely handled directly)

### Gateway
The KerPlace process that speaks S3 to clients and does all the work — encryption,
erasure coding, hashing. In a cluster, clients talk to the gateway and it spreads
data across the drive nodes.

### Drive node
In a multi-node cluster, a machine that just stores raw shards of data and serves
simple positioned reads/writes. Drive nodes never see plaintext or hold keys.

### Erasure coding (Reed-Solomon)
A way to split each object into *K* data shards + *M* parity shards across drives, so
the object survives losing any *M* of them — more space-efficient than full copies.
Each shard also carries a checksum so silent corruption ("bitrot") is detected and
repaired. See [`docs/ERASURE_CODING_DESIGN.md`](ERASURE_CODING_DESIGN.md).

### Shard
One piece of an erasure-coded object stored on one drive (a data shard or a parity
shard).

### BLAKE3
A very fast modern cryptographic hash KerPlace uses to checksum shards and detect
bitrot (distinct from the [MD5](#etag) used for the S3 ETag).

---

*Missing a term, or something unclear? Email **support@kerplace.com** — we'll add it.*
