# Encryption at rest

How KerPlace encrypts objects on disk: what is encrypted, when, with which
algorithm, and how to control it. For the *why* of post-quantum see
[POST_QUANTUM.md](POST_QUANTUM.md); for the threat model and its honest limits,
[SECURITY_MODEL.md](SECURITY_MODEL.md); for definitions, the [glossary](GLOSSARY.md).

## On by default (secure by default)

**At-rest encryption is ON by default.** A plain install — storage path, API port,
console port — encrypts every object as it is written. There is nothing to enable and
**no KMS to deploy**: the default `file` key provider holds the keys on the host.

To turn it off, set **`KP_ENCRYPT=false`** explicitly.

> This is the opposite default to stock MinIO, which stores objects unencrypted unless
> you configure per-bucket auto-encryption *and* run an external KMS (KES). KerPlace is
> encrypted out of the box, with no extra infrastructure.

## Transparent to S3 clients

Encryption is **server-side and transparent** (the SSE-S3 model): clients upload
plaintext, the server encrypts on write and decrypts on read, and clients read plaintext
back. **`mc`, `aws s3`, `rclone`, `s3fs` and any S3 SDK work unchanged** — `cp`, `ls`,
`mirror`, multipart and range reads all behave normally. The client never sees or handles
ciphertext or keys.

The only observable difference is the **ETag**: encrypted objects return an *opaque*
ETag instead of the plaintext MD5 — exactly as AWS does for server-side-encrypted
objects. Tools do not rely on ETag being the MD5, so nothing breaks.

## What triggers encryption (layered, OR'd)

An object is encrypted on write if **any** of these is true:

| Trigger | How it's set | Scope |
|---|---|---|
| **Global default** | `KP_ENCRYPT` (default **true**) | every object on the server |
| **Per-bucket** | `mc encrypt set sse-s3 alias/bucket` (S3 `PutBucketEncryption`) | every object in that bucket |
| **Per-object** | the `x-amz-server-side-encryption: AES256` request header | that single object |

So with the default on, everything is already encrypted and `mc encrypt set` is accepted
but **redundant** (it succeeds and is reported by `GetBucketEncryption`, it just has no
additional effect). With `KP_ENCRYPT=false`, the per-bucket and per-object triggers let
you encrypt selectively.

## Which algorithm — set by the key provider, not the S3 label

`mc encrypt set` decides *whether* to encrypt; it does **not** choose the algorithm. The
algorithm is determined by the active **key provider**:

| Provider (`KP_KEY_PROVIDER`) | DEK wrapping | Post-quantum? | Custody |
|---|---|---|---|
| **`file`** (default) | **ML-KEM-1024** + AES-256-GCM data | ✅ **yes** | keys on host |
| `passphrase` | Argon2id-derived KEK, AES-256 wrap | no (classical) | KEK from a passphrase, never on disk |
| `kms` | external KMS (e.g. Vault Transit) | depends on the KMS (classical) | off-host, revocable |

With the **default `file` provider**, every encrypted object is **post-quantum**: a fresh
per-object data key is wrapped with **ML-KEM-1024** (NIST FIPS 203) and the bytes are
sealed with **AES-256-GCM**.

> **The `AES256` label is not the whole story.** S3 only has the label `AES256` for
> server-side encryption, so that is what `mc encrypt info` and the response header
> report. It refers to the **data** cipher (which is indeed AES-256-GCM). The
> post-quantum part is the **key wrapping** (ML-KEM-1024), for which S3 has no label.
> With the `file` provider, the encryption is post-quantum even though the label says
> `AES256`.

## What it protects (and what it doesn't)

At-rest encryption protects against a **stolen disk** or a **leaked backup** — those
yield only ciphertext. With the default `file` provider the keys live on the same host,
so it does **not** protect against a compromise of the running server (which holds the
keys). For "not even the host can read it", move key custody off-host with the `kms`
provider — see [Off-host key custody](OFFHOST_KMS_CUSTODY.md). This is stated plainly in
the [security model](SECURITY_MODEL.md); KerPlace publishes its limits rather than hiding
them.

## Quick reference

```bash
# Encrypted by default — nothing to set:
kerplace                                   # KP_ENCRYPT defaults to true

# Turn it off (store plaintext):
KP_ENCRYPT=false kerplace

# Off-host, revocable key custody (keys never on the storage host):
KP_KEY_PROVIDER=kms KP_KMS_ADDR=… kerplace
```
