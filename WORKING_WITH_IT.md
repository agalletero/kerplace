# Working with KerPlace

> Living document — how to use KerPlace day to day: aliases, buckets, encryption,
> versioning, users, mounting, and verifying at-rest encryption.

KerPlace speaks the **S3 protocol**, so you use standard S3 tooling (`mc`, `aws`,
`rclone`, `s3fs`, any S3 SDK) and just point it at KerPlace with **path-style**
addressing. Nothing imports a "KerPlace library".

## 1. Configure the `mc` alias

```bash
mc alias set myn http://localhost:9000 minioadmin minioadmin
# TLS: use https:// and add --insecure for the self-signed dev cert
mc alias set myn https://localhost:9000 minioadmin minioadmin --insecure
```

`mc` stores aliases in `~/.mc/config.json` (override with `MC_CONFIG_DIR`).
Keep the alias config **outside** `KP_DATA_DIR` (otherwise its folder shows
up as a phantom bucket).

## 2. Buckets

```bash
mc mb myn/my-bucket            # create
mc ls myn                      # list buckets
mc ls --recursive myn/my-bucket
mc rb myn/my-bucket            # remove (must be empty; --force to drain)
```
Also doable from the **web console** (http://localhost:9001).

## 3. Encryption at rest (per bucket — recommended)

Encryption is **per object**, decided at write time. Turn it on for a bucket so
every **new** object is encrypted (ML-KEM-1024 post-quantum DEK wrap + AES-256-GCM):

```bash
mc encrypt set sse-s3 myn/my-bucket     # enable
mc encrypt info myn/my-bucket           # check
mc encrypt clear myn/my-bucket          # disable (future writes)
```
Or the console: bucket **⚙ Settings → Encryption at rest → Enable**.

- Applies to objects written **after** enabling; existing objects are unchanged
  (re-upload to encrypt them).
- Reads are transparent: any authorized client (mc, mount, console) sees
  plaintext; the server decrypts on the fly.
- Global alternative: `KP_ENCRYPT=true` encrypts every object in every bucket.

### Verify encryption actually happened (at rest)
The only way to tell is to look at the **raw bytes on disk** — a mount/console
always shows plaintext (that's by design):

```bash
# Encrypted objects start with the MNE1 magic:
head -c 4 "$KP_DATA_DIR/my-bucket/file.bin" | xxd
#   4d4e 4531  → "MNE1"  = encrypted ✅
#   anything else (e.g. PNG/JPEG magic) = stored in plaintext
```

## 4. Versioning

```bash
mc version enable  myn/my-bucket
mc version info    myn/my-bucket
mc ls --versions   myn/my-bucket          # list versions + delete markers
mc cp --version-id <vid> myn/my-bucket/k ./   # fetch a specific version
mc version suspend myn/my-bucket
```
Console: bucket **⚙ Settings → Versioning**. The version viewer (object → **Versions**)
lets you download/delete individual versions and delete markers.

## 5. Users & access (IAM)

Canned policies: `readwrite`, `readonly`, `writeonly`, `admin` (consoleAdmin).

```bash
# Seed at startup (in-memory, ephemeral unless mutated):
KP_USERS="alice:alicesecret:readonly,bob:bobsecret:readwrite" ./kerplace

# Or manage at runtime (persisted to .kerplace.sys/iam/users.json):
mc admin user add     myn alice alicesecret
mc admin user list    myn
mc admin user disable myn alice
mc admin user remove  myn alice
```
Console: **Users** tab (add with a policy, enable/disable, delete; **⟳ Generate**
makes a random secret).

Each user is its own `mc alias` / credential:
```bash
mc alias set alice http://localhost:9000 alice alicesecret
mc cp file alice/my-bucket/   # subject to alice's policy (readonly → denied)
```

## 6. Mounting buckets as folders (`kerplace.sh` + s3fs)

```bash
KP_URL=http://localhost:9000 KP_ACCESS_KEY=admin KP_SECRET_KEY=secret \
KP_MOUNT_BASE=/mnt/datalake \
  ./kerplace.sh mount-all          # mounts every bucket under $KP_MOUNT_BASE
./kerplace.sh show-mount           # dashboard: buckets, encryption, versioning, users, mounts
./kerplace.sh umount-all
```
Encryption/versioning are transparent through the mount: you read/write normal
files; the server encrypts/versions underneath.

## 7. Programming applications

Point any S3 SDK at KerPlace with path-style + credentials. Example (Python/boto3):
```python
import boto3
s3 = boto3.client("s3", endpoint_url="http://localhost:9000",
    aws_access_key_id="minioadmin", aws_secret_access_key="minioadmin",
    region_name="us-east-1",
    config=boto3.session.Config(s3={"addressing_style": "path"}))
```
Not yet supported (would affect some apps): CORS (browser direct-upload),
ListObjects v1, S3 Select, bucket notifications/replication.

## Handy reference
- Config: env vars only (`KP_*`) — see INSTALL.md.
- Storage path: `KP_DATA_DIR` (default `./data`); keys in `.kerplace.sys/`.
- Ports: S3 API `:9000`, console `:9001`.
- mc alias config: `~/.mc/config.json` (or `MC_CONFIG_DIR`).
