# Access control — who can reach which bucket

A cookbook for giving each person (or each machine) exactly the buckets they
need: **Alice → `reports`, Bob → `logs`, Carol → both**, and every variation of
that shape.

---

## The model in one line

> **Policy answers *what*. Scope answers *where*. Both must allow the request.**

| | Question | Values |
|---|---|---|
| **Policy** | what may this credential *do*? | `readwrite`, `readonly`, `writeonly`, `admin` |
| **Scope** | which buckets may it *touch*? | a bucket allow-list, or unset = **every bucket** |

They are ANDed. A `readwrite` credential scoped to `reports` can read and write
`reports` — and gets `403 AccessDenied` on everything else.

Two properties worth knowing up front:

- **Unset scope means every bucket.** That is the default, and it is what every
  credential created before this feature has. Nothing changes until you scope it.
- **`ListBuckets` is filtered to the caller's scope.** A scoped credential does
  not even learn that the other buckets exist.

---

## Quick start: A → X, B → Y, C → X+Y

### At boot — `KP_USERS`

The 4th field is the scope; buckets are `|`-separated, entries are `,`-separated:

```bash
KP_USERS="alice:alicesecret:readwrite:reports,\
bob:bobsecret:readwrite:logs,\
carol:carolsecret:readwrite:reports|logs" \
  kerplace
```

That is the whole thing. Result:

| | `reports` | `logs` | `ListBuckets` shows |
|---|---|---|---|
| **alice** | ✅ read+write | ⛔ 403 | `reports` |
| **bob** | ⛔ 403 | ✅ read+write | `logs` |
| **carol** | ✅ read+write | ✅ read+write | `reports logs` |
| **root** | ✅ | ✅ | both (root is never scoped) |

> `KP_USERS` seeds users the **first** time they are seen; it never overwrites a
> user already persisted in `users.json`. To change an existing user's scope, use
> the admin endpoint below.

### At runtime — `set-user-buckets`

```
PUT /kerplace/admin/v3/set-user-buckets?accessKey=<user>&buckets=<a>|<b>
```

Passing `buckets=` **empty** clears the scope (back to every bucket). That is a
privilege-*widening* operation, so it must be spelled out — omitting the
parameter is an error, not a shortcut for "clear".

The endpoint is SigV4-signed like any admin call. `mc`/`aws` cannot address it
directly (it is KerPlace-native), so sign it with the snippet in
[Calling the admin endpoint](#calling-the-admin-endpoint) below.

Read the current scope back with:

```
GET /kerplace/admin/v3/user-info?accessKey=alice
→ {"buckets":["reports"],"policyName":"readwrite","status":"enabled"}
```

`"buckets": null` means unscoped (every bucket).

---

## Recipes

### 1. One bucket per team

The base case. Each team gets a bucket and a credential that can see nothing else.

```bash
KP_USERS="finance:…:readwrite:finance,legal:…:readwrite:legal,ops:…:readwrite:ops"
```

Nobody can enumerate another team's bucket, let alone read it.

### 2. The auditor — read everything, change nothing

Policy does the work; leave the scope unset.

```bash
KP_USERS="auditor:…:readonly"
```

### 3. The auditor of a single department

Combine both halves:

```bash
KP_USERS="legal-auditor:…:readonly:legal"
```

Reads `legal`. Cannot write it. Cannot see `finance` at all.

### 4. Backup drop-box — write-only, cannot read back

A `writeonly` credential scoped to one bucket can deposit but never retrieve.
Useful for backup agents: if the agent's host is compromised, the attacker
cannot use its credential to read (or exfiltrate) the existing backups.

```bash
KP_USERS="backup-agent:…:writeonly:backups"
```

> Note the honest limit: `writeonly` does not stop an attacker from *overwriting*
> backups. Pair it with versioning + object lock for that.

### 5. Two servers sharing one bucket, plus a private one each

The clinic case: a doctors' server and a clinic's server both need the patient
records; only the doctors' server needs the imaging bucket.

```bash
KP_USERS="doctors-srv:…:readwrite:patients|imaging,\
clinic-srv:…:readwrite:patients"
```

Both reach `patients`. Only `doctors-srv` reaches `imaging` — and `clinic-srv`
cannot even list it.

### 6. Application vs. human

Give the application the narrowest scope it needs and keep the human wide:

```bash
KP_USERS="webapp:…:readwrite:uploads,oncall:…:readonly"
```

A leak of the app's credential exposes `uploads` only.

### 7. Onboarding someone

1. Create the credential (`mc admin user add`, or `KP_USERS` on first boot).
2. Scope it: `set-user-buckets?accessKey=dana&buckets=reports`.
3. Verify: `user-info?accessKey=dana` shows `"buckets":["reports"]`.

### 8. Offboarding someone

Disable rather than scope to nothing:

```
PUT /kerplace/admin/v3/set-user-status?accessKey=dana&status=disabled
```

(then `remove-user` when you are done retaining their access history). Their
past activity stays in the [access log](#verifying-it) either way.

### 9. Rotating a secret **without** widening access

Re-issuing a credential (`mc admin user add` with a new secret) **keeps** the
scope. This is deliberate: otherwise a routine secret rotation would silently
hand the user every bucket. To actually change the scope, call
`set-user-buckets` explicitly.

### 10. Temporarily granting a second bucket

```
PUT …/set-user-buckets?accessKey=alice&buckets=reports|logs   # widen
… work …
PUT …/set-user-buckets?accessKey=alice&buckets=reports        # back to normal
```

Takes effect immediately — no restart, and the change survives one (it is
persisted to `users.json`).

---

## Verifying it

Three checks, in increasing order of confidence:

1. **Ask the server what it thinks:**
   `GET …/user-info?accessKey=alice` → `"buckets":["reports"]`.
2. **Try the denial** (the only proof that matters):
   ```bash
   AWS_ACCESS_KEY_ID=alice AWS_SECRET_ACCESS_KEY=… \
     aws --endpoint-url $KP s3api list-objects-v2 --bucket logs
   # → An error occurred (AccessDenied)
   ```
3. **Read the audit trail.** With `KP_ACCESS_LOG` set, every attempt — including
   the refusal — is recorded with who, what, when and the outcome:
   ```json
   {"ts":"…","access_key":"alice","op":"ListObjects","bucket":"logs","status":403}
   ```

---

## What this does *not* do

Stated plainly, so nothing is over-promised:

- **Bucket granularity, not prefix.** You cannot scope a credential to
  `reports/2026/` — only to `reports`. Model with separate buckets for now.
- **Root is never scopeable.** Attempting it returns `400`. Use a non-root user.
- **STS credentials are unscoped.** Their signed payload carries a policy id with
  no room for a bucket list, so temporary credentials get the policy only.
- **S3 bucket *policy documents* are still not consulted.** `PUT /{bucket}?policy`
  stores a document for client compatibility, but this scope — not that document
  — is what the server enforces.
- **Only four canned policies.** No custom policy documents, no groups, no roles.

---

## Calling the admin endpoint

Any SigV4-capable client works. A dependency-free signer for scripting:

```python
#!/usr/bin/env python3
"""sigv4.py METHOD PATH [k=v ...] — signed request to the KerPlace admin API."""
import datetime, hashlib, hmac, sys, urllib.error, urllib.parse, urllib.request

HOST, AK, SK, REGION = "127.0.0.1:9000", "kpadmin", "kpadminsecret", "us-east-1"

def _sign(k, m): return hmac.new(k, m.encode(), hashlib.sha256).digest()

method, path = sys.argv[1], sys.argv[2]
params = dict(p.split("=", 1) for p in sys.argv[3:])
t = datetime.datetime.now(datetime.timezone.utc)
amz, day = t.strftime("%Y%m%dT%H%M%SZ"), t.strftime("%Y%m%d")
ph = hashlib.sha256(b"").hexdigest()
qs = "&".join(f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
              for k, v in sorted(params.items()))
ch = f"host:{HOST}\nx-amz-content-sha256:{ph}\nx-amz-date:{amz}\n"
sh = "host;x-amz-content-sha256;x-amz-date"
cr = f"{method}\n{urllib.parse.quote(path, safe='/')}\n{qs}\n{ch}\n{sh}\n{ph}"
scope = f"{day}/{REGION}/s3/aws4_request"
sts = f"AWS4-HMAC-SHA256\n{amz}\n{scope}\n{hashlib.sha256(cr.encode()).hexdigest()}"
key = _sign(_sign(_sign(_sign(("AWS4" + SK).encode(), day), REGION), "s3"), "aws4_request")
sig = hmac.new(key, sts.encode(), hashlib.sha256).hexdigest()

req = urllib.request.Request(f"http://{HOST}{path}" + (f"?{qs}" if qs else ""),
                             method=method, data=b"")
req.add_header("x-amz-content-sha256", ph)
req.add_header("x-amz-date", amz)
req.add_header("Authorization", f"AWS4-HMAC-SHA256 Credential={AK}/{scope}, "
                                f"SignedHeaders={sh}, Signature={sig}")
try:
    with urllib.request.urlopen(req) as r: print(r.status, r.read().decode())
except urllib.error.HTTPError as e: print(e.code, e.read().decode())
```

```bash
python3 sigv4.py PUT /kerplace/admin/v3/set-user-buckets accessKey=alice 'buckets=reports|logs'
python3 sigv4.py GET /kerplace/admin/v3/user-info accessKey=alice
```

---

## See also

- [Security model](SECURITY_MODEL.md) — the threat model these controls sit in.
- `KP_ACCESS_LOG` in the [README](../README.md) — the audit trail that records
  every use (and refusal) of these credentials.
