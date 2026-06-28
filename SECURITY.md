# Security Policy

KerPlace stores other people's data at rest, so we take security reports
seriously and respond to them honestly. This document explains **how to report a
vulnerability**, **what to expect**, and **what is and isn't in scope**.

For the design-level threat model — what KerPlace protects against, and the
limits it *declares rather than hides* — see
**[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)**.

---

## Supported versions

KerPlace is early-stage (v0.1). Security fixes land on the **latest released
version only**; there are no long-term-support branches yet.

| Version | Supported |
|---------|-----------|
| latest `0.1.x` | ✅ fixes here |
| older pre-releases / tags | ❌ upgrade to the latest |

When a 1.0 line exists this table will be updated with a real support window.

---

## Reporting a vulnerability

**Please report privately first — do not open a public issue for a
vulnerability.** Public issues disclose the flaw to everyone, including
attackers, before a fix exists.

- **Email:** security@kerplace.com (or support@kerplace.com)
- **Subject:** start it with `KerPlace security:` so it is triaged quickly.
- If your host supports it, a **private security advisory** on the repository is
  equally welcome.

Encrypt sensitive details if you can; if no PGP key is published yet, email
first and we will arrange a secure channel before you send a working exploit.

### What to include

A good report lets us reproduce the issue fast:

- KerPlace **version** (`kerplace --version`) and how it was built/run
  (release binary, `cargo build`, profile `open`/`sealed`, key provider).
- The **impact** (what an attacker gains) and the **affected component**
  (S3 plane, console, SigV4 auth, OIDC/STS, cluster RPC, at-rest crypto, …).
- **Steps to reproduce** — a request sequence, `curl`/`mc` invocation, or a
  minimal script. A proof-of-concept is ideal but not required.
- Relevant config (`KP_*` env), with secrets redacted.

### What to expect

This is maintained by a small team, so these are honest targets, not a
contractual SLA:

| Stage | Target |
|-------|--------|
| Acknowledge your report | within **3 business days** |
| Initial assessment (valid? severity?) | within **7 days** |
| Fix or mitigation plan | depends on severity, communicated with the assessment |

We practise **coordinated disclosure**: we ask you to hold public details until
a fix is released (or 90 days have passed, whichever comes first), and we will
credit you in the release notes unless you prefer to stay anonymous.

---

## Scope

**In scope** — anything that breaks KerPlace's stated guarantees:

- Authentication / authorization bypass (SigV4, presigned URLs, IAM policy
  enforcement, OIDC ID-token validation, STS credential forgery).
- At-rest confidentiality failures (key material leaking, the envelope
  invariant being violated, a decrypt path that silently returns plaintext on a
  custody failure instead of failing closed).
- Cluster RPC trust failures (drive RPC accepting unauthenticated/forged
  requests, mTLS not actually enforced when `KP_CLUSTER_TLS=true`).
- `KP_PROFILE=sealed` failing **open** — i.e. the server starting despite a
  violated fail-closed invariant.
- Memory-safety issues, path traversal, SSRF, injection, and the usual web
  classes in the S3 plane or console.

**Out of scope** — things already documented as limits, not bugs:

- Anything KerPlace **declares it does not protect** in
  [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) (e.g. the console SSO session
  token landing in browser history via the URL fragment, or an on-host `file`
  key provider not defending against a root-level host compromise — that is why
  `passphrase`/`kms` exist).
- Features marked 🗓️ **planned** rather than implemented.
- Findings that require already having root on the server host, or physical
  access to the disks, unless they defeat a guarantee we explicitly claim.
- Missing hardening that is the operator's responsibility (running with
  `KP_AUTH=false`, exposing the console to the public internet, default
  `minioadmin` credentials in production, etc.). Use `KP_PROFILE=sealed` to make
  those misconfigurations fail-closed.

If you are unsure whether something is in scope, **report it anyway** — we would
rather triage a non-issue than miss a real one.

---

## Our side of the bargain

- We will not pursue legal action against good-faith research that follows this
  policy (no data destruction, no privacy violations, no service degradation for
  other users, and you stop at proof-of-concept).
- We fix in the open: the threat model in
  [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) is kept honest, and known
  limits are written down rather than buried. That honesty is part of the
  product.
