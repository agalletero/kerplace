# Reference: a laptop KMS for off-host key custody

This is a runnable reference for the deployment described in
**[docs/OFFHOST_KMS_CUSTODY.md](../../docs/OFFHOST_KMS_CUSTODY.md)**: a persistent,
TLS-enabled HashiCorp Vault (Transit engine) on **your laptop**, acting as the
external KMS for a KerPlace instance running on **untrusted hosting**. The host
holds only ciphertext + wrapped DEKs; the unwrap key never leaves your laptop.

```
Hosting (KerPlace, /kerplace = ciphertext + vault:v1:…)  ──TLS over SSH tunnel──▶  Laptop (this Vault)
```

## Files

| File | Purpose |
|---|---|
| `docker-compose.yml` | Vault in server mode, persistent (`vault-data` volume), TLS, loopback-only. |
| `config/vault.hcl` | Vault config: file storage + TLS listener. |
| `gen-certs.sh` | Generates a private CA + Vault server cert into `vault/tls/` (→ `ca.crt` is your `KP_KMS_CA`). |
| `start.sh` | Idempotent: gen-certs, `compose up`, init + **unseal**, ensure Transit key + scoped token. Also the unseal-keeper the timer runs. |
| `systemd/` | `--user` units: the reverse tunnel (`Restart=always`) + a timer that keeps Vault unsealed. |
| `adminKP.sh` | VPN-style control of the whole thing: `--enable` / `--disable` / `--mount` / `--umount` / `--backup` / `--status`. **Edit its config block first.** See **[OFFHOST_KMS_CUSTODY.md](../../docs/OFFHOST_KMS_CUSTODY.md)**. |

Runtime secrets (`vault/tls/`, `.vault-init.json`, `.kms-token`) are **gitignored** —
they are generated locally and must never be committed.

## Quick start (on the laptop)

```bash
./start.sh
# prints KP_KMS_* values and saves:
#   .vault-init.json  → unseal key + root token   (BACK THIS UP)
#   .kms-token        → the scoped token for KerPlace
```

Then open the tunnel so the host can reach this Vault as `https://localhost:8200`:

```bash
ssh -N -R 8200:localhost:8200 user@your-host
```

For a setup that **survives logout and reboot**, install the `systemd/` user units
(edit the paths/host inside them first), then:

```bash
mkdir -p ~/.config/systemd/user && cp systemd/* ~/.config/systemd/user/
loginctl enable-linger "$USER"          # start user services at boot, before login
systemctl --user daemon-reload
systemctl --user enable --now kerplace-kms-vault.timer kerplace-kms-tunnel.service
```

- **kerplace-kms-tunnel.service** — the reverse tunnel, `Restart=always`
  (autossh-equivalent; no extra package needed).
- **kerplace-kms-vault.timer** → **…vault.service** — brings Vault up and
  **auto-unseals** it on boot and every 2 min, so a restarted container self-heals.

## On the host (KerPlace)

```bash
KP_DATA_DIR=/kerplace KP_ENCRYPT=true \
KP_KEY_PROVIDER=kms \
KP_KMS_ENDPOINT=https://localhost:8200 \
KP_KMS_KEY=kerplace \
KP_KMS_TOKEN="$(cat .kms-token)" \
KP_KMS_CA=/etc/kerplace/kms-ca.crt \
kerplace
```

Copy `vault/tls/ca.crt` to the host as `/etc/kerplace/kms-ca.crt`. KerPlace
fail-closed-checks the KMS at boot, so it will not start if the laptop is
unreachable.

## Security notes (read before trusting it with real data)

- This Vault uses a **single unseal key** (`-key-shares=1`) stored locally in
  `.vault-init.json` for convenience. That is fine for a personal laptop KMS but
  weaker than Shamir-split keys or a real auto-unseal (cloud KMS / transit). **Back
  up `.vault-init.json`** — losing it means the DEKs can never be unwrapped and the
  data is gone.
- The KerPlace **root credentials** and the **scoped token** are the keys to the
  kingdom while the tunnel is up — keep them secret; rotate the token to revoke.
- TLS uses a **private CA**; the SSH tunnel already encrypts the hop, so the KMS
  TLS is end-to-end certificate-pinned defence-in-depth.
