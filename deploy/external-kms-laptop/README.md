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
| `start.sh` | Container lifter. **First run:** gen-certs, `compose up`, init + bootstrap Transit key + scoped token (writes `.vault-init.json`, to be moved to the USB). **Steady state:** just `compose up` and leaves the Vault **sealed** — no secrets on disk; unseal is manual from the USB via `adminKP.sh`. |
| `systemd/` | `--user` units: the SSH tunnel (both forwards, KEX-pinned) + a timer that keeps the Vault **container up** (sealed; it no longer auto-unseals). |
| `adminKP.sh` | VPN-style control: `--enable` / `--disable` / `--mount` / `--umount` / `--backup` / `--provision-usb` / `--status`. Config comes from `<XDG_CONFIG_HOME>/kerplace/adminkp.env` (copy `adminkp.env.example`). |
| `adminkp.env.example` | Config template for `adminKP.sh` (`KP_ADMIN_*` vars). |
| `HARDENING.md` | **Hardened operator runbook**: loopback bind, USB unseal, KEX/host-key pinning, scoped S3 user, split backup. Start here. |

Runtime secrets (`vault/tls/`, `.vault-init.json`, `.kms-token`, `adminkp.env`,
`*.tar.gz.gpg`) are **gitignored** — they are generated/held locally and must never
be committed.

## Quick start (on the laptop)

```bash
./start.sh
# prints KP_KMS_* values and, on first run, saves:
#   .vault-init.json  → unseal key + root token   (TEMPORARY — move to USB below)
#   .kms-token        → the scoped token for KerPlace
```

Then move the unseal material off the disk onto your USB (see `HARDENING.md`), and
open the tunnel. A single SSH connection carries custody (`-R`) and the S3 data
plane (`-L`), with the KEX pinned to post-quantum:

```bash
./adminKP.sh --provision-usb           # .vault-init.json -> encrypted USB, then shred the original
ssh -N -T -R 127.0.0.1:8200:127.0.0.1:8200 -L 127.0.0.1:9000:127.0.0.1:9000 \
  -o KexAlgorithms=mlkem768x25519-sha256 user@your-host
```

For a setup that **survives logout and reboot**, install the `systemd/` user units
(edit the paths/host inside them first), then:

```bash
mkdir -p ~/.config/systemd/user && cp systemd/* ~/.config/systemd/user/
loginctl enable-linger "$USER"          # start user services at boot, before login
systemctl --user daemon-reload
systemctl --user enable --now kerplace-kms-vault.timer   # keeps the container up (sealed)
# do NOT auto-enable the tunnel — adminKP.sh starts/stops it on --enable/--disable
```

- **kerplace-kms-tunnel.service** — the SSH tunnel (custody `-R` + data `-L`,
  KEX-pinned, host-key-pinned), `Restart=on-failure` (autossh-equivalent).
- **kerplace-kms-vault.timer** → **…vault.service** — keeps the Vault **container
  up** on boot and every 2 min (sealed; it no longer auto-unseals — unsealing is
  manual from the USB via `adminKP.sh --enable`).

## On the host (KerPlace)

```bash
KP_DATA_DIR=/kerplace KP_ENCRYPT=true \
KP_ADDRESS=127.0.0.1:9000 \
KP_KEY_PROVIDER=kms \
KP_KMS_ENDPOINT=https://localhost:8200 \
KP_KMS_KEY=kerplace \
KP_KMS_TOKEN="$(cat .kms-token)" \
KP_KMS_CA=/etc/kerplace/kms-ca.crt \
kerplace
```

`KP_ADDRESS=127.0.0.1:9000` binds S3 to **loopback only** (reachable via the tunnel's
`-L`), so **close the public 9000** in the host firewall. Copy `vault/tls/ca.crt` to
the host as `/etc/kerplace/kms-ca.crt`. KerPlace fail-closed-checks the KMS at boot,
so it will not start if the laptop is unreachable.

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
