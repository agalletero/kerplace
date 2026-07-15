# Operator guide — hardened custody mode (hardening)

Runbook for the hardened **custody-tethered** deployment of KerPlace: data plane
over the tunnel, unseal from USB, SSH channel pinned to PQC and scoped credentials.
The *concept* lives in [`docs/OFFHOST_KMS_CUSTODY.md`](../../docs/OFFHOST_KMS_CUSTODY.md);
what follows are the **provisioning steps** and the hardened lifecycle.

Pieces: `adminKP.sh` (orchestrator, the single on/off switch), `start.sh` (brings up
the Vault container; no secrets at steady state), the `systemd --user` unit for the
tunnel and a custody USB holding the unseal material.

---

## 0. Configuration (one-time)

All config comes from an environment file; the script aborts if it is missing:

```bash
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/kerplace"
cp deploy/external-kms-laptop/adminkp.env.example \
   "${XDG_CONFIG_HOME:-$HOME/.config}/kerplace/adminkp.env"
chmod 600 "${XDG_CONFIG_HOME:-$HOME/.config}/kerplace/adminkp.env"
# edit the 5 mandatory variables (KP_ADMIN_HOST, _SSH_KEY, _ACCESS_KEY,
# _SECRET_FILE, _KMS_DIR). Everything else has defaults.
```

Alternative path: `./adminKP.sh --config <path> <subcommand>`.

---

## 1. Data plane over the tunnel + close the S3 port (T1)

S3 traffic (the object payloads) does **not** travel over the Internet any more: it
comes in through the same SSH channel as the custody, in the reverse direction.

- The tunnel unit publishes two forwards (see §5):
  `-R 127.0.0.1:8200` (custody) and `-L 127.0.0.1:9000` (data).
- `KP_ADMIN_S3_ENDPOINT=http://127.0.0.1:9000` (loopback; encryption in transit is
  provided by SSH/ML-KEM).
- **On the host**, KerPlace listens on loopback only and the public port is closed:
  ```bash
  # /etc/kerplace.env on the host
  KP_ADDRESS=127.0.0.1:9000
  # then, in the host's security group / firewall: CLOSE inbound 9000.
  ```
  `KP_ADDRESS` is pure configuration (it does not touch the core). With this, the
  public S3 surface is zero: with no tunnel there is no reachable endpoint.

---

## 2. Cryptographic and identity pinning of the SSH channel (T4)

1. **Post-quantum KEX by policy.** Both the unit and `ssh_aws()` force
   `KexAlgorithms=mlkem768x25519-sha256` (variable `KP_ADMIN_KEX`). If the server
   does not offer ML-KEM, the connection **fails** (it does not downgrade to classic).

2. **Host key pinning (no TOFU).** `StrictHostKeyChecking=yes` against a dedicated
   `known_hosts` (`KP_ADMIN_KNOWN_HOSTS`). Populate it once, on a trusted network,
   and **verify the fingerprint** over a separate channel:
   ```bash
   ssh-keyscan -t ed25519 <HOST> >> "$HOME/.config/kerplace/known_hosts"
   ssh-keygen -lf "$HOME/.config/kerplace/known_hosts"   # compare the fingerprint
   ```

3. **Tunnel key restricted on the host.** In the `~/.ssh/authorized_keys` of the host
   user, the custody key carries restrictions (no shell, pty, agent or X11; only the
   two forwards this mode needs):
   ```
   restrict,port-forwarding,permitlisten="127.0.0.1:8200",permitopen="127.0.0.1:9000" ssh-ed25519 AAAA...custody-key... custody
   ```
   `permitlisten` enables the −R (custody); `permitopen` enables the −L (data).

---

## 3. S3 data plane credentials (T3)

1. **Scoped S3 user `kp-mounter`** (not the KerPlace root). Create it with a policy
   limited to the buckets to be mounted (list/get/put/delete on those ARNs, no admin
   rights):
   ```bash
   mc admin user add   <alias-root> kp-mounter <SECRET>
   mc admin policy create <alias-root> kp-mounter kp-mounter-policy.json
   mc admin policy attach <alias-root> kp-mounter --user kp-mounter
   ```
   `kp-mounter-policy.json` (adjust the ARNs to your buckets):
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       { "Effect": "Allow",
         "Action": ["s3:ListBucket"],
         "Resource": ["arn:aws:s3:::mybucket"] },
       { "Effect": "Allow",
         "Action": ["s3:GetObject","s3:PutObject","s3:DeleteObject"],
         "Resource": ["arn:aws:s3:::mybucket/*"] }
     ]
   }
   ```
   Put that user in the config: `KP_ADMIN_ACCESS_KEY=kp-mounter` and its secret in
   `KP_ADMIN_SECRET_FILE` (chmod 600). Root is left for explicit admin only.

2. **s3fs passwd hygiene.** `adminKP.sh` creates it with `umask 077` and **deletes**
   it (`shred -u`) on `--disable`. After `--disable` no `~/.passwd-s3fs*` should
   exist.

---

## 4. Unseal from USB, not from disk (T2)

The unseal material (unseal key + root token) **does not live on the laptop's
disk**: it lives encrypted with symmetric GPG (AES-256) on a custody USB. Factors =
possession (USB) + knowledge (passphrase).

**Initial migration** (after the first `start.sh`, which still leaves
`.vault-init.json` on disk temporarily):

```bash
# take a backup FIRST (see §6)
./adminKP.sh --backup
# format/label the USB with LABEL=KPCUSTODY (or adjust KP_ADMIN_USB_LABEL)
./adminKP.sh --provision-usb            # finds the USB by LABEL, encrypts, verifies
#   the round-trip (encrypt→decrypt→compare), and OFFERS to shred the original.
```

`--provision-usb` is idempotent and only offers to delete the original once the
round-trip is verified. It also accepts an explicit path:
`--provision-usb /media/$USER/KPCUSTODY`.

**On every `--enable`**: if Vault is sealed, the material is decrypted **in memory**
(never to disk) and fed to `vault operator unseal -` over stdin. Interactive
passphrase (pinentry). No USB present ⇒ `[ERR]` and abort (the tunnel does not come
up if the unseal fails). The `ADMINKP_PASSPHRASE` escape hatch exists only for
automation (it is exposed in `/proc/<pid>/environ`).

> **Phase 2 (not implemented, future evolution):** upgrade to YubiKey/FIDO2 with a
> resident key (`sk-ssh-ed25519`) for non-clonable possession, and a udev rule for
> auto-enable on insert / auto-disable on removal.

---

## 5. systemd unit for the tunnel (T6)

Template in [`systemd/kerplace-kms-tunnel.service`](systemd/kerplace-kms-tunnel.service):
the two forwards from §1, the KEX + known_hosts pinning from §2,
`ExitOnForwardFailure=yes`, `ServerAliveInterval=15`/`CountMax=3`,
`ConnectTimeout=10`, `Restart=on-failure`, `RestartSec=5s`. Install it as a user unit
and enable linger so it survives logout/reboot:

```bash
mkdir -p ~/.config/systemd/user
cp deploy/external-kms-laptop/systemd/*.service \
   deploy/external-kms-laptop/systemd/*.timer   ~/.config/systemd/user/
# edit YOUR_USER@YOUR_HOST and the key/known_hosts paths (%h = your home)
loginctl enable-linger "$USER"                 # user services at boot
systemctl --user daemon-reload
systemctl --user enable --now kerplace-kms-vault.timer   # keeps the container up (sealed)
```

Do **not** enable the tunnel unit for auto-start: `adminKP.sh` is the single switch
and starts/stops it on `--enable`/`--disable` (`systemctl --user start/stop`).
The local Vault is persistent (the timer keeps it up, sealed).

---

## 6. Backup: two separate artifacts (T7)

`--backup` produces **two** files with **independent passphrases**, so they can be
held in separate custody:

```bash
./adminKP.sh --backup [dir]     # dir defaults to: $HOME
#   kms-data-<ts>.tar.gz.gpg    -> Vault volume + config + certs (large, rotates often)
#   kms-unseal-<ts>.tar.gz.gpg  -> .vault-init.json + token (small, almost never changes)
```

The **unseal** one alone (with its passphrase) is enough to unseal: keep it in a
different custody from the data one. If you already migrated the unseal material to
the USB, the backup pulls it from the USB so that DR remains complete. Restore and
token expiry warning (720h): see the `RESTORE.md` included in the data artifact.

Passphrases via variables (automation): `ADMINKP_PASSPHRASE` (data) and
`ADMINKP_UNSEAL_PASSPHRASE` (unseal).

---

## 7. Fail-closed guarantees (checklist)

- Tunnel down ⇒ `mc ls` fails, KerPlace serves no data (loopback bind + closed
  port), `--status` reflects it. No route from the Internet reaches S3.
- sshd without ML-KEM ⇒ the connection **fails** (KEX pinned by policy), no
  downgrade.
- No USB ⇒ `--enable` aborts at the unseal; the tunnel is not left up.
- After `--disable` ⇒ no `~/.passwd-s3fs*`, no mounts, the tunnel is stopped and the
  local Vault stays up (sealed). Decrypted unseal material never touches the disk.

> **Known limitation (not covered by this mode).** The hardening above closes the
> *deployment plane*. A gap remains in the *core*, out of scope for this guide: a
> write (`PUT`) that arrives while the KMS is unreachable **mid-session** may respond
> `200` with a 0-byte object instead of failing closed (the read path was already
> closed in v0.1.1; the write path was not). It requires a core change; it is being
> addressed separately. With the port closed and the loopback bind, the vector only
> applies to a client already inside the tunnel when the KMS goes down.
