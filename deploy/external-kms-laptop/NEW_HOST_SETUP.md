# Provision a NEW custody host (GCP or another server)

Exact list of commands to turn a fresh server into a **KerPlace custody host**
that talks to the KMS (OpenBao) on your laptop. Two sides: the **host**
(serves S3, stores ciphertext only) and the **laptop** (holds the keys). Replace
the `<PLACEHOLDERS>`. Living reference: the current AWS deployment.

Placeholders:
- `<NEW_HOST>` = `user@ip` of the new server (e.g. `alex@34.x.x.x` on GCP)
- `<SSH_KEY>` = private SSH key for that host (on the laptop)
- `<SCOPED_TOKEN>` = new scoped token (minted in step P2)

---

## A · On the NEW HOST

### 1. KerPlace binary (static musl)
Quick option — copy the already-working binary from the current host:
```bash
# from the LAPTOP:
scp -i <CURRENT_SSH_KEY> <CURRENT_HOST>:/usr/local/bin/kerplace /tmp/kerplace
scp -i <SSH_KEY> /tmp/kerplace <NEW_HOST>:/tmp/kerplace
```
Or download it from releases (verify the published checksum):
```bash
curl -fsSL -o /tmp/kerplace https://github.com/agalletero/kerplace/releases/latest/download/kerplace-x86_64-unknown-linux-musl
```
Install it on the host:
```bash
sudo install -m 755 /tmp/kerplace /usr/local/bin/kerplace && rm -f /tmp/kerplace
/usr/local/bin/kerplace --version 2>/dev/null || true
```

### 2. Data dir
```bash
sudo mkdir -p /kerplace && sudo chown "$USER:$USER" /kerplace
```

### 3. Config `/etc/kerplace.env`
```bash
sudo install -d /etc/kerplace
sudo tee /etc/kerplace.env >/dev/null <<EOF
KP_DATA_DIR=/kerplace
KP_ENCRYPT=true
KP_ADDRESS=127.0.0.1:9000          # loopback: no public S3 surface (T1)
KP_CONSOLE_ADDRESS=127.0.0.1:9001
KP_KEY_PROVIDER=kms
KP_KMS_ENDPOINT=https://localhost:8200   # the laptop's Vault, via the -R tunnel
KP_KMS_KEY=kerplace
KP_KMS_CA=/etc/kerplace/kms-ca.crt
KP_KMS_TOKEN=<SCOPED_TOKEN>
KP_ROOT_USER=kpadmin
KP_ROOT_PASSWORD=$(openssl rand -hex 12)
EOF
sudo chmod 600 /etc/kerplace.env
```

### 4. The KMS CA
The laptop copies it over for you (step P1). It must end up at `/etc/kerplace/kms-ca.crt`.

### 5. systemd unit
```bash
sudo tee /etc/systemd/system/kerplace.service >/dev/null <<'EOF'
[Unit]
Description=KerPlace (S3) with external KMS custody
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/kerplace.env
ExecStart=/usr/local/bin/kerplace
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
# Do NOT enable it for auto-start: adminKP.sh starts/stops it. Without KMS, it fails closed.
```

### 6. Hardened SSH (T4)
Confirm the host's sshd offers ML-KEM (otherwise the PQC tunnel will not come up):
```bash
ssh -Q kex | grep mlkem768x25519-sha256    # it must show up
```
Restrict the tunnel key in the host's `~/.ssh/authorized_keys` (a single line;
no shell/pty/agent, only the two forwards the mode needs):
```
restrict,port-forwarding,permitlisten="127.0.0.1:8200",permitopen="127.0.0.1:9000" ssh-ed25519 AAAA...custody-key... custody
```

### 7. Firewall — close the public 9000 (GCP)
With `KP_ADDRESS=127.0.0.1:9000` S3 is only reachable through the tunnel; close the port:
```bash
# GCP: do NOT open 9000/9001 in the firewall rules. If a rule exists, remove it:
gcloud compute firewall-rules delete allow-kerplace-9000 2>/dev/null || true
# leave only 22 (SSH) open. Everything else goes through the tunnel.
```

---

## B · On the LAPTOP (KMS side)

### P1. Copy the CA to the new host
```bash
scp -i <SSH_KEY> /home/alex/.config/kerplace/kms-ca.crt <NEW_HOST>:/tmp/kms-ca.crt
ssh -i <SSH_KEY> <NEW_HOST> 'sudo install -D -m 644 /tmp/kms-ca.crt /etc/kerplace/kms-ca.crt && rm -f /tmp/kms-ca.crt'
```

### P2. Mint a NEW scoped token for this host
One token per host (independently revocable). On the laptop, with OpenBao
unsealed:
```bash
export VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT=/home/alex/.config/kerplace/kms-ca.crt
export VAULT_TOKEN=$(sudo python3 -c 'import json;print(json.load(open("/etc/openbao/.vault-init.json"))["root_token"])')
bao token create -policy=kerplace-kms -ttl=720h -renewable=true -field=token
# that value -> <SCOPED_TOKEN> in the host's /etc/kerplace.env (step A3):
#   ssh <NEW_HOST> "sudo sed -i 's|^KP_KMS_TOKEN=.*|KP_KMS_TOKEN=<SCOPED_TOKEN>|' /etc/kerplace.env"
```

### P3. Pin the host identity (pin, no TOFU — T4)
```bash
ssh-keyscan -t ed25519 <HOST_IP> >> "$HOME/.config/kerplace/known_hosts"
ssh-keygen -lf "$HOME/.config/kerplace/known_hosts"    # VERIFY the fingerprint out of band
```
And point the adminKP config at the new host (`adminkp.env`):
```
KP_ADMIN_HOST=<NEW_HOST>
KP_ADMIN_SSH_KEY=<SSH_KEY>
```

### P4. Tunnel + startup
```bash
./adminKP.sh --enable
# brings up the tunnel (-R 8200 custody + -L 9000 data, ML-KEM KEX),
# starts KerPlace on the host (its fail-closed check passes because the KMS is reachable),
# and mounts the buckets.
```

---

## C · Verification (fail-closed)
- With the tunnel down: `mc ls` fails and KerPlace does not start (or does not serve). The public
  9000 is closed, so there is no route from the Internet.
- sshd without ML-KEM ⇒ the tunnel does not come up (no downgrade).
- `--status` reflects: KMS unsealed (USB), tunnel up, KerPlace up.

> **Data migration:** the new host starts empty. The old host's objects are
> ciphertext bound to the SAME Transit key (still in your OpenBao), so they are copied with
> `mc mirror <old> <new>` while both are `--enabled` — they are decrypted on read from the
> old one and re-encrypted on write to the new one, under the same custody.
