#!/usr/bin/env bash
#
# openBoo.sh — provisions the NATIVE custody KMS (OpenBao) on THIS laptop,
# replacing Vault-in-Docker. No data migration (by decision: the current buckets
# are a PoC). It leaves OpenBao installed and running, NOT yet initialised — the
# init/unseal/token/USB steps are interactive and come afterwards, via adminKP.
#
#   RUN AS ROOT:  sudo bash openBoo.sh
#
# Phases: 0 preflight → 1 tear the old setup down → 2 ENCRYPTED swap
#         → 3 install OpenBao (verified .deb) → 4 TLS + hardened config
#         → 5 summary + next steps.
#
# Parameterised by environment (or edit the CONFIG block). Real paths are passed
# in as variables so no user-specific path is baked into the repo.
set -euo pipefail

# ── CONFIG (review it before running) ────────────────────────────────────────
OPENBAO_VERSION="${OPENBAO_VERSION:-2.5.5}"
REL_BASE="https://github.com/openbao/openbao/releases/download/v${OPENBAO_VERSION}"
DEB="openbao_${OPENBAO_VERSION}_linux_amd64.deb"

SWAP_SIZE_GB="${SWAP_SIZE_GB:-8}"                 # size of the encrypted swap
SWAP_IMG="${SWAP_IMG:-/var/lib/swap/cryptswap.img}"
SWAP_MAPPER="cryptswap"

# Old infrastructure to stop (there is no data to migrate). Empty = skipped.
DOCKER_VAULT="${DOCKER_VAULT:-kerplace-vault}"    # local Vault container to stop
MOUNT_BASE="${MOUNT_BASE:-}"                      # base of the s3fs mounts to unmount
AWS_HOST="${AWS_HOST:-}"                          # e.g. ubuntu@1.2.3.4  (empty = leave AWS alone)
AWS_KEY="${AWS_KEY:-}"                            # ssh key for AWS_HOST
TUNNEL_UNIT="${TUNNEL_UNIT:-kerplace-kms-tunnel.service}"
VAULT_TIMER="${VAULT_TIMER:-kerplace-kms-vault.timer}"    # the --user timer that RESURRECTS the container
VAULT_SVC="${VAULT_SVC:-kerplace-kms-vault.service}"

# Native OpenBao
OB_USER="openbao"
OB_CONF="/etc/openbao/openbao.hcl"
OB_TLS="/etc/openbao/tls"
OB_DATA="${OB_DATA:-/opt/openbao/data}"
OB_SERVICE="openbao"

VERIFY_GPG="${VERIFY_GPG:-0}"                     # 1 = also verify the GPG signature
ASSUME_YES="${ASSUME_YES:-0}"                     # 1 = do not prompt

# ── logging (no ANSI) ────────────────────────────────────────────────────────
info(){ printf '[INFO] %s\n' "$*"; }
warn(){ printf '[WARN] %s\n' "$*" >&2; }
die(){  printf '[ERR] %s\n'  "$*" >&2; exit 1; }
as_user(){ if [ -n "${SUDO_USER:-}" ]; then sudo -u "$SUDO_USER" "$@"; else "$@"; fi; }
# systemctl --user in the real user's context (to stop --user timers/units from root)
ruser_systemctl(){
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    local uid; uid="$(id -u "$SUDO_USER")"
    sudo -u "$SUDO_USER" XDG_RUNTIME_DIR="/run/user/$uid" systemctl --user "$@"
  else systemctl --user "$@"; fi
}

[ "$(id -u)" -eq 0 ] || die "run it as root: sudo bash openBoo.sh"
REAL_USER="${SUDO_USER:-root}"

info "Plan: stop KerPlace(AWS)+Vault(docker) · ENCRYPTED swap · install native OpenBao ${OPENBAO_VERSION}."
info "  real user: $REAL_USER · docker vault: ${DOCKER_VAULT:-(none)} · swap: ${SWAP_SIZE_GB}G at $SWAP_IMG"
if [ "$ASSUME_YES" != "1" ]; then
  printf 'Type YES to continue: '; read -r ans; [ "$ans" = "YES" ] || die "cancelled"
fi

# ── PHASE 1 · tear the old setup down (best-effort; no data to migrate) ───────
info "1/5  stopping the previous setup"
if [ -n "$MOUNT_BASE" ] && [ -d "$MOUNT_BASE" ]; then
  while read -r _ mp fstype _; do
    [ "$fstype" = "fuse.s3fs" ] || continue
    case "$mp" in "$MOUNT_BASE"/*)
      sync; as_user fusermount3 -u "$mp" 2>/dev/null || umount -l "$mp" 2>/dev/null || true
      info "  unmounted: $mp" ;;
    esac
  done < /proc/mounts
fi
# Stop the RESURRECTION: the --user timer recreates the container every 2 min
# (start.sh -> docker compose up). Without disabling it, Vault-in-Docker comes
# back and collides with OpenBao on :8200.
ruser_systemctl stop "$VAULT_TIMER" "$VAULT_SVC" 2>/dev/null || true
ruser_systemctl disable "$VAULT_TIMER" 2>/dev/null || true
ruser_systemctl stop "$TUNNEL_UNIT" 2>/dev/null || true
info "  Vault (docker) auto-start timer stopped and disabled"
# KerPlace on AWS (optional)
if [ -n "$AWS_HOST" ] && [ -n "$AWS_KEY" ]; then
  if as_user ssh -i "$AWS_KEY" -o ConnectTimeout=12 -o BatchMode=yes "$AWS_HOST" 'sudo systemctl stop kerplace' 2>/dev/null; then
    info "  KerPlace stopped on AWS"
  else
    warn "  could not stop KerPlace on AWS (continuing)"
  fi
else
  warn "  AWS_HOST/AWS_KEY not set: leaving AWS alone (stop it yourself if needed)"
fi
# Vault in Docker (the volume is kept; only the container is stopped/removed).
# -f forces it even with restart=unless-stopped; the timer is already disabled above.
if [ -n "$DOCKER_VAULT" ] && docker inspect "$DOCKER_VAULT" >/dev/null 2>&1; then
  docker rm -f "$DOCKER_VAULT" >/dev/null 2>&1 || true
  if docker inspect "$DOCKER_VAULT" >/dev/null 2>&1; then
    warn "  $DOCKER_VAULT is still there — something recreates it (another timer/compose?); check before phase 3"
  else
    info "  container $DOCKER_VAULT removed (the volume is NOT deleted)"
  fi
fi

# ── PHASE 2 · ENCRYPTED swap (random key per boot) ────────────────────────────
info "2/5  creating the encrypted swap (${SWAP_SIZE_GB}G)"
command -v cryptsetup >/dev/null || { apt-get update -qq && apt-get install -y cryptsetup-bin; }
mkdir -p "$(dirname "$SWAP_IMG")"
if [ ! -f "$SWAP_IMG" ]; then
  fallocate -l "${SWAP_SIZE_GB}G" "$SWAP_IMG" || dd if=/dev/zero of="$SWAP_IMG" bs=1M count=$((SWAP_SIZE_GB*1024)) status=none
  chmod 600 "$SWAP_IMG"
fi
# Open it with a random key and activate it in THIS session (before touching the
# old swap). Idempotent: if the mapper is already open and already an active
# swap, it is not re-initialised (mkswap over an active swap would corrupt it).
# The check looks at /proc/swaps for the RESOLVED device (/dev/dm-N), not the
# mapper name (swapon --show resolves it).
if [ ! -e "/dev/mapper/$SWAP_MAPPER" ]; then
  cryptsetup open --type plain --cipher aes-xts-plain64 --key-size 512 \
    --key-file /dev/urandom "$SWAP_IMG" "$SWAP_MAPPER"
fi
SWAP_DEV="$(readlink -f "/dev/mapper/$SWAP_MAPPER")"
if ! grep -q "^${SWAP_DEV}[[:space:]]" /proc/swaps; then
  mkswap "/dev/mapper/$SWAP_MAPPER" >/dev/null
  swapon "/dev/mapper/$SWAP_MAPPER"
fi
grep -q "^${SWAP_DEV}[[:space:]]" /proc/swaps \
  || die "the encrypted swap did not activate — aborting without touching the old swap"
info "  encrypted swap active: /dev/mapper/$SWAP_MAPPER ($SWAP_DEV)"

# Persist it (crypttab + fstab with nofail so a boot never blocks) and drop the old one.
cp -n /etc/fstab /etc/fstab.bak.openboo 2>/dev/null || true
touch /etc/crypttab
grep -q "^${SWAP_MAPPER}[[:space:]]" /etc/crypttab || \
  printf '%s %s /dev/urandom swap,cipher=aes-xts-plain64,size=512\n' "$SWAP_MAPPER" "$SWAP_IMG" >> /etc/crypttab
grep -q "/dev/mapper/$SWAP_MAPPER" /etc/fstab || \
  printf '/dev/mapper/%s none swap sw,nofail,pri=10 0 0\n' "$SWAP_MAPPER" >> /etc/fstab
# deactivate and comment out the unencrypted swapfiles
for old in /swapfile /swapfile_extra; do
  [ -e "$old" ] || continue
  swapoff "$old" 2>/dev/null || true
  sed -i -E "s|^(${old}[[:space:]].*)|# \1  # disabled by openBoo (unencrypted swap)|" /etc/fstab || true
  info "  unencrypted swap disabled: $old (file kept; delete it whenever you like)"
done

# ── PHASE 3 · install OpenBao (official .deb, SHA256-verified) ────────────────
info "3/5  installing OpenBao ${OPENBAO_VERSION} (verified .deb)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
( cd "$TMP"
  curl -fsSL -o "$DEB"                "$REL_BASE/$DEB"
  curl -fsSL -o checksums-linux.txt   "$REL_BASE/checksums-linux.txt"
  grep "  ${DEB}\$" checksums-linux.txt > deb.sha256 || die "cannot find the checksum for $DEB"
  sha256sum -c deb.sha256 || die "the .deb's SHA256 does NOT match — aborting (possible tampering)"
  info "  SHA256 verified"
  if [ "$VERIFY_GPG" = "1" ]; then
    curl -fsSL -o checksums-linux.txt.gpgsig "$REL_BASE/checksums-linux.txt.gpgsig" || true
    warn "  GPG verification requested: import OpenBao's signing key and validate checksums-linux.txt.gpgsig manually"
  fi
  DEBIAN_FRONTEND=noninteractive apt-get install -y "./$DEB"
)
BAO_BIN="$(command -v bao || echo /usr/bin/bao)"
info "  OpenBao installed: $BAO_BIN — $(bao version 2>/dev/null | head -1)"

# ── PHASE 4 · TLS + hardened config + systemd drop-in ─────────────────────────
info "4/5  TLS + config + hardening"
id "$OB_USER" >/dev/null 2>&1 || useradd --system --home-dir /var/lib/openbao --shell /usr/sbin/nologin "$OB_USER"
install -d -m 750 -o "$OB_USER" -g "$OB_USER" "$(dirname "$OB_CONF")" "$OB_DATA"
install -d -m 750 -o "$OB_USER" -g "$OB_USER" "$OB_TLS"

# Private CA + server cert (127.0.0.1 / localhost). ca.crt = the new KP_KMS_CA.
if [ ! -f "$OB_TLS/ca.crt" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -keyout "$OB_TLS/ca.key" -out "$OB_TLS/ca.crt" -subj "/CN=KerPlace KMS CA" >/dev/null 2>&1
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$OB_TLS/tls.key" -out "$OB_TLS/tls.csr" -subj "/CN=127.0.0.1" >/dev/null 2>&1
  openssl x509 -req -in "$OB_TLS/tls.csr" -CA "$OB_TLS/ca.crt" -CAkey "$OB_TLS/ca.key" -CAcreateserial \
    -days 3650 -out "$OB_TLS/tls.crt" \
    -extfile <(printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth') \
    >/dev/null 2>&1
  rm -f "$OB_TLS/tls.csr"
fi
chown -R "$OB_USER:$OB_USER" "$OB_TLS"; chmod 640 "$OB_TLS"/*.key "$OB_TLS"/*.crt

# OpenBao 2.x REMOVED mlock: the recommended mitigation is encrypting the swap
# (phase 2). That is why 'disable_mlock' is NOT set — its presence breaks startup.
cat > "$OB_CONF" <<EOF
ui = false
storage "file" { path = "$OB_DATA" }
listener "tcp" {
  address       = "127.0.0.1:8200"
  tls_cert_file = "$OB_TLS/tls.crt"
  tls_key_file  = "$OB_TLS/tls.key"
}
api_addr = "https://127.0.0.1:8200"
EOF
chown "$OB_USER:$OB_USER" "$OB_CONF"; chmod 640 "$OB_CONF"

# Hardening drop-in (sandbox). The package already sets User=$OB_USER.
install -d -m 755 "/etc/systemd/system/${OB_SERVICE}.service.d"
# mlock no longer applies on OpenBao 2.x (the encrypted swap mitigates it); this
# is only the systemd sandbox.
cat > "/etc/systemd/system/${OB_SERVICE}.service.d/10-hardening.conf" <<EOF
[Service]
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=$OB_DATA
# Make sure the server uses OUR config (adjust if the packaged unit differs):
ExecStart=
ExecStart=$BAO_BIN server -config=$OB_CONF
EOF

systemctl daemon-reload
systemctl enable "$OB_SERVICE" >/dev/null 2>&1 || true
if systemctl restart "$OB_SERVICE"; then
  info "  OpenBao started (uninitialised / sealed)"
else
  warn "  OpenBao did not start first time — check: systemctl status $OB_SERVICE ; journalctl -u $OB_SERVICE -n40"
fi

# ── PHASE 5 · summary + next steps (interactive, NOT in this script) ──────────
info "5/5  done."
cat <<EOF

==================================================================
 OpenBao ${OPENBAO_VERSION} installed (native, systemd) and the swap is ENCRYPTED.
   config : $OB_CONF
   data   : $OB_DATA        (empty: the KMS is NOT initialised)
   TLS CA : $OB_TLS/ca.crt   <-- the new KP_KMS_CA for the AWS host
   service: systemctl status $OB_SERVICE     (endpoint https://127.0.0.1:8200)

 NEXT STEPS (interactive — they need your passphrase and touch AWS):
  export VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT=$OB_TLS/ca.crt
  1) bao operator init -key-shares=1 -key-threshold=1 -format=json > .vault-init.json
  2) bao operator unseal <unseal_key>
  3) bao secrets enable transit
     bao write -f transit/keys/kerplace
     (policy kerplace-kms: datakey+decrypt) ; bao token create -policy=kerplace-kms -ttl=720h
  4) ./adminKP.sh --provision-usb   (moves .vault-init.json onto the USB; asks for the passphrase)
  5) copy $OB_TLS/ca.crt to the AWS host as /etc/kerplace/kms-ca.crt
     and put the new KP_KMS_TOKEN in /etc/kerplace.env ; restart KerPlace
  6) ./adminKP.sh --enable
 (adminKP.sh/start.sh are to be adapted to native mode, automating 1-3 and the reseal.)
==================================================================
EOF
