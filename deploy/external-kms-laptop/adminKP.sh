#!/usr/bin/env bash
#
# adminKP.sh — "VPN-style" control for a remote KerPlace whose keys live on THIS
# laptop (off-host KMS custody). See docs/OFFHOST_KMS_CUSTODY.md in the repo.
#
#   ./adminKP.sh --enable    connect: KMS up -> tunnel up -> start KerPlace on AWS
#                            -> mount every bucket via s3fs under ./buckets/<name>
#   ./adminKP.sh --disable   disconnect: unmount cleanly -> stop KerPlace -> drop tunnel
#                            (the local Vault stays up but becomes unreachable)
#   ./adminKP.sh --mount <bucket> [mount_point]   mount one bucket (ad-hoc)
#   ./adminKP.sh --umount <bucket|mount_point>    unmount one bucket
#   ./adminKP.sh --backup    encrypted snapshot of everything needed to rebuild the
#                            KMS after a laptop reinstall (NOT the bucket data —
#                            back that up classically from the mounted dirs)
#   ./adminKP.sh --status    show what's currently up/mounted
#
set -u

# ── configuration ── EDIT THESE for your deployment ──────────────────────────
AWS_HOST="ubuntu@YOUR_HOST"                     # ssh target of the KerPlace host
AWS_KEY="$HOME/.ssh/your-host.pem"              # ssh private key for it
S3_ENDPOINT="http://YOUR_HOST:9000"             # KerPlace S3 endpoint (use https:// if KP_TLS)
ACCESS_KEY="kpadmin"                            # an S3 access key (root or a scoped user)
SECRET_FILE="$HOME/.config/adminkp/secret"      # file holding that key's secret (chmod 600)
KMS_DIR="$HOME/kerplace-kms"                     # this reference dir: compose + start.sh + secrets
MOUNT_BASE="$HOME/buckets"                       # where buckets appear as folders
TUNNEL_UNIT="kerplace-kms-tunnel.service"        # systemd --user reverse-tunnel unit
VAULT_CONTAINER="kerplace-vault"
VAULT_VOLUME="kerplace-kms_vault-data"
PASSWD_S3FS="$HOME/.passwd-s3fs-adminkp"

# ── helpers ──────────────────────────────────────────────────────────────────
c()   { printf '\033[%sm%s\033[0m' "$1" "$2"; }
info(){ printf '%s %s\n' "$(c '1;34' '▶')" "$*"; }
ok()  { printf '%s %s\n' "$(c '1;32' '✓')" "$*"; }
warn(){ printf '%s %s\n' "$(c '1;33' '!')" "$*"; }
die() { printf '%s %s\n' "$(c '1;31' '✗')" "$*" >&2; exit 1; }
ssh_aws(){ ssh -i "$AWS_KEY" -o ConnectTimeout=12 -o StrictHostKeyChecking=accept-new "$AWS_HOST" "$@"; }
secret(){ cat "$SECRET_FILE" 2>/dev/null; }

vault_sealed(){ docker exec "$VAULT_CONTAINER" vault status -format=json 2>/dev/null \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["sealed"])' 2>/dev/null; }

# AWS can reach the local Vault through the tunnel?
kms_reachable_from_aws(){
  [ "$(ssh_aws 'curl -s -o /dev/null -w "%{http_code}" --max-time 6 --cacert /etc/kerplace/kms-ca.crt https://localhost:8200/v1/sys/health 2>/dev/null')" = "200" ]
}

bucket_list(){
  local sec; sec="$(secret)"
  mc alias set adminkp "$S3_ENDPOINT" "$ACCESS_KEY" "$sec" >/dev/null 2>&1 || return 1
  mc ls adminkp 2>/dev/null | awk '{print $NF}' | sed 's#/$##'
}

ensure_passwd(){ printf '%s:%s\n' "$ACCESS_KEY" "$(secret)" > "$PASSWD_S3FS"; chmod 600 "$PASSWD_S3FS"; }

# Mount one bucket at a path (idempotent). Args: <bucket> <mount_point>
mount_one(){
  local b="$1" mp="$2"
  mkdir -p "$mp"
  if mountpoint -q "$mp" 2>/dev/null; then ok "already mounted: $b -> $mp"; return 0; fi
  if s3fs "$b" "$mp" -o url="$S3_ENDPOINT" -o use_path_request_style \
          -o passwd_file="$PASSWD_S3FS" -o dbglevel=err 2>/dev/null; then
    ok "mounted: $b -> $mp"; return 0
  fi
  warn "failed to mount $b at $mp"; return 1
}

# Unmount one path cleanly (sync + lazy fallback). Arg: <mount_point>
umount_one(){
  local mp="$1"
  mountpoint -q "$mp" 2>/dev/null || { warn "not mounted: $mp"; return 0; }
  sync
  fusermount3 -u "$mp" 2>/dev/null || { sleep 1; fusermount3 -z -u "$mp" 2>/dev/null; }
  if mountpoint -q "$mp" 2>/dev/null; then warn "could not unmount $mp"; return 1; fi
  ok "unmounted: $mp"; return 0
}

# ── enable ───────────────────────────────────────────────────────────────────
do_enable(){
  info "1/5  ensuring the local KMS (Vault) is up and unsealed"
  if [ "$(vault_sealed)" != "False" ]; then
    ( cd "$KMS_DIR" && ./start.sh >/dev/null 2>&1 )
  fi
  [ "$(vault_sealed)" = "False" ] || die "Vault is not unsealed — run $KMS_DIR/start.sh"
  ok "KMS unsealed"

  info "2/5  bringing up the reverse tunnel"
  systemctl --user start "$TUNNEL_UNIT" 2>/dev/null
  local i
  for i in $(seq 1 15); do kms_reachable_from_aws && break; sleep 1; done
  kms_reachable_from_aws || die "AWS cannot reach the KMS through the tunnel"
  ok "tunnel up — AWS reaches the KMS (TLS)"

  info "3/5  starting KerPlace on AWS"
  ssh_aws 'sudo systemctl start kerplace' || die "could not start KerPlace"
  for i in $(seq 1 15); do
    [ "$(ssh_aws 'systemctl is-active kerplace' 2>/dev/null)" = "active" ] && break; sleep 1
  done
  [ "$(ssh_aws 'systemctl is-active kerplace' 2>/dev/null)" = "active" ] \
    || die "KerPlace did not become active (KMS unreachable? check the tunnel)"
  ok "KerPlace active on AWS (booted over the off-host KMS)"

  info "4/5  preparing s3fs credentials"
  ensure_passwd

  info "5/5  mounting buckets under $MOUNT_BASE"
  mkdir -p "$MOUNT_BASE"
  local b n=0
  for b in $(bucket_list); do mount_one "$b" "$MOUNT_BASE/$b" && n=$((n+1)); done
  echo; ok "ENABLED — $n bucket(s) mounted. Your remote KerPlace is online and local."
}

# ── disable ──────────────────────────────────────────────────────────────────
do_disable(){
  info "1/3  unmounting buckets cleanly"
  local mp
  if [ -d "$MOUNT_BASE" ]; then
    for mp in "$MOUNT_BASE"/*/; do
      [ -d "$mp" ] || continue; mp="${mp%/}"
      mountpoint -q "$mp" 2>/dev/null && umount_one "$mp"
    done
  fi

  info "2/3  stopping KerPlace on AWS"
  ssh_aws 'sudo systemctl stop kerplace' 2>/dev/null && ok "KerPlace stopped" || warn "could not reach AWS to stop KerPlace"

  info "3/3  dropping the tunnel (AWS is now isolated from your KMS)"
  systemctl --user stop "$TUNNEL_UNIT" 2>/dev/null
  ok "tunnel down — the local Vault stays up but is unreachable"
  echo; ok "DISABLED — remote KerPlace offline; no host can reach your keys."
}

# ── backup (KMS only) ────────────────────────────────────────────────────────
do_backup(){
  local dest="${1:-$HOME/kms-backup-$(date +%Y%m%d-%H%M%S).tar.gz.gpg}"
  command -v gpg >/dev/null || die "gpg not found"
  local stage; stage="$(mktemp -d)"
  trap 'rm -rf "$stage"' RETURN

  info "snapshotting the Vault storage (the non-exportable Transit key lives here)"
  docker run --rm -v "${VAULT_VOLUME}:/data:ro" -v "$stage:/backup" alpine \
    tar czf /backup/vault-data.tar.gz -C /data . 2>/dev/null || die "could not snapshot $VAULT_VOLUME"

  info "collecting KMS config + unseal material"
  cp "$KMS_DIR/.vault-init.json" "$stage/" 2>/dev/null || warn ".vault-init.json missing"
  cp "$KMS_DIR/.kms-token"       "$stage/" 2>/dev/null || true
  cp "$KMS_DIR/docker-compose.yml" "$KMS_DIR/start.sh" "$KMS_DIR/gen-certs.sh" "$stage/" 2>/dev/null || true
  mkdir -p "$stage/vault/config" "$stage/vault/tls"
  cp "$KMS_DIR/vault/config/vault.hcl" "$stage/vault/config/" 2>/dev/null || true
  cp "$KMS_DIR"/vault/tls/* "$stage/vault/tls/" 2>/dev/null || true

  cat > "$stage/RESTORE.md" <<'EOF'
# Restoring the KerPlace KMS on a fresh laptop

You need: Docker, this archive, and your gpg passphrase.

1. Decrypt + unpack:
     gpg -d kms-backup-*.tar.gz.gpg | tar xz
2. Recreate the Vault data volume from vault-data.tar.gz:
     docker volume create kerplace-kms_vault-data
     docker run --rm -v kerplace-kms_vault-data:/data -v "$PWD:/b" alpine \
       sh -c 'cd /data && tar xzf /b/vault-data.tar.gz'
3. Put the config back where adminKP/start.sh expect it
   (e.g. ~/kerplace-kms/): docker-compose.yml, start.sh,
   gen-certs.sh, vault/config/vault.hcl, vault/tls/*, .vault-init.json, .kms-token
4. Bring it up + unseal:  ./start.sh   (it auto-unseals from .vault-init.json)
5. The same Transit key is back -> your existing buckets decrypt again.
   On the KerPlace host, KP_KMS_CA (kms-ca.crt) still matches because the CA
   in vault/tls/ca.crt is the same one. Then: adminKP.sh --enable.

6. Token expiry (only if MORE THAN ~30 days passed since the last backup/renewal):
   the scoped token (KP_KMS_TOKEN on the host) has a 720h TTL and may have lapsed.
   Mint a fresh one on the laptop after start.sh:
     ROOT=$(python3 -c 'import json;print(json.load(open(".vault-init.json"))["root_token"])')
     docker exec -e VAULT_TOKEN="$ROOT" kerplace-vault \
       vault token create -policy=kerplace-kms -ttl=720h -renewable=true -field=token
   then set that value as KP_KMS_TOKEN in /etc/kerplace.env on the KerPlace host
   and restart it (sudo systemctl restart kerplace, or adminKP.sh --disable/--enable).
   The Transit key and CA are unchanged, so the data still decrypts — only the
   token needed refreshing.

KEEP THIS ARCHIVE SAFE: it contains the unseal key. Anyone with it + network
access to the KMS can decrypt your data.
EOF

  info "encrypting with your passphrase (AES-256)"
  local gpgargs=(--symmetric --cipher-algo AES256)
  [ -n "${ADMINKP_PASSPHRASE:-}" ] && gpgargs=(--batch --pinentry-mode loopback --passphrase "$ADMINKP_PASSPHRASE" "${gpgargs[@]}")
  ( cd "$stage" && tar czf - . ) | gpg "${gpgargs[@]}" -o "$dest" || die "encryption failed"
  chmod 600 "$dest"
  echo; ok "BACKUP -> $dest"
  warn "store it off the laptop (it holds the unseal key). The bucket DATA is backed up separately, from $MOUNT_BASE while --enabled."
}

# ── status ───────────────────────────────────────────────────────────────────
do_status(){
  local sealed tun ker
  sealed="$(vault_sealed)"; [ "$sealed" = "False" ] && sealed="up & unsealed" || sealed="DOWN/sealed"
  tun="$(systemctl --user is-active "$TUNNEL_UNIT" 2>/dev/null)"
  ker="$(ssh_aws 'systemctl is-active kerplace' 2>/dev/null)"; [ -z "$ker" ] && ker="unreachable"
  printf '  local KMS (Vault) : %s\n' "$sealed"
  printf '  tunnel to AWS     : %s\n' "$tun"
  printf '  KerPlace on AWS   : %s\n' "$ker"
  printf '  s3fs mounts (default + custom):\n'
  # Enumerate the REAL s3fs mounts from /proc/mounts, so custom paths show too.
  local found=0 dev mpt fstype rest
  while read -r dev mpt fstype rest; do
    [ "$fstype" = "fuse.s3fs" ] || continue
    case "$mpt" in
      "$MOUNT_BASE"/*) printf '    • %s\n' "$mpt" ;;
      *)               printf '    • %s  (custom)\n' "$mpt" ;;
    esac
    found=1
  done < /proc/mounts
  [ $found -eq 0 ] && printf '    (none mounted)\n'
  return 0
}

# ── mount / unmount a single bucket ──────────────────────────────────────────
do_mount(){   # <bucket> [mount_point]
  local b="$1" mp="${2:-$MOUNT_BASE/$1}"
  [ -n "$b" ] || die "usage: --mount <bucket> [mount_point]   (default: $MOUNT_BASE/<bucket>)"
  [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 "$S3_ENDPOINT/" 2>/dev/null)" = "403" ] \
    || warn "KerPlace S3 ($S3_ENDPOINT) not responding — run --enable first, or I/O will fail"
  ensure_passwd
  mount_one "$b" "$mp" || die "mount failed (bucket name correct? KerPlace --enabled?)"
}

do_umount(){  # <bucket|mount_point>
  local arg="$1" mp
  [ -n "$arg" ] || die "usage: --umount <bucket|mount_point>"
  if mountpoint -q "$arg" 2>/dev/null; then mp="$arg"
  elif mountpoint -q "$MOUNT_BASE/$arg" 2>/dev/null; then mp="$MOUNT_BASE/$arg"
  else die "not a current mount: $arg (see --status)"; fi
  umount_one "$mp"
}

usage(){ cat <<'U'
adminKP.sh — "VPN-style" control for a remote KerPlace whose keys live on THIS
laptop (off-host KMS custody). See docs/OFFHOST_KMS_CUSTODY.md.

  --enable                 connect: KMS up -> tunnel -> start KerPlace on AWS
                           -> mount EVERY bucket under ./buckets/<name>
  --disable                disconnect: unmount -> stop KerPlace -> drop tunnel
  --mount  <bucket> [pt]   mount ONE bucket (default pt: ./buckets/<bucket>)
  --umount <bucket|pt>     unmount ONE bucket (by name or by path)
  --backup [file]          gpg-encrypted snapshot to rebuild the KMS (+ RESTORE.md)
  --status                 show what's up / mounted
U
}

case "${1:---help}" in
  --enable)  do_enable ;;
  --disable) do_disable ;;
  --mount)   do_mount "${2:-}" "${3:-}" ;;
  --umount)  do_umount "${2:-}" ;;
  --backup)  do_backup "${2:-}" ;;
  --status)  do_status ;;
  *) usage ;;
esac
