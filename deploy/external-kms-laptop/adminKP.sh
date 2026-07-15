#!/usr/bin/env bash
#
# adminKP.sh — "VPN"-style control for a remote KerPlace whose keys live on
# THIS laptop (off-host KMS custody). See docs/OFFHOST_KMS_CUSTODY.md.
#
# All configuration is read from an environment file (KP_ADMIN_* variables):
#   ${XDG_CONFIG_HOME:-$HOME/.config}/kerplace/adminkp.env   (or --config <path>)
# Copy adminkp.env.example, fill it in and protect it (chmod 600).
#
# Subcommands:
#   --enable                 connect: Vault up -> unseal (USB) -> tunnel ->
#                            start KerPlace on the host -> mount buckets (s3fs)
#   --disable                disconnect: unmount -> stop KerPlace -> tunnel down
#                            -> wipe the s3fs passwd from disk
#   --mount  <bucket> [mp]   mount ONE bucket (mp defaults to <MOUNT_BASE>/<bucket>)
#   --umount <bucket|mp>     unmount ONE bucket (by name or by path)
#   --backup [dir]           encrypted KMS snapshot as TWO artifacts (data /
#                            unseal) with independent passphrases (+ RESTORE.md)
#   --provision-usb [path]   migrate the unseal material from disk to encrypted USB
#   --status                 show what is active / mounted
#   --config <path>          use a different configuration file (global flag)
#
set -u

# ── logging (no colors; [INFO]/[WARN]/[ERR]/[DEBUG] prefixes) ─────────────────
info(){ printf '[INFO] %s\n'  "$*"; }
warn(){ printf '[WARN] %s\n'  "$*" >&2; }
err(){  printf '[ERR] %s\n'   "$*" >&2; }
dbg(){  [ -n "${KP_ADMIN_DEBUG:-}" ] && printf '[DEBUG] %s\n' "$*" >&2 || true; }
die(){  err "$*"; exit 1; }

# ── global --config flag (must come first) ───────────────────────────────────
CONFIG_PATH="${KP_ADMIN_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/kerplace/adminkp.env}"
if [ "${1:-}" = "--config" ]; then
  [ -n "${2:-}" ] || die "--config requires a path"
  CONFIG_PATH="$2"; shift 2
fi

usage(){ cat <<'U'
adminKP.sh — "VPN" control for a remote KerPlace with local key custody.
See docs/OFFHOST_KMS_CUSTODY.md. Configuration: <XDG_CONFIG_HOME>/kerplace/adminkp.env

  --enable                 Vault up -> unseal(USB) -> tunnel -> start KerPlace
                           -> mount EVERY bucket under <MOUNT_BASE>/<name>
  --disable                unmount -> stop KerPlace -> tunnel down -> wipe passwd
  --mount  <bucket> [mp]   mount ONE bucket (mp defaults to <MOUNT_BASE>/<bucket>)
  --umount <bucket|mp>     unmount ONE bucket (by name or by path)
  --backup [dir]           encrypted KMS snapshot as 2 artifacts (+ RESTORE.md)
  --provision-usb [path]   move the unseal material from disk to encrypted USB
  --status                 show what is active / mounted
  --config <path>          use a different configuration file (global flag)
U
}

case "${1:---help}" in
  --help|-h|help) usage; exit 0 ;;
esac

# ── configuration load and validation ────────────────────────────────────────
[ -f "$CONFIG_PATH" ] || die "configuration not found: $CONFIG_PATH
Copy adminkp.env.example there and fill in the KP_ADMIN_* variables (chmod 600)."
# shellcheck source=/dev/null
. "$CONFIG_PATH"

CONFIG_DIR="$(dirname "$CONFIG_PATH")"
# Defaults (the mandatory ones have NO default; see the validation below).
: "${KP_ADMIN_S3_ENDPOINT:=http://127.0.0.1:9000}"     # loopback: encryption in transit is provided by the SSH tunnel (T1)
: "${KP_ADMIN_MOUNT_BASE:=$HOME/buckets}"
: "${KP_ADMIN_TUNNEL_UNIT:=kerplace-kms-tunnel.service}"
: "${KP_ADMIN_USB_LABEL:=KPCUSTODY}"
: "${KP_ADMIN_USB_FILE:=kerplace-custody/unseal.json.gpg}"
: "${KP_ADMIN_KNOWN_HOSTS:=$CONFIG_DIR/known_hosts}"
: "${KP_ADMIN_KEX:=mlkem768x25519-sha256}"             # PQC KEX pinned by policy (T4)
: "${KP_ADMIN_VAULT_CONTAINER:=kerplace-vault}"
: "${KP_ADMIN_VAULT_VOLUME:=kerplace-kms_vault-data}"
: "${KP_ADMIN_PASSWD_S3FS:=$HOME/.passwd-s3fs-adminkp}"

_missing=""
for _v in KP_ADMIN_HOST KP_ADMIN_SSH_KEY KP_ADMIN_ACCESS_KEY KP_ADMIN_SECRET_FILE KP_ADMIN_KMS_DIR; do
  [ -n "${!_v:-}" ] || _missing="$_missing $_v"
done
[ -z "$_missing" ] || die "missing mandatory variables in $CONFIG_PATH:$_missing"

# Hardened SSH options (T4): post-quantum KEX by policy + host key pinning (no
# TOFU) against a dedicated known_hosts. If the server does not offer PQC, or the
# host key does not match, the connection FAILS (fail-closed); it does not degrade.
SSH_OPTS=(
  -i "$KP_ADMIN_SSH_KEY"
  -o "KexAlgorithms=$KP_ADMIN_KEX"
  -o StrictHostKeyChecking=yes
  -o "UserKnownHostsFile=$KP_ADMIN_KNOWN_HOSTS"
  -o ConnectTimeout=12
  -o BatchMode=yes
)

# ── helpers ──────────────────────────────────────────────────────────────────
# The command is sent as a literal to be run on the remote HOST; client-side
# expansion is the intent (there are no local variables to interpolate here).
# shellcheck disable=SC2029
ssh_aws(){ ssh "${SSH_OPTS[@]}" "$KP_ADMIN_HOST" "$@"; }
secret(){ cat "$KP_ADMIN_SECRET_FILE" 2>/dev/null; }

# Is known_hosts populated? (T4: without it, StrictHostKeyChecking=yes fails ugly)
require_known_hosts(){
  [ -s "$KP_ADMIN_KNOWN_HOSTS" ] || die "known_hosts empty or missing: $KP_ADMIN_KNOWN_HOSTS
Populate it at provisioning time (once, on a trusted network):
  ssh-keyscan -t ed25519 <HOST> >> $KP_ADMIN_KNOWN_HOSTS   # and VERIFY the fingerprint"
}

# Local Vault seal state: 'False' unsealed, 'True' sealed, '' down.
vault_sealed(){ docker exec "$KP_ADMIN_VAULT_CONTAINER" vault status -format=json 2>/dev/null \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["sealed"])' 2>/dev/null; }

# Does the host reach the local Vault through the tunnel (−R)?
kms_reachable_from_aws(){
  [ "$(ssh_aws 'curl -s -o /dev/null -w "%{http_code}" --max-time 6 --cacert /etc/kerplace/kms-ca.crt https://localhost:8200/v1/sys/health 2>/dev/null')" = "200" ]
}

# Decrypts a GPG file to stdout. Interactive passphrase (pinentry) unless
# ADMINKP_PASSPHRASE is set (automation escape hatch; it is exposed in
# /proc/<pid>/environ — use it deliberately only).
gpg_decrypt(){
  if [ -n "${ADMINKP_PASSPHRASE:-}" ]; then
    gpg --batch --pinentry-mode loopback --passphrase "$ADMINKP_PASSPHRASE" -d "$1" 2>/dev/null
  else
    gpg -d "$1"
  fi
}

# Locates the mount point of the custody USB by filesystem LABEL.
usb_mount(){
  command -v findmnt >/dev/null || { warn "findmnt not available; cannot locate the USB by LABEL"; return 1; }
  local t; t="$(findmnt -rn -S "LABEL=$KP_ADMIN_USB_LABEL" -o TARGET 2>/dev/null | head -n1)"
  [ -n "$t" ] || return 1
  printf '%s\n' "$t"
}

# Unseals the Vault with the material from the USB, decrypted IN MEMORY (never to disk):
# gpg -> extract unseal key -> 'vault operator unseal -' over stdin. (T2)
usb_unseal(){
  command -v gpg >/dev/null || die "gpg not found"
  local mnt f
  mnt="$(usb_mount)" || die "custody USB '$KP_ADMIN_USB_LABEL' not present — insert it (fail-closed)"
  f="$mnt/$KP_ADMIN_USB_FILE"
  [ -f "$f" ] || die "unseal material not found on the USB: $f"
  info "decrypting the unseal material from the USB (in memory, never to disk)"
  gpg_decrypt "$f" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["unseal_keys_b64"][0])' \
    | docker exec -i "$KP_ADMIN_VAULT_CONTAINER" vault operator unseal - >/dev/null 2>&1 || true
  [ "$(vault_sealed)" = "False" ] || die "unseal failed (wrong passphrase, invalid USB or Vault down?)"
  info "Vault unsealed from the USB"
}

# Registers mc's 'adminkp' alias against the S3 endpoint (loopback via the tunnel).
s3_alias(){ mc alias set adminkp "$KP_ADMIN_S3_ENDPOINT" "$KP_ADMIN_ACCESS_KEY" "$(secret)" >/dev/null 2>&1; }

# S3 data plane alive? tunnel active + a real 'mc ls' (replaces the 403 health-check
# against the public endpoint, which no longer exists after T1).
s3_ready(){
  [ "$(systemctl --user is-active "$KP_ADMIN_TUNNEL_UNIT" 2>/dev/null)" = "active" ] \
    && s3_alias && mc ls adminkp >/dev/null 2>&1
}

bucket_list(){ s3_alias || return 1; mc ls adminkp 2>/dev/null | awk '{print $NF}' | sed 's#/$##'; }

# Writes the s3fs passwd with umask 077 from the start (never chmod afterwards). (T3)
ensure_passwd(){ ( umask 077; printf '%s:%s\n' "$KP_ADMIN_ACCESS_KEY" "$(secret)" > "$KP_ADMIN_PASSWD_S3FS" ); }

# Wipes the s3fs passwd from disk (shred if available). (T3)
wipe_passwd(){
  [ -f "$KP_ADMIN_PASSWD_S3FS" ] || return 0
  if command -v shred >/dev/null; then shred -u "$KP_ADMIN_PASSWD_S3FS" 2>/dev/null; else rm -f "$KP_ADMIN_PASSWD_S3FS"; fi
  info "s3fs passwd wiped from disk"
}

# Mounts a bucket at a path (idempotent). Args: <bucket> <mount_point>
mount_one(){
  local b="$1" mp="$2"
  mkdir -p "$mp"
  if mountpoint -q "$mp" 2>/dev/null; then info "already mounted: $b -> $mp"; return 0; fi
  if s3fs "$b" "$mp" -o url="$KP_ADMIN_S3_ENDPOINT" -o use_path_request_style \
          -o passwd_file="$KP_ADMIN_PASSWD_S3FS" -o dbglevel=err 2>/dev/null; then
    info "mounted: $b -> $mp"; return 0
  fi
  warn "could not mount $b at $mp"; return 1
}

# Unmounts a path cleanly (sync + lazy fallback). Arg: <mount_point>
umount_one(){
  local mp="$1"
  mountpoint -q "$mp" 2>/dev/null || { warn "not mounted: $mp"; return 0; }
  sync
  fusermount3 -u "$mp" 2>/dev/null || { sleep 1; fusermount3 -z -u "$mp" 2>/dev/null; }
  if mountpoint -q "$mp" 2>/dev/null; then warn "could not unmount $mp"; return 1; fi
  info "unmounted: $mp"; return 0
}

# ── enable ───────────────────────────────────────────────────────────────────
do_enable(){
  require_known_hosts

  info "1/5  bringing up the KMS (Vault) and unsealing it from the USB"
  ( cd "$KP_ADMIN_KMS_DIR" && ./start.sh >/dev/null 2>&1 ) || die "could not bring up the Vault container ($KP_ADMIN_KMS_DIR/start.sh)"
  if [ "$(vault_sealed)" != "False" ]; then usb_unseal; else info "Vault was already unsealed"; fi
  [ "$(vault_sealed)" = "False" ] || die "Vault is not unsealed"

  info "2/5  bringing up the SSH tunnel (custody −R 8200 + data −L 9000)"
  systemctl --user start "$KP_ADMIN_TUNNEL_UNIT" 2>/dev/null
  for _ in $(seq 1 15); do kms_reachable_from_aws && break; sleep 1; done
  kms_reachable_from_aws || die "the host does not reach the KMS through the tunnel"
  info "tunnel active — the host reaches the KMS (TLS)"

  info "3/5  starting KerPlace on the host"
  ssh_aws 'sudo systemctl start kerplace' || die "could not start KerPlace"
  for _ in $(seq 1 15); do
    [ "$(ssh_aws 'systemctl is-active kerplace' 2>/dev/null)" = "active" ] && break; sleep 1
  done
  [ "$(ssh_aws 'systemctl is-active kerplace' 2>/dev/null)" = "active" ] \
    || die "KerPlace did not become active (KMS unreachable? check the tunnel)"
  info "KerPlace active on the host (started against the off-host KMS)"

  info "4/5  preparing s3fs credentials"
  ensure_passwd

  info "5/5  mounting buckets under $KP_ADMIN_MOUNT_BASE"
  mkdir -p "$KP_ADMIN_MOUNT_BASE"
  local b n=0
  for b in $(bucket_list); do mount_one "$b" "$KP_ADMIN_MOUNT_BASE/$b" && n=$((n+1)); done
  info "ENABLED — $n bucket(s) mounted. Your remote KerPlace is online and local."
}

# ── disable ──────────────────────────────────────────────────────────────────
do_disable(){
  info "1/4  unmounting buckets cleanly"
  local mp
  if [ -d "$KP_ADMIN_MOUNT_BASE" ]; then
    for mp in "$KP_ADMIN_MOUNT_BASE"/*/; do
      [ -d "$mp" ] || continue; mp="${mp%/}"
      mountpoint -q "$mp" 2>/dev/null && umount_one "$mp"
    done
  fi

  info "2/4  stopping KerPlace on the host"
  if ssh_aws 'sudo systemctl stop kerplace' 2>/dev/null; then info "KerPlace stopped"; else warn "could not reach the host to stop KerPlace"; fi

  info "3/4  taking the tunnel down and re-sealing the local Vault"
  systemctl --user stop "$KP_ADMIN_TUNNEL_UNIT" 2>/dev/null
  # Re-seal by restarting the container (file storage -> it boots sealed): needs no
  # token, and forces presenting the USB on the next --enable (possession per
  # session). The container stays UP; it is merely sealed.
  if docker restart "$KP_ADMIN_VAULT_CONTAINER" >/dev/null 2>&1; then
    info "Vault re-sealed (the next --enable will require the USB)"
  else
    warn "could not re-seal the local Vault"
  fi

  info "4/4  wiping the s3fs passwd from disk"
  wipe_passwd
  info "DISABLED — remote KerPlace offline; no host reaches your keys."
}

# ── USB provisioning (migrate unseal from disk to the encrypted USB) ──────────
do_provision_usb(){
  command -v gpg >/dev/null || die "gpg not found"
  local target="${1:-}" mnt f src="$KP_ADMIN_KMS_DIR/.vault-init.json"
  [ -f "$src" ] || die "no unseal material on disk ($src) — already provisioned? nothing to do"
  if [ -n "$target" ]; then mnt="$target"; else mnt="$(usb_mount)" || die "USB '$KP_ADMIN_USB_LABEL' not present; pass the path as an argument"; fi
  [ -d "$mnt" ] || die "the target is not a directory: $mnt"
  f="$mnt/$KP_ADMIN_USB_FILE"
  mkdir -p "$(dirname "$f")" || die "cannot create $(dirname "$f") on the USB"

  info "encrypting the unseal material to the USB (AES-256): $f"
  local gpgenc=(--symmetric --cipher-algo AES256 --yes)
  [ -n "${ADMINKP_PASSPHRASE:-}" ] && gpgenc=(--batch --pinentry-mode loopback --passphrase "$ADMINKP_PASSPHRASE" "${gpgenc[@]}")
  ( umask 077; gpg "${gpgenc[@]}" -o "$f" "$src" ) || die "encryption failed"
  chmod 600 "$f" 2>/dev/null || true

  info "verifying round-trip (decrypt and compare against the original)"
  local a b
  a="$(python3 -c 'import sys,json;d=json.load(open(sys.argv[1]));print(d["unseal_keys_b64"][0]+"|"+d.get("root_token",""))' "$src" 2>/dev/null)"
  b="$(gpg_decrypt "$f" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["unseal_keys_b64"][0]+"|"+d.get("root_token",""))' 2>/dev/null)"
  [ -n "$a" ] && [ "$a" = "$b" ] || die "round-trip does NOT match — do NOT delete the original"
  info "round-trip OK — the USB holds the same material as the disk"

  warn "before deleting the original, have a recent --backup (the USB is now your possession factor)"
  printf '[INFO] delete the original from disk (%s)? type DELETE to confirm: ' "$src"
  local ans; read -r ans
  if [ "$ans" = "DELETE" ]; then
    if command -v shred >/dev/null; then shred -u "$src"; else rm -f "$src"; fi
    info "original deleted; the unseal now lives only on the USB (+ your passphrase)"
  else
    info "original kept on disk; re-run --provision-usb whenever you want to complete the migration"
  fi
}

# ── KMS backup: TWO artifacts with independent passphrases (T7) ────────────────
do_backup(){
  command -v gpg >/dev/null || die "gpg not found"
  local outdir="${1:-$HOME}" ts
  ts="$(date +%Y%m%d-%H%M%S)"
  [ -d "$outdir" ] || die "output directory does not exist: $outdir"
  local data_out="$outdir/kms-data-$ts.tar.gz.gpg"
  local unseal_out="$outdir/kms-unseal-$ts.tar.gz.gpg"

  local stage; stage="$(mktemp -d)"; trap 'rm -rf "$stage"' RETURN

  # ── Artifact 1: DATA (Vault volume + config + certs). Large, rotates often.
  info "snapshotting the Vault volume (this is where the non-exportable Transit key lives)"
  docker run --rm -v "${KP_ADMIN_VAULT_VOLUME}:/data:ro" -v "$stage:/backup" alpine \
    tar czf /backup/vault-data.tar.gz -C /data . 2>/dev/null || die "could not snapshot $KP_ADMIN_VAULT_VOLUME"
  mkdir -p "$stage/data/vault/config" "$stage/data/vault/tls"
  mv "$stage/vault-data.tar.gz" "$stage/data/"
  cp "$KP_ADMIN_KMS_DIR/docker-compose.yml" "$KP_ADMIN_KMS_DIR/start.sh" "$KP_ADMIN_KMS_DIR/gen-certs.sh" "$stage/data/" 2>/dev/null || true
  cp "$KP_ADMIN_KMS_DIR/vault/config/vault.hcl" "$stage/data/vault/config/" 2>/dev/null || true
  cp "$KP_ADMIN_KMS_DIR"/vault/tls/* "$stage/data/vault/tls/" 2>/dev/null || true
  write_restore_md > "$stage/data/RESTORE.md"

  # ── Artifact 2: UNSEAL (seal material + token only). Small, kept in separate
  #    custody, changes almost never. Preference: from disk; if it was already
  #    migrated to the USB (T2), it is taken from there so DR stays complete.
  mkdir -p "$stage/unseal"
  if [ -f "$KP_ADMIN_KMS_DIR/.vault-init.json" ]; then
    cp "$KP_ADMIN_KMS_DIR/.vault-init.json" "$stage/unseal/"
    cp "$KP_ADMIN_KMS_DIR/.kms-token" "$stage/unseal/" 2>/dev/null || true
  else
    info "unseal material is not on disk; extracting it from the USB for the backup"
    local mnt; mnt="$(usb_mount)" || die "no USB and no .vault-init.json on disk: cannot back up the unseal"
    gpg_decrypt "$mnt/$KP_ADMIN_USB_FILE" > "$stage/unseal/.vault-init.json" \
      || die "could not decrypt the unseal from the USB"
    cp "$KP_ADMIN_KMS_DIR/.kms-token" "$stage/unseal/" 2>/dev/null || true
  fi

  info "encrypting the DATA artifact (AES-256) — data passphrase"
  backup_encrypt "$stage/data" "$data_out" "${ADMINKP_PASSPHRASE:-}"
  info "encrypting the UNSEAL artifact (AES-256) — unseal passphrase (independent)"
  backup_encrypt "$stage/unseal" "$unseal_out" "${ADMINKP_UNSEAL_PASSPHRASE:-}"

  info "BACKUP -> $data_out"
  info "BACKUP -> $unseal_out"
  warn "keep both artifacts in SEPARATE custody. The unseal one alone (with its"
  warn "passphrase) is enough to unseal; keep it apart from the data one. Bucket DATA"
  warn "is backed up separately, from $KP_ADMIN_MOUNT_BASE while you are --enabled."
}

# Encrypts a directory into a .tar.gz.gpg. Args: <dir> <out> <passphrase|"">
backup_encrypt(){
  local dir="$1" out="$2" pass="$3"
  local gpgargs=(--symmetric --cipher-algo AES256)
  [ -n "$pass" ] && gpgargs=(--batch --pinentry-mode loopback --passphrase "$pass" "${gpgargs[@]}")
  ( cd "$dir" && tar czf - . ) | gpg "${gpgargs[@]}" -o "$out" || die "encryption failed: $out"
  chmod 600 "$out"
}

# ── status ───────────────────────────────────────────────────────────────────
do_status(){
  local sealed tun ker
  sealed="$(vault_sealed)"; [ "$sealed" = "False" ] && sealed="up & unsealed" || sealed="DOWN/sealed"
  tun="$(systemctl --user is-active "$KP_ADMIN_TUNNEL_UNIT" 2>/dev/null)"
  if [ -s "$KP_ADMIN_KNOWN_HOSTS" ]; then
    ker="$(ssh_aws 'systemctl is-active kerplace' 2>/dev/null)"; [ -z "$ker" ] && ker="unreachable"
  else
    ker="(known_hosts not populated)"
  fi
  printf '  local KMS (Vault) : %s\n' "$sealed"
  printf '  tunnel to host    : %s\n' "$tun"
  printf '  remote KerPlace   : %s\n' "$ker"
  printf '  s3fs mounts:\n'
  local found=0 mpt fstype
  while read -r _ mpt fstype _; do
    [ "$fstype" = "fuse.s3fs" ] || continue
    case "$mpt" in
      "$KP_ADMIN_MOUNT_BASE"/*) printf '    - %s\n' "$mpt" ;;
      *)                        printf '    - %s  (custom)\n' "$mpt" ;;
    esac
    found=1
  done < /proc/mounts
  [ "$found" -eq 0 ] && printf '    (none mounted)\n'
  return 0
}

# ── mount / umount of a single bucket ────────────────────────────────────────
do_mount(){   # <bucket> [mount_point]
  local b="$1" mp="${2:-$KP_ADMIN_MOUNT_BASE/$1}"
  [ -n "$b" ] || die "usage: --mount <bucket> [mount_point]   (default: $KP_ADMIN_MOUNT_BASE/<bucket>)"
  s3_ready || warn "S3 data plane unavailable (tunnel down? --enable first?) — I/O will fail"
  ensure_passwd
  mount_one "$b" "$mp" || die "mount failed (correct bucket name? KerPlace --enabled?)"
}

do_umount(){  # <bucket|mount_point>
  local arg="$1" mp
  [ -n "$arg" ] || die "usage: --umount <bucket|mount_point>"
  if mountpoint -q "$arg" 2>/dev/null; then mp="$arg"
  elif mountpoint -q "$KP_ADMIN_MOUNT_BASE/$arg" 2>/dev/null; then mp="$KP_ADMIN_MOUNT_BASE/$arg"
  else die "not a current mount: $arg (see --status)"; fi
  umount_one "$mp"
}

# RESTORE.md text (used by the DATA artifact). References the two-artifact flow
# and keeps the token expiry warning (720h).
write_restore_md(){ cat <<'EOF'
# Restoring the KerPlace KMS on a new laptop

You need: Docker, BOTH backup artifacts, and their two passphrases.

  - kms-data-<ts>.tar.gz.gpg    -> Vault volume + config + certs (this archive)
  - kms-unseal-<ts>.tar.gz.gpg  -> .vault-init.json (unseal key + root token) + token

1. Decrypt + unpack both:
     gpg -d kms-data-<ts>.tar.gz.gpg   | tar xz          # -> vault-data.tar.gz, config, certs, RESTORE.md
     gpg -d kms-unseal-<ts>.tar.gz.gpg | tar xz          # -> .vault-init.json, .kms-token
2. Recreate the Vault data volume from vault-data.tar.gz:
     docker volume create kerplace-kms_vault-data
     docker run --rm -v kerplace-kms_vault-data:/data -v "$PWD:/b" alpine \
       sh -c 'cd /data && tar xzf /b/vault-data.tar.gz'
3. Put the config where adminKP/start.sh expect it (e.g. <KMS_DIR>/):
   docker-compose.yml, start.sh, gen-certs.sh, vault/config/vault.hcl, vault/tls/*
   and the unseal material: .vault-init.json, .kms-token
4. Bring the container up:  ./start.sh   (leaves Vault SEALED; it no longer auto-unseals)
   Then migrate the unseal to the USB and unseal:
     ./adminKP.sh --provision-usb <usb_path>     (moves .vault-init.json to the USB)
     ./adminKP.sh --enable                       (unseals from the USB)
   The same Transit key comes back -> your buckets decrypt again. The CA in
   vault/tls/ca.crt did not change, so KP_KMS_CA on the host still matches.

5. Token expiry (only if MORE than ~30 days passed since the last backup):
   the scoped token (KP_KMS_TOKEN on the host) has a 720h TTL and may have expired.
   Mint a new one on the laptop after the unseal:
     ROOT=$(python3 -c 'import json;print(json.load(open(".vault-init.json"))["root_token"])')
     docker exec -e VAULT_TOKEN="$ROOT" kerplace-vault \
       vault token create -policy=kerplace-kms -ttl=720h -renewable=true -field=token
   set that value as KP_KMS_TOKEN in the host's /etc/kerplace.env and restart it.
   The Transit key and the CA do not change, so the data keeps decrypting.

KEEP THE UNSEAL ARTIFACT SEPARATE: it contains the unseal key. Whoever holds it
(+ its passphrase) + network access to the KMS can decrypt your data.
EOF
}

# ── dispatcher ───────────────────────────────────────────────────────────────
case "${1:---help}" in
  --enable)        do_enable ;;
  --disable)       do_disable ;;
  --mount)         do_mount "${2:-}" "${3:-}" ;;
  --umount)        do_umount "${2:-}" ;;
  --backup)        do_backup "${2:-}" ;;
  --provision-usb) do_provision_usb "${2:-}" ;;
  --status)        do_status ;;
  *) usage; exit 1 ;;
esac
