#!/usr/bin/env bash
#
# kerplace.sh — operate a KerPlace server from the command line.
#
#   * mount/unmount buckets as local filesystems (via s3fs-fuse), and
#   * inspect server state: buckets, users + policies, encryption, versioning,
#     and active mounts.
#
# It is the KerPlace counterpart of the legacy MinIO mount scripts
# (mount_legacy.sh / umount_legacy.sh), pointed at KerPlace with path-style
# addressing and SigV4.
#
# Configuration is taken from environment variables (sensible defaults below);
# override any of them inline, e.g.:
#
#   KP_URL=https://10.1.15.6:9000 KP_ACCESS_KEY=app KP_SECRET_KEY=secret \
#     ./kerplace.sh mount-all
#
set -uo pipefail

# ── Configuration (override via environment) ─────────────────────────────────
KP_ALIAS="${KP_ALIAS:-kerplace}"                       # mc alias name
KP_URL="${KP_URL:-http://localhost:9000}"           # S3 API endpoint
KP_ACCESS_KEY="${KP_ACCESS_KEY:-minioadmin}"        # access key
KP_SECRET_KEY="${KP_SECRET_KEY:-minioadmin}"        # secret key
KP_MOUNT_BASE="${KP_MOUNT_BASE:-/mnt/datalake}"     # where buckets are mounted
KP_PASSWD_FILE="${KP_PASSWD_FILE:-$HOME/.passwd-s3fs-kerplace}"  # s3fs credentials

# s3fs tuning (mirrors the legacy mount script).
S3FS_OPTS=(
  -o use_path_request_style
  -o sigv4
  -o parallel_count=10
  -o multipart_size=64
  -o connect_timeout=10
  -o readwrite_timeout=30
  -o retries=3
)

# ── Pretty output ────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'
  C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_CYAN=$'\033[36m'
else
  C_RESET=""; C_DIM=""; C_BOLD=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_CYAN=""
fi
info()  { printf '%s\n' "$*"; }
ok()    { printf '  %s✅ %s%s\n' "$C_GREEN" "$*" "$C_RESET"; }
warn()  { printf '  %s⚠️  %s%s\n' "$C_YELLOW" "$*" "$C_RESET"; }
err()   { printf '  %s❌ %s%s\n' "$C_RED" "$*" "$C_RESET"; }
head2() { printf '\n%s%s== %s ==%s\n' "$C_BOLD" "$C_CYAN" "$*" "$C_RESET"; }

# ── Prerequisites ────────────────────────────────────────────────────────────
need() {
  command -v "$1" >/dev/null 2>&1 || { err "'$1' is required but not installed."; exit 1; }
}

# Configure the mc alias for this server (idempotent).
ensure_alias() {
  need mc
  local insecure=()
  [[ "$KP_URL" == https://* ]] && insecure=(--insecure)
  mc alias set "$KP_ALIAS" "$KP_URL" "$KP_ACCESS_KEY" "$KP_SECRET_KEY" \
    "${insecure[@]}" >/dev/null 2>&1 \
    || { err "could not set mc alias '$KP_ALIAS' for $KP_URL"; exit 1; }
}

# Write the s3fs credentials file (accessKey:secretKey), mode 600.
ensure_passwd() {
  if [ ! -f "$KP_PASSWD_FILE" ] || \
     [ "$(cat "$KP_PASSWD_FILE" 2>/dev/null)" != "$KP_ACCESS_KEY:$KP_SECRET_KEY" ]; then
    printf '%s:%s\n' "$KP_ACCESS_KEY" "$KP_SECRET_KEY" > "$KP_PASSWD_FILE"
    chmod 600 "$KP_PASSWD_FILE"
  fi
}

# Print the bucket names (one per line), stripping mc's trailing slash.
list_buckets() {
  mc ls "$KP_ALIAS" 2>/dev/null | awk '{print $NF}' | sed 's:/*$::' | grep -v '^$'
}

# ── Mount / unmount ──────────────────────────────────────────────────────────
mount_one() {
  need s3fs
  local bucket="$1" mp="$KP_MOUNT_BASE/$1"
  mkdir -p "$mp" 2>/dev/null || { sudo mkdir -p "$mp" && sudo chown "$(id -u):$(id -g)" "$mp"; }
  if mountpoint -q "$mp" 2>/dev/null; then
    warn "$bucket already mounted at $mp"; return 0
  fi
  if s3fs "$bucket" "$mp" \
        -o url="$KP_URL" \
        -o passwd_file="$KP_PASSWD_FILE" \
        -o uid="$(id -u)" -o gid="$(id -g)" -o mp_umask=002 \
        "${S3FS_OPTS[@]}"; then
    ok "$bucket → $mp"
  else
    err "failed to mount $bucket"
    return 1
  fi
}

umount_one() {
  local mp="$1" name; name="$(basename "$mp")"
  mountpoint -q "$mp" 2>/dev/null || { info "  $name: not mounted"; return 0; }
  if fusermount -u "$mp" 2>/dev/null || umount "$mp" 2>/dev/null || umount -l "$mp" 2>/dev/null; then
    ok "unmounted $name"
  else
    err "could not unmount $mp"
    return 1
  fi
}

cmd_mount_all() {
  ensure_alias; ensure_passwd
  head2 "Mounting all buckets of '$KP_ALIAS' ($KP_URL) under $KP_MOUNT_BASE"
  local buckets; buckets="$(list_buckets)"
  [ -z "$buckets" ] && { warn "no buckets found"; return 0; }
  local total=0 ok_n=0
  while IFS= read -r b; do
    [ -z "$b" ] && continue
    total=$((total+1)); mount_one "$b" && ok_n=$((ok_n+1))
  done <<< "$buckets"
  info ""; info "Mounted $ok_n/$total buckets."
}

cmd_umount_all() {
  head2 "Unmounting everything under $KP_MOUNT_BASE"
  [ -d "$KP_MOUNT_BASE" ] || { warn "$KP_MOUNT_BASE does not exist"; return 0; }
  shopt -s nullglob
  local any=0
  for mp in "$KP_MOUNT_BASE"/*/; do
    any=1; umount_one "${mp%/}"
  done
  [ "$any" = 0 ] && info "  (nothing to unmount)"
}

cmd_mount()   { [ $# -ge 1 ] || { err "usage: kerplace.sh mount <bucket>"; exit 1; }; ensure_alias; ensure_passwd; mount_one "$1"; }
cmd_umount()  { [ $# -ge 1 ] || { err "usage: kerplace.sh umount <bucket>"; exit 1; }; umount_one "$KP_MOUNT_BASE/$1"; }

# ── Status dashboard (show-mount) ────────────────────────────────────────────
cmd_status() {
  ensure_alias
  head2 "Server"
  if mc admin info "$KP_ALIAS" >/dev/null 2>&1; then
    mc admin info "$KP_ALIAS" 2>/dev/null | sed 's/^/  /' | head -8
  else
    warn "could not reach $KP_URL (is KerPlace running?)"
  fi

  head2 "Buckets (encryption · versioning)"
  local buckets; buckets="$(list_buckets)"
  if [ -z "$buckets" ]; then
    info "  (none)"
  else
    while IFS= read -r b; do
      [ -z "$b" ] && continue
      local enc ver
      enc="$(mc encrypt info "$KP_ALIAS/$b" 2>/dev/null | grep -ioE 'sse-s3|aes256|kms' | head -1)"
      [ -z "$enc" ] && enc="off"
      ver="$(mc version info "$KP_ALIAS/$b" 2>/dev/null | grep -ioE 'enabled|suspended' | head -1)"
      [ -z "$ver" ] && ver="off"
      printf '  %s📦 %-28s%s enc=%s%-8s%s ver=%s%s%s\n' \
        "$C_BOLD" "$b" "$C_RESET" \
        "$C_GREEN" "$enc" "$C_RESET" "$C_GREEN" "$ver" "$C_RESET"
    done <<< "$buckets"
  fi

  head2 "Users & policies"
  if mc admin user list "$KP_ALIAS" >/dev/null 2>&1; then
    mc admin user list "$KP_ALIAS" 2>/dev/null | sed 's/^/  /'
    info "  ${C_DIM}(root '$KP_ACCESS_KEY' is implicit / admin)${C_RESET}"
  else
    warn "user listing unavailable (need an admin credential)"
  fi

  head2 "Active s3fs mounts"
  local mounts; mounts="$(mount 2>/dev/null | grep s3fs)"
  if [ -z "$mounts" ]; then
    info "  (none)"
  else
    printf '%s\n' "$mounts" | awk '{print "  "$1" → "$3}'
  fi
  info ""
}

# ── Usage ────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
${C_BOLD}kerplace.sh${C_RESET} — mount KerPlace buckets and inspect server state.

${C_BOLD}Usage:${C_RESET} kerplace.sh <command> [args]

${C_BOLD}Commands:${C_RESET}
  mount-all            Mount every bucket under \$KP_MOUNT_BASE (via s3fs)
  umount-all           Unmount everything under \$KP_MOUNT_BASE
  mount   <bucket>     Mount a single bucket
  umount  <bucket>     Unmount a single bucket
  show-mount | status  Dashboard: buckets, encryption, versioning, users, mounts
  help                 Show this help

${C_BOLD}Configuration (env vars, current values):${C_RESET}
  KP_ALIAS=$KP_ALIAS
  KP_URL=$KP_URL
  KP_ACCESS_KEY=$KP_ACCESS_KEY
  KP_SECRET_KEY=${C_DIM}****${C_RESET}
  KP_MOUNT_BASE=$KP_MOUNT_BASE
  KP_PASSWD_FILE=$KP_PASSWD_FILE

${C_BOLD}Example:${C_RESET}
  KP_URL=http://localhost:9000 ./kerplace.sh show-mount
EOF
}

# ── Dispatch ─────────────────────────────────────────────────────────────────
main() {
  local cmd="${1:-help}"; shift || true
  cmd="${cmd#--}"   # tolerate flag-style invocation (e.g. --mount-all)
  case "$cmd" in
    mount-all)            cmd_mount_all "$@" ;;
    umount-all|unmount-all) cmd_umount_all "$@" ;;
    mount)                cmd_mount "$@" ;;
    umount|unmount)       cmd_umount "$@" ;;
    show-mount|status)    cmd_status "$@" ;;
    help|-h|--help)       usage ;;
    *) err "unknown command: $cmd"; echo; usage; exit 1 ;;
  esac
}
main "$@"
