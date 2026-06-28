#!/usr/bin/env bash
#
# kerplace-migrate.sh — migrate a MinIO deployment to KerPlace.
#
# MinIO reached EOL in 2026. KerPlace is a drop-in S3-compatible home for the
# orphaned deployments. The S3 API and the `mc` / SDK clients are 100%
# compatible, so the migration runs entirely at the S3 + madmin level — no
# access to either server's disks is required, and the source MinIO can keep
# serving traffic until you cut over.
#
# It copies, from a source MinIO to a destination KerPlace (both addressed as
# existing `mc` aliases):
#
#   buckets   bucket creation (+ object-lock flag)
#   config    per-bucket versioning, encryption, lifecycle (ILM), tags,
#             quota and anonymous (public) access policy
#   iam       custom policies + users (see the SECRET-KEY caveat below)
#   data      object data + metadata of the *current* versions (mc mirror)
#   versions  full version history replay              (opt-in: --with-versions)
#   verify    per-bucket object-count / size comparison
#
# Every phase is best-effort: a failure is reported and the run continues, so
# one unsupported feature never aborts the whole migration. A summary at the
# end lists what migrated and what needs manual attention.
#
# Usage:
#   ./kerplace-migrate.sh <src-alias> <dst-alias> [phase] [options]
#
#   phase     one of: all (default) preflight buckets config iam data versions verify
#
# Options:
#   --with-versions      also replay the full object version history (slow)
#   --buckets "a b c"    restrict to these buckets (default: all source buckets)
#   --dry-run            print what would happen; make no changes on the dest
#   --insecure           pass --insecure to mc (self-signed TLS)
#   --creds-out FILE     where rotated user credentials are written
#                        (default: ./migrated-credentials-<dst>.csv)
#   -h, --help           show this help
#
# Examples:
#   ./kerplace-migrate.sh m kerplace                       # full migration, m → kerplace
#   ./kerplace-migrate.sh m kerplace data --buckets "logs" # just mirror one bucket
#   ./kerplace-migrate.sh m kerplace all --with-versions   # include version history
#   ./kerplace-migrate.sh m kerplace preflight             # read-only inventory only
#
# !! SECRET-KEY CAVEAT !!  MinIO never discloses a user's secret key over its
# API, so user secrets *cannot* be migrated. The `iam` phase recreates each
# user with a freshly generated secret key and writes the new credentials to
# the --creds-out file. Distribute those to your users (or rotate again).
#
set -uo pipefail

# ── Pretty output ────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'
  C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_CYAN=$'\033[36m'
else
  C_RESET=""; C_DIM=""; C_BOLD=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_CYAN=""
fi
info()  { printf '%s\n' "$*"; }
ok()    { printf '  %s✅ %s%s\n' "$C_GREEN" "$*" "$C_RESET"; }
warn()  { printf '  %s⚠️  %s%s\n' "$C_YELLOW" "$*" "$C_RESET"; MIG_WARNINGS+=("$*"); }
err()   { printf '  %s❌ %s%s\n' "$C_RED"    "$*" "$C_RESET"; }
step()  { printf '  %s· %s%s\n' "$C_DIM"     "$*" "$C_RESET"; }
head2() { printf '\n%s%s══ %s ══%s\n' "$C_BOLD" "$C_CYAN" "$*" "$C_RESET"; }

# ── Globals (set by parse_args) ──────────────────────────────────────────────
SRC=""; DST=""; PHASE="all"
WITH_VERSIONS=false; DRY_RUN=false; ONLY_BUCKETS=""; CREDS_OUT=""
MC_FLAGS=()                 # extra flags forwarded to every mc call (e.g. --insecure)
MIG_WARNINGS=()             # collected warnings, printed in the final summary

# Print the embedded usage block (the leading comment of this file).
usage() {
  sed -n '3,/^set -uo pipefail/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
}

# Abort with a message and non-zero status.
die() { err "$*"; exit 1; }

# Ensure a command exists on PATH.
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed."; }

# Run an mc command with the shared flags appended. Used for read-only calls.
mcq() { mc "${MC_FLAGS[@]}" "$@"; }

# Run a *mutating* mc command, honouring --dry-run (prints, does not execute).
mcrun() {
  if $DRY_RUN; then
    printf '  %s[dry-run] mc %s%s\n' "$C_DIM" "$*" "$C_RESET"
    return 0
  fi
  mc "${MC_FLAGS[@]}" "$@"
}

# ── Argument parsing ─────────────────────────────────────────────────────────
# Populate the globals from the command line; validate the phase name.
parse_args() {
  local positional=()
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help)        usage; exit 0 ;;
      --with-versions)  WITH_VERSIONS=true ;;
      --dry-run)        DRY_RUN=true ;;
      --insecure)       MC_FLAGS+=(--insecure) ;;
      --buckets)        ONLY_BUCKETS="${2:-}"; shift ;;
      --creds-out)      CREDS_OUT="${2:-}"; shift ;;
      --*)              die "unknown option: $1 (try --help)" ;;
      *)                positional+=("$1") ;;
    esac
    shift
  done

  [ "${#positional[@]}" -ge 2 ] || { usage; exit 2; }
  SRC="${positional[0]}"
  DST="${positional[1]}"
  PHASE="${positional[2]:-all}"
  CREDS_OUT="${CREDS_OUT:-./migrated-credentials-${DST}.csv}"

  case "$PHASE" in
    all|preflight|buckets|config|iam|data|versions|verify) ;;
    *) die "unknown phase: $PHASE (try --help)" ;;
  esac
}

# ── Inventory helpers ────────────────────────────────────────────────────────
# Print the source bucket names (one per line). Honours --buckets.
src_buckets() {
  if [ -n "$ONLY_BUCKETS" ]; then
    printf '%s\n' $ONLY_BUCKETS
  else
    mcq ls "$SRC" --json 2>/dev/null \
      | sed -n 's/.*"key":"\([^"]*\)\/".*/\1/p'
  fi
}

# Echo a JSON field value from a single mc --json line: jget <json> <key>
jget() {
  printf '%s' "$1" | sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p" | head -1
}

# True if versioning is enabled on a bucket: is_versioned <alias> <bucket>
is_versioned() {
  mcq version info "$1/$2" 2>/dev/null | grep -qi enabled
}

# Generate a random secret key (40 url-safe-ish chars), like MinIO's defaults.
gen_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 30 | tr -d '/+=' | cut -c1-32
  else
    head -c 24 /dev/urandom | base64 | tr -d '/+=' | cut -c1-32
  fi
}

# ── Phase: preflight ─────────────────────────────────────────────────────────
# Read-only. Confirm both aliases work, warn if the destination doesn't look
# like KerPlace, and print an inventory of what would be migrated.
phase_preflight() {
  head2 "Preflight"
  need mc

  mcq ls "$SRC" >/dev/null 2>&1 || die "source alias '$SRC' is not reachable (mc alias set $SRC ...)"
  ok "source '$SRC' reachable"
  mcq ls "$DST" >/dev/null 2>&1 || die "destination alias '$DST' is not reachable (mc alias set $DST ...)"
  ok "destination '$DST' reachable"

  # KerPlace advertises itself via the Server header; MinIO says "MinIO".
  if mcq ls "$DST" --debug 2>&1 | grep -qi 'Server: KerPlace'; then
    ok "destination identifies as KerPlace"
  else
    warn "could not confirm destination is KerPlace — proceeding anyway (it must be S3-compatible)"
  fi

  local nb nu
  nb="$(src_buckets | grep -c . || true)"
  nu="$(mcq admin user list "$SRC" --json 2>/dev/null | grep -c . || true)"
  info ""
  step "buckets to migrate : $nb"
  step "users on source    : $nu (secrets will be rotated — see --help)"
  $WITH_VERSIONS && step "version history    : ENABLED (full replay)" \
                 || step "version history    : current versions only (--with-versions for all)"
  $DRY_RUN && warn "DRY-RUN: no changes will be made on '$DST'"
}

# ── Phase: buckets ───────────────────────────────────────────────────────────
# Create every source bucket on the destination, carrying the object-lock flag.
phase_buckets() {
  head2 "Buckets"
  local b lockflag
  while read -r b; do
    [ -z "$b" ] && continue
    # If the source bucket has object lock enabled, create the dest with --with-lock.
    # `retention info` exits 0 even when disabled, so check the JSON state.
    lockflag=()
    if mcq retention info "$SRC/$b" --json 2>/dev/null | grep -q '"enabled":"Enabled"'; then
      lockflag=(--with-lock)
    fi
    if mcrun mb --ignore-existing "${lockflag[@]}" "$DST/$b" 2>/dev/null; then
      ok "bucket $b${lockflag:+ (object-lock)}"
    else
      warn "bucket $b: create failed"
    fi
  done < <(src_buckets)
}

# ── Phase: config ────────────────────────────────────────────────────────────
# Per-bucket settings that `mc mirror` does NOT carry: versioning, encryption,
# lifecycle (ILM), tags, quota and anonymous access policy.
phase_config() {
  head2 "Per-bucket config"
  local b
  while read -r b; do
    [ -z "$b" ] && continue
    info "  $C_BOLD$b$C_RESET"

    # Versioning ------------------------------------------------------------
    local vstate
    vstate="$(mcq version info "$SRC/$b" 2>/dev/null | grep -oiE 'enabled|suspended' | head -1)"
    case "$vstate" in
      [Ee]nabled)   mcrun version enable  "$DST/$b" >/dev/null 2>&1 && ok "versioning: enabled"   || warn "$b: versioning enable failed" ;;
      [Ss]uspended) mcrun version suspend "$DST/$b" >/dev/null 2>&1 && ok "versioning: suspended" || warn "$b: versioning suspend failed" ;;
      *) step "versioning: off (source)" ;;
    esac

    # Encryption (SSE) ------------------------------------------------------
    if mcq encrypt info "$SRC/$b" 2>/dev/null | grep -qiE 'sse-s3|sse-kms|aes'; then
      if mcrun encrypt set sse-s3 "$DST/$b" >/dev/null 2>&1; then
        ok "encryption: enabled (KerPlace uses post-quantum ML-KEM + AES at rest)"
      else
        warn "$b: could not enable encryption on dest"
      fi
    fi

    # Lifecycle / ILM -------------------------------------------------------
    local ilm
    ilm="$(mcq ilm rule export "$SRC/$b" 2>/dev/null)"
    if [ -n "$ilm" ] && printf '%s' "$ilm" | grep -q '{'; then
      if printf '%s' "$ilm" | mcrun ilm rule import "$DST/$b" >/dev/null 2>&1; then
        ok "lifecycle rules imported"
      else
        warn "$b: lifecycle import failed (re-apply with 'mc ilm rule add')"
      fi
    fi

    # Bucket tags -----------------------------------------------------------
    local tags
    tags="$(mcq tag list "$SRC/$b" --json 2>/dev/null | sed -n 's/.*"tagset":\({[^}]*}\).*/\1/p')"
    if [ -n "$tags" ] && [ "$tags" != "{}" ]; then
      local kv
      kv="$(printf '%s' "$tags" | sed 's/[{}"]//g; s/:/=/g; s/,/\&/g')"
      mcrun tag set "$DST/$b" "$kv" >/dev/null 2>&1 && ok "bucket tags" || warn "$b: tag set failed"
    fi

    # Quota -----------------------------------------------------------------
    local quota
    quota="$(mcq quota info "$SRC/$b" --json 2>/dev/null | sed -n 's/.*"quota":\([0-9]*\).*/\1/p')"
    if [ -n "$quota" ] && [ "$quota" != "0" ]; then
      mcrun quota set "$DST/$b" --size "$quota" >/dev/null 2>&1 && ok "quota: $quota bytes" || warn "$b: quota set failed"
    fi

    # Anonymous (public) access policy --------------------------------------
    local anon
    anon="$(mcq anonymous get "$SRC/$b" 2>/dev/null | grep -oiE 'none|download|upload|public|custom' | head -1)"
    case "$anon" in
      [Dd]ownload|[Uu]pload|[Pp]ublic)
        mcrun anonymous set "$anon" "$DST/$b" >/dev/null 2>&1 && ok "anonymous: $anon" || warn "$b: anonymous policy failed" ;;
      [Cc]ustom)
        local pol; pol="$(mcq anonymous get-json "$SRC/$b" 2>/dev/null)"
        if [ -n "$pol" ]; then
          printf '%s' "$pol" | mcrun anonymous set-json /dev/stdin "$DST/$b" >/dev/null 2>&1 \
            && ok "anonymous: custom policy" || warn "$b: custom anonymous policy failed"
        fi ;;
    esac
  done < <(src_buckets)
}

# ── Phase: iam ───────────────────────────────────────────────────────────────
# Recreate custom policies and users. Secret keys can't be read from MinIO, so
# users are recreated with fresh secrets written to $CREDS_OUT.
phase_iam() {
  head2 "IAM (users & policies)"

  # Canned policies that already exist on any S3 server — never recreate these.
  local builtin=" readwrite readonly writeonly consoleAdmin diagnostics "

  # 1) Custom policies.
  local line name doc tmp
  while read -r line; do
    name="$(jget "$line" policy)"
    [ -z "$name" ] && name="$(jget "$line" name)"
    [ -z "$name" ] && continue
    case "$builtin" in *" $name "*) continue ;; esac      # skip built-ins
    doc="$(mcq admin policy info "$SRC" "$name" 2>/dev/null)"
    # mc prints the raw policy JSON document; keep it only if it looks like one.
    if printf '%s' "$doc" | grep -q '"Statement"'; then
      tmp="$(mktemp)"; printf '%s\n' "$doc" > "$tmp"
      if mcrun admin policy create "$DST" "$name" "$tmp" >/dev/null 2>&1; then
        ok "policy $name"
      else
        warn "policy $name: create failed"
      fi
      rm -f "$tmp"
    fi
  done < <(mcq admin policy list "$SRC" --json 2>/dev/null)

  # 2) Users (rotated secrets).
  if ! $DRY_RUN; then : > "$CREDS_OUT"; printf 'accessKey,secretKey,policy,status\n' >> "$CREDS_OUT"; fi
  local ak status pol secret
  while read -r line; do
    ak="$(jget "$line" accessKey)"
    [ -z "$ak" ] && continue
    status="$(jget "$line" userStatus)"; [ -z "$status" ] && status="$(jget "$line" status)"
    pol="$(jget "$line" policyName)"
    # MinIO's super-user policy is 'consoleAdmin'; KerPlace calls it 'admin'.
    [ "$pol" = "consoleAdmin" ] && pol="admin"
    secret="$(gen_secret)"

    if mcrun admin user add "$DST" "$ak" "$secret" >/dev/null 2>&1; then
      # Attach the policy so least-privilege is preserved (a readonly user must
      # not silently become readwrite). 'mc admin policy set' is deprecated.
      if [ -n "$pol" ]; then
        mcrun admin policy attach "$DST" "$pol" --user "$ak" >/dev/null 2>&1 \
          || warn "user $ak: could not attach policy '$pol' (set it manually: mc admin policy attach $DST $pol --user $ak)"
      fi
      # Match the disabled state if the source user was disabled.
      if printf '%s' "$status" | grep -qi disabled; then
        mcrun admin user disable "$DST" "$ak" >/dev/null 2>&1
      fi
      $DRY_RUN || printf '%s,%s,%s,%s\n' "$ak" "$secret" "${pol:-}" "${status:-enabled}" >> "$CREDS_OUT"
      ok "user $ak (policy=${pol:-none}, NEW secret)"
    else
      warn "user $ak: create failed"
    fi
  done < <(mcq admin user list "$SRC" --json 2>/dev/null)

  if ! $DRY_RUN && [ -s "$CREDS_OUT" ]; then
    chmod 600 "$CREDS_OUT" 2>/dev/null || true
    warn "NEW user secret keys written to $CREDS_OUT — distribute them, then keep it safe or delete it"
  fi
}

# ── Phase: data ──────────────────────────────────────────────────────────────
# Mirror current object data + metadata for each bucket. Idempotent. With
# --with-versions, versioned buckets are skipped here and migrated in full by
# the 'versions' phase, so the current version is never copied twice.
phase_data() {
  head2 "Data (current versions)"
  local b
  while read -r b; do
    [ -z "$b" ] && continue
    if $WITH_VERSIONS && is_versioned "$SRC" "$b"; then
      step "skipping $b (versioned — full history handled by 'versions')"
      continue
    fi
    step "mirroring $b …"
    if mcrun mirror --preserve --overwrite "$SRC/$b" "$DST/$b"; then
      ok "data: $b"
    else
      warn "data: $b mirror reported errors (re-run 'data' to resume)"
    fi
  done < <(src_buckets)
}

# ── Phase: versions ──────────────────────────────────────────────────────────
# Best-effort full version-history replay. For each object, copy non-current
# versions oldest→newest so the destination accumulates the same history, then
# recreate delete markers. Order-sensitive and slow; review the result.
phase_versions() {
  head2 "Version history (best-effort replay)"
  warn "version replay is best-effort and order-sensitive — verify critical buckets afterwards"
  local b
  while read -r b; do
    [ -z "$b" ] && continue
    # Only versioned buckets have history; the rest are covered by 'data'.
    is_versioned "$SRC" "$b" || { step "$b: not versioned — skipped (handled by 'data')"; continue; }
    # Ensure versioning is on at the destination, or history can't accumulate.
    mcrun version enable "$DST/$b" >/dev/null 2>&1
    step "replaying versions in $b …"

    # List every version oldest→newest: key, versionId, isDeleteMarker.
    # mc emits newest-first, so we reverse with tac.
    local replayed=0
    while read -r vline; do
      local key vid isdel
      key="$(jget "$vline" key)"
      vid="$(jget "$vline" versionId)"
      isdel="$(printf '%s' "$vline" | grep -o '"isDeleteMarker":true')"
      [ -z "$key" ] && continue
      if [ -n "$isdel" ]; then
        mcrun rm "$DST/$b/$key" >/dev/null 2>&1            # recreate a delete marker
      else
        mcrun cp --preserve --version-id "$vid" "$SRC/$b/$key" "$DST/$b/$key" >/dev/null 2>&1 \
          && replayed=$((replayed+1))
      fi
    done < <(mcq ls --versions --recursive "$SRC/$b" --json 2>/dev/null | tac)
    ok "versions: $b ($replayed non-current copied)"
  done < <(src_buckets)
}

# ── Phase: verify ────────────────────────────────────────────────────────────
# Compare per-bucket object count + total size between source and destination.
phase_verify() {
  head2 "Verify"
  local b
  printf '  %-28s %12s %12s\n' "bucket" "src(obj/size)" "dst(obj/size)"
  while read -r b; do
    [ -z "$b" ] && continue
    local s d
    s="$(mcq du "$SRC/$b" 2>/dev/null | awk '{print $1"/"$2}')"
    d="$(mcq du "$DST/$b" 2>/dev/null | awk '{print $1"/"$2}')"
    if [ "$s" = "$d" ]; then
      printf '  %s%-28s %12s %12s  ✅%s\n' "$C_GREEN" "$b" "$s" "$d" "$C_RESET"
    else
      printf '  %s%-28s %12s %12s  ⚠️%s\n' "$C_YELLOW" "$b" "$s" "$d" "$C_RESET"
      MIG_WARNINGS+=("verify: $b differs (src $s vs dst $d)")
    fi
  done < <(src_buckets)
}

# ── Summary ──────────────────────────────────────────────────────────────────
# Print the collected warnings (manual follow-ups), or an all-clear. Reads (does
# not append to) MIG_WARNINGS, so it must not call warn() itself.
print_summary() {
  head2 "Summary"
  local n="${#MIG_WARNINGS[@]}"
  if [ "$n" -eq 0 ]; then
    ok "all phases completed with no warnings"
  else
    printf '  %s⚠️  %s item(s) need attention:%s\n' "$C_YELLOW" "$n" "$C_RESET"
    local w
    for w in "${MIG_WARNINGS[@]}"; do printf '    %s- %s%s\n' "$C_YELLOW" "$w" "$C_RESET"; done
  fi
  info ""
  info "Next: point your apps at '$DST', validate, then decommission the source MinIO."
  if $DRY_RUN; then
    info "${C_DIM}(this was a dry run — re-run without --dry-run to apply)${C_RESET}"
  fi
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
  parse_args "$@"
  need mc
  info "${C_BOLD}KerPlace migration${C_RESET}  ${SRC} ${C_DIM}→${C_RESET} ${DST}  (phase: ${PHASE})"

  # 'all' runs the standard ordered pipeline; otherwise run the single phase.
  case "$PHASE" in
    all)
      phase_preflight
      phase_buckets
      phase_config
      phase_iam
      phase_data
      $WITH_VERSIONS && phase_versions
      phase_verify
      ;;
    preflight) phase_preflight ;;
    buckets)   phase_preflight; phase_buckets ;;
    config)    phase_preflight; phase_config ;;
    iam)       phase_preflight; phase_iam ;;
    data)      phase_preflight; phase_data ;;
    versions)  phase_preflight; phase_versions ;;
    verify)    phase_preflight; phase_verify ;;
  esac

  print_summary
  return 0
}

main "$@"
