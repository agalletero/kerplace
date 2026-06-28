#!/usr/bin/env bash
#
# cluster-node.sh — launch a KerPlace cluster node over a Tailscale (or WireGuard)
# overlay, and generate the systemd units to make it boot-persistent.
#
# It wires the right KP_* environment for each role and, for a drive node,
# binds the internal RPC to this machine's tailnet address so it is never
# exposed on a public interface. See docs/PRODUCTION_TAILSCALE.md.
#
# Usage:
#   ./cluster-node.sh drive             # run this node as a drive (shard) node
#   ./cluster-node.sh gateway           # run this node as the S3 gateway
#   ./cluster-node.sh tailnet-ip        # print this node's tailnet IPv4
#   ./cluster-node.sh systemd-drive     # print a systemd unit for a drive node
#   ./cluster-node.sh systemd-gateway   # print a systemd unit for the gateway
#   ./cluster-node.sh status            # tailnet + listener status
#   ./cluster-node.sh -h | --help
#
# Configuration (environment variables, with defaults):
#   KP_BIN              path to the kerplace binary       (auto-detected)
#   KP_DATA_DIR         shard/data directory           (/var/lib/kerplace)
#   KP_CLUSTER_SECRET   shared drive-RPC bearer secret (required: drive/gateway)
#   KP_DRIVE_PORT       drive RPC port                 (9100)
#   KP_ADDRESS          gateway S3 listen address      (0.0.0.0:9000)
#   KP_CONSOLE_ADDRESS  gateway console listen address (0.0.0.0:9001)
#   KP_NODES            gateway shard map              (required: gateway)
#                          e.g. "0=local,1=kerplace-n1:9100,2=kerplace-n2:9100"
#   KP_NODE_INDEX       shard slot hosted locally      (0)
#   KP_ERASURE_PARITY   parity M                       (2)
#   KP_CLUSTER_LOCKS    quorum locks (multi-gateway)   (unset)
#
set -uo pipefail

# ── Pretty output ────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'
  C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_CYAN=$'\033[36m'
else
  C_RESET=""; C_BOLD=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_CYAN=""
fi
ok()   { printf '  %s✅ %s%s\n' "$C_GREEN" "$*" "$C_RESET"; }
warn() { printf '  %s⚠️  %s%s\n' "$C_YELLOW" "$*" "$C_RESET"; }
die()  { printf '  %s❌ %s%s\n' "$C_RED" "$*" "$C_RESET"; exit 1; }

# ── Configuration with defaults ──────────────────────────────────────────────
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
KP_DATA_DIR="${KP_DATA_DIR:-/var/lib/kerplace}"
KP_DRIVE_PORT="${KP_DRIVE_PORT:-9100}"
KP_ADDRESS="${KP_ADDRESS:-0.0.0.0:9000}"
KP_CONSOLE_ADDRESS="${KP_CONSOLE_ADDRESS:-0.0.0.0:9001}"
KP_NODE_INDEX="${KP_NODE_INDEX:-0}"
KP_ERASURE_PARITY="${KP_ERASURE_PARITY:-2}"

# Locate the kerplace binary if not given explicitly.
find_bin() {
  if [ -n "${KP_BIN:-}" ]; then printf '%s' "$KP_BIN"; return; fi
  for c in ./kerplace ./target/release/kerplace ./dist/kerplace "$(command -v kerplace 2>/dev/null)"; do
    [ -n "$c" ] && [ -x "$c" ] && { printf '%s' "$c"; return; }
  done
  die "kerplace binary not found (set KP_BIN=/path/to/kerplace)"
}

# Print this node's tailnet IPv4, or empty if Tailscale isn't up.
tailnet_ip() {
  command -v tailscale >/dev/null 2>&1 || return 0
  tailscale ip -4 2>/dev/null | head -1
}

# Require a non-empty environment variable, or die.
require() {
  local name="$1"
  [ -n "${!name:-}" ] || die "$name is required for this role (see --help)"
}

# Print the leading comment of this file as usage.
usage() { sed -n '3,/^set -uo pipefail/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }

# ── Roles ────────────────────────────────────────────────────────────────────
# Launch this node as a drive (shard) node, binding the RPC to the tailnet.
run_drive() {
  require KP_CLUSTER_SECRET
  local bin ip addr
  bin="$(find_bin)"
  ip="$(tailnet_ip)"
  if [ -n "$ip" ]; then
    addr="${ip}:${KP_DRIVE_PORT}"
    ok "binding drive RPC to tailnet $addr"
  else
    addr="0.0.0.0:${KP_DRIVE_PORT}"
    warn "Tailscale not detected — binding $addr (ensure a firewall restricts it!)"
  fi
  mkdir -p "$KP_DATA_DIR" 2>/dev/null || true
  exec env \
    KP_ROLE=drive \
    KP_DRIVE_ADDR="$addr" \
    KP_DATA_DIR="$KP_DATA_DIR" \
    KP_CLUSTER_SECRET="$KP_CLUSTER_SECRET" \
    "$bin"
}

# Launch this node as the S3 gateway, sharding across KP_NODES.
run_gateway() {
  require KP_CLUSTER_SECRET
  require KP_NODES
  local bin
  bin="$(find_bin)"
  mkdir -p "$KP_DATA_DIR" 2>/dev/null || true
  ok "gateway S3 $KP_ADDRESS · nodes $KP_NODES · parity $KP_ERASURE_PARITY"
  exec env \
    KP_ADDRESS="$KP_ADDRESS" \
    KP_CONSOLE_ADDRESS="$KP_CONSOLE_ADDRESS" \
    KP_DATA_DIR="$KP_DATA_DIR" \
    KP_NODES="$KP_NODES" \
    KP_NODE_INDEX="$KP_NODE_INDEX" \
    KP_ERASURE_PARITY="$KP_ERASURE_PARITY" \
    ${KP_CLUSTER_LOCKS:+KP_CLUSTER_LOCKS="$KP_CLUSTER_LOCKS"} \
    KP_CLUSTER_SECRET="$KP_CLUSTER_SECRET" \
    "$bin"
}

# Emit a systemd unit for the given role (drive|gateway). Secrets/config live in
# /etc/kerplace.env (mode 600), so they stay out of the unit file.
emit_systemd() {
  local role="$1" desc
  [ "$role" = "drive" ] && desc="KerPlace drive node" || desc="KerPlace S3 gateway"
  cat <<UNIT
[Unit]
Description=$desc
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=simple
# Put KP_CLUSTER_SECRET, KP_NODES, KP_DATA_DIR, … here (chmod 600):
EnvironmentFile=/etc/kerplace.env
ExecStart=$SELF $role
Restart=on-failure
RestartSec=3
# Run as an unprivileged user that owns KP_DATA_DIR:
User=kerplace
Group=kerplace

[Install]
WantedBy=multi-user.target
UNIT
}

# Show tailnet membership and whether this node's port is listening.
show_status() {
  printf '%s%s== Tailscale ==%s\n' "$C_BOLD" "$C_CYAN" "$C_RESET"
  if command -v tailscale >/dev/null 2>&1; then
    tailscale status 2>/dev/null | head -8
    local ip; ip="$(tailnet_ip)"
    [ -n "$ip" ] && ok "this node: $ip" || warn "Tailscale installed but not up (tailscale up)"
  else
    warn "tailscale not installed"
  fi
  printf '%s%s== Listeners ==%s\n' "$C_BOLD" "$C_CYAN" "$C_RESET"
  if command -v ss >/dev/null 2>&1; then
    ss -ltnp 2>/dev/null | grep -E ":(9000|9001|${KP_DRIVE_PORT})\b" || warn "no KerPlace port listening"
  else
    warn "ss not available"
  fi
}

# ── Dispatch ─────────────────────────────────────────────────────────────────
case "${1:-}" in
  drive)            run_drive ;;
  gateway)          run_gateway ;;
  tailnet-ip)       tailnet_ip ;;
  systemd-drive)    emit_systemd drive ;;
  systemd-gateway)  emit_systemd gateway ;;
  status)           show_status ;;
  -h|--help|"")     usage ;;
  *)                die "unknown command: $1 (try --help)" ;;
esac
