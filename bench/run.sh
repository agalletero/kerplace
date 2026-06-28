#!/usr/bin/env bash
#
# Phase-0 end-to-end S3 benchmark harness (docs/PERFORMANCE.md §2).
#
# Boots a LOCAL mono-node KerPlace with a frozen config, runs a `warp` workload,
# and drops the results (warp output + server log + a CPU snapshot) into a
# timestamped dir under bench/results/. Mono-node on purpose: it separates the
# implementation ceiling from the distributed gateway-funnel.
#
# Usage (all overridable via env):
#   ./bench/run.sh                                  # mixed, 1MiB, c8, encrypt on, erasure
#   OP=get OBJSIZE=4KiB CONCURRENT=16 ./bench/run.sh
#   KP_ENCRYPT=false ./bench/run.sh                 # isolate the crypto cost (Phase 0f)
#   KP_BACKEND=fs ./bench/run.sh                    # isolate the erasure cost
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WARP="${WARP:-$HOME/go/bin/warp}"
BIN="${BIN:-$ROOT/target/release/kerplace}"

HOST="${HOST:-127.0.0.1:9000}"
AK="${AK:-benchadmin}"
SK="${SK:-benchadminsecret123}"
ENCRYPT="${KP_ENCRYPT:-true}"
BACKEND="${KP_BACKEND:-erasure}"
PROVIDER="${KP_KEY_PROVIDER:-file}"
OP="${OP:-mixed}"            # get | put | mixed | stat | list
OBJSIZE="${OBJSIZE:-1MiB}"
DURATION="${DURATION:-20s}"
CONCURRENT="${CONCURRENT:-8}"

[ -x "$BIN" ]  || { echo "✗ build first: cargo build --release  (missing $BIN)"; exit 1; }
[ -x "$WARP" ] || { echo "✗ warp not found at $WARP (go install github.com/minio/warp@latest)"; exit 1; }

STAMP="$(date +%Y%m%d-%H%M%S)"
TAG="${OP}-${OBJSIZE}-c${CONCURRENT}-enc${ENCRYPT}-${BACKEND}"
OUT="$ROOT/bench/results/${STAMP}-${TAG}"
# IMPORTANT: the object store MUST live on a real disk, NOT tmpfs. `mktemp -d`
# defaults to /tmp, which on this box is tmpfs (RAM): under concurrency, many fast
# writers then contend on tmpfs page-allocation locks, which has *inverted* A/B
# results before (a faster code path looked ~30% slower purely from that contention,
# while single-stream and real-disk runs showed it +15-25% faster). Default the data
# dir to a repo-local, gitignored, disk-backed path; override with KP_BENCH_DATA_ROOT.
DATA_ROOT="${KP_BENCH_DATA_ROOT:-$ROOT/bench/.benchdata}"
mkdir -p "$DATA_ROOT"
DATA="$(mktemp -d "$DATA_ROOT/run-XXXXXX")"
mkdir -p "$OUT"
FSTYPE="$(stat -f -c %T "$DATA" 2>/dev/null || echo '?')"
[ "$FSTYPE" = "tmpfs" ] && echo "⚠ WARNING: bench data is on tmpfs ($DATA) — concurrency numbers will be skewed; set KP_BENCH_DATA_ROOT to a real disk"

echo "▶ config : op=$OP size=$OBJSIZE concurrent=$CONCURRENT encrypt=$ENCRYPT backend=$BACKEND provider=$PROVIDER"
echo "▶ data   : $DATA  (fs: $FSTYPE)"
echo "▶ results: $OUT"

# Ensure the port is free first — avoid hitting a stale server from a prior run.
PORT="${HOST##*:}"
for _ in $(seq 1 30); do ss -tln 2>/dev/null | grep -q ":$PORT " || break; sleep 0.5; done
ss -tln 2>/dev/null | grep -q ":$PORT " && { echo "✗ port $PORT still in use — aborting"; exit 1; }

# --- boot KerPlace (mono-node, no console) ---
KP_DATA_DIR="$DATA" KP_ADDRESS="$HOST" KP_CONSOLE=false KP_AUTH=true \
  KP_ROOT_USER="$AK" KP_ROOT_PASSWORD="$SK" \
  KP_ENCRYPT="$ENCRYPT" KP_BACKEND="$BACKEND" KP_KEY_PROVIDER="$PROVIDER" \
  KP_DEBUG=warn "$BIN" > "$OUT/server.log" 2>&1 &
SRV=$!
cleanup() { kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; rm -rf "$DATA" 2>/dev/null; }
trap cleanup EXIT

echo "▶ waiting for KerPlace..."
ready=0
for _ in $(seq 1 40); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://$HOST/minio/health/live" 2>/dev/null)
  [ "$code" = "200" ] && { ready=1; break; }
  kill -0 "$SRV" 2>/dev/null || { echo "✗ server died — see $OUT/server.log"; tail -5 "$OUT/server.log"; exit 1; }
  sleep 0.5
done
[ "$ready" = 1 ] || { echo "✗ health never returned 200"; tail -8 "$OUT/server.log"; exit 1; }
echo "✓ up"

# --- CPU snapshot during the run (best effort) ---
( command -v mpstat >/dev/null && mpstat 2 999 > "$OUT/mpstat.txt" 2>/dev/null ) &
MON=$!

# --- warp ---
echo "▶ warp $OP ..."
"$WARP" "$OP" \
  --host "$HOST" --access-key "$AK" --secret-key "$SK" \
  --bucket warp-bench --obj.size "$OBJSIZE" \
  --duration "$DURATION" --concurrent "$CONCURRENT" \
  --no-color --benchdata "$OUT/warp" 2>&1 | tee "$OUT/warp.txt"

kill "$MON" 2>/dev/null

# --- context + summary ---
{
  echo "commit:   $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null)"
  echo "cpu:      $(grep -m1 'Model name' <(lscpu) | sed 's/Model name: *//')  ($(nproc) threads)"
  echo "config:   op=$OP size=$OBJSIZE concurrent=$CONCURRENT encrypt=$ENCRYPT backend=$BACKEND provider=$PROVIDER"
  echo "date:     $STAMP"
} > "$OUT/context.txt"

echo
echo "✓ done → $OUT"
grep -iE 'Throughput|Requests|obj/s|MiB/s|GiB/s|50th|90th|99th|Average' "$OUT/warp.txt" | head -30 || true
