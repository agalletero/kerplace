#!/usr/bin/env bash
#
# Build a fully-static (musl) release binary of KerPlace.
#
# A musl build links no glibc, so the resulting binary runs on ANY Linux of the
# same architecture — including old distributions whose glibc is too old for a
# normal build. Output goes to dist/ (ready to attach to a GitHub release).
#
# Requirements (one-time): the Rust musl target + a musl C toolchain, e.g.
#   rustup target add x86_64-unknown-linux-musl
#   sudo apt-get install -y musl-tools        # Debian/Ubuntu
#
# Usage:
#   ./build-static.sh                 # build for the host arch (x86_64)
#   TARGET=aarch64-unknown-linux-musl ./build-static.sh   # cross (needs toolchain)

set -euo pipefail
cd "$(dirname "$0")"

TARGET="${TARGET:-x86_64-unknown-linux-musl}"
VERSION="$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"
ARCH="${TARGET%%-*}"
OUT_NAME="kerplace-v${VERSION}-${ARCH}-linux-musl"

echo "▶ building static KerPlace v${VERSION} for ${TARGET}"
rustup target add "${TARGET}" >/dev/null 2>&1 || true
cargo build --release --target "${TARGET}"

BIN="target/${TARGET}/release/kerplace"
mkdir -p dist
cp "${BIN}" "dist/${OUT_NAME}"
strip "dist/${OUT_NAME}" 2>/dev/null || true
( cd dist && sha256sum "${OUT_NAME}" > "${OUT_NAME}.sha256" )

echo "✓ dist/${OUT_NAME}  ($(du -h "dist/${OUT_NAME}" | cut -f1))"
file "dist/${OUT_NAME}"
echo "  sha256: $(cut -d' ' -f1 "dist/${OUT_NAME}.sha256")"
echo "  → upload dist/${OUT_NAME}* to the GitHub release."
