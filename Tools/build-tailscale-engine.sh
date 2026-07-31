#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
# Build the open-source Tailscale client stack (tailscale.com, BSD-3-Clause) as
# a static C archive for the packet-tunnel system extension — SimpleVPN's
# Tailscale / Headscale VPN kind runs IN-PROCESS, not by driving the tailscaled
# daemon. Compiles the cgo shim in Vendor/tailscale-engine/src
# (-buildmode=c-archive, darwin/arm64) and installs
# Vendor/tailscale-engine/libtsengine.a. The Swift-facing header is the
# hand-written, stable Vendor/tailscale-engine/include/tsengine.h — the
# cgo-generated header is kept alongside it as libtsengine.h for reference and
# the exported symbols are cross-checked against it here. -trimpath keeps the
# archive reproducible (no $HOME/go paths baked in); symbols are NOT stripped,
# matching the project's STRIP_INSTALLED_PRODUCT=NO crash-report policy.
#
# Same shape as Tools/build-onepassword-sdk.sh (the other Go c-archive), with
# one addition: the Go contract tests run before the archive is produced, so a
# rename on either side of the JSON boundary fails HERE rather than as a tunnel
# that connects and carries nothing.
set -euo pipefail

# Pin exactly, never float — bump deliberately (must match go.mod). Even minor
# versions are Tailscale's stable releases; .1 is the settled patch for 1.102.
TS_MODULE="tailscale.com"
TS_VERSION="v1.102.1"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$REPO/Vendor/tailscale-engine/src"
OUT="$REPO/Vendor/tailscale-engine"
INCLUDE="$OUT/include"

command -v go >/dev/null || { echo "error: Go toolchain not found" >&2; exit 1; }

cd "$SRC"

# go.mod is the source of truth for the pin; fail loudly if it drifts from the
# version this script declares (both must be bumped together).
go mod download
pinned="$(go list -m "$TS_MODULE" | awk '{print $2}')"
if [ "$pinned" != "$TS_VERSION" ]; then
  echo "error: go.mod pins $TS_MODULE $pinned but this script expects $TS_VERSION" >&2
  exit 1
fi
go mod verify

# Style + correctness gates. gofmt is checked rather than applied: a build
# script that rewrites tracked source under you is a nasty surprise in CI.
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
  echo "error: not gofmt-clean:" >&2
  echo "$unformatted" >&2
  exit 1
fi
go vet ./...
go test ./...

# c-archive: Go runtime + Tailscale stack + shim in one .a. The generated
# header lands next to the archive; rename it to libtsengine.h (reference only
# — Swift includes the stable include/tsengine.h instead).
mkdir -p "$INCLUDE"
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
  go build -trimpath -buildmode=c-archive -o "$OUT/libtsengine.a" .
mv "$OUT/libtsengine.h" "$INCLUDE/libtsengine.h"

# The stable header must declare exactly what the archive exports.
for sym in _TSSetCallbacks _TSStart _TSStop _TSStatus _TSUpdatePrefs _TSPacketIn _TSFree; do
  nm -gU "$OUT/libtsengine.a" 2>/dev/null | grep -q " T $sym\$" \
    || { echo "error: $sym missing from libtsengine.a" >&2; exit 1; }
  grep -q "${sym#_}" "$INCLUDE/tsengine.h" \
    || { echo "error: ${sym#_} not declared in include/tsengine.h" >&2; exit 1; }
done

# Size note: this archive is large (~50 MB) because it carries the whole
# Tailscale stack plus gVisor's netstack. Dead-code stripping at link time cuts
# what actually lands in the extension binary to a fraction of it, but the
# number is worth watching — a jump means a new dependency got pulled in.
echo "tailscale.com: $TS_VERSION (BSD-3-Clause)"
echo "archive: $OUT/libtsengine.a ($(du -h "$OUT/libtsengine.a" | cut -f1 | tr -d ' '))"
shasum -a 256 "$OUT/libtsengine.a"
