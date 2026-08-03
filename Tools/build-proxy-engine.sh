#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
# Build the proxy-tunnel engine — a tun2socks-style userspace TCP/IP stack
# (gVisor netstack) that terminates every flow on the utun and re-dials it
# through an upstream SOCKS5 / HTTP(S) CONNECT proxy — for SimpleVPN's Proxy
# Tunnel VPN kind. The engine runs IN-PROCESS inside the packet-tunnel system
# extension.
#
# TWO ROLES, ONE SOURCE:
#   1. STANDALONE VERIFICATION (what this script does): compile the pxengine
#      package as its own static C archive (Vendor/proxy-engine/libpxengine.a),
#      after running gofmt -l, go vet and the full loopback handshake test suite,
#      then cross-check the exported symbols against the hand-written stable
#      header include/pxengine.h. This proves the engine is self-contained and
#      on-spec, exactly like Tools/build-tailscale-engine.sh does for Tailscale.
#   2. SHIPPING: two Go c-archives CANNOT be linked into one binary — the Go
#      runtime symbols (_crosscall2, __cgo_topofstack, …) collide. PacketTunnel
#      already links the Tailscale Go archive, so the pxengine package is folded
#      INTO that archive: Vendor/tailscale-engine/src/main.go blank-imports
#      "pxengine" (via a replace directive in its go.mod), so both engines'
#      //export symbols land in the ONE libtsengine.a that PacketTunnel links.
#      Run Tools/build-tailscale-engine.sh to produce the shipping archive; the
#      pxengine symbol cross-check lives there too.
#
# -trimpath keeps the archive reproducible; symbols are NOT stripped, matching
# the project's STRIP_INSTALLED_PRODUCT=NO crash-report policy.
set -euo pipefail

# Pin exactly, never float — must match go.mod (and the Tailscale engine's pin,
# since both fold into one archive; gVisor is the shared dependency).
GVISOR_MODULE="gvisor.dev/gvisor"
GVISOR_VERSION="v0.0.0-20260224225140-573d5e7127a8"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$REPO/Vendor/proxy-engine/src"
OUT="$REPO/Vendor/proxy-engine"
INCLUDE="$OUT/include"

command -v go >/dev/null || { echo "error: Go toolchain not found" >&2; exit 1; }

cd "$SRC"

# go.mod is the source of truth for the pin; fail loudly if it drifts.
go mod download
pinned="$(go list -m "$GVISOR_MODULE" | awk '{print $2}')"
if [ "$pinned" != "$GVISOR_VERSION" ]; then
  echo "error: go.mod pins $GVISOR_MODULE $pinned but this script expects $GVISOR_VERSION" >&2
  exit 1
fi
go mod verify

# Style + correctness gates. gofmt is checked, not applied: a build script that
# rewrites tracked source under you is a nasty surprise in CI.
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
  echo "error: not gofmt-clean:" >&2
  echo "$unformatted" >&2
  exit 1
fi
go vet ./...
# The loopback handshake suite (SOCKS5 / CONNECT / DNS-over-TCP / SOCKS-UDP
# framing) — no network, no real proxy. A wire-format regression fails HERE.
go test ./...

# c-archive: Go runtime + gVisor netstack + the proxy dialers + the shim in one
# .a, built from the thin carchive/ main that blank-imports pxengine. No cgo
# header is emitted here: carchive/main.go does not itself `import "C"` (the
# //export functions live in the pxengine package it imports), and cgo only
# generates a header for the package that directly uses cgo. Swift includes the
# hand-written stable include/pxengine.h regardless; the symbol cross-check
# below is what guarantees they agree.
mkdir -p "$INCLUDE"
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
  go build -trimpath -buildmode=c-archive -o "$OUT/libpxengine.a" ./carchive

# The stable header must declare exactly what the archive exports.
for sym in _PXSetCallbacks _PXStart _PXStop _PXStatus _PXPacketIn _PXFree; do
  nm -gU "$OUT/libpxengine.a" 2>/dev/null | grep -q " T $sym\$" \
    || { echo "error: $sym missing from libpxengine.a" >&2; exit 1; }
  grep -q "${sym#_}" "$INCLUDE/pxengine.h" \
    || { echo "error: ${sym#_} not declared in include/pxengine.h" >&2; exit 1; }
done

echo "gVisor netstack: $GVISOR_VERSION"
echo "archive: $OUT/libpxengine.a ($(du -h "$OUT/libpxengine.a" | cut -f1 | tr -d ' '))"
echo "note: the SHIPPING archive is libtsengine.a — run Tools/build-tailscale-engine.sh"
shasum -a 256 "$OUT/libpxengine.a"
