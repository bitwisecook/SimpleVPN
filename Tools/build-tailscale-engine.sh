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
# `go mod verify` checks the downloaded deps against go.sum. The folded-in
# pxengine is a LOCAL directory replace (its source is tracked right here), so it
# has no module zip to hash — go reports a benign "missing ziphash" for it. Fail
# on any OTHER verification error, but never on that one expected line.
verify_out="$(go mod verify 2>&1 || true)"
if printf '%s\n' "$verify_out" | grep -v 'pxengine .*missing ziphash' | grep -qiE 'mismatch|not verified|SECURITY ERROR'; then
  echo "error: go mod verify reported a problem:" >&2
  printf '%s\n' "$verify_out" >&2
  exit 1
fi

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

# The proxy-tunnel engine (SimpleVPN's Proxy Tunnel VPN kind) is FOLDED into this
# archive: main.go blank-imports "pxengine" so its cgo //export symbols compile
# in here — two Go c-archives cannot be linked into one binary, and PacketTunnel
# already links this one. Run its own build/verify (gofmt, vet, the loopback
# handshake tests) so a proxy-engine regression fails HERE too, before the
# shipping archive is produced. It shares this build's gVisor pin.
PXSRC="$REPO/Vendor/proxy-engine/src"
if [ -d "$PXSRC" ]; then
  ( cd "$PXSRC"
    go mod verify
    px_unformatted="$(gofmt -l .)"
    if [ -n "$px_unformatted" ]; then
      echo "error: pxengine not gofmt-clean:" >&2; echo "$px_unformatted" >&2; exit 1
    fi
    go vet ./...
    go test ./... )
else
  echo "warning: $PXSRC not found — proxy engine will not be in this archive" >&2
fi

# c-archive: Go runtime + Tailscale stack + the proxy-tunnel engine + shim in one
# .a. The generated header lands next to the archive; rename it to libtsengine.h
# (reference only — Swift includes the stable include/tsengine.h + pxengine.h).
mkdir -p "$INCLUDE"
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
  go build -trimpath -buildmode=c-archive -o "$OUT/libtsengine.a" .
mv "$OUT/libtsengine.h" "$INCLUDE/libtsengine.h"

# The stable headers must declare exactly what the archive exports — BOTH engines
# now live in this one archive (Tailscale's own symbols and the folded-in proxy
# engine's), so both symbol sets are cross-checked against their stable headers.
for sym in _TSSetCallbacks _TSStart _TSStop _TSStatus _TSUpdatePrefs _TSPacketIn _TSFree; do
  nm -gU "$OUT/libtsengine.a" 2>/dev/null | grep -q " T $sym\$" \
    || { echo "error: $sym missing from libtsengine.a" >&2; exit 1; }
  grep -q "${sym#_}" "$INCLUDE/tsengine.h" \
    || { echo "error: ${sym#_} not declared in include/tsengine.h" >&2; exit 1; }
done
PXHEADER="$REPO/Vendor/proxy-engine/include/pxengine.h"
for sym in _PXSetCallbacks _PXStart _PXStop _PXStatus _PXPacketIn _PXFree; do
  nm -gU "$OUT/libtsengine.a" 2>/dev/null | grep -q " T $sym\$" \
    || { echo "error: folded-in $sym missing from libtsengine.a" >&2; exit 1; }
  grep -q "${sym#_}" "$PXHEADER" \
    || { echo "error: ${sym#_} not declared in $PXHEADER" >&2; exit 1; }
done
# Third family in the same archive: the plain-WireGuard engine (wireguard.go),
# declared by its own stable header next to tsengine.h.
for sym in _WGSetCallbacks _WGStart _WGStop _WGStatus _WGPacketIn _WGFree; do
  nm -gU "$OUT/libtsengine.a" 2>/dev/null | grep -q " T $sym\$" \
    || { echo "error: $sym missing from libtsengine.a" >&2; exit 1; }
  grep -q "${sym#_}" "$INCLUDE/wgengine.h" \
    || { echo "error: ${sym#_} not declared in include/wgengine.h" >&2; exit 1; }
done

# Size note: this archive is large (~50 MB) because it carries the whole
# Tailscale stack plus gVisor's netstack. Dead-code stripping at link time cuts
# what actually lands in the extension binary to a fraction of it, but the
# number is worth watching — a jump means a new dependency got pulled in.
# Notices for the TRANSITIVE Go dependencies — this archive's module graph is by
# far the largest body of third-party code SimpleVPN ships (the whole Tailscale
# stack, gVisor, wireguard-go and everything under them). About ▸ Open-Source
# Components names the ones a reader would recognise; this file enumerates the
# rest, whose MIT/BSD/Apache notices we convey too. SOFT-FAILS by design, like
# Tools/fetch-geoip.sh: a fresh clone must build without another tool first.
#   go install github.com/google/go-licenses@latest
NOTICES="$OUT/THIRD-PARTY-LICENSES.csv"
if command -v go-licenses >/dev/null 2>&1; then
  if go-licenses csv . > "$NOTICES" 2>/dev/null; then
    echo "notices: $NOTICES ($(wc -l < "$NOTICES" | tr -d ' ') modules)"
  else
    echo "note: go-licenses failed; $NOTICES may be missing or incomplete"
  fi
else
  echo "note: go-licenses not installed — skipping $NOTICES"
  echo "      (go install github.com/google/go-licenses@latest)"
fi

echo "tailscale.com: $TS_VERSION (BSD-3-Clause)"
echo "archive: $OUT/libtsengine.a ($(du -h "$OUT/libtsengine.a" | cut -f1 | tr -d ' '))"
shasum -a 256 "$OUT/libtsengine.a"
