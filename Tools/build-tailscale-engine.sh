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
# that connects and carries nothing. Those tests include a REAL WireGuard
# handshake — wireguard_handshake_test.go stands up two wireguard-go devices over
# loopback UDP and drives one of them with renderWGUAPI's own output — so a key
# encoding, allowed_ip or endpoint regression fails here too, with no live peer
# and no hardware.
set -euo pipefail

# Pin exactly, never float — bump deliberately (must match go.mod). Even minor
# versions are Tailscale's stable releases.
TS_MODULE="tailscale.com"
TS_VERSION="v1.104.7"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$REPO/Vendor/tailscale-engine/src"
OUT="$REPO/Vendor/tailscale-engine"
INCLUDE="$OUT/include"

source "$REPO/Tools/routing-native-env.sh"
cd "$SRC"
TS_WORKSPACE="$(python3 "$REPO/Tools/Tailscale/prepare-workspace.py" "$REPO/build/engine/tailscale-source")"

build_archive() {
  local directory="$1"
  mkdir -p "$directory"
  GOWORK="$TS_WORKSPACE" go build -tags routing_rust -trimpath -buildmode=c-archive -o "$directory/libtsengine.a" .
  # The Go c-archive leaves its Rust references for the final Darwin linker.
  local routing_refs symbol
  routing_refs="$(nm -guj "$directory/libtsengine.a" 2>/dev/null | awk '/^_(rc_eval|rc_rich_eval|svp_compact_match)$/')"
  for symbol in _rc_eval _rc_rich_eval _svp_compact_match; do
    if ! grep -Fxq "$symbol" <<< "$routing_refs"; then
      echo "error: packet router has no reference to $symbol" >&2
      return 1
    fi
  done
  if ! cmp -s "$ROUTING_RUST_ARCHIVE" "$directory/libsimplevpn_routing_core.a"; then
    cp "$ROUTING_RUST_ARCHIVE" "$directory/libsimplevpn_routing_core.a"
  fi
}

# Ordinary Xcode builds use the same archive recipe without running the release suite.
if [[ "${1:-}" == --archive-only && $# == 2 ]]; then
  build_archive "$2"
  exit 0
fi
if [[ $# != 0 ]]; then echo "usage: $0 [--archive-only OUTPUT_DIRECTORY]" >&2; exit 2; fi

cargo clippy --workspace --manifest-path "$REPO/Vendor/routing-core/Cargo.toml" --target-dir "$ROUTING_CARGO_DIR" \
  --target aarch64-apple-darwin --all-targets --all-features --locked --offline --release -- -D warnings

cargo test --workspace --manifest-path "$REPO/Vendor/routing-core/Cargo.toml" --target-dir "$ROUTING_CARGO_DIR" \
  --target aarch64-apple-darwin --locked --offline --release

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
if ! verify_out="$(go mod verify 2>&1)"; then
  unexpected="$(printf '%s\n' "$verify_out" | grep -v '^pxengine v0.0.0: missing ziphash:' || true)"
  if [ -n "$unexpected" ] || [ -z "$verify_out" ]; then
    echo "error: go mod verify failed:" >&2
    printf '%s\n' "$verify_out" >&2
    exit 1
  fi
fi

# Style + correctness gates. gofmt is checked rather than applied: a build
# script that rewrites tracked source under you is a nasty surprise in CI.
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
  echo "error: not gofmt-clean:" >&2
  echo "$unformatted" >&2
  exit 1
fi
GOWORK="$TS_WORKSPACE" go vet -tags routing_rust ./...
GOWORK="$TS_WORKSPACE" go test -tags routing_rust,tailscale_scoped -ldflags "$ROUTING_GO_LDFLAGS" ./...

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
    go test ./...
    go vet -tags routing_rust,pxcgotest ./...
    go test -tags routing_rust,pxcgotest -ldflags "$ROUTING_GO_LDFLAGS" ./... )
else
  echo "error: required proxy engine missing at $PXSRC" >&2
  exit 1
fi

# c-archive: Go runtime + Tailscale stack + the proxy-tunnel engine + shim in one
# .a. The generated header lands next to the archive; rename it to libtsengine.h
# (reference only — Swift includes the stable include/tsengine.h + pxengine.h).
mkdir -p "$INCLUDE"
build_archive "$OUT"
mv "$OUT/libtsengine.h" "$INCLUDE/libtsengine.h"

# The stable headers must declare exactly what the archive exports — BOTH engines
# now live in this one archive (Tailscale's own symbols and the folded-in proxy
# engine's), so both symbol sets are cross-checked against their stable headers.
# Read nm completely before matching: grep -q in a pipe can make nm fail
# with SIGPIPE under pipefail even when the required symbol exists.
symbols="$(nm -gU "$OUT/libtsengine.a" 2>/dev/null)"
for sym in _TSSetCallbacks _TSStart _TSStop _TSStatus _TSUpdatePrefs _TSPacketIn _TSFree _TSCreateInstance _TSStopInstance _TSStatusInstance _TSReauthenticateInstance _TSUpdatePrefsInstance _TSPacketInInstance _TSNodeState _TSNodeStateSince _TSAckNodeState; do
  grep -q " T $sym\$" <<< "$symbols" \
    || { echo "error: $sym missing from libtsengine.a" >&2; exit 1; }
  grep -q "${sym#_}" "$INCLUDE/tsengine.h" \
    || { echo "error: ${sym#_} not declared in include/tsengine.h" >&2; exit 1; }
done
PXHEADER="$REPO/Vendor/proxy-engine/include/pxengine.h"
for sym in _PXSetCallbacks _PXSetFlowDialCallback _PXStart _PXStop _PXStatus _PXPacketIn _PXFree _PXCreateInstance _PXStopInstance _PXStatusInstance _PXPacketInInstance; do
  grep -q " T $sym\$" <<< "$symbols" \
    || { echo "error: folded-in $sym missing from libtsengine.a" >&2; exit 1; }
  grep -q "${sym#_}" "$PXHEADER" \
    || { echo "error: ${sym#_} not declared in $PXHEADER" >&2; exit 1; }
done
# Third family in the same archive: the plain-WireGuard engine (wireguard.go),
# declared by its own stable header next to tsengine.h.
for sym in _WGSetCallbacks _WGStart _WGStop _WGStatus _WGPacketIn _WGFree _WGCreateInstance _WGStopInstance _WGStatusInstance _WGPacketInInstance; do
  grep -q " T $sym\$" <<< "$symbols" \
    || { echo "error: $sym missing from libtsengine.a" >&2; exit 1; }
  grep -q "${sym#_}" "$INCLUDE/wgengine.h" \
    || { echo "error: ${sym#_} not declared in include/wgengine.h" >&2; exit 1; }
done

for sym in _VRCreateInstance _VRSetUnderlayInterface _VRPacketIn _VRPacketInWithSource _VRApplyPolicy _VRCheckPolicy _VRValidateEvents _VRInspect _VRStatus _VRPacketStats _VRStopPort _VRStopInstance _VRFree; do
  grep -q " T $sym\$" <<< "$symbols" \
    || { echo "error: $sym missing from libtsengine.a" >&2; exit 1; }
  grep -q "${sym#_}" "$INCLUDE/virtualrouter.h" \
    || { echo "error: ${sym#_} not declared in include/virtualrouter.h" >&2; exit 1; }
done

for sym in _PPCreate _PPCreateWithContext _PPDirectionNeedsPackets _PPObserve _PPApply _PPStatus _PPDestroy _PPFree; do
  grep -q " T $sym\$" <<< "$symbols" \
    || { echo "error: $sym missing from libtsengine.a" >&2; exit 1; }
  grep -q "${sym#_}(" "$INCLUDE/packetpolicy.h" \
    || { echo "error: ${sym#_} not declared in include/packetpolicy.h" >&2; exit 1; }
done

# Verify the same ARC wrapper used by the NE packet pumps. No tunnel is started.
probe="$(mktemp "${TMPDIR:-/tmp}/simplevpn-packet-policy.XXXXXXXX")"
trap 'rm -f "$probe"' EXIT
xcrun clang++ -std=c++20 -O2 -fobjc-arc -arch arm64 -I"$REPO/PacketTunnel/Bridges" -I"$INCLUDE" \
  "$REPO/Tools/PacketPolicyProbe.mm" "$REPO/PacketTunnel/Bridges/SVPPacketPolicy.mm" -L"$OUT" \
  -ltsengine -lsimplevpn_routing_core -framework Foundation -framework CoreFoundation \
  -framework Security -framework SystemConfiguration -framework IOKit -lresolv -o "$probe"
"$probe"

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
