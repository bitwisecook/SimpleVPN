#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
# Build the 1Password Go SDK (github.com/1Password/onepassword-sdk-go) as a
# static C archive for in-process desktop-app authentication — replaces
# shelling out to the `op` CLI. Compiles the cgo shim in
# Vendor/onepassword-native/src (-buildmode=c-archive, darwin/arm64, CGO on:
# the SDK's desktop-auth path is behind a `cgo` build tag) and installs
# Vendor/onepassword-native/libopnative.a. The Swift-facing header is the
# hand-written, stable Vendor/onepassword-native/include/opnative.h — the
# cgo-generated header is kept alongside it as libopnative.h for reference and
# the exported symbols are cross-checked against it here. -trimpath keeps the
# archive reproducible (no $HOME/go paths baked in); symbols are NOT stripped,
# matching the project's STRIP_INSTALLED_PRODUCT=NO crash-report policy.
set -euo pipefail

# Pin exactly, never float — bump deliberately (must match go.mod).
SDK_MODULE="github.com/1password/onepassword-sdk-go"
SDK_VERSION="v0.4.1"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$REPO/Vendor/onepassword-native/src"
OUT="$REPO/Vendor/onepassword-native"
INCLUDE="$OUT/include"

command -v go >/dev/null || { echo "error: Go toolchain not found" >&2; exit 1; }

cd "$SRC"

# go.mod is the source of truth for the pin; fail loudly if it drifts from the
# version this script declares (both must be bumped together).
go mod download
pinned="$(go list -m "$SDK_MODULE" | awk '{print $2}')"
if [ "$pinned" != "$SDK_VERSION" ]; then
  echo "error: go.mod pins $SDK_MODULE $pinned but this script expects $SDK_VERSION" >&2
  exit 1
fi
go mod verify

# Same gate as build-tailscale-engine.sh: the shim's pure logic (title ranking,
# link parsing, error classification) is checked before an archive is produced,
# so a broken lookup can't reach a build.
gofmt -l . | grep . && { echo "error: gofmt found unformatted files (above)" >&2; exit 1; }
go vet ./...
go test ./...

# c-archive: Go runtime + SDK + shim in one .a. The generated header lands next
# to the archive; rename it to libopnative.h (reference only — Swift includes
# the stable include/opnative.h instead).
mkdir -p "$INCLUDE"
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
  go build -trimpath -buildmode=c-archive -o "$OUT/libopnative.a" .
mv "$OUT/libopnative.h" "$INCLUDE/libopnative.h"

# The stable header must declare exactly what the archive exports.
for sym in _OPNativeResolve _OPNativeGetItem _OPNativeList _OPNativeLookup _OPNativeProbe _OPNativeFree; do
  nm -gU "$OUT/libopnative.a" 2>/dev/null | grep -q " T $sym\$" \
    || { echo "error: $sym missing from libopnative.a" >&2; exit 1; }
  grep -q "${sym#_}" "$INCLUDE/opnative.h" \
    || { echo "error: ${sym#_} not declared in include/opnative.h" >&2; exit 1; }
done

echo "onepassword-sdk-go: $SDK_VERSION"
echo "archive: $OUT/libopnative.a ($(du -h "$OUT/libopnative.a" | cut -f1 | tr -d ' '))"
shasum -a 256 "$OUT/libopnative.a"
