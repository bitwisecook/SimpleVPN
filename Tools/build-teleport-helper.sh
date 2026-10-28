#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
# One-shot pairing tool. The same protocol package is linked into libtsengine;
# the app-side helper does not link or run a second WireGuard implementation.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${BUILT_PRODUCTS_DIR:-$REPO/Vendor/tailscale-engine}/teleport-pair"
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
cd "$REPO/Vendor/tailscale-engine/src"
mkdir -p "$(dirname "$OUT")"
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -o "$OUT" ./cmd/teleport-pair
