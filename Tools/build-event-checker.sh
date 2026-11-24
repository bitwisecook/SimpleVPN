#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
source "$REPO/Tools/routing-native-env.sh"
cd "$REPO/Vendor/proxy-engine/src"
mkdir -p "${BUILT_PRODUCTS_DIR:?}"
go build -tags routing_rust -trimpath -ldflags "$ROUTING_GO_LDFLAGS" -o "$BUILT_PRODUCTS_DIR/routecheck" ./cmd/routecheck
