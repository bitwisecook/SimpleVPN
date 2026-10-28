#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
# Build the same deployment-compatible OpenSSL locally and in CI. No Homebrew
# tap or global keg changes: every engine consumes the repository-local root.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
"$REPO/Tools/build-openssl.sh"
