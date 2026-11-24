#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
source "$repo/Tools/routing-rust-paths.sh" "$repo"
case "${ARCHS:-arm64}" in
    arm64) target=aarch64-apple-darwin ;;
    *) echo "error: unsupported routing language server architecture: $ARCHS" >&2; exit 1 ;;
esac
# Cargo discovers the crate's vendored registry config from its working directory.
cd "$repo/Tools/RoutingLSP"
target_dir="${PROJECT_TEMP_DIR:-$repo/build}/routing-lsp-cargo"
cargo clippy --all-targets --locked --offline --release --target "$target" --target-dir "$target_dir" -- -D warnings
cargo build --locked --offline --release --target "$target" --target-dir "$target_dir" --bin routing-lsp
binary="$target_dir/$target/release/routing-lsp"
output="${BUILT_PRODUCTS_DIR:?}/routing-lsp"
mkdir -p "$BUILT_PRODUCTS_DIR"
if ! cmp -s "$binary" "$output"; then
    install -m 755 "$binary" "$output"
fi
