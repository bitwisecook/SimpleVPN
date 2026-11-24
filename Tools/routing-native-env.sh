# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
# Shared by the shipping Go archive, routecheck and the standalone verification scripts.
# Source with REPO set to the repository root.
export PATH="${HOME}/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
source "$REPO/Tools/routing-rust-paths.sh" "$REPO"
case "${ARCHS:-arm64}" in
  arm64) ;;
  *) echo "error: the shipping engine frameworks support arm64 only (requested $ARCHS)" >&2; exit 1 ;;
esac

# Build against the same macOS minimum as the other static engine archives.
export MACOSX_DEPLOYMENT_TARGET=26.0
ROUTING_CARGO_DIR="$REPO/build/routing-core"
cargo build --manifest-path "$REPO/Vendor/routing-core/Cargo.toml" --target-dir "$ROUTING_CARGO_DIR" \
  --target aarch64-apple-darwin --locked --offline --release --quiet
ROUTING_RUST_LIB_DIR="$ROUTING_CARGO_DIR/aarch64-apple-darwin/release"
ROUTING_RUST_ARCHIVE="$ROUTING_RUST_LIB_DIR/libsimplevpn_routing_core.a"

# Go does not track external C headers or static archives in its cache. Rebuild
# the cgo bindings for ABI changes, but only relink executables for Rust changes.
# Each tiny symlink gives the Go linker a content-specific input name.
header_digest="$(cat "$REPO"/Vendor/routing-core/include/*.h | shasum -a 256 | cut -c1-64)"
archive_digest="$(shasum -a 256 "$ROUTING_RUST_ARCHIVE" | cut -c1-64)"
routing_link_name="simplevpn_routing_core_$archive_digest"
routing_link="$ROUTING_RUST_LIB_DIR/lib$routing_link_name.a"
if [[ ! -L "$routing_link" ]]; then
  ln -s libsimplevpn_routing_core.a "$routing_link" || [[ -L "$routing_link" ]]
fi
export CGO_ENABLED=1 GOOS=darwin GOARCH=arm64
export CGO_CFLAGS="-mmacosx-version-min=26.0 -DSIMPLEVPN_ROUTING_ABI_${header_digest}=1 ${CGO_CFLAGS:-}"
export CGO_LDFLAGS="-mmacosx-version-min=26.0 ${CGO_LDFLAGS:-}"
# Pass the archive to the final executable linker once. CGO_LDFLAGS would
# repeat the library for every cgo package. LIBRARY_PATH handles spaces in
# checkout paths without nesting shell quoting inside the Go linker flags.
export LIBRARY_PATH="$ROUTING_RUST_LIB_DIR${LIBRARY_PATH:+:$LIBRARY_PATH}"
ROUTING_GO_LDFLAGS="-linkmode=external -extldflags=-l$routing_link_name"
