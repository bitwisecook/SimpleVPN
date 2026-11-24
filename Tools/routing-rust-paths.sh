# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
# Source with the repository root as the first argument. Panic locations in the
# compiled Rust crates must not publish the developer account or checkout path.
routing_flags="${CARGO_ENCODED_RUSTFLAGS:-}"
if [[ -z "$routing_flags" && -n "${RUSTFLAGS:-}" ]]; then
    read -ra inherited_rust_flags <<< "$RUSTFLAGS"
    printf -v routing_flags '%s\x1f' "${inherited_rust_flags[@]}"
    routing_flags="${routing_flags%$'\x1f'}"
fi
for prefix in "$HOME=/build-user" "$(rustc --print sysroot)=/rust-toolchain" "$1=/simplevpn"; do
    routing_flags="${routing_flags:+$routing_flags$'\x1f'}--remap-path-prefix=$prefix"
done
export CARGO_ENCODED_RUSTFLAGS="$routing_flags"
