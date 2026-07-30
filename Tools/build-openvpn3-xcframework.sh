#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
# Build OpenVPNEngine.xcframework — the OpenVPN 3 client core (with TunBuilder), OpenSSL and lz4
# statically linked, for arm64 macOS — plus vendored headers the ObjC++ bridge needs.
#
# Outputs (gitignored, regenerate any time):
#   Vendor/OpenVPNEngine.xcframework   — link this into the PacketTunnel target
#   Vendor/openvpn3-include/           — headers for #include <client/ovpncli.hpp> in the bridge
#
# Requires Homebrew deps: asio fmt lz4 xxhash openssl@3 (auto-installed if missing).
set -euo pipefail

PIN=1512c16622288f3c01da09d3278ac61a86dca26d   # openvpn3 revision (core 3.12) — bump deliberately
# Keep IDENTICAL across all three engine scripts (see build-openconnect for why:
# three statically-bundled OpenSSL copies land in one binary; version skew between
# them is a linker/ABI hazard). Bump all three together.
OPENSSL_PIN="3.6.3"
MIN=26.0                                        # macOS deployment target
ARCH=arm64

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$REPO/build/openvpn3-src"
BUILD="$REPO/build/engine"
VENDOR="$REPO/Vendor"

echo "==> Homebrew deps"
for f in asio fmt lz4 xxhash openssl@3; do brew list "$f" >/dev/null 2>&1 || brew install "$f"; done
O3="$(brew --prefix openssl@3)"; LZ4="$(brew --prefix lz4)"; BREW_INC="$(brew --prefix)/include"

have_ssl="$("$O3/bin/openssl" version 2>/dev/null | awk '{print $2}')"
if [ "$have_ssl" != "$OPENSSL_PIN" ]; then
  echo "FATAL: openssl@3 is $have_ssl but the pin is $OPENSSL_PIN."
  echo "       Align Homebrew or bump OPENSSL_PIN in ALL THREE engine scripts, then rebuild all three."
  exit 1
fi

echo "==> openvpn3 @ $PIN"
if [ ! -d "$WORK/.git" ]; then rm -rf "$WORK"; git clone https://github.com/OpenVPN/openvpn3.git "$WORK"; fi
git -C "$WORK" fetch --tags origin >/dev/null 2>&1 || true
git -C "$WORK" checkout -q "$PIN"

DEFS=(-DASIO_STANDALONE -DHAVE_LZ4 -DUSE_ASIO -DUSE_OPENSSL -DUSE_TUN_BUILDER -DFMT_HEADER_ONLY)
INC=(-I"$WORK" -isystem "$O3/include" -isystem "$BREW_INC")
CXX=(clang++ -std=c++20 -arch "$ARCH" -mmacosx-version-min="$MIN" -fvisibility=hidden -O2 "${DEFS[@]}" "${INC[@]}")

# Only two TUs of openvpn3 are non-header-only for the pinned core; the rest is
# header-only. The smoke-test below fails the build if that assumption breaks on a
# future bump (a missing TU would otherwise surface as a cryptic app-link error,
# masked by the OpenSSL symbols already present in this archive).
echo "==> compile core TUs"
rm -rf "$BUILD"; mkdir -p "$BUILD/obj"
"${CXX[@]}" -c "$WORK/client/ovpncli.cpp"            -o "$BUILD/obj/ovpncli.o"
"${CXX[@]}" -c "$WORK/openvpn/crypto/data_epoch.cpp" -o "$BUILD/obj/data_epoch.o"

echo "==> merge static lib (core + OpenSSL + lz4)"
if ! libtool -static -o "$BUILD/libOpenVPNEngine.a" \
  "$BUILD"/obj/*.o "$O3/lib/libssl.a" "$O3/lib/libcrypto.a" "$LZ4/lib/liblz4.a" 2> "$BUILD/libtool.err"; then
  cat "$BUILD/libtool.err"; echo "FATAL: libtool merge failed"; exit 1
fi
grep -v 'has no symbols' "$BUILD/libtool.err" >&2 || true

echo "==> smoke-test: OpenVPN client entry point present"
# NOTE: grep -c, not grep -q. Under `set -o pipefail`, grep -q exits on the first match
# and closes the pipe, nm dies of SIGPIPE, and the whole pipeline reports failure — so a
# PASSING smoke test reads as FATAL. grep -c consumes all input, so nm exits cleanly.
if ! nm "$BUILD/libOpenVPNEngine.a" 2>/dev/null | grep -c 'OpenVPNClient' >/dev/null; then
  echo "FATAL: openvpn3 client symbols missing — a required TU may not be compiled for this pin."; exit 1
fi

echo "==> package xcframework"
mkdir -p "$VENDOR"; rm -rf "$VENDOR/OpenVPNEngine.xcframework"
xcodebuild -create-xcframework -library "$BUILD/libOpenVPNEngine.a" -output "$VENDOR/OpenVPNEngine.xcframework"

echo "==> vendor headers for the bridge"
rm -rf "$VENDOR/openvpn3-include"; mkdir -p "$VENDOR/openvpn3-include"
cp -R "$WORK/openvpn" "$VENDOR/openvpn3-include/"
cp -R "$WORK/client"  "$VENDOR/openvpn3-include/"
cp -RL "$BREW_INC/asio" "$VENDOR/openvpn3-include/" 2>/dev/null || true      # -L: brew paths are symlinks into the Cellar
cp -L  "$BREW_INC/asio.hpp" "$VENDOR/openvpn3-include/" 2>/dev/null || true
cp -RL "$O3/include/openssl" "$VENDOR/openvpn3-include/" 2>/dev/null || true
cp -RL "$BREW_INC/fmt" "$VENDOR/openvpn3-include/" 2>/dev/null || true
for h in xxhash.h xxh3.h; do cp -L "$BREW_INC/$h" "$VENDOR/openvpn3-include/" 2>/dev/null || true; done

echo "==> done. openvpn3 pin=$PIN"
echo "    $VENDOR/OpenVPNEngine.xcframework"
echo "    $VENDOR/openvpn3-include/"
