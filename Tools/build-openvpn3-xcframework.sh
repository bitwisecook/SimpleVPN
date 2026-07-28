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
MIN=26.0                                        # macOS deployment target
ARCH=arm64

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$REPO/build/openvpn3-src"
BUILD="$REPO/build/engine"
VENDOR="$REPO/Vendor"

echo "==> Homebrew deps"
for f in asio fmt lz4 xxhash openssl@3; do brew list "$f" >/dev/null 2>&1 || brew install "$f"; done
O3="$(brew --prefix openssl@3)"; LZ4="$(brew --prefix lz4)"; BREW_INC="$(brew --prefix)/include"

echo "==> openvpn3 @ $PIN"
if [ ! -d "$WORK/.git" ]; then rm -rf "$WORK"; git clone https://github.com/OpenVPN/openvpn3.git "$WORK"; fi
git -C "$WORK" fetch --tags origin >/dev/null 2>&1 || true
git -C "$WORK" checkout -q "$PIN"

DEFS=(-DASIO_STANDALONE -DHAVE_LZ4 -DUSE_ASIO -DUSE_OPENSSL -DUSE_TUN_BUILDER -DFMT_HEADER_ONLY)
INC=(-I"$WORK" -isystem "$O3/include" -isystem "$BREW_INC")
CXX=(clang++ -std=c++20 -arch "$ARCH" -mmacosx-version-min="$MIN" -fvisibility=hidden -O2 "${DEFS[@]}" "${INC[@]}")

echo "==> compile core TUs"
rm -rf "$BUILD"; mkdir -p "$BUILD/obj"
"${CXX[@]}" -c "$WORK/client/ovpncli.cpp"            -o "$BUILD/obj/ovpncli.o"
"${CXX[@]}" -c "$WORK/openvpn/crypto/data_epoch.cpp" -o "$BUILD/obj/data_epoch.o"

echo "==> merge static lib (core + OpenSSL + lz4)"
libtool -static -o "$BUILD/libOpenVPNEngine.a" \
  "$BUILD"/obj/*.o "$O3/lib/libssl.a" "$O3/lib/libcrypto.a" "$LZ4/lib/liblz4.a" 2>&1 | grep -v 'has no symbols' || true

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
