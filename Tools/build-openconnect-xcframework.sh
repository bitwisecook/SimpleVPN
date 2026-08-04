#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
# Build OpenConnectEngine.xcframework — libopenconnect (OpenSSL backend) statically
# linked with its deps for arm64 macOS — so the SSL-VPN engines (Fortinet / F5 APM /
# AnyConnect / GlobalProtect) run in-process instead of shelling out to `openconnect`.
#
# Outputs (gitignored, regenerate any time):
#   Vendor/OpenConnectEngine.xcframework   — link into the OpenConnect provider target
#   Vendor/openconnect-include/            — openconnect.h for the bridge
#
# Homebrew deps (auto-installed): autoconf automake libtool pkg-config openssl@3 lz4.
# libxml2 + zlib + iconv are macOS *system* libraries — linked at app-link time
# (-lxml2 -lz -liconv), not vendored (Homebrew ships no static libxml2.a, and the
# system one is always present and notarization-safe).
set -euo pipefail

PIN=v9.12                 # openconnect release tag — bump deliberately
# Pin OpenSSL too. Three engines (this, OpenVPN, SSH) each statically bundle
# OpenSSL and all three are linked into the same binaries; if two builds pick up
# different OpenSSL point releases, the linker can resolve one engine's calls
# against another's OpenSSL → ABI skew / corruption. Keep this constant IDENTICAL
# across build-openvpn3 / build-openconnect / build-libssh, and bump all three
# together. The guard below fails loudly if Homebrew drifts from the pin.
OPENSSL_PIN="3.6.3"
MIN=26.0
ARCH=arm64

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$REPO/build/openconnect-src"
BUILD="$REPO/build/openconnect"
VENDOR="$REPO/Vendor"

echo "==> Homebrew deps"
for f in autoconf automake libtool pkg-config openssl@3 lz4; do
  brew list "$f" >/dev/null 2>&1 || brew install "$f"
done
O3="$(brew --prefix openssl@3)"; LZ4="$(brew --prefix lz4)"
SDK="$(xcrun --show-sdk-path)"   # system libxml2 headers live here

# Enforce the OpenSSL pin so this build is reproducible and stays byte-aligned
# with the other two engine builds (see OPENSSL_PIN above).
have_ssl="$("$O3/bin/openssl" version 2>/dev/null | awk '{print $2}')"
if [ "$have_ssl" != "$OPENSSL_PIN" ]; then
  echo "FATAL: openssl@3 is $have_ssl but the pin is $OPENSSL_PIN."
  echo "       Align Homebrew (brew install/switch openssl@3) or bump OPENSSL_PIN"
  echo "       in ALL THREE engine build scripts together, then rebuild all three."
  exit 1
fi

# lz4 is statically linked into this engine as well, so it is pinned on the same
# policy as OpenSSL (see build-openvpn3-xcframework.sh's BREW_PINS block): a
# `brew upgrade` between two rebuilds must not change the shipped binary quietly.
LZ4_PIN="1.10.0"
have_lz4="$(brew list --versions lz4 2>/dev/null | awk '{print $2}')"
if [ "$have_lz4" != "$LZ4_PIN" ]; then
  echo "FATAL: lz4 is ${have_lz4:-not installed} but the pin is $LZ4_PIN."
  echo "       Align Homebrew or bump LZ4_PIN here and in build-openvpn3-xcframework.sh's"
  echo "       BREW_PINS, then rebuild both engines."
  exit 1
fi

echo "==> openconnect @ $PIN"
if [ ! -d "$WORK/.git" ]; then rm -rf "$WORK"; git clone https://gitlab.com/openconnect/openconnect.git "$WORK"; fi
git -C "$WORK" fetch --tags origin >/dev/null 2>&1 || true
git -C "$WORK" checkout -q "$PIN"

export PKG_CONFIG_PATH="$O3/lib/pkgconfig:$LZ4/lib/pkgconfig"
export CC="clang"
export CFLAGS="-arch $ARCH -mmacosx-version-min=$MIN -O2 -fvisibility=hidden -I$O3/include -I$LZ4/include -I$SDK/usr/include/libxml2"
export LDFLAGS="-arch $ARCH -L$O3/lib -L$LZ4/lib"
# Point openconnect's libxml2 detection at the SDK's system libxml2 (bypass pkg-config).
export LIBXML2_CFLAGS="-I$SDK/usr/include/libxml2"
export LIBXML2_LIBS="-lxml2"

echo "==> configure (static, OpenSSL backend, system libxml2, CLI extras off)"
cd "$WORK"
[ -x ./configure ] || ./autogen.sh
./configure \
  --host="$ARCH-apple-darwin" \
  --with-openssl --without-gnutls \
  --enable-static --disable-shared \
  --without-libpcsclite --without-stoken --without-libpskc \
  --without-gssapi --without-libproxy --without-java \
  --disable-nls --with-vpnc-script=/etc/vpnc/vpnc-script
# Note: the baked vpnc-script path does not exist in the sandboxed system
# extension, but it is never invoked — OpenConnectBridge drives the tun via
# openconnect_setup_tun_fd + openconnect_get_ip_info and applies all routes/DNS
# through NEPacketTunnelNetworkSettings, so the library's OS-integration script
# path is never taken. The value is only a build-time configure requirement.

echo "==> build libopenconnect"
make -j"$(sysctl -n hw.ncpu)" libopenconnect.la

echo "==> merge static lib (openconnect + OpenSSL + lz4; libxml2/z/iconv are system)"
rm -rf "$BUILD"; mkdir -p "$BUILD"
# Capture stderr and check libtool's own exit status — do NOT pipe to grep with a
# trailing `|| true`, which would swallow a real merge failure and ship an empty
# or incomplete archive that only errors much later at app-link.
if ! libtool -static -o "$BUILD/libOpenConnectEngine.a" \
  "$WORK/.libs/libopenconnect.a" \
  "$O3/lib/libssl.a" "$O3/lib/libcrypto.a" \
  "$LZ4/lib/liblz4.a" 2> "$BUILD/libtool.err"; then
  cat "$BUILD/libtool.err"; echo "FATAL: libtool merge failed"; exit 1
fi
grep -v 'has no symbols' "$BUILD/libtool.err" >&2 || true

echo "==> smoke-test: required symbols present in the merged archive"
# NOTE: grep -c, not grep -q. Under `set -o pipefail`, grep -q exits on the first match
# and closes the pipe, nm dies of SIGPIPE, and the whole pipeline reports failure — so a
# PASSING smoke test reads as FATAL. grep -c consumes all input, so nm exits cleanly.
if ! nm "$BUILD/libOpenConnectEngine.a" 2>/dev/null | grep -c '_openconnect_vpninfo_new' >/dev/null; then
  echo "FATAL: libopenconnect symbols missing — the merge produced an incomplete archive."; exit 1
fi

echo "==> package xcframework"
mkdir -p "$VENDOR"; rm -rf "$VENDOR/OpenConnectEngine.xcframework"
xcodebuild -create-xcframework -library "$BUILD/libOpenConnectEngine.a" -output "$VENDOR/OpenConnectEngine.xcframework"

echo "==> vendor headers"
rm -rf "$VENDOR/openconnect-include"; mkdir -p "$VENDOR/openconnect-include"
cp "$WORK/openconnect.h" "$VENDOR/openconnect-include/"

echo "==> done: $VENDOR/OpenConnectEngine.xcframework"
echo "    (app/provider must also link -lz -liconv and Security/CoreFoundation)"
