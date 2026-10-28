#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
# Build one verified OpenSSL archive set for all three native engines, with the
# app's deployment target even when Homebrew bottles require a newer macOS.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
PIN="$(awk -F'"' '/^OPENSSL_PIN=/{print $2; exit}' "$REPO/Tools/build-openvpn3-xcframework.sh")"
SHA256=a2157c2830efdec3788939b00c9b0638306d3f0bbb76dc4832ee503bb397df98
PREFIX="$REPO/build/pinned-openssl"
WORK="$REPO/build/pinned-openssl-src"
TARBALL="$REPO/build/openssl-$PIN.tar.gz"
for script in build-openconnect-xcframework.sh build-libssh-xcframework.sh; do
  other="$(awk -F'"' '/^OPENSSL_PIN=/{print $2; exit}' "$REPO/Tools/$script")"
  [ "$PIN" = "$other" ] || { echo "FATAL: OpenSSL pins disagree in $script" >&2; exit 1; }
done
# The receipt binds this installation to this script's source checksum, target
# and flags, rather than trusting an unrelated executable's version string.
RECEIPT="$PIN $SHA256 darwin64-arm64-cc macOS26.0 no-shared no-module"
if [ -f "$PREFIX/.simplevpn-build" ] && [ "$(cat "$PREFIX/.simplevpn-build")" = "$RECEIPT" ] \
   && [ -f "$PREFIX/lib/libssl.a" ] && [ -f "$PREFIX/lib/libcrypto.a" ]; then
  echo "==> OpenSSL $PIN already built for macOS 26"
  exit 0
fi
mkdir -p "$REPO/build"
if [ ! -f "$TARBALL" ]; then
  curl -fL --retry 3 -o "$TARBALL.tmp" "https://github.com/openssl/openssl/releases/download/openssl-$PIN/openssl-$PIN.tar.gz"
  mv "$TARBALL.tmp" "$TARBALL"
fi
echo "$SHA256  $TARBALL" | shasum -a 256 -c -
rm -rf "$WORK"
mkdir -p "$WORK"
tar -xf "$TARBALL" -C "$WORK" --strip-components=1
cd "$WORK"
./Configure darwin64-arm64-cc --prefix="$PREFIX" --libdir=lib \
  no-shared no-module -mmacosx-version-min=26.0
make -j"$(sysctl -n hw.ncpu)"
make install_sw
printf '%s\n' "$RECEIPT" > "$PREFIX/.simplevpn-build"
echo "==> OpenSSL $PIN installed at $PREFIX"
