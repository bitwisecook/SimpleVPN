#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
# Build SSHEngine.xcframework — libssh2 (OpenSSL crypto backend) statically linked
# for arm64 macOS — so SSH tunnels (SOCKS / port-forwards / net-tunnel) run in-process
# instead of shelling out to /usr/bin/ssh.
#
# Outputs (gitignored, regenerate any time):
#   Vendor/SSHEngine.xcframework   — link into the SSH engine
#   Vendor/libssh2-include/        — libssh2.h for the bridge
#
# Homebrew deps (auto-installed): cmake openssl@3. zlib is a system library (-lz).
set -euo pipefail

PIN=libssh2-1.11.1        # libssh2 release tag — bump deliberately
# Keep IDENTICAL across all three engine scripts (see build-openconnect for why).
OPENSSL_PIN="3.6.3"
MIN=26.0
ARCH=arm64

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$REPO/build/libssh2-src"
BUILD="$REPO/build/libssh2"
VENDOR="$REPO/Vendor"

echo "==> Homebrew deps"
for f in cmake openssl@3; do brew list "$f" >/dev/null 2>&1 || brew install "$f"; done
O3="$(brew --prefix openssl@3)"

have_ssl="$("$O3/bin/openssl" version 2>/dev/null | awk '{print $2}')"
if [ "$have_ssl" != "$OPENSSL_PIN" ]; then
  echo "FATAL: openssl@3 is $have_ssl but the pin is $OPENSSL_PIN."
  echo "       Align Homebrew or bump OPENSSL_PIN in ALL THREE engine scripts, then rebuild all three."
  exit 1
fi

echo "==> libssh2 @ $PIN"
if [ ! -d "$WORK/.git" ]; then rm -rf "$WORK"; git clone https://github.com/libssh2/libssh2.git "$WORK"; fi
git -C "$WORK" fetch --tags origin >/dev/null 2>&1 || true
git -C "$WORK" checkout -q "$PIN"

# ENABLE_DEBUG_LOGGING defines LIBSSH2DEBUG, which is what compiles libssh2_trace() and
# libssh2_trace_sethandler() in AT ALL. Without it both are no-ops, and an SSH connection
# that fails during handshake or auth leaves nothing whatsoever in a diagnostics bundle —
# the library's own account of what happened is simply absent. It only enables the
# capability; SSHBridge chooses the trace mask, and deliberately omits the raw
# byte-level channels (see the mask there).
echo "==> configure (static, OpenSSL backend, trace enabled)"
rm -rf "$BUILD"
cmake -S "$WORK" -B "$BUILD" \
  -DCMAKE_OSX_ARCHITECTURES="$ARCH" \
  -DCMAKE_OSX_DEPLOYMENT_TARGET="$MIN" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DCRYPTO_BACKEND=OpenSSL \
  -DOPENSSL_ROOT_DIR="$O3" \
  -DENABLE_ZLIB_COMPRESSION=ON \
  -DENABLE_DEBUG_LOGGING=ON \
  -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF -DLIBSSH2_NO_DEPRECATED=ON

echo "==> build"
cmake --build "$BUILD" --config Release -j"$(sysctl -n hw.ncpu)"

# libssh2's static archive lands under src/ (name may be libssh2.a or libssh2_static.a).
LIB="$(find "$BUILD" -name 'libssh2*.a' | head -1)"
[ -n "$LIB" ] || { echo "ERROR: libssh2 static archive not found"; exit 1; }
echo "==> found $LIB"

echo "==> merge static lib (libssh2 + OpenSSL; zlib is system)"
if ! libtool -static -o "$BUILD/libSSHEngine.a" \
  "$LIB" "$O3/lib/libssl.a" "$O3/lib/libcrypto.a" 2> "$BUILD/libtool.err"; then
  cat "$BUILD/libtool.err"; echo "FATAL: libtool merge failed"; exit 1
fi
grep -v 'has no symbols' "$BUILD/libtool.err" >&2 || true

echo "==> smoke-test: libssh2 symbols present"
# NOTE: grep -c, not grep -q. Under `set -o pipefail`, grep -q exits on the first match
# and closes the pipe, nm dies of SIGPIPE, and the whole pipeline reports failure — so a
# PASSING smoke test reads as FATAL. grep -c consumes all input, so nm exits cleanly.
if ! nm "$BUILD/libSSHEngine.a" 2>/dev/null | grep -c '_libssh2_session_init_ex' >/dev/null; then
  echo "FATAL: libssh2 symbols missing from the merged archive."; exit 1
fi

echo "==> package xcframework"
mkdir -p "$VENDOR"; rm -rf "$VENDOR/SSHEngine.xcframework"
xcodebuild -create-xcframework -library "$BUILD/libSSHEngine.a" -output "$VENDOR/SSHEngine.xcframework"

echo "==> vendor headers"
rm -rf "$VENDOR/libssh2-include"; mkdir -p "$VENDOR/libssh2-include"
cp "$WORK/include/libssh2.h" "$WORK/include/libssh2_publickey.h" "$WORK/include/libssh2_sftp.h" "$VENDOR/libssh2-include/" 2>/dev/null || true
# CMake writes the version'd header into the build tree.
find "$BUILD" -name 'libssh2_version.h' -exec cp {} "$VENDOR/libssh2-include/" \; 2>/dev/null || true

echo "==> done: $VENDOR/SSHEngine.xcframework (link also -lz)"
