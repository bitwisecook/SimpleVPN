#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
# Build SSHEngine.xcframework — libssh (OpenSSL crypto backend) statically linked
# for arm64 macOS — so SSH tunnels (SOCKS / port-forwards / net-tunnel) run in-process
# instead of shelling out to /usr/bin/ssh. (Replaced libssh2 in a straight cutover:
# libssh brings GSSAPI sign-in, post-quantum kex and a maintained known-hosts API.)
#
# Outputs (gitignored, regenerate any time):
#   Vendor/SSHEngine.xcframework   — link into the SSH engine
#   Vendor/libssh-include/         — libssh public headers for the bridge
#
# Homebrew deps (auto-installed): cmake openssl@3. zlib is a system library (-lz);
# GSSAPI comes from the macOS SDK (MIT-shim headers + libgssapi_krb5.tbd → GSS
# framework), so the app links -lgssapi_krb5 — see project.yml.
set -euo pipefail

PIN=0.12.2                # libssh release — bump deliberately (update SHA256 with it)
# The release tarball's SHA-256. libssh is fetched over HTTPS as a tarball (no git
# tag to pin), so the hash IS the pin — a mismatch means a different artifact, and
# the build must stop rather than compile it.
TARBALL_SHA256="49560f677d96e3706a904ac2de1116e25f3680937d51e5c92198fcba4a1c1e9f"
# Keep IDENTICAL across all three engine scripts (see build-openconnect for why).
OPENSSL_PIN="3.6.3"
MIN=26.0
ARCH=arm64

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$REPO/build/libssh-src"
BUILD="$REPO/build/libssh"
VENDOR="$REPO/Vendor"
TARBALL="$REPO/build/libssh-$PIN.tar.xz"

echo "==> Homebrew deps"
for f in cmake openssl@3; do brew list "$f" >/dev/null 2>&1 || brew install "$f"; done
O3="$(brew --prefix openssl@3)"

have_ssl="$("$O3/bin/openssl" version 2>/dev/null | awk '{print $2}')"
if [ "$have_ssl" != "$OPENSSL_PIN" ]; then
  echo "FATAL: openssl@3 is $have_ssl but the pin is $OPENSSL_PIN."
  echo "       Align Homebrew or bump OPENSSL_PIN in ALL THREE engine scripts, then rebuild all three."
  exit 1
fi

echo "==> libssh @ $PIN (pinned tarball)"
mkdir -p "$REPO/build"
if [ ! -f "$TARBALL" ]; then
  curl -fsSL -o "$TARBALL" "https://www.libssh.org/files/${PIN%.*}/libssh-$PIN.tar.xz"
fi
have_sha="$(shasum -a 256 "$TARBALL" | awk '{print $1}')"
if [ "$have_sha" != "$TARBALL_SHA256" ]; then
  echo "FATAL: libssh-$PIN.tar.xz SHA-256 is $have_sha, expected $TARBALL_SHA256."
  echo "       Refusing to build an unverified tarball. Delete it and re-run, or"
  echo "       update the pin DELIBERATELY alongside the version bump."
  exit 1
fi
rm -rf "$WORK"; mkdir -p "$WORK"
tar -xf "$TARBALL" -C "$WORK" --strip-components=1

# tun@openssh.com channel-open: OpenSSH's net-tunnel (-w) channel type. libssh has
# no public API for arbitrary channel types (its channel_open() is static), so a
# small wrapper is appended to channels.c where that function and the default
# window/packet constants are in scope. Payload per PROTOCOL of OpenSSH:
# tunnel-mode(uint32) + remote-unit(uint32). SSHBridge declares the prototype.
if ! grep -q libsshx_channel_open_tun "$WORK/src/channels.c"; then
cat >> "$WORK/src/channels.c" <<'EOF'

/* --- SimpleVPN addition (Tools/build-libssh-xcframework.sh appends this) ---
 * Open a tun@openssh.com channel (OpenSSH -w net-tunnel). tun_mode is
 * SSH_TUNMODE_POINTOPOINT(1)/ETHERNET(2); remote_unit is the server tun unit
 * or 0x7fffffff for "any". Reuses the file-local channel_open() above. */
__attribute__((visibility("default")))
int libsshx_channel_open_tun(ssh_channel channel,
                             uint32_t tun_mode,
                             uint32_t remote_unit)
{
    ssh_buffer payload = NULL;
    int rc;

    if (channel == NULL) {
        return SSH_ERROR;
    }
    payload = ssh_buffer_new();
    if (payload == NULL) {
        ssh_set_error_oom(channel->session);
        return SSH_ERROR;
    }
    rc = ssh_buffer_pack(payload, "dd", tun_mode, remote_unit);
    if (rc != SSH_OK) {
        ssh_set_error_oom(channel->session);
        SSH_BUFFER_FREE(payload);
        return SSH_ERROR;
    }
    rc = channel_open(channel,
                      "tun@openssh.com",
                      WINDOW_DEFAULT,
                      CHANNEL_MAX_PACKET,
                      payload);
    SSH_BUFFER_FREE(payload);
    return rc;
}
EOF
fi

# Client library only: server, examples, tests, SFTP, pcap capture and the
# config-driven exec paths (ProxyCommand/match exec — a VPN app must never let a
# config file run commands) are all OFF. GSSAPI stays ON — that's a migration
# win over libssh2 (Kerberos single sign-on) and macOS provides it in the SDK.
echo "==> configure (static, OpenSSL backend, GSSAPI on, server/examples/tests off)"
rm -rf "$BUILD"
cmake -S "$WORK" -B "$BUILD" \
  -DCMAKE_OSX_ARCHITECTURES="$ARCH" \
  -DCMAKE_OSX_DEPLOYMENT_TARGET="$MIN" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DOPENSSL_ROOT_DIR="$O3" \
  -DWITH_GSSAPI=ON \
  -DWITH_ZLIB=ON \
  -DWITH_SERVER=OFF \
  -DWITH_EXAMPLES=OFF \
  -DUNIT_TESTING=OFF \
  -DWITH_SFTP=OFF \
  -DWITH_PCAP=OFF \
  -DWITH_NACL=OFF \
  -DWITH_EXEC=OFF \
  | tee "$BUILD.cmake.log"

# ConfigureChecks silently flips WITH_GSSAPI off when the SDK lookup fails —
# that would ship an engine without Kerberos and nobody would notice until a
# gssapi-with-mic server refused everyone. Fail here instead.
if ! grep -q "GSSAPI support : ON" "$BUILD.cmake.log"; then
  echo "FATAL: cmake did not find GSSAPI (expected the macOS SDK's MIT shim:"
  echo "       /usr/bin/krb5-config + <gssapi/gssapi.h> + libgssapi_krb5.tbd)."
  exit 1
fi
rm -f "$BUILD.cmake.log"

echo "==> build"
cmake --build "$BUILD" --config Release -j"$(sysctl -n hw.ncpu)"

LIB="$BUILD/src/libssh.a"
[ -f "$LIB" ] || LIB="$(find "$BUILD" -name 'libssh*.a' | head -1)"
[ -n "$LIB" ] && [ -f "$LIB" ] || { echo "ERROR: libssh static archive not found"; exit 1; }
echo "==> found $LIB"

echo "==> merge static lib (libssh + OpenSSL; zlib + GSSAPI are system)"
if ! libtool -static -o "$BUILD/libSSHEngine.a" \
  "$LIB" "$O3/lib/libssl.a" "$O3/lib/libcrypto.a" 2> "$BUILD/libtool.err"; then
  cat "$BUILD/libtool.err"; echo "FATAL: libtool merge failed"; exit 1
fi
grep -v 'has no symbols' "$BUILD/libtool.err" >&2 || true

echo "==> smoke-test: required symbols present in the merged archive"
# NOTE: grep -c, not grep -q. Under `set -o pipefail`, grep -q exits on the first match
# and closes the pipe, nm dies of SIGPIPE, and the whole pipeline reports failure — so a
# PASSING smoke test reads as FATAL. grep -c consumes all input, so nm exits cleanly.
NM="$BUILD/nm.symbols"
nm "$BUILD/libSSHEngine.a" 2>/dev/null > "$NM"
for sym in _ssh_new _ssh_connect _ssh_session_is_known_server _ssh_userauth_gssapi \
           _ssh_gssapi_set_creds _libsshx_channel_open_tun; do
  if ! grep -c "$sym" "$NM" >/dev/null; then
    echo "FATAL: $sym missing from the merged archive."; exit 1
  fi
done
# Straight-cutover sanity: no libssh2 can sneak back in through a stale build dir.
if grep -c '_libssh2_session_init_ex' "$NM" >/dev/null 2>&1; then
  echo "FATAL: libssh2 symbols found in the merged archive — stale build tree?"; exit 1
fi
rm -f "$NM"

echo "==> package xcframework"
mkdir -p "$VENDOR"; rm -rf "$VENDOR/SSHEngine.xcframework"
xcodebuild -create-xcframework -library "$BUILD/libSSHEngine.a" -output "$VENDOR/SSHEngine.xcframework"

echo "==> vendor headers (public API only; the bridge imports <libssh/libssh.h>)"
rm -rf "$VENDOR/libssh-include"; mkdir -p "$VENDOR/libssh-include/libssh"
cp "$WORK/include/libssh/libssh.h" "$WORK/include/libssh/callbacks.h" \
   "$WORK/include/libssh/legacy.h" "$VENDOR/libssh-include/libssh/"
# CMake writes the version'd header into the build tree.
find "$BUILD" -name 'libssh_version.h' -exec cp {} "$VENDOR/libssh-include/libssh/" \; 2>/dev/null || true
[ -f "$VENDOR/libssh-include/libssh/libssh_version.h" ] || {
  echo "FATAL: generated libssh_version.h not found"; exit 1; }

echo "==> done: $VENDOR/SSHEngine.xcframework (link also -lz and -lgssapi_krb5)"
