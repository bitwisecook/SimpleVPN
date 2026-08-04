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
# Homebrew deps (auto-installed): cmake openssl@3 libfido2. zlib is a system library
# (-lz); GSSAPI comes from the macOS SDK (MIT-shim headers + libgssapi_krb5.tbd → GSS
# framework), so the app links -lgssapi_krb5 — see project.yml.
#
# FIDO2 (hardware security keys as KEY FILES): WITH_FIDO2=ON compiles pki_sk.c +
# sk_usbhid.c, which is what makes an `sk-ssh-ed25519@openssh.com` /
# `sk-ecdsa-sha2-nistp256@openssh.com` private-key FILE usable. Without it only
# agent-held security keys work (the agent does the touch). It needs libfido2
# (Homebrew, static `libfido2.a`) and libcbor — Homebrew ships libcbor dylib-only,
# so a STATIC libcbor is built from source here and merged into the archive the same
# way OpenSSL is. The app/extension must link IOKit + CoreFoundation for the USB HID
# transport (see project.yml).
set -euo pipefail

PIN=0.12.2                # libssh release — bump deliberately (update SHA256 with it)
# The release tarball's SHA-256. libssh is fetched over HTTPS as a tarball (no git
# tag to pin), so the hash IS the pin — a mismatch means a different artifact, and
# the build must stop rather than compile it.
TARBALL_SHA256="49560f677d96e3706a904ac2de1116e25f3680937d51e5c92198fcba4a1c1e9f"
# Keep IDENTICAL across all three engine scripts (see build-openconnect for why).
OPENSSL_PIN="3.6.3"
# Homebrew formulae compiled INTO this engine — same policy as OPENSSL_PIN and
# build-openvpn3-xcframework.sh's BREW_PINS: a `brew upgrade` between two rebuilds
# must not change the shipped binary quietly.
BREW_PINS="libfido2=1.17.0"
# libcbor is a libfido2 dependency and Homebrew ships it dylib-only, so it is built
# STATIC from source here. Pinned by tag AND by the tarball's SHA-256, exactly like
# the libssh tarball above — the hash is the pin.
CBOR_PIN="v0.14.0"
CBOR_TARBALL_SHA256="a8c1516e741562cf95aa4479c64916c3d4d2623e24fdc35e414e2320e7300aae"
MIN=26.0
ARCH=arm64

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$REPO/build/libssh-src"
BUILD="$REPO/build/libssh"
VENDOR="$REPO/Vendor"
TARBALL="$REPO/build/libssh-$PIN.tar.xz"
CBOR_WORK="$REPO/build/libcbor-src"
CBOR_BUILD="$REPO/build/libcbor"
CBOR_TARBALL="$REPO/build/libcbor-$CBOR_PIN.tar.gz"

echo "==> Homebrew deps"
for f in cmake openssl@3 libfido2; do brew list "$f" >/dev/null 2>&1 || brew install "$f"; done
O3="$(brew --prefix openssl@3)"; FIDO2="$(brew --prefix libfido2)"

have_ssl="$("$O3/bin/openssl" version 2>/dev/null | awk '{print $2}')"
if [ "$have_ssl" != "$OPENSSL_PIN" ]; then
  echo "FATAL: openssl@3 is $have_ssl but the pin is $OPENSSL_PIN."
  echo "       Align Homebrew or bump OPENSSL_PIN in ALL THREE engine scripts, then rebuild all three."
  exit 1
fi

for spec in $BREW_PINS; do
  f="${spec%%=*}"; want="${spec#*=}"
  have="$(brew list --versions "$f" 2>/dev/null | awk '{print $2}')"
  if [ "$have" != "$want" ]; then
    echo "FATAL: $f is ${have:-not installed} but the pin is $want."
    echo "       Align Homebrew (brew install/switch $f) or bump BREW_PINS in this script"
    echo "       and rebuild the engine — this input is compiled into the shipped binary."
    exit 1
  fi
done

# Homebrew's libfido2 must be the STATIC archive: a dylib would need the hardened
# runtime relaxed and a copied library at install time, which this engine's whole
# static-linking design exists to avoid.
[ -f "$FIDO2/lib/libfido2.a" ] || {
  echo "FATAL: $FIDO2/lib/libfido2.a not found — Homebrew's libfido2 must ship the"
  echo "       static archive (it does as of 1.17.0). A dylib-only libfido2 can't be"
  echo "       merged into SSHEngine.xcframework."; exit 1; }

echo "==> libcbor @ $CBOR_PIN (static, from source — Homebrew is dylib-only)"
mkdir -p "$REPO/build"
if [ ! -f "$CBOR_TARBALL" ]; then
  curl -fsSL -o "$CBOR_TARBALL" "https://github.com/PJK/libcbor/archive/refs/tags/$CBOR_PIN.tar.gz"
fi
have_cbor_sha="$(shasum -a 256 "$CBOR_TARBALL" | awk '{print $1}')"
if [ "$have_cbor_sha" != "$CBOR_TARBALL_SHA256" ]; then
  echo "FATAL: libcbor-$CBOR_PIN.tar.gz SHA-256 is $have_cbor_sha, expected $CBOR_TARBALL_SHA256."
  echo "       Refusing to build an unverified tarball. Delete it and re-run, or update"
  echo "       the pin DELIBERATELY alongside the version bump."
  exit 1
fi
rm -rf "$CBOR_WORK" "$CBOR_BUILD"; mkdir -p "$CBOR_WORK"
tar -xf "$CBOR_TARBALL" -C "$CBOR_WORK" --strip-components=1
cmake -S "$CBOR_WORK" -B "$CBOR_BUILD" \
  -DCMAKE_OSX_ARCHITECTURES="$ARCH" \
  -DCMAKE_OSX_DEPLOYMENT_TARGET="$MIN" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DWITH_TESTS=OFF \
  -DWITH_EXAMPLES=OFF \
  -DCMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE=OFF >/dev/null
# ^ libcbor turns LTO on for Release builds, which emits LLVM-BITCODE members
# instead of Mach-O objects; `xcodebuild -create-xcframework` then refuses the
# merged archive ("Unknown header: 0xb17c0de"). Plain objects only here.
cmake --build "$CBOR_BUILD" --config Release -j"$(sysctl -n hw.ncpu)" >/dev/null
CBOR_LIB="$CBOR_BUILD/src/libcbor.a"
[ -f "$CBOR_LIB" ] || { echo "FATAL: static libcbor.a not produced"; exit 1; }

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

/* --- SimpleVPN addition ---
 * Session keepalive (OpenSSH ServerAliveInterval's message): a
 * "keepalive@openssh.com" global request with want_reply, so an idle tunnel
 * keeps NAT/firewall state alive AND a dead peer is detected. libssh's own
 * ssh_send_keepalive() lives in src/server.c, which WITH_SERVER=OFF does not
 * compile, and ssh_global_request() is not public API — so the wrapper lives
 * here for the same reason the tun one does. SSHBridge declares the prototype. */
__attribute__((visibility("default")))
int libsshx_send_keepalive(ssh_session session)
{
    if (session == NULL) {
        return SSH_ERROR;
    }
    /* The peer answers with REQUEST_FAILURE (it is not a request anyone grants);
     * that round trip is the point. Its error code is not meaningful. */
    (void)ssh_global_request(session, "keepalive@openssh.com", NULL, 1);
    return SSH_OK;
}
EOF
fi

# Client library only: server, examples, tests, SFTP, pcap capture and the
# config-driven exec paths (ProxyCommand/match exec — a VPN app must never let a
# config file run commands) are all OFF. GSSAPI stays ON — that's a migration
# win over libssh2 (Kerberos single sign-on) and macOS provides it in the SDK.
echo "==> configure (static, OpenSSL backend, GSSAPI + FIDO2 on, server/examples/tests off)"
rm -rf "$BUILD"
# LIBFIDO2_LIBRARY is seeded so cmake's find_library can't prefer the dylib (its
# search suffixes put .dylib before .a on Apple) — a dylib here would defeat the
# whole static-linking design.
cmake -S "$WORK" -B "$BUILD" \
  -DCMAKE_OSX_ARCHITECTURES="$ARCH" \
  -DCMAKE_OSX_DEPLOYMENT_TARGET="$MIN" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DOPENSSL_ROOT_DIR="$O3" \
  -DWITH_GSSAPI=ON \
  -DWITH_FIDO2=ON \
  -DLIBFIDO2_ROOT_DIR="$FIDO2" \
  -DLIBFIDO2_INCLUDE_DIR="$FIDO2/include" \
  -DLIBFIDO2_LIBRARY="$FIDO2/lib/libfido2.a" \
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
# Same trap for FIDO2: a missing libfido2 is a WARNING in libssh's CMakeLists and
# HAVE_LIBFIDO2 silently goes OFF, which would ship an engine that cannot use an
# sk- key file at all — the exact gap this option exists to close.
if ! grep -q "With libfido2 (internal usb-hid support): ON" "$BUILD.cmake.log"; then
  echo "FATAL: cmake did not find libfido2, so sk-ssh-ed25519 / sk-ecdsa key FILES"
  echo "       would not work (agent-held keys still would). Expected the Homebrew"
  echo "       static archive at $FIDO2/lib/libfido2.a with headers in $FIDO2/include."
  exit 1
fi
rm -f "$BUILD.cmake.log"

echo "==> build"
cmake --build "$BUILD" --config Release -j"$(sysctl -n hw.ncpu)"

LIB="$BUILD/src/libssh.a"
[ -f "$LIB" ] || LIB="$(find "$BUILD" -name 'libssh*.a' | head -1)"
[ -n "$LIB" ] && [ -f "$LIB" ] || { echo "ERROR: libssh static archive not found"; exit 1; }
echo "==> found $LIB"

echo "==> merge static lib (libssh + OpenSSL + libfido2 + libcbor; zlib/GSSAPI/IOKit are system)"
if ! libtool -static -o "$BUILD/libSSHEngine.a" \
  "$LIB" "$O3/lib/libssl.a" "$O3/lib/libcrypto.a" \
  "$FIDO2/lib/libfido2.a" "$CBOR_LIB" 2> "$BUILD/libtool.err"; then
  cat "$BUILD/libtool.err"; echo "FATAL: libtool merge failed"; exit 1
fi
grep -v 'has no symbols' "$BUILD/libtool.err" >&2 || true

echo "==> smoke-test: required symbols DEFINED in the merged archive"
# NOTE: grep -c, not grep -q. Under `set -o pipefail`, grep -q exits on the first match
# and closes the pipe, nm dies of SIGPIPE, and the whole pipeline reports failure — so a
# PASSING smoke test reads as FATAL. grep -c consumes all input, so nm exits cleanly.
NM="$BUILD/nm.symbols"
nm "$BUILD/libSSHEngine.a" 2>/dev/null > "$NM"
# DEFINED, not merely mentioned. A bare `grep _fido_dev_open` also matches the
# UNDEFINED reference (`U _fido_dev_open`) that libssh's own object files carry, and
# matches the archive-member header line `sk_usbhid.c.o:` for anything named after
# its file — so the check would pass on an archive with libfido2 MISSING, which is
# exactly the failure it exists to catch. Anchor on nm's address + `T` (external) or
# `t` (static — libssh's sk_usbhid entry points are file-static) instead.
#
# _pki_sk_enroll_key proves WITH_FIDO2 compiled the sk key paths;
# _ssh_sk_usbhid_load_resident_keys proves libfido2 itself was found (sk_usbhid.c is
# gated on HAVE_LIBFIDO2); _fido_dev_open proves the merged archive carries libfido2.
# Without them an sk- key FILE fails to authenticate and only agent-held security
# keys work — silently, which is the whole reason these are asserted.
# SimpleVPNTests/ControlPlane/SecurityKeySSHTests.swift re-checks the same symbols
# against the SHIPPED archive, so this can't be the only place that knows.
for sym in _ssh_new _ssh_connect _ssh_session_is_known_server _ssh_userauth_gssapi \
           _ssh_gssapi_set_creds _libsshx_channel_open_tun _libsshx_send_keepalive \
           _pki_sk_enroll_key _ssh_sk_usbhid_load_resident_keys _fido_dev_open \
           _cbor_load; do
  if ! grep -cE "^[0-9a-f]+ [Tt] ${sym}\$" "$NM" >/dev/null; then
    echo "FATAL: $sym is not DEFINED in the merged archive."
    echo "       (found: $(grep -E "[ ]${sym}\$" "$NM" | head -3 | tr '\n' ';' || echo 'nothing'))"
    exit 1
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

echo "==> done: $VENDOR/SSHEngine.xcframework"
echo "    (link also -lz, -lgssapi_krb5, and IOKit + CoreFoundation for libfido2's USB HID)"
