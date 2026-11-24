#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
# Rebuild the strongSwan packet-flow archive and test its IKE/ESP integration.
# The release digest was verified against upstream's detached OpenPGP signature
# (Andreas Steffen, 948F158A4E76A27BF3D07532DF42C170B34DBA77).
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
version=6.1.0
digest=fe6c97481298767213cfc2e9a1da29fdd8018d481ff4cb9cf0283099654f20d4
work="${STRONGSWAN_BUILD_DIR:-$repo/build/strongswan-$version}"
source_dir="$work/src"
archive="${STRONGSWAN_TARBALL:-$work/strongswan-$version.tar.bz2}"
bridge="$repo/Tools/StrongSwan"
crypto="$repo/build/pinned-openssl"
mkdir -p "$work" "$repo/Vendor/strongswan-include"
"$repo/Tools/build-openssl.sh"
if [[ ! -f "$archive" ]]; then
    curl --fail --location --retry 3 "https://download.strongswan.org/strongswan-$version.tar.bz2" -o "$work/download.tmp"
    mv "$work/download.tmp" "$archive"
fi
echo "$digest  $archive" | shasum -a 256 -c -
"$bridge/L2TP/build.sh" "$work/ppp"
receipt="$digest $(xcrun --show-sdk-build-version) $(clang --version) $(shasum -a 256 "$bridge/packet-flow.patch" "$bridge/L2TP/transport.patch" "$repo/Tools/build-strongswan.sh" "$crypto/.simplevpn-build")"
if [[ ! -f "$work/configured" || "$(cat "$work/configured")" != "$receipt" ]]; then
    rm -rf "$source_dir"
    mkdir -p "$source_dir"
    tar -xjf "$archive" -C "$source_dir" --strip-components=1
    cd "$source_dir"
    patch -p1 < "$bridge/packet-flow.patch"
    patch -p1 < "$bridge/L2TP/transport.patch"
    CC=clang CFLAGS="-O2 -g0 -arch arm64 -mmacosx-version-min=26.0" \
    CPPFLAGS="-I$crypto/include" LDFLAGS="-arch arm64 -mmacosx-version-min=26.0 -L$crypto/lib" \
    ./configure --prefix=/usr/share/simplevpn/strongswan --disable-defaults --enable-static --disable-shared --enable-monolithic \
        --enable-charon --enable-ikev2 --enable-ikev1 --enable-libipsec --enable-kernel-libipsec \
        --enable-socket-default --enable-openssl --enable-random --enable-nonce --enable-kdf --enable-hmac \
        --enable-x509 --enable-pubkey --enable-pem --enable-pkcs1 --enable-pkcs8 \
        --enable-md4 --enable-des --enable-xauth-generic --enable-eap-mschapv2 --enable-eap-identity
    # Static registry only: the extension loads no engine plug-ins from disk.
    sed -i '' '/^#define HAVE_DLADDR /d' config.h
    printf '%s\n' "$receipt" > "$work/configured"
fi
cd "$source_dir"
make -j"${BUILD_JOBS:-8}" -C src/libstrongswan
make -j"${BUILD_JOBS:-8}" -C src/libipsec
make -j"${BUILD_JOBS:-8}" -C src/libcharon
flags=(-O2 -arch arm64 -mmacosx-version-min=26.0 -Werror -include "$source_dir/config.h"
       -I src/libstrongswan -I src/libcharon -I src/libipsec)
libs=("$work/ppp/ppp.o" src/libcharon/.libs/libcharon.a src/libipsec/.libs/libipsec.a src/libstrongswan/.libs/libstrongswan.a)
clang "${flags[@]}" -c "$bridge/engine.c" -o "$work/engine.o"
clang "${flags[@]}" -c "$bridge/Worker/worker-client.c" -o "$work/worker-client.o"
clang "${flags[@]}" -c "$bridge/Worker/worker.c" -o "$work/worker.o"
clang "${flags[@]}" -c "$bridge/apple-trust.c" -o "$work/apple-trust.o"
clang "${flags[@]}" -DSIMPLEVPN_IPSEC_FIXTURE "$bridge/apple-trust.c" "$bridge/peer-test.c" "${libs[@]}" "$crypto/lib/libcrypto.a" -framework CoreFoundation -framework Security -o "$work/peer-test"
python3 "$bridge/peer-test.py" "$work/peer-test" "$work/ppp/lns-fixture"
if [[ "${IPSEC_UDP_PEER_TEST:-0}" = 1 ]]; then
    clang "${flags[@]}" -DSIMPLEVPN_IPSEC_FIXTURE -DSIMPLEVPN_IPSEC_UDP_FIXTURE \
        "$bridge/apple-trust.c" "$bridge/peer-test.c" "${libs[@]}" "$crypto/lib/libcrypto.a" \
        -framework CoreFoundation -framework Security -o "$work/udp-peer-test"
    python3 "$bridge/peer-test.py" "$work/udp-peer-test" "$work/ppp/lns-fixture"
    clang "${flags[@]}" -I"$bridge" -DSIMPLEVPN_IPSEC_FIXTURE -DSIMPLEVPN_IPSEC_UDP_FIXTURE "$bridge/Worker/main.c" \
        "$bridge/Worker/worker.c" "$bridge/engine.c" "$bridge/apple-trust.c" "${libs[@]}" "$crypto/lib/libcrypto.a" \
        -framework Security -framework CoreFoundation -o "$work/worker-fixture"
    codesign --force --sign - --identifier com.bragi0.SimpleVPN.IPsecFixture "$work/worker-fixture"
    clang "${flags[@]}" -DSIMPLEVPN_WORKER_FIXTURE "$bridge/Worker/worker-client.c" "$bridge/Worker/member-test.c" \
        -framework Security -framework CoreFoundation -o "$work/worker-test"
    python3 "$bridge/Worker/member-test.py" "$work/worker-test" "$work/worker-fixture" "$work/udp-peer-test"
fi
# Other native provider libraries already supply the same pinned libcrypto.
# Keep upstream static plugin registrations under their original object names.
/usr/bin/libtool -D -static -o "$work/libSimpleIPsec.a" "$work/engine.o" "$work/apple-trust.o" "$work/worker-client.o" "$work/worker.o" "${libs[@]}"
cp "$bridge/SVIPsec.h" "$bridge/SVIPsecWorker.h" "$repo/Vendor/strongswan-include/"
mv "$work/libSimpleIPsec.a" "$repo/Vendor/libSimpleIPsec.a"
