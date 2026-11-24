#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
# The OpenSSH 10.6p2 tarball was verified with the upstream release signature.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
version=10.6p2
digest=9ae44872090cf2f06b3cf9ff147e7f16f309671340763ed2f99248398ae29d5b
work="$repo/build/openssh-client"
crypto="$repo/build/pinned-openssl"
archive="${OPENSSH_TARBALL:-$work/openssh-$version.tar.gz}"
mkdir -p "$work" "$repo/Vendor/openssh/bin"
"$repo/Tools/build-openssl.sh"
if [[ ! -f "$archive" ]]; then
    curl --fail --location --retry 3 "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-$version.tar.gz" -o "$work/download.tmp"
    mv "$work/download.tmp" "$archive"
fi
echo "$digest  $archive" | shasum -a 256 -c -
receipt="$(shasum -a 256 "$repo/Tools/OpenSSH/supervised-listeners.patch" "$0" "$crypto/.simplevpn-build") $(xcrun --show-sdk-build-version) $digest"
if [[ ! -f "$work/configured" || "$(cat "$work/configured")" != "$receipt" ]]; then
    src="$(mktemp -d "$work/build.XXXXXX")"
    tar -xzf "$archive" --strip-components=1 -C "$src"
    cd "$src"
    patch -p1 < "$repo/Tools/OpenSSH/supervised-listeners.patch"
    CC=/usr/bin/clang KRB5CONF=/usr/bin/krb5-config CFLAGS="-O2 -g0 -arch arm64 -mmacosx-version-min=26.0" CPPFLAGS="-I$crypto/include" LDFLAGS="-L$crypto/lib -framework GSS" ./configure --with-ssl-dir="$crypto" --with-kerberos5 --sysconfdir=/etc/ssh --with-default-path=/usr/bin:/bin
    make -j8 ssh
    install -m 755 ssh "$repo/Vendor/openssh/bin/ssh"
    printf '%s' "$receipt" > "$work/configured"
fi
