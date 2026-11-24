#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
work="${1:?usage: build.sh work-directory}"
pin=77dcd25a72509eb83f72b033d219b1d40cd8eb95
mkdir -p "$work"
tree="$work/lwip.tar"
if [[ ! -e "$tree" ]]; then
    checkout="${LWIP_CHECKOUT:-$work/upstream}"
    if [[ ! -d "$checkout" ]]; then
        git clone --depth 1 --branch STABLE-2_2_1_RELEASE https://github.com/lwip-tcpip/lwip.git "$checkout"
    fi
    git -C "$checkout" archive --format=tar --prefix=lwip/ "$pin" > "$tree.new"
    mv "$tree.new" "$tree"
fi
echo "1b4ccd012ae8d696ccb9597f2b042dc2455136c3dd8cddc042536b77b7fc331c  $tree" | shasum -a 256 -c -
stamp="$(shasum -a 256 "$here"/*.h "$here"/*.c "$here"/lwip.patch "$here"/build.sh) $(xcrun --show-sdk-build-version) $(clang --version)"
if [[ -f "$work/ppp.o" && -f "$work/lns-fixture" && -f "$work/receipt" && "$(cat "$work/receipt")" = "$stamp" ]]; then exit 0; fi
tar -xf "$tree" -C "$work"
cd "$work/lwip"
patch -p1 < "$here/lwip.patch"
# Materialize tentative lwIP pools in bss. Mach-O otherwise infers 32 KiB
# alignment from the 64 KiB ram_heap size; lwIP aligns its own arena to MEM_ALIGNMENT.
flags=(-O2 -fno-common -arch arm64 -mmacosx-version-min=26.0 -DSIMPLEVPN_IPCP_DNS_ONLY -I"$here" -Isrc/include -Icontrib/ports/unix/port/include)
mkdir -p "$work/objects"
sources=(src/core/*.c src/core/ipv4/*.c src/netif/ppp/*.c src/netif/ppp/polarssl/*.c)
objects=()
for path in "${sources[@]}"; do
    object="$work/objects/${path//\//_}.o"
    clang "${flags[@]}" -c "$path" -o "$object"
    objects+=("$object")
done
clang "${flags[@]}" -Werror -c "$here/ppp-adapter.c" -o "$work/objects/adapter.o"
# Make the private lwIP stack a single relocatable object, keeping global
# symbols of other embedded networking engines independent of this version.
xcrun ld -r -arch arm64 -o "$work/combined.o" "$work/objects/adapter.o" "${objects[@]}"
nm -gU "$work/objects/adapter.o" | awk '$3 ~ /^_sv_ppp_/ {print $3}' > "$work/exports"
xcrun nmedit -s "$work/exports" -o "$work/ppp.o" "$work/combined.o"
# PPP_SERVER changes upstream PCB layout. Test code has its own build and
# never enters the provider archive.
clang "${flags[@]}" -DSIMPLEVPN_PPP_FIXTURE "$here/lns-fixture.c" "${sources[@]}" -o "$work/lns-fixture"
printf '%s\n' "$stamp" > "$work/receipt"
