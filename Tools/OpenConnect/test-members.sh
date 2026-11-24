#!/bin/bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
# Run against an existing signed Xcode build. Every gateway is local to the test.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
derived="${1:?Usage: test-members.sh PATH/TO/DERIVED-DATA [Release|Debug]}"
configuration="${2:-Release}"
case "$configuration" in Release|Debug) ;; *) echo "Expected Release or Debug" >&2; exit 2 ;; esac
objects="$derived/Build/Intermediates.noindex/SimpleVPN.build/$configuration/PacketTunnel.build/Objects-normal/arm64"
helper="$derived/Build/Products/$configuration/SimpleVPN.app/Contents/MacOS/ocauth-helper"
tmp="$(mktemp -d)"
trap 'rm -f "$tmp/probe"; rmdir "$tmp"' EXIT
xcrun clang++ -std=c++20 -fobjc-arc -I "$root/PacketTunnel/Bridges" -I "$root/Vendor/openconnect-include" \
  "$root/Tools/OpenConnect/MemberProbe.mm" "$objects/OpenConnectBridge.o" "$objects/VirtualDatagramPort.o" \
  "$root/Vendor/OpenConnectEngine.xcframework/macos-arm64/libOpenConnectEngine.a" \
  -framework Foundation -framework Security -framework NetworkExtension -framework CoreFoundation \
  -lxml2 -lz -liconv -lresolv -o "$tmp/probe"
python3 -B "$root/Tools/OpenConnect/member-peer-test.py" "$tmp/probe"
python3 -B "$root/Tools/OpenConnect/legacy-member-peer-test.py" "$tmp/probe"
python3 -B "$root/Tools/OpenConnect/legacy-auth-peer-test.py" "$helper"
