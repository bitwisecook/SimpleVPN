#!/bin/bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
app=${1:?expected the built SimpleVPN.app}
extension="$app/Contents/Library/SystemExtensions/com.bragi0.SimpleVPN.PacketTunnel.systemextension"
requirement='anchor apple generic and identifier "com.bragi0.SimpleVPN.SourceIdentity" and certificate leaf[subject.OU] = "QVUFB5676H"'
for host in "$app" "$extension"; do
    helper="$host/Contents/XPCServices/SourceIdentityHelper.xpc"
    /usr/bin/codesign --verify --strict -R "=$requirement" "$helper"
    /usr/bin/codesign -d --entitlements - --xml "$helper" 2>/dev/null | /usr/bin/python3 -c '
import plistlib, sys
entitlements = plistlib.loads(sys.stdin.buffer.read())
allowed = {"com.apple.security.app-sandbox", "com.apple.application-identifier", "com.apple.developer.team-identifier"}
if entitlements.get("com.apple.security.app-sandbox") is not True or set(entitlements) - allowed:
    raise SystemExit("Unexpected source identity helper entitlements")
'
done
