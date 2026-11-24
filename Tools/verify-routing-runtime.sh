#!/bin/bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
app="${1:?expected the built SimpleVPN.app}"
helpers="$app/Contents/Helpers"
provider_id="com.bragi0.SimpleVPN.PacketTunnel"
extension="$app/Contents/Library/SystemExtensions/$provider_id.systemextension"
provider="$extension/Contents/MacOS/$provider_id"
if ! LC_ALL=C /usr/bin/grep -aFq 'SimpleVPN IPsec packet flow / strongSwan 6.1.0' "$provider"; then
    echo "error: packet provider is missing the verified strongSwan engine" >&2
    exit 1
fi
for tool in routing-lsp routecheck ssh; do
    requirement="anchor apple generic and identifier \"com.bragi0.SimpleVPN.$tool\" and certificate leaf[subject.OU] = \"QVUFB5676H\""
    /usr/bin/codesign --verify --strict -R "=$requirement" "$helpers/$tool"
done
worker="$extension/Contents/Helpers/IPsecMemberWorker"
worker_requirement='anchor apple generic and identifier "com.bragi0.SimpleVPN.IPsecMemberWorker" and certificate leaf[subject.OU] = "QVUFB5676H"'
/usr/bin/codesign --verify --strict -R "=$worker_requirement" "$worker"
/usr/bin/codesign -d --entitlements - --xml "$worker" 2>/dev/null | /usr/bin/python3 -c '
import plistlib, sys
expected = {"com.apple.security.app-sandbox": True, "com.apple.security.inherit": True}
if plistlib.loads(sys.stdin.buffer.read()) != expected:
    raise SystemExit("Unexpected IPsec worker entitlements")
'
# The private OpenSSH dispatch and the packet extension have different hooks.
# Compiling each exercises the embedded native engine and its matching schema.
printf '%s\n' 'on check: ssh.reverse_delivery { if ssh.port == 25 { drop(); } }' |
    "$helpers/routecheck" --check-live-events ssh-openssh-reverse - >/dev/null
printf '%s\n' 'on check: ip.packet { count(); }' |
    "$helpers/routecheck" --check-live-events ikev2-strongswan - >/dev/null
printf '%s\n' 'on check: ip.packet { count(); }' |
    "$helpers/routecheck" --check-live-events l2tp-strongswan - >/dev/null
printf '%s\n' 'on check: route.select { if port.dst == 443 { route.exit_node("nExample"); } }' |
    "$helpers/routecheck" --check-live-events wireguard-shared - >/dev/null
