#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
# Build a notarizable Developer ID release of SimpleVPN (app + system extension),
# notarize it, staple the ticket, and install to /Applications so the system
# extension can activate with SIP enabled (no developer mode needed).
#
# Requires: a notarytool keychain profile named "SimpleVPN-Notary" (already set up).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DD="$REPO/build/dd"

# Monotonic build number so you can confirm the running app is this build.
mkdir -p "$REPO/build"
BUILDNO_FILE="$REPO/build/buildnumber.txt"
BUILDNO=$(( $(cat "$BUILDNO_FILE" 2>/dev/null || echo 0) + 1 ))
echo "$BUILDNO" > "$BUILDNO_FILE"
echo "==> build number $BUILDNO"
APP="$DD/Build/Products/Release/SimpleVPN.app"
ZIP="$REPO/build/SimpleVPN.zip"

# Notary credentials passed directly (keychain-profile lookups are unreliable in
# non-interactive/background contexts). Key + IDs come from the asc credentials.
NOTARY_KEYID="$(python3 -c "import json,os;C=json.load(open(os.path.expanduser('~/.asc/credentials.json')));print(C['accounts'][C['active']]['keyID'])")"
NOTARY_KEY="$HOME/.asc/AuthKey_${NOTARY_KEYID}.p8"
NOTARY_ISSUER="$(python3 -c "import json,os;C=json.load(open(os.path.expanduser('~/.asc/credentials.json')));print(C['accounts'][C['active']]['issuerID'])")"

echo "==> Release build (Developer ID, hardened runtime, no get-task-allow)"
# codesign --timestamp contacts Apple's TSA and can fail transiently; retry a few times.
build_once() {
  xcodebuild -project "$REPO/SimpleVPN.xcodeproj" -scheme SimpleVPN -configuration Release \
    -destination 'generic/platform=macOS' -derivedDataPath "$DD" \
    CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO \
    OTHER_CODE_SIGN_FLAGS="--timestamp" \
    CURRENT_PROJECT_VERSION="$BUILDNO" \
    clean build
}
n=0
until build_once; do
  n=$((n + 1))
  if [ "$n" -ge 3 ]; then echo "ERROR: Release build failed after $n attempts"; exit 1; fi
  echo "   build failed (likely transient TSA/codesign) — retry $n in 8s…"; sleep 8
done

echo "==> verify not debuggable (no get-task-allow)"
if codesign -d --entitlements - --xml "$APP" 2>/dev/null | grep -q "get-task-allow"; then
  echo "ERROR: get-task-allow present; not notarizable"; exit 1
fi
echo "    ok"

echo "==> zip + submit to notary (waits for result)"
rm -f "$ZIP"
/usr/bin/ditto -c -k --keepParent "$APP" "$ZIP"
xcrun notarytool submit "$ZIP" --key "$NOTARY_KEY" --key-id "$NOTARY_KEYID" --issuer "$NOTARY_ISSUER" --wait

echo "==> staple"
xcrun stapler staple "$APP"

echo "==> install to /Applications"
rm -rf "/Applications/SimpleVPN.app"
cp -R "$APP" /Applications/
echo "==> done: /Applications/SimpleVPN.app (build $BUILDNO)"
spctl -a -vvv --type exec "/Applications/SimpleVPN.app" 2>&1 | head -3 || true
