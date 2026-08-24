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
REUSE_EXISTING_BUILD=false

if [ "${1:-}" = "--reuse-build" ]; then
  REUSE_EXISTING_BUILD=true
elif [ -n "${1:-}" ]; then
  echo "usage: $0 [--reuse-build]" >&2
  exit 64
fi

# Monotonic build number so you can confirm the running app is this build.
# The helper updates both the committed source of truth and Xcode's Debug
# default; leaving one at its old value is how reports once said build 1 while
# the release/appcast said 120.
APP="$DD/Build/Products/Release/SimpleVPN.app"
ZIP="$REPO/build/SimpleVPN.zip"
if "$REUSE_EXISTING_BUILD"; then
  BUILDNO="$(tr -d '\n' < "$REPO/BUILDNUMBER")"
  if [ ! -d "$APP" ]; then
    echo "ERROR: no existing Release app at $APP" >&2
    exit 1
  fi
  echo "==> reusing build number $BUILDNO"
else
  BUILDNO="$("$REPO/Tools/bump-build-number.sh")"
  ( cd "$REPO" && xcodegen generate )
  echo "==> build number $BUILDNO"
fi

# Notary credentials passed directly (keychain-profile lookups are unreliable in
# non-interactive/background contexts). Key + IDs come from the asc credentials.
NOTARY_KEYID="$(python3 -c "import json,os;C=json.load(open(os.path.expanduser('~/.asc/credentials.json')));print(C['accounts'][C['active']]['keyID'])")"
NOTARY_KEY="$HOME/.asc/AuthKey_${NOTARY_KEYID}.p8"
NOTARY_ISSUER="$(python3 -c "import json,os;C=json.load(open(os.path.expanduser('~/.asc/credentials.json')));print(C['accounts'][C['active']]['issuerID'])")"

echo "==> geoip database freshness (refetched when >1 week old; soft-fails offline)"
"$REPO/Tools/fetch-geoip.sh"

if ! "$REUSE_EXISTING_BUILD"; then
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
fi

echo "==> re-sign Sparkle nested executables (notary requires our Developer ID + timestamp)"
# A stapled ticket lives at Contents/CodeResources.  It must not be present
# when the app is re-sealed: otherwise a reuse of an already-notarized build
# seals the old ticket as an ordinary resource, and the next staple changes a
# sealed file.  It is generated notarization output, never user content.
rm -f "$APP/Contents/CodeResources"
"$REPO/Tools/resign-sparkle.sh" "$APP"

echo "==> verify not debuggable (no get-task-allow)"
if codesign -d --entitlements - --xml "$APP" 2>/dev/null | grep -q "get-task-allow"; then
  echo "ERROR: get-task-allow present; not notarizable"; exit 1
fi
echo "    ok"

echo "==> zip + submit to notary (waits for result)"
rm -f "$ZIP"
/usr/bin/ditto -c -k --keepParent "$APP" "$ZIP"
# Capture the submission id and status so a rejection can be diagnosed — `submit
# --wait` alone prints "Invalid" with no reason; the notary *log* has the details.
SUBMIT_OUT="$(xcrun notarytool submit "$ZIP" --key "$NOTARY_KEY" --key-id "$NOTARY_KEYID" --issuer "$NOTARY_ISSUER" --wait 2>&1)"
echo "$SUBMIT_OUT"
SUBID="$(echo "$SUBMIT_OUT" | awk '/^ *id:/ {print $2; exit}')"
if ! echo "$SUBMIT_OUT" | grep -q "status: Accepted"; then
  echo "ERROR: notarization was not Accepted."
  if [ -n "$SUBID" ]; then
    echo "==> fetching notary log for $SUBID"
    xcrun notarytool log "$SUBID" --key "$NOTARY_KEY" --key-id "$NOTARY_KEYID" --issuer "$NOTARY_ISSUER" || true
  fi
  exit 1
fi

echo "==> staple"
xcrun stapler staple "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"

echo "==> install to /Applications"
rm -rf "/Applications/SimpleVPN.app"
cp -R "$APP" /Applications/
codesign --verify --deep --strict --verbose=2 "/Applications/SimpleVPN.app"
echo "==> done: /Applications/SimpleVPN.app (build $BUILDNO)"
spctl -a -vvv --type exec "/Applications/SimpleVPN.app" 2>&1 | head -3 || true
