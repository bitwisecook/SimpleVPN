#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
#
# End-to-end DISTRIBUTION build: Release build -> notarize+staple the .app ->
# build the drag-install DMG -> notarize+staple the DMG -> verify everything a
# recipient's Mac will check. Deliberately does NOT install to /Applications —
# that is what Tools/build-notarize-install.sh is for (the local live-test
# path). This script is the one CI runs, and it is written to behave
# identically when run by hand on a dev Mac, which is how it must be proven
# before it is ever trusted in CI (see Docs/Release.md).
#
# Usage: Tools/build-release-dmg.sh [version]
#   VERSION resolves, in order: $1, $MARKETING_VERSION env,
#     `git describe --tags --exact-match` with a leading "v" stripped, then the
#     MARKETING_VERSION literal in project.yml (so a plain local run still
#     produces a sensibly-named DMG instead of erroring out).
#   BUILDNO resolves from $CURRENT_PROJECT_VERSION env, else the same local
#     build/buildnumber.txt monotonic counter build-notarize-install.sh uses.
#     CI must set CURRENT_PROJECT_VERSION (release.yml passes the committed BUILDNUMBER)
#     because an ephemeral runner's own counter would always read back as 1.
#
# Notarization credentials: set NOTARY_KEY/NOTARY_KEYID/NOTARY_ISSUER (CI path)
# or leave unset to fall back to the local ~/.asc credential store — see
# Tools/lib/notary.sh for the full resolution order.
#
# NOTE ON VALIDATION: syntax-checked (bash -n) and the ordering/verify logic has
# been reviewed, but the build -> notarize -> staple path has NOT been exercised
# end to end — that needs a real Xcode Release build and live notary
# credentials. Treat the notarization/stapling steps as unvalidated until a real
# run confirms them (which Docs/Release.md requires before trusting CI).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=Tools/lib/notary.sh
source "$REPO/Tools/lib/notary.sh"

VERSION="${1:-${MARKETING_VERSION:-}}"
if [ -z "$VERSION" ]; then
  VERSION="$(git -C "$REPO" describe --tags --exact-match 2>/dev/null || true)"
  VERSION="${VERSION#v}"
fi
if [ -z "$VERSION" ]; then
  # Last resort: the literal xcodebuild would have used by default anyway.
  VERSION="$(awk -F'"' '/MARKETING_VERSION:/ {print $2; exit}' "$REPO/project.yml")"
fi
if [ -z "$VERSION" ]; then
  echo "FATAL: no version given, \$MARKETING_VERSION unset, no exact tag checked out,"
  echo "       and no MARKETING_VERSION found in project.yml."
  echo "       usage: Tools/build-release-dmg.sh <version>"
  exit 1
fi

if [ -n "${CURRENT_PROJECT_VERSION:-}" ]; then
  BUILDNO="$CURRENT_PROJECT_VERSION"
else
  # Local runs bump the same counter build-notarize-install.sh uses, so two
  # hand-built DMGs of one version aren't both build 1 (which the notary and
  # Gatekeeper tolerate, but which makes crash reports ambiguous).
  mkdir -p "$REPO/build"
  BUILDNO_FILE="$REPO/build/buildnumber.txt"
  BUILDNO=$(( $(cat "$BUILDNO_FILE" 2>/dev/null || echo 0) + 1 ))
  echo "$BUILDNO" > "$BUILDNO_FILE"
fi

echo "==> SimpleVPN release build: version=$VERSION build=$BUILDNO"

DD="$REPO/build/dd"
APP="$DD/Build/Products/Release/SimpleVPN.app"
ZIP="$REPO/build/SimpleVPN.zip"
SYSEXT="$APP/Contents/Library/SystemExtensions/com.bragi0.SimpleVPN.PacketTunnel.systemextension"

# --- Ordering is load-bearing: geoip -> xcodegen -> build -----------------
# Vendor/geoip/dbip-country-lite.mmdb is `optional: true` in project.yml, so
# xcodegen only wires it into the Copy Resources phase if the file already
# exists at *generate* time. Running fetch-geoip.sh after `xcodegen generate`
# would produce a build that succeeds but silently ships with no GeoIP DB (no
# error — just a degraded endpoint map). And because SimpleVPN.xcodeproj/ and
# all of Vendor/ are gitignored, CI has nothing else to fall back on: this is
# the one and only chance to get the mmdb into the generated project.
echo "==> geoip database freshness (refetched when >7 days old; soft-fails offline)"
"$REPO/Tools/fetch-geoip.sh"

echo "==> xcodegen generate"
( cd "$REPO" && xcodegen generate )

echo "==> Release build (Developer ID, hardened runtime, no get-task-allow)"
# codesign --timestamp contacts Apple's TSA and can fail transiently; retry a
# few times rather than fail the whole release job on a blip (verbatim retry
# shape from Tools/build-notarize-install.sh).
build_once() {
  xcodebuild -project "$REPO/SimpleVPN.xcodeproj" -scheme SimpleVPN -configuration Release \
    -destination 'generic/platform=macOS' -derivedDataPath "$DD" \
    CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO \
    OTHER_CODE_SIGN_FLAGS="--timestamp" \
    MARKETING_VERSION="$VERSION" \
    CURRENT_PROJECT_VERSION="$BUILDNO" \
    clean build
}
n=0
until build_once; do
  n=$((n + 1))
  if [ "$n" -ge 3 ]; then echo "ERROR: Release build failed after $n attempts"; exit 1; fi
  echo "   build failed (likely transient TSA/codesign) — retry $n in 8s…"; sleep 8
done

echo "==> re-sign Sparkle nested executables (notary requires our Developer ID + timestamp)"
"$REPO/Tools/resign-sparkle.sh" "$APP"

echo "==> verify not debuggable (no get-task-allow)"
if codesign -d --entitlements - --xml "$APP" 2>/dev/null | grep -q "get-task-allow"; then
  echo "ERROR: get-task-allow present; not notarizable"; exit 1
fi
echo "    ok"

echo "==> deep verify app signature"
codesign --verify --deep --strict --verbose=2 "$APP"

# A missing/unsigned embedded system extension is the failure that otherwise
# only shows up much later as a user-facing "extension failed to activate"
# error, with nothing in the build log to point at it — check for it here
# where it is cheap to diagnose.
echo "==> verify embedded system extension is present and signed"
if [ ! -d "$SYSEXT" ]; then
  echo "FATAL: embedded system extension missing: $SYSEXT"; exit 1
fi
codesign --verify --strict --verbose=2 "$SYSEXT"
APP_TEAM="$(codesign -dv "$APP" 2>&1 | awk -F'=' '/^TeamIdentifier=/{print $2}')"
SYSEXT_TEAM="$(codesign -dv "$SYSEXT" 2>&1 | awk -F'=' '/^TeamIdentifier=/{print $2}')"
if [ "$APP_TEAM" != "$SYSEXT_TEAM" ] || [ -z "$APP_TEAM" ]; then
  echo "FATAL: app TeamIdentifier ($APP_TEAM) != sysext TeamIdentifier ($SYSEXT_TEAM)"; exit 1
fi
echo "    ok ($APP_TEAM)"

# --- Pass 1: notarize + staple the .app itself -----------------------------
# Notarizing only the DMG *is* accepted by the notary service (its ticket does
# cover nested code), but stapling only attaches a ticket to the thing you ran
# stapler on. A user who drags SimpleVPN.app out of the DMG would then be
# carrying an app with no embedded ticket, dependent on an online Gatekeeper
# lookup — a bad trade for an app whose whole job is networking and which may
# first launch on a captive or broken network. So: staple the app too.
echo "==> zip app + submit to notary (pass 1 of 2)"
rm -f "$ZIP"
/usr/bin/ditto -c -k --keepParent "$APP" "$ZIP"
notary_submit "$ZIP"

echo "==> staple app"
xcrun stapler staple "$APP"

# --- DMG (stages the now-stapled app) --------------------------------------
"$REPO/Tools/make-dmg.sh" "$APP" "$VERSION"
DMG="$REPO/build/dist/SimpleVPN-${VERSION}-arm64.dmg"

# --- Pass 2: notarize + staple the DMG --------------------------------------
echo "==> submit DMG to notary (pass 2 of 2)"
notary_submit "$DMG"

echo "==> staple DMG"
xcrun stapler staple "$DMG"

echo "==> final verification"
spctl -a -vvv --type exec "$APP"
spctl -a -vvv -t open --context context:primary-signature "$DMG"
xcrun stapler validate "$DMG"
shasum -a 256 "$DMG" | tee "$DMG.sha256"

echo "==> done: $DMG"
