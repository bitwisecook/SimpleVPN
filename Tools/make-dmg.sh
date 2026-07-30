#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
#
# Build a drag-install DMG from an already-built (and ideally already-notarized
# + stapled) SimpleVPN.app. Deliberately NOT a Finder-styled DMG: no background
# image, no window geometry, no custom volume icon, no .DS_Store. All of that
# requires driving Finder over AppleScript (`tell application "Finder" to ...`),
# which needs a logged-in GUI session — it cannot work headless on a GitHub
# Actions runner, and this script is written to run identically there and here.
#
# Also, honestly: there is currently no artwork for a volume icon even locally.
# SimpleVPN/Assets.xcassets/AppIcon.appiconset/ contains only Contents.json with
# zero image files, and the built app has no Contents/Resources/AppIcon.icns
# (icons are compiled into Assets.car instead). When real icon art lands, this
# can be upgraded to the UDRW -> attach -> SetFile -a C -> detach -> hdiutil
# convert two-step to add a volume icon.
#
# Usage: Tools/make-dmg.sh <app-path> <version> [out-dir]
set -euo pipefail

APP="${1:?usage: make-dmg.sh <app-path> <version> [out-dir]}"
VERSION="${2:?usage: make-dmg.sh <app-path> <version> [out-dir]}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${3:-$REPO/build/dist}"

if [ ! -d "$APP" ]; then
  echo "FATAL: app not found at $APP"; exit 1
fi

STAGE="$REPO/build/dmg-stage"
# ARCHS is arm64-only project-wide (project.yml: engine xcframeworks are arm64
# slices) so the filename must say so — an unqualified SimpleVPN.dmg that
# silently fails to launch on Intel would be a support disaster.
DMG_NAME="SimpleVPN-${VERSION}-arm64.dmg"
DMG="$OUT_DIR/$DMG_NAME"

echo "==> stage DMG contents"
rm -rf "$STAGE"
mkdir -p "$STAGE" "$OUT_DIR"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
if [ -f "$REPO/LICENSE" ]; then
  cp "$REPO/LICENSE" "$STAGE/LICENSE.txt"
fi
cat > "$STAGE/Read Me First.txt" <<'EOF'
SimpleVPN — Read Me First
==========================

1. Drag SimpleVPN.app to the Applications folder (the shortcut is right here
   in this window). Do NOT run it directly from this disk image — macOS will
   refuse to load the system extension until the app is in /Applications.

2. Open SimpleVPN from Applications, then go to System Settings > General >
   Login Items & Extensions and approve the SimpleVPN network extension.
   Until you approve it there, connections will not work.

This build is Apple Silicon (arm64) only.
EOF

echo "==> hdiutil create $DMG_NAME"
rm -f "$DMG"
hdiutil create \
  -volname "SimpleVPN $VERSION" \
  -srcfolder "$STAGE" \
  -ov -fs HFS+ -format UDZO -imagekey zlib-level=9 \
  "$DMG"

# Sign the DMG itself (separate from the app's own signature, already applied
# and notarized/stapled before this script ran). SIGN_ID defaults to the
# Developer ID Application identity; override via env if more than one is
# ever installed in the signing keychain.
SIGN_ID="${SIGN_ID:-Developer ID Application}"
echo "==> codesign DMG ($SIGN_ID)"
codesign --force --timestamp --sign "$SIGN_ID" "$DMG"
codesign --verify --strict --verbose=2 "$DMG"

echo "==> done: $DMG"
