#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
#
# Build the installer DMG from an already-built, stapled SimpleVPN.app.
# dmgbuild writes the Finder layout without requiring a GUI session.
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

mkdir -p "$REPO/build" "$OUT_DIR"
STAGE="$(mktemp -d "$REPO/build/dmg-stage.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
# ARCHS is arm64-only project-wide (project.yml: engine xcframeworks are arm64
# slices) so the filename must say so — an unqualified SimpleVPN.dmg that
# silently fails to launch on Intel would be a support disaster.
DMG_NAME="SimpleVPN-${VERSION}-arm64.dmg"
DMG="$OUT_DIR/$DMG_NAME"
BUILDNO="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$APP/Contents/Info.plist")"

echo "==> stage DMG contents"
cp -R "$APP" "$STAGE/"
if [ -f "$REPO/LICENSE" ]; then
  cp "$REPO/LICENSE" "$STAGE/LICENSE.txt"
fi
cat > "$STAGE/Read Me First.txt" <<'EOF'
SimpleVPN — Read Me First
==========================

1. Double-click SimpleVPN.app in this window. Follow the installer to
   install or update SimpleVPN and open the copy in Applications.

2. If prompted, approve the SimpleVPN network extension in System Settings >
   General > Login Items & Extensions.

This build is Apple Silicon (arm64) only.
EOF

echo "==> build Finder layout and create $DMG_NAME"
xcrun swift -module-cache-path "$REPO/build/dmg-module-cache" \
  "$REPO/Tools/dmg-background.swift" "$STAGE/background.png"
mkdir "$STAGE/Volume.iconset"
xcrun swift -module-cache-path "$REPO/build/dmg-module-cache" \
  "$REPO/Tools/dmg-icon.swift" "$STAGE/Volume.iconset"
iconutil -c icns "$STAGE/Volume.iconset" -o "$STAGE/Volume.icns"
rm -f "$DMG"
dmgbuild -s "$REPO/Tools/dmg-settings.py" \
  -D "stage=$STAGE" -D "background=$STAGE/background.png" -D "icon=$STAGE/Volume.icns" \
  "SimpleVPN $VERSION (build $BUILDNO)" "$DMG"

# Sign the DMG itself (separate from the app's own signature, already applied
# and notarized/stapled before this script ran). SIGN_ID defaults to the
# Developer ID Application identity; override via env if more than one is
# ever installed in the signing keychain.
SIGN_ID="${SIGN_ID:-Developer ID Application}"
echo "==> codesign DMG ($SIGN_ID)"
codesign --force --timestamp --sign "$SIGN_ID" "$DMG"
codesign --verify --strict --verbose=2 "$DMG"

echo "==> done: $DMG"
