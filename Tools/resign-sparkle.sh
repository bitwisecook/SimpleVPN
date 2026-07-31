#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
#
# Re-sign Sparkle.framework's nested executables with OUR Developer ID and a
# secure timestamp, then re-seal the app. Sparkle ships pre-signed with the
# Sparkle project's own certificate, and Xcode's embed step re-signs only the
# framework itself — the nested XPC services / Autoupdate / Updater.app keep
# the upstream signature, which the notary rejects ("not signed with a valid
# Developer ID certificate" / "no secure timestamp"). Order is inside-out per
# Sparkle's sandboxing/signing docs; the app is re-signed last because
# touching anything inside it invalidates its seal.
#
# Usage: resign-sparkle.sh <path-to-SimpleVPN.app> [identity]
set -euo pipefail

APP="${1:?usage: resign-sparkle.sh <app> [identity]}"
IDENTITY="${2:-Developer ID Application}"
SPARKLE="$APP/Contents/Frameworks/Sparkle.framework"

if [ ! -d "$SPARKLE" ]; then
  echo "resign-sparkle: no Sparkle.framework in $APP" >&2
  exit 1
fi

V="$SPARKLE/Versions/B"
sign() { codesign -f -s "$IDENTITY" -o runtime --timestamp "$@"; }

# Installer.xpc keeps its own entitlements (it needs them to install updates).
sign --preserve-metadata=entitlements "$V/XPCServices/Installer.xpc"
sign "$V/XPCServices/Downloader.xpc"
sign "$V/Autoupdate"
sign "$V/Updater.app"
sign "$SPARKLE"

# Re-seal the app (its resource seal covers the framework we just modified),
# keeping the entitlements xcodebuild applied (NetworkExtension et al).
sign --preserve-metadata=entitlements "$APP"

codesign --verify --deep --strict "$APP"
echo "resign-sparkle: ok ($APP)"
