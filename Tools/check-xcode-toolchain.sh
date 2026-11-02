#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail

if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != --icon-composer ]; }; then
  echo "usage: $0 [--icon-composer]" >&2
  exit 64
fi

xcodebuild -version
SDK_VERSION="$(xcrun --sdk macosx --show-sdk-version)"
if ! python3 - "$SDK_VERSION" <<'PYSDK'
import sys
version = tuple(int(part) for part in sys.argv[1].split('.')[:2])
sys.exit(0 if version >= (26, 0) else 1)
PYSDK
then
  echo "FATAL: macOS SDK 26.0 or later is required; selected SDK is $SDK_VERSION." >&2
  exit 1
fi

if [ "${1:-}" = --icon-composer ]; then
  DEVELOPER_DIR_PATH="$(xcode-select -p)"
  ICTOOL="$(dirname "$DEVELOPER_DIR_PATH")/Applications/Icon Composer.app/Contents/Executables/ictool"
  if [ ! -x "$ICTOOL" ]; then
    echo "FATAL: the selected Xcode does not include Icon Composer." >&2
    exit 1
  fi
  # Older Icon Composer rejects the document's refractivity/specular features.
  if ! "$ICTOOL" --version | python3 -c 'import json,sys; v=json.load(sys.stdin)["short-bundle-version"]; sys.exit(0 if int(v.split(".")[0]) >= 2 else 1)'; then
    echo "FATAL: the app icon requires Icon Composer 2 or later (Xcode 27+)." >&2
    exit 1
  fi
fi

echo "Toolchain ready (macOS SDK $SDK_VERSION; deployment target macOS 26.0)."
