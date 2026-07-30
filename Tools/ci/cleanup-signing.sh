#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
#
# CI-only: undo import-signing.sh. Invoke this from an `if: always()` step so
# it runs even when the build/notarize steps fail — the signing key and
# provisioning profiles must not linger on the runner regardless of outcome.
# The runner is destroyed after the job either way, but delete anyway rather
# than rely on that.
set -uo pipefail  # not -e: best-effort cleanup, keep going if one step fails

KEYCHAIN="${SIMPLEVPN_CI_KEYCHAIN:-${RUNNER_TEMP:-}/simplevpn-signing.keychain-db}"

echo "==> delete temporary signing keychain"
if [ -n "$KEYCHAIN" ] && [ -f "$KEYCHAIN" ]; then
  security delete-keychain "$KEYCHAIN" 2>/dev/null || echo "    (already gone or delete failed, continuing)"
fi

echo "==> remove installed provisioning profiles"
rm -f "$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles/"*.provisionprofile
rm -f "$HOME/Library/MobileDevice/Provisioning Profiles/"*.provisionprofile

echo "==> remove decoded secrets from disk"
if [ -n "${RUNNER_TEMP:-}" ]; then
  rm -f "$RUNNER_TEMP/devid-app-cert.p12" \
        "$RUNNER_TEMP/DeveloperIDG2CA.cer" \
        "$RUNNER_TEMP/AppleIncRootCertificate.cer" \
        "$RUNNER_TEMP/app.mobileprovision" \
        "$RUNNER_TEMP/tunnel.mobileprovision"
  rm -rf "$RUNNER_TEMP/asc"
fi

echo "==> cleanup done"
