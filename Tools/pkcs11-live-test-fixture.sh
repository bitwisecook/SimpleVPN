#!/bin/bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
#
# Stands up a SOFTWARE PKCS#11 token so PKCS11LiveIntegrationTests can exercise the
# real enumeration path (our Swift code → the user's p11tool/pkcs11-tool → a real
# provider module → a real token holding a real certificate). Without it those tests
# skip, and PKCS11LiveIntegrationTests says so out loud.
#
# THIS IS A TEST DEPENDENCY ONLY. Nothing SoftHSM installs ends up in the app, and
# SimpleVPN never bundles a provider module for anyone's hardware (AGENTS.md /
# Docs/AuthSecPKCS11.md). Remove it all again with:
#
#     ./Tools/pkcs11-live-test-fixture.sh --remove
#
# Requires: brew install softhsm gnutls   (opensc as well, to exercise that parser)

set -euo pipefail

BREW="$(brew --prefix 2>/dev/null || echo /opt/homebrew)"
MODULE="$BREW/lib/softhsm/libsofthsm2.so"
LABEL="SimpleVPN PKCS11 Live Test"
TOKEN_URI="pkcs11:token=SimpleVPN%20PKCS11%20Live%20Test"
SO_PIN=3737363636
USER_PIN=123456
WORK="${TMPDIR:-/tmp}/simplevpn-pkcs11-live"

if [ "${1:-}" = "--remove" ]; then
  echo "==> removing the live PKCS#11 fixture"
  serial="$("$BREW/bin/softhsm2-util" --show-slots 2>/dev/null \
            | awk -v l="$LABEL" '$0 ~ "Label:[[:space:]]*"l {found=1} /Serial number:/ && found {print $3; exit}')"
  if [ -n "${serial:-}" ]; then
    "$BREW/bin/softhsm2-util" --delete-token --serial "$serial" || true
  fi
  rm -rf "$WORK"
  echo "    done. (SoftHSM itself: brew uninstall softhsm)"
  exit 0
fi

for tool in softhsm2-util p11tool; do
  if [ ! -x "$BREW/bin/$tool" ]; then
    echo "FATAL: $BREW/bin/$tool is missing."
    echo "       brew install softhsm gnutls"
    exit 1
  fi
done
[ -f "$MODULE" ] || { echo "FATAL: no SoftHSM module at $MODULE"; exit 1; }

mkdir -p "$WORK"
echo "==> initialising the token"
"$BREW/bin/softhsm2-util" --init-token --free --label "$LABEL" \
    --so-pin "$SO_PIN" --pin "$USER_PIN"

echo "==> generating a client certificate (CN=alex.hunt, 365 days)"
/usr/bin/openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$WORK/client.key" -out "$WORK/client.crt" -days 365 \
    -subj "/CN=alex.hunt/O=Example Corp/OU=Engineering" 2>/dev/null

echo "==> writing the key and certificate onto the token"
GNUTLS_PIN="$USER_PIN" GNUTLS_SO_PIN="$SO_PIN" "$BREW/bin/p11tool" --provider "$MODULE" \
    --login --write --load-privkey "$WORK/client.key" \
    --label "PIV AUTH key" --id 01 "$TOKEN_URI" --batch >/dev/null
GNUTLS_PIN="$USER_PIN" GNUTLS_SO_PIN="$SO_PIN" "$BREW/bin/p11tool" --provider "$MODULE" \
    --login --write --load-certificate "$WORK/client.crt" \
    --label "Certificate for PIV Authentication" --id 01 "$TOKEN_URI" --batch >/dev/null

echo
echo "==> ready. Run the live tests with:"
echo "    TEST_RUNNER_SIMPLEVPN_PKCS11_MODULE=$MODULE \\"
echo "      xcodebuild -project SimpleVPN.xcodeproj -scheme SimpleVPN \\"
echo "      -destination 'platform=macOS' test -only-testing:SimpleVPNTests"
