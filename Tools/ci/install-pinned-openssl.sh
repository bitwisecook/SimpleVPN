#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
#
# CI-only: make sure `brew install openssl@3` on the runner lands on exactly
# the version the three engine scripts are pinned to (OPENSSL_PIN), so their
# own drift guard (`have_ssl != $OPENSSL_PIN` -> FATAL, exit 1) passes instead
# of hard-failing the very first cache-miss build.
#
# HONESTY NOTE: Homebrew has no first-class "pin to this exact version"
# feature for source formulae once homebrew-core has moved past it — a plain
# `brew install openssl@3` always gets whatever the current formula says. This
# script works around that by installing the pinned version from a snapshot
# of the homebrew-core formula (via a throwaway local tap), which costs a
# source build (~6-10 minutes on a GitHub-hosted runner) instead of a fast
# bottle install. This is a workaround, not a supported Homebrew feature:
# `brew install --build-from-source` from a local tap could be affected by
# future Homebrew CLI changes, and `brew --prefix openssl@3` resolving to the
# local-tap keg afterwards is behaviour inferred from Homebrew's normal
# keg-linking, not something exercised on a runner yet — the first cache-miss
# CI run is the real test of this script. If it proves fragile, the honest
# fallback is to teach the three engine scripts to build OpenSSL from an
# upstream tarball at the pinned version instead of consuming Homebrew's — a
# bigger change touching all three scripts and local dev behaviour too.
#
# The engine scripts' own OPENSSL_PIN guard remains the authority: if this
# script's install doesn't take, the engine build fails loudly with the
# existing FATAL message rather than silently shipping OpenSSL-version-skewed
# xcframeworks.
#
# The pin is parsed out of build-openvpn3-xcframework.sh (never hardcoded
# here) so a deliberate pin bump in the engine scripts can't desync from CI.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PIN_SRC="$REPO/Tools/build-openvpn3-xcframework.sh"

OPENSSL_PIN="$(awk -F'"' '/^OPENSSL_PIN=/{print $2; exit}' "$PIN_SRC")"
if [ -z "$OPENSSL_PIN" ]; then
  echo "FATAL: could not parse OPENSSL_PIN out of $PIN_SRC"; exit 1
fi
echo "==> engine scripts pin openssl@3 to $OPENSSL_PIN"

have_ssl=""
if brew list --versions openssl@3 >/dev/null 2>&1; then
  have_ssl="$("$(brew --prefix openssl@3)/bin/openssl" version | awk '{print $2}')"
fi

if [ "$have_ssl" = "$OPENSSL_PIN" ]; then
  echo "==> openssl@3 $have_ssl already installed and matches the pin — nothing to do"
else
  echo "==> installed openssl@3 is '${have_ssl:-<none>}', pin wants $OPENSSL_PIN — installing pinned version"

  # Verified formula snapshot for OpenSSL 3.6.4 (Homebrew revision 1).
  # Update this SHA alongside OPENSSL_PIN; never default to moving master.
  HOMEBREW_CORE_COMMIT="${HOMEBREW_CORE_COMMIT_FOR_OPENSSL_PIN:-070af00fb0a104b18bb5e1a7c2be36b0177b917e}"
  FORMULA_URL="https://raw.githubusercontent.com/Homebrew/homebrew-core/${HOMEBREW_CORE_COMMIT}/Formula/o/openssl@3.rb"

  TAP_DIR="$(brew --repository)/Library/Taps/local/homebrew-pin"
  if [ ! -d "$TAP_DIR" ]; then
    brew tap-new local/pin --no-git
  fi
  mkdir -p "$(brew --repository)/Library/Taps/local/homebrew-pin/Formula"
  curl -fsSL "$FORMULA_URL" -o "$(brew --repository)/Library/Taps/local/homebrew-pin/Formula/openssl@3.rb"

  brew install --build-from-source local/pin/openssl@3
  brew link --overwrite --force openssl@3
fi

resolved="$("$(brew --prefix openssl@3)/bin/openssl" version 2>/dev/null | awk '{print $2}')"
if [ "$resolved" != "$OPENSSL_PIN" ]; then
  echo "FATAL: after install, '$(brew --prefix openssl@3)/bin/openssl version' reports '$resolved', not the pinned $OPENSSL_PIN."
  echo "       The pinned-tap workaround did not take. See the header comment in this script"
  echo "       for the honest fallback (build OpenSSL from an upstream tarball in the engine scripts)."
  exit 1
fi
echo "==> confirmed: $(brew --prefix openssl@3)/bin/openssl is $resolved"
