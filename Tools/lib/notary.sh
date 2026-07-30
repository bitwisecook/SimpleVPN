#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
#
# Sourced helper for notarytool credentials + submit-and-diagnose. This file has
# NO side effects on import (no `set -e` toggling the caller's shell, nothing
# executed at source time) — it only defines functions. Source it, then call:
#
#   notary_creds        # sets NOTARY_KEY / NOTARY_KEYID / NOTARY_ISSUER
#   notary_submit PATH  # zip/dmg already built; submits + waits + diagnoses
#
# Credential resolution is env-first, then falls back to the local ~/.asc
# layout used by build-notarize-install.sh, so this file is a drop-in extraction
# of that script's logic (lines 25-27, 60-70 as of the pre-CI version) rather
# than a rewrite — local behaviour must stay byte-identical.
#
# WHY --key/--key-id/--issuer instead of --keychain-profile:
# `xcrun notarytool submit --keychain-profile SimpleVPN-Notary` reads the
# profile from the *login* keychain via a Security framework call that requires
# an interactive/unlocked session. It is unreliable in background shells locally
# (see AGENTS.md) and simply does not work at all on a CI runner, which has no
# login keychain with that profile ever stored in it. Direct key material passed
# as flags works identically in both contexts, so it is the only path this repo
# uses for notarization now.

notary_creds() {
  if [ -n "${NOTARY_KEY:-}" ] && [ -n "${NOTARY_KEYID:-}" ] && [ -n "${NOTARY_ISSUER:-}" ]; then
    # CI path: the caller (import-signing.sh) already wrote the .p8 to disk and
    # exported these three. Nothing to resolve.
    return 0
  fi
  # Local path: read the same ~/.asc credential store the `asc` CLI and
  # build-notarize-install.sh use.
  NOTARY_KEYID="$(python3 -c "import json,os;C=json.load(open(os.path.expanduser('~/.asc/credentials.json')));print(C['accounts'][C['active']]['keyID'])")"
  NOTARY_KEY="$HOME/.asc/AuthKey_${NOTARY_KEYID}.p8"
  NOTARY_ISSUER="$(python3 -c "import json,os;C=json.load(open(os.path.expanduser('~/.asc/credentials.json')));print(C['accounts'][C['active']]['issuerID'])")"
  export NOTARY_KEY NOTARY_KEYID NOTARY_ISSUER
}

notary_submit() {
  local path="$1"
  notary_creds
  # Capture the submission id and status so a rejection can be diagnosed —
  # `submit --wait` alone prints "Invalid" with no reason; the notary *log* has
  # the details. This is verbatim the same capture/awk/log-on-rejection shape
  # build-notarize-install.sh already used before this file existed.
  local submit_out
  submit_out="$(xcrun notarytool submit "$path" --key "$NOTARY_KEY" --key-id "$NOTARY_KEYID" --issuer "$NOTARY_ISSUER" --wait 2>&1)"
  echo "$submit_out"
  local subid
  subid="$(echo "$submit_out" | awk '/^ *id:/ {print $2; exit}')"
  if ! echo "$submit_out" | grep -q "status: Accepted"; then
    echo "ERROR: notarization of $path was not Accepted."
    if [ -n "$subid" ]; then
      echo "==> fetching notary log for $subid"
      xcrun notarytool log "$subid" --key "$NOTARY_KEY" --key-id "$NOTARY_KEYID" --issuer "$NOTARY_ISSUER" || true
    fi
    return 1
  fi
}
