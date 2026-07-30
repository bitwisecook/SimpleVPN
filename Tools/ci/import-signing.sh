#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
#
# CI-only: build a temporary keychain, import the Developer ID Application
# certificate + Apple intermediates, and install both provisioning profiles,
# so xcodebuild's Manual signing (CODE_SIGN_STYLE: Manual, project.yml) can
# resolve everything by name. Always pair this with cleanup-signing.sh in an
# `if: always()` step — see .github/workflows/release.yml.
#
# Required environment (all secrets — see Docs/Release.md for how to produce
# each one):
#   DEVID_APP_CERT_P12_BASE64     base64 of the exported Developer ID
#                                  Application cert + private key, as a .p12
#   DEVID_APP_CERT_P12_PASSWORD   password the .p12 was exported with
#   CI_KEYCHAIN_PASSWORD          password for the throwaway CI keychain
#                                  (only ever exists for this job's lifetime)
#   PROFILE_APP_BASE64            base64 of "SimpleVPN App DirectDist.provisionprofile"
#   PROFILE_TUNNEL_BASE64         base64 of "SimpleVPN Tunnel DirectDist.provisionprofile"
#   ASC_API_KEY_P8_BASE64         base64 of the App Store Connect API .p8
#   ASC_API_KEY_ID                the API key's Key ID
#   ASC_API_ISSUER_ID             the API key's Issuer ID
#
# Notarization env vars (consumed by Tools/lib/notary.sh via
# build-release-dmg.sh, not read directly here): this script writes the .p8 to
# disk and exports NOTARY_KEY/NOTARY_KEYID/NOTARY_ISSUER via $GITHUB_ENV so
# later steps in the same job see them.
set -euo pipefail

: "${RUNNER_TEMP:?RUNNER_TEMP must be set (this script is CI-only)}"
: "${DEVID_APP_CERT_P12_BASE64:?missing secret DEVID_APP_CERT_P12_BASE64}"
: "${DEVID_APP_CERT_P12_PASSWORD:?missing secret DEVID_APP_CERT_P12_PASSWORD}"
: "${CI_KEYCHAIN_PASSWORD:?missing secret CI_KEYCHAIN_PASSWORD}"
: "${PROFILE_APP_BASE64:?missing secret PROFILE_APP_BASE64}"
: "${PROFILE_TUNNEL_BASE64:?missing secret PROFILE_TUNNEL_BASE64}"
: "${ASC_API_KEY_P8_BASE64:?missing secret ASC_API_KEY_P8_BASE64}"
: "${ASC_API_KEY_ID:?missing secret ASC_API_KEY_ID}"
: "${ASC_API_ISSUER_ID:?missing secret ASC_API_ISSUER_ID}"

KEYCHAIN="$RUNNER_TEMP/simplevpn-signing.keychain-db"
CERT_P12="$RUNNER_TEMP/devid-app-cert.p12"
INTERMEDIATE_G2="$RUNNER_TEMP/DeveloperIDG2CA.cer"
APPLE_ROOT="$RUNNER_TEMP/AppleIncRootCertificate.cer"

echo "==> create temporary keychain"
security create-keychain -p "$CI_KEYCHAIN_PASSWORD" "$KEYCHAIN"
# 6 hours: comfortably longer than any single release job should ever take,
# short enough that a leaked/abandoned keychain on a runner is not a standing
# risk (the runner is destroyed after the job anyway, but be careful by habit).
security set-keychain-settings -lut 21600 "$KEYCHAIN"
security unlock-keychain -p "$CI_KEYCHAIN_PASSWORD" "$KEYCHAIN"
# Prepend rather than replace, so xcodebuild/codesign can still see the
# runner's default login/System keychains if they need to (e.g. root CAs).
security list-keychains -d user -s "$KEYCHAIN" login.keychain-db

echo "==> import Developer ID Application certificate"
echo "$DEVID_APP_CERT_P12_BASE64" | base64 --decode >"$CERT_P12"
# -T (not -A): grant codesign/security access explicitly rather than "always
# allow" to every app, which is broader than this identity needs.
security import "$CERT_P12" -k "$KEYCHAIN" -P "$DEVID_APP_CERT_P12_PASSWORD" \
  -f pkcs12 -T /usr/bin/codesign -T /usr/bin/security

echo "==> import Apple intermediate + root CA certs"
# A Keychain-exported .p12 usually carries only the leaf + private key.
# codesign needs the full chain to Apple Root CA to trust the signature; a
# missing intermediate reads as a bogus "no identity found" rather than a
# clear chain-of-trust error, so fetch these explicitly rather than assume.
curl -fsSL -o "$INTERMEDIATE_G2" "https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer"
curl -fsSL -o "$APPLE_ROOT" "https://www.apple.com/certificateauthority/AppleIncRootCertificate.cer"
security import "$INTERMEDIATE_G2" -k "$KEYCHAIN" -T /usr/bin/codesign -T /usr/bin/security
security import "$APPLE_ROOT" -k "$KEYCHAIN" -T /usr/bin/codesign -T /usr/bin/security

echo "==> allow codesign to use the imported key without a UI prompt"
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$CI_KEYCHAIN_PASSWORD" "$KEYCHAIN"

echo "==> assert exactly one Developer ID Application identity is present"
IDENTITIES="$(security find-identity -v -p codesigning "$KEYCHAIN")"
echo "$IDENTITIES"
COUNT="$(echo "$IDENTITIES" | grep -c '"Developer ID Application: .*(QVUFB5676H)"' || true)"
if [ "$COUNT" -ne 1 ]; then
  echo "FATAL: expected exactly one 'Developer ID Application: ... (QVUFB5676H)' identity, found $COUNT"
  exit 1
fi

echo "==> install provisioning profiles"
XCODE_PP_DIR="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"
MOBILEDEVICE_PP_DIR="$HOME/Library/MobileDevice/Provisioning Profiles"
mkdir -p "$XCODE_PP_DIR" "$MOBILEDEVICE_PP_DIR"

install_profile() {
  local b64_var="$1" expected_name="$2" out_basename="$3"
  local raw="$RUNNER_TEMP/$out_basename"
  echo "${!b64_var}" | base64 --decode >"$raw"

  local uuid name
  uuid="$(security cms -D -i "$raw" 2>/dev/null | plutil -extract UUID raw -)"
  name="$(security cms -D -i "$raw" 2>/dev/null | plutil -extract Name raw -)"
  if [ "$name" != "$expected_name" ]; then
    echo "FATAL: $out_basename embeds Name '$name', expected '$expected_name' (project.yml PROVISIONING_PROFILE_SPECIFIER mismatch)"
    exit 1
  fi
  local expiry_epoch now_epoch days_left
  expiry_epoch="$(security cms -D -i "$raw" 2>/dev/null | plutil -extract ExpirationDate raw - | xargs -I{} date -j -f "%Y-%m-%d %H:%M:%S %z" "{}" +%s 2>/dev/null || echo 0)"
  now_epoch="$(date +%s)"
  days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
  if [ "$expiry_epoch" -gt 0 ] && [ "$days_left" -lt 30 ]; then
    echo "WARNING: profile '$name' expires in $days_left day(s) — renew it soon (Developer ID certs/profiles need the account holder, see AGENTS.md)"
  fi

  # macOS looks in two places depending on which tool asked; install to both so
  # xcodebuild's Manual signing resolution finds it regardless.
  cp "$raw" "$XCODE_PP_DIR/$uuid.provisionprofile"
  cp "$raw" "$MOBILEDEVICE_PP_DIR/$uuid.provisionprofile"
  echo "    installed '$name' ($uuid), expires in ${days_left}d"
}

install_profile PROFILE_APP_BASE64 "SimpleVPN App DirectDist" "app.mobileprovision"
install_profile PROFILE_TUNNEL_BASE64 "SimpleVPN Tunnel DirectDist" "tunnel.mobileprovision"

echo "==> write App Store Connect API key (for notarytool)"
mkdir -p "$RUNNER_TEMP/asc"
ASC_P8="$RUNNER_TEMP/asc/AuthKey_${ASC_API_KEY_ID}.p8"
echo "$ASC_API_KEY_P8_BASE64" | base64 --decode >"$ASC_P8"
chmod 600 "$ASC_P8"

if [ -n "${GITHUB_ENV:-}" ]; then
  {
    echo "NOTARY_KEY=$ASC_P8"
    echo "NOTARY_KEYID=$ASC_API_KEY_ID"
    echo "NOTARY_ISSUER=$ASC_API_ISSUER_ID"
    echo "SIMPLEVPN_CI_KEYCHAIN=$KEYCHAIN"
  } >>"$GITHUB_ENV"
fi

echo "==> signing environment ready"
