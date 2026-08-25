#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
#
# Allocate the next build number and keep Xcode's source default aligned.
#
# Xcode calls this through the BuildNumber legacy dependency for every Build
# action, regardless of whether the action came from Run, Test, Profile,
# Archive, xcodebuild, or the release tooling. The app and packet-tunnel targets
# stamp the allocated value into their generated plists before signing.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_FILE="$REPO/BUILDNUMBER"
PROJECT_FILE="$REPO/project.yml"
LOCK_DIR="$REPO/build/.build-number.lock"

mkdir -p "$REPO/build"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "FATAL: another SimpleVPN build is allocating a build number" >&2
  echo "       (stale after an unclean kill? remove $LOCK_DIR)" >&2
  exit 1
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT INT TERM

CURRENT="$(tr -d '[:space:]' < "$BUILD_FILE")"
case "$CURRENT" in
  ''|*[!0-9]*) echo "FATAL: BUILDNUMBER must be a positive integer: $CURRENT" >&2; exit 1 ;;
esac
if [ "$CURRENT" -lt 1 ]; then
  echo "FATAL: BUILDNUMBER must be greater than zero: $CURRENT" >&2; exit 1
fi

assert_sources_match() {
  if ! grep -Eq "^[[:space:]]*CURRENT_PROJECT_VERSION:[[:space:]]*\"$CURRENT\"[[:space:]]*(#.*)?$" "$PROJECT_FILE"; then
    echo "FATAL: BUILDNUMBER ($CURRENT) and project.yml are not in sync" >&2
    exit 1
  fi
}

if [ "${1:-}" = "--check" ]; then
  if [ "$#" -ne 1 ]; then
    echo "usage: $0 [--check]" >&2; exit 2
  fi
  assert_sources_match
  echo "$CURRENT"
  exit 0
fi
if [ "$#" -ne 0 ]; then
  echo "usage: $0 [--check]" >&2; exit 2
fi

assert_sources_match
NEXT=$((CURRENT + 1))
# The project is generated, so project.yml—not project.pbxproj—is the source
# that must change. Require exactly one replacement to catch a renamed setting
# rather than quietly producing another build-1 debug app.
MATCHES="$(grep -Ec '^[[:space:]]*CURRENT_PROJECT_VERSION:[[:space:]]*"[0-9]+"[[:space:]]*(#.*)?$' "$PROJECT_FILE")"
if [ "$MATCHES" -ne 1 ]; then
  echo "FATAL: expected exactly one CURRENT_PROJECT_VERSION setting in project.yml" >&2
  exit 1
fi
perl -0pi -e 's/(CURRENT_PROJECT_VERSION:\s*")[0-9]+(")/${1}'"$NEXT"'${2}/' "$PROJECT_FILE"
if ! grep -q "CURRENT_PROJECT_VERSION: \"$NEXT\"" "$PROJECT_FILE"; then
  echo "FATAL: could not update CURRENT_PROJECT_VERSION in project.yml" >&2
  exit 1
fi

printf '%s\n' "$NEXT" > "$BUILD_FILE"
echo "$NEXT"
