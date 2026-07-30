#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
# Fetch/refresh the DB-IP Country Lite database (CC-BY-4.0) the app bundles for
# endpoint-map country lookups. Keeps Vendor/geoip/dbip-country-lite.mmdb at most
# 7 days stale (tracked via a manifest date). Soft-fails on network trouble so an
# offline build still builds — the app tolerates a stale (or missing) DB.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$REPO/Vendor/geoip"
DB="$DIR/dbip-country-lite.mmdb"
MANIFEST="$DIR/manifest"
MAX_AGE_DAYS=7

mkdir -p "$DIR"

today="$(date +%Y-%m-%d)"
if [ -f "$MANIFEST" ] && [ -f "$DB" ]; then
  last="$(cat "$MANIFEST")"
  # BSD date first (macOS build hosts), GNU fallback; unparseable → refetch.
  last_epoch="$(date -j -f %Y-%m-%d "$last" +%s 2>/dev/null || date -d "$last" +%s 2>/dev/null || echo 0)"
  age_days=$(( ($(date +%s) - last_epoch) / 86400 ))
  if [ "$age_days" -le "$MAX_AGE_DAYS" ]; then
    echo "geoip: cached DB is fresh ($last)"
    exit 0
  fi
fi

# Monthly releases: https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.mmdb.gz
# The current month can 404 right after a month rolls over — fall back one month.
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
fetch() {
  curl -fsSL --connect-timeout 15 "https://download.db-ip.com/free/dbip-country-lite-$1.mmdb.gz" -o "$TMP" \
    && gzip -t "$TMP" 2>/dev/null      # reject truncated downloads too
}
this_month="$(date +%Y-%m)"
prev_month="$(date -v-1m +%Y-%m 2>/dev/null || date -d 'last month' +%Y-%m)"

if fetch "$this_month" || fetch "$prev_month"; then
  gzip -dc "$TMP" > "$DB"
  echo "$today" > "$MANIFEST"
  echo "geoip: refreshed $DB ($today)"
else
  echo "geoip: WARNING — could not refresh database, building with stale data" >&2
  exit 0
fi
