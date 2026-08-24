#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
# Fetch reproducible offline globe assets. Do not run during ordinary app builds.

set -euo pipefail

task_tmp="$(mktemp -d)"
trap 'rm -rf "$task_tmp"' EXIT
task_root="$(cd "$(dirname "$0")/.." && pwd)"
task_map="$task_root/SimpleVPN/Resources/Map"

curl -L --fail --show-error --silent \
  -o "$task_tmp/ne_110m_admin_0_boundary_lines_land.geojson" \
  https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_boundary_lines_land.geojson
python3 "$task_root/Tools/convert-naturalearth-borders.py" \
  "$task_tmp/ne_110m_admin_0_boundary_lines_land.geojson" "$task_map/border-110m.bin"

# NASA Earth Observatory, "Earth at Night (Black Marble) 2016", 0.1° JPEG.
# NASA asks that its imagery be credited and permits informational use under
# its media guidelines; the app's About panel carries that attribution.
curl -L --fail --show-error --silent \
  -o "$task_map/black-marble-2016-01deg.jpg" \
  https://eoimages.gsfc.nasa.gov/images/imagerecords/144000/144898/BlackMarble_2016_01deg.jpg

# NASA Visible Earth, Blue Marble Next Generation, December true-colour
# equirectangular imagery (5,400 × 2,700). It uses the same geography and
# top-left image origin as Black Marble, so the shader can blend the two cleanly
# across the live terminator. The app's About panel carries the attribution.
curl -L --fail --show-error --silent \
  -o "$task_map/blue-marble-2004-5400.jpg" \
  https://eoimages.gsfc.nasa.gov/images/imagerecords/74000/74218/world.200412.3x5400x2700.jpg

printf 'fetched Natural Earth borders and NASA Blue/Black Marble globe imagery\n'
