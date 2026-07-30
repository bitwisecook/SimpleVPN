#!/usr/bin/env python3
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
# Convert the Natural Earth 110m land GeoJSON into the compact binary polyline
# file the endpoint map renders (SimpleVPN/Resources/Map/land-110m.bin).
# Dev-time tool, stdlib only; the output is committed so builds never run this.
#
# Input (download separately, one file):
#   https://github.com/nvkelso/natural-earth-vector/blob/master/geojson/ne_110m_land.geojson
#
# Format "SVMAP1" (also emitted as a sibling land-110m.md):
#   magic   6 bytes ASCII "SVMAP1"
#   u32le   polygon count
#   per polygon:
#     u32le             point count
#     f32le lon, f32le lat  × point count
# Exterior rings only — holes are dropped (invisible at 110m scale).

import json
import struct
import sys
from pathlib import Path

FORMAT_DOC = """\
# land-110m.bin — SVMAP1 format

Compact binary polylines for the endpoint map's land outlines, generated from
Natural Earth 110m land by `Tools/convert-naturalearth.py`. Little-endian.

| field | type | notes |
|---|---|---|
| magic | 6 bytes ASCII | `SVMAP1` |
| polygon count | u32le | |
| — per polygon — | | |
| point count | u32le | |
| points | f32le × 2 × count | (lon, lat) pairs |

Exterior rings only — holes are dropped (invisible at 110m scale).

Source data: Natural Earth (public domain),
https://github.com/nvkelso/natural-earth-vector/blob/master/geojson/ne_110m_land.geojson
"""

USAGE = f"""\
usage: {Path(sys.argv[0]).name} <ne_110m_land.geojson> [output.bin]

Download the input from:
  https://github.com/nvkelso/natural-earth-vector/blob/master/geojson/ne_110m_land.geojson
Default output: SimpleVPN/Resources/Map/land-110m.bin (plus a land-110m.md format doc).
"""


def exterior_rings(geometry):
    """Exterior rings of a Polygon/MultiPolygon geometry; holes dropped."""
    kind = geometry.get("type")
    coords = geometry.get("coordinates") or []
    if kind == "Polygon":
        return [coords[0]] if coords else []
    if kind == "MultiPolygon":
        return [polygon[0] for polygon in coords if polygon]
    return []


def main():
    if len(sys.argv) < 2:
        print(USAGE, end="", file=sys.stderr)
        sys.exit(2)
    src = Path(sys.argv[1])
    repo = Path(__file__).resolve().parent.parent
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else repo / "SimpleVPN/Resources/Map/land-110m.bin"

    geojson = json.loads(src.read_text())
    features = geojson.get("features", [geojson] if "geometry" in geojson else [])
    rings = []
    for feature in features:
        rings.extend(exterior_rings(feature.get("geometry") or {}))
    if not rings:
        print(f"error: no Polygon/MultiPolygon features in {src}", file=sys.stderr)
        sys.exit(1)

    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "wb") as fh:
        fh.write(b"SVMAP1")
        fh.write(struct.pack("<I", len(rings)))
        for ring in rings:
            fh.write(struct.pack("<I", len(ring)))
            for point in ring:
                fh.write(struct.pack("<ff", float(point[0]), float(point[1])))
    out.with_name("land-110m.md").write_text(FORMAT_DOC)

    total = sum(len(r) for r in rings)
    print(f"wrote {len(rings)} polygons / {total} points → {out}")


if __name__ == "__main__":
    main()
