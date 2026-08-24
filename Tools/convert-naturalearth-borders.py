#!/usr/bin/env python3
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
"""Convert Natural Earth's admin-0 land boundaries to compact globe polylines.

Input: ne_110m_admin_0_boundary_lines_land.geojson (Natural Earth, public domain)
Output: SimpleVPN/Resources/Map/border-110m.bin in SVLINE1 format.
"""

import json
import struct
import sys
from pathlib import Path

FORMAT_DOC = """\\
# border-110m.bin — SVLINE1 format

Compact country-boundary polylines for the globe, generated from Natural Earth
110m Admin 0 Boundary Lines (land) by `Tools/convert-naturalearth-borders.py`.
Little-endian.

| field | type | notes |
|---|---|---|
| magic | 7 bytes ASCII | `SVLINE1` |
| line count | u32le | |
| — per line — | | |
| point count | u32le | |
| points | f32le × 2 × count | (lon, lat) pairs |

Source data: Natural Earth (public domain),
https://www.naturalearthdata.com/downloads/110m-cultural-vectors/
"""


def lines(geometry):
    kind = geometry.get("type")
    coords = geometry.get("coordinates") or []
    if kind == "LineString":
        return [coords]
    if kind == "MultiLineString":
        return coords
    return []


def main():
    if len(sys.argv) not in (2, 3):
        print(f"usage: {Path(sys.argv[0]).name} <boundary.geojson> [output.bin]", file=sys.stderr)
        raise SystemExit(2)
    src = Path(sys.argv[1])
    repo = Path(__file__).resolve().parent.parent
    out = Path(sys.argv[2]) if len(sys.argv) == 3 else repo / "SimpleVPN/Resources/Map/border-110m.bin"
    geojson = json.loads(src.read_text())
    paths = []
    for feature in geojson.get("features", []):
        paths.extend(line for line in lines(feature.get("geometry") or {}) if len(line) >= 2)
    if not paths:
        print(f"error: no LineString or MultiLineString geometry in {src}", file=sys.stderr)
        raise SystemExit(1)

    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as fh:
        fh.write(b"SVLINE1")
        fh.write(struct.pack("<I", len(paths)))
        for line in paths:
            fh.write(struct.pack("<I", len(line)))
            for lon, lat, *_ in line:
                fh.write(struct.pack("<ff", float(lon), float(lat)))
    out.with_name("border-110m.md").write_text(FORMAT_DOC)
    print(f"wrote {len(paths)} boundary lines → {out}")


if __name__ == "__main__":
    main()
