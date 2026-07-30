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
