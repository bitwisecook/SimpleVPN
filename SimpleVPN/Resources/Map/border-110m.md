\
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
