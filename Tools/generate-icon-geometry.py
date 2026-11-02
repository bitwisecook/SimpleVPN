#!/usr/bin/env python3
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
"""Project the app icon's solid geometry into editable Icon Composer SVG layers.

Standard library only. Material, lighting and refraction live in icon.json;
these assets contain geometry, with no baked shadows or specular highlights.
"""

import math
from pathlib import Path


ASSETS = Path(__file__).resolve().parents[1] / "SimpleVPN/SimpleVPN.icon/Assets"
YAW = math.radians(-24)
LEAN = math.radians(-18)
TILT = math.radians(-13)
SCALE = 1.23
FOCAL_LENGTH = 1450


def project(point, depth):
    x, y = point
    # Right and bottom edges advance toward the viewer. Extruding away from
    # the face reveals the right side and underside, rather than the top.
    x, depth = math.cos(YAW) * x + math.sin(YAW) * depth, -math.sin(YAW) * x + math.cos(YAW) * depth
    y, depth = math.cos(LEAN) * y + math.sin(LEAN) * depth, -math.sin(LEAN) * y + math.cos(LEAN) * depth
    x, y = math.cos(TILT) * x - math.sin(TILT) * y, math.sin(TILT) * x + math.cos(TILT) * y
    perspective = FOCAL_LENGTH / (FOCAL_LENGTH - depth)
    return 512 + SCALE * x * perspective, 500 + SCALE * y * perspective


def arc(cx, cy, rx, ry, start, stop, steps=24):
    return [(cx + rx * math.cos(t), cy + ry * math.sin(t))
            for t in [math.radians(start + (stop - start) * i / steps)
                      for i in range(steps + 1)]]


def rounded_rectangle(left, top, right, bottom, radius):
    return (arc(right - radius, top + radius, radius, radius, -90, 0)
            + arc(right - radius, bottom - radius, radius, radius, 0, 90)
            + arc(left + radius, bottom - radius, radius, radius, 90, 180)
            + arc(left + radius, top + radius, radius, radius, 180, 270))


def path(points, depth):
    coordinates = [project(p, depth) for p in points]
    return "M " + " L ".join(f"{x:.3f} {y:.3f}" for x, y in coordinates) + " Z"


def side_faces(points, front, back, inside=False):
    # Group consecutive visible quads into one surface to avoid seams in the
    # native glass renderer. On a hole, the surface normal points inward.
    edges = []
    for i, a in enumerate(points):
        b = points[(i + 1) % len(points)]
        nx, ny = b[1] - a[1], a[0] - b[0]
        nz = -math.sin(YAW) * nx * math.cos(LEAN) - math.sin(LEAN) * ny
        edges.append(nz < 0 if inside else nz > 0)
    surfaces = []
    for start in range(len(edges)):
        if not edges[start] or edges[start - 1]:
            continue
        chain = [points[start]]
        i = start
        while edges[i]:
            chain.append(points[(i + 1) % len(points)])
            i = (i + 1) % len(points)
        coords = [project(p, front) for p in chain] + [project(p, back) for p in reversed(chain)]
        surfaces.append("M " + " L ".join(f"{x:.3f} {y:.3f}" for x, y in coords) + " Z")
    return " ".join(surfaces)


def write_svg(name, paths):
    data = "\n".join(f'  <path fill="#ffffff" fill-rule="evenodd" d="{p}"/>' for p in paths)
    (ASSETS / name).write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">\n'
        + data + "\n</svg>\n")


def main():
    ASSETS.mkdir(parents=True, exist_ok=True)
    body = rounded_rectangle(-246, -40, 246, 312, 67)
    keyhole = arc(0, 113, 35, 35, 132, 408, 48) + [(28, 202), (-28, 202)]
    # An 84-point smooth band, with a larger opening than the original icon.
    shackle = (arc(0, -171, 166, 166, 180, 360, 64)
               + [(166, -40), (82, -40)]
               + list(reversed(arc(0, -171, 82, 82, 180, 360, 64)))
               + [(-82, -40), (-166, -40)])
    write_svg("body-front.svg", [path(body, 32) + " " + path(keyhole, 32)])
    write_svg("body-side.svg", [side_faces(body, 32, -34), side_faces(keyhole, 32, -34, inside=True)])
    # The band has its own depth and material; its feet end at the body's top.
    write_svg("shackle-front.svg", [path(shackle, 6)])
    write_svg("shackle-side.svg", [side_faces(shackle, 6, -28)])


if __name__ == "__main__":
    main()
