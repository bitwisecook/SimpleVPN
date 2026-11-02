#!/usr/bin/env python3
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
"""Derive the installer icon from the app's authored icon, preserving every appearance."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "SimpleVPN/SimpleVPN.icon"
DESTINATION = ROOT / "Installer/InstallerIcon.icon"
BADGE = '''<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">
<circle cx="800" cy="232" r="150" fill="white"/>
</svg>
'''
ARROW = '''<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">
<path d="M800 145v117m-49-45 49 49 49-49M726 281v32h148v-32" fill="none" stroke="white" stroke-width="24" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
'''


def outputs():
    document = json.loads((SOURCE / "icon.json").read_text())
    document["groups"] = [
        {
            "name": "Install bubble", "lighting": "individual", "layers": [
                {"name": "Install arrow", "image-name": "install-arrow.svg",
                 "fill": {"solid": "srgb:1,1,1,1"}, "glass": False},
                {"name": "Install bubble", "image-name": "install-bubble.svg",
                "fill-specializations": [
                    {"value": {"solid": "srgb:0.08,0.72,0.39,1"}},
                    {"appearance": "dark", "value": {"solid": "srgb:0.03,0.49,0.24,1"}},
                    {"appearance": "tinted", "value": {"solid": "srgb:0.25,0.25,0.25,1"}},
                ], "glass": True}],
            "shadow": {"kind": "neutral", "opacity": 0.35}, "specular": True,
            "translucency": {"enabled": False, "value": 0},
        },
        *document["groups"],
    ]
    result = {"icon.json": (json.dumps(document, indent=2) + "\n").encode(),
        "Assets/install-bubble.svg": BADGE.encode(), "Assets/install-arrow.svg": ARROW.encode()}
    result.update({"Assets/" + p.name: p.read_bytes() for p in (SOURCE / "Assets").iterdir() if p.is_file()})
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for relative, data in outputs().items():
        path = DESTINATION / relative
        if args.check:
            if not path.exists() or path.read_bytes() != data:
                raise SystemExit(f"Installer icon is out of date: {path}. Run Tools/generate-installer-icon.py")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    print("Installer icon matches the main app plus its install bubble.")
