#!/usr/bin/env python3
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
"""Export the canonical Icon Composer design for documentation and standalone use.

Requires Xcode 27+ with Icon Composer. The self-contained SVG embeds Apple's
rendered PNG so its native glass effects match the app exactly.
"""

import argparse
import base64
import shutil
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-logo", type=Path,
                        help="Also refresh an existing standalone SVG at this path")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    developer = Path(subprocess.check_output(["xcode-select", "-p"], text=True).strip())
    ictool = developer.parent / "Applications/Icon Composer.app/Contents/Executables/ictool"
    if not ictool.is_file():
        parser.error("Icon Composer's ictool was not found in the selected Xcode")
    if args.workspace_logo and (args.workspace_logo.suffix.lower() != ".svg"
                                or not args.workspace_logo.is_file()):
        parser.error("--workspace-logo must name an existing .svg file")
    output = repo / "Docs/Assets"
    output.mkdir(parents=True, exist_ok=True)
    for rendition, filename in [("Default", "AppIcon.png"), ("Dark", "AppIcon-Dark.png")]:
        subprocess.run([str(ictool), str(repo / "SimpleVPN/SimpleVPN.icon"),
                        "--export-image", "--output-file", str(output / filename),
                        "--platform", "macOS", "--rendition", rendition,
                        "--width", "1024", "--height", "1024", "--scale", "1"], check=True)
    png = base64.b64encode((output / "AppIcon.png").read_bytes()).decode("ascii")
    svg = output / "SimpleVPN-logo.svg"
    svg.write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" '
        'viewBox="0 0 1024 1024" role="img" aria-labelledby="title">\n'
        '  <title id="title">SimpleVPN</title>\n'
        '  <desc>Generated from SimpleVPN/SimpleVPN.icon by Tools/export-app-icon.py. '
        'The embedded native rendering preserves Liquid Glass effects.</desc>\n'
        f'  <image width="1024" height="1024" href="data:image/png;base64,{png}"/>\n'
        '</svg>\n')
    if args.workspace_logo:
        shutil.copyfile(svg, args.workspace_logo)
    print(f"Exported app icon to {output}")


if __name__ == "__main__":
    main()
