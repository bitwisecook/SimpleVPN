# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only

import os

stage = defines["stage"]
files = [os.path.join(stage, name) for name in
         ("SimpleVPN.app", "Read Me First.txt", "LICENSE.txt")
         if os.path.exists(os.path.join(stage, name))]
background = defines["background"]
icon = defines["icon"]
format = "UDZO"
window_rect = ((160, 160), (600, 460))
icon_size = 96
text_size = 13
icon_locations = {
    "SimpleVPN.app": (300, 175),
    "Read Me First.txt": (104, 310),
    "LICENSE.txt": (496, 310),
}
