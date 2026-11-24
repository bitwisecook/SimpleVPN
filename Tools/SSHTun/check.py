#!/usr/bin/env python3
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise the production libssh and packet bridge over authenticated SSH on loopback."""
from pathlib import Path
import subprocess as sp
import tempfile

root = Path(__file__).resolve().parents[2]
fixture = root / "Tools/SSHTun"
with tempfile.TemporaryDirectory(prefix="simplevpn-ssh-tun-") as tmp:
    client, server = Path(tmp)/"client", Path(tmp)/"peer"
    sp.run(["xcrun", "clang", "-fobjc-arc", "-fblocks", "-Werror",
            "-IShared", "-IVendor/libssh-include", "Shared/SSHBridge.m", fixture/"probe.m",
            "Vendor/SSHEngine.xcframework/macos-arm64/libSSHEngine.a",
            "-framework", "Foundation", "-framework", "IOKit", "-framework", "CoreFoundation",
            "-lz", "-lgssapi_krb5", "-o", client], cwd=root, check=True)
    sp.run(["go", "build", "-o", server, fixture/"peer.go"], cwd=root/"Vendor/tailscale-engine/src", check=True)
    for mode in ["echo", "denied", "wrongpin"]:
        with sp.Popen([server, mode], stdout=sp.PIPE, text=True) as peer:
            try:
                port, pin = peer.stdout.readline().split()
                if mode == "wrongpin": pin = "00"*32
                sp.run([client, port, pin, mode], check=True, timeout=8)
                assert peer.wait(timeout=5) == 0
            finally:
                if peer.poll() is None: peer.kill()
        print("Passed SSH point-to-point", mode)
