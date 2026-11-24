# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
"""Two real IPsec responders and two separately spawned, interface-bound worker clients."""
import os
import selectors
import subprocess
import sys

driver, worker, peer = sys.argv[1:]
servers = []
try:
    ports = []
    for marker in ("A", "B"):
        child = subprocess.Popen([peer, "server", "v1"], env={**os.environ, "FIXTURE_MEMBER_MARK": marker},
                                 stdout=subprocess.PIPE)
        servers.append(child)
        with selectors.DefaultSelector() as sel:
            sel.register(child.stdout, selectors.EVENT_READ)
            line = child.stdout.readline().split() if sel.select(10) else []
            if len(line) != 2 or line[0] != b"READY" or not line[1].isdigit():
                raise RuntimeError("isolated loopback responder did not start")
            ports.append(line[1].decode())
    subprocess.run([driver, worker, *ports], check=True, timeout=24)
    print("Passed simultaneous IKE workers with identical selectors and independent teardown", flush=True)
finally:
    for child in servers:
        if child.poll() is None:
            child.terminate()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
