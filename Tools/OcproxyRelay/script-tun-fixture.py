#!/usr/bin/env python3
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
"""Implements only OpenConnect's documented script-tun FD handoff, using private test sockets."""
import array
import os
import socket
import subprocess
import sys

args = sys.argv[1:]
if args[-2:] != ["--", "vpn.fixture.invalid"] or "--disable-dtls" not in args:
    raise SystemExit("advanced options or server were lost")
if sys.stdin.buffer.read() != b"fixture-cookie\n":
    raise SystemExit("private settings changed the authentication input")
carrier, script = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
control.connect(os.environ["FIXTURE_SOCKET"])
control.sendmsg([b"V"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [carrier.fileno()]))])
# Same raw IP datagram handoff, script process group, shell and environment as upstream tun.c.
child = subprocess.Popen(["/bin/sh", "-c", args[args.index("--script") + 1]],
                         env={**os.environ, "INTERNAL_IP4_ADDRESS": "192.0.2.8", "INTERNAL_IP4_MTU": "1400",
                              "VPNFD": str(script.fileno())}, pass_fds=[3, script.fileno()],
                         process_group=0)
script.close()
carrier.close()
raise SystemExit(child.wait())
