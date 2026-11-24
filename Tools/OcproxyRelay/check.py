#!/usr/bin/env python3
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise an actual ocproxy SOCKS5 connection across the compiled packet gate. No routes or live VPN."""
import array
import contextlib
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid

routecheck, ocproxy = map(os.path.abspath, sys.argv[1:])
fixture = Path(__file__).with_name("script-tun-fixture.py").resolve()

def checksum(b):
    if len(b) & 1: b += b"\0"
    n = sum(struct.unpack("!%dH" % (len(b)//2), b))
    while n >> 16: n = (n & 65535) + (n >> 16)
    return (~n) & 65535

def tcp_reply(original, seq, ack, flags, data=b""):
    src, dst = original[16:20], original[12:16]
    peer, client = struct.unpack("!HH", original[20:24])
    tcp = struct.pack("!HHIIBBHHH", client, peer, seq, ack, 5<<4, flags, 32768, 0, 0) + data
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45,0,20+len(tcp),1,0,64,6,0,src,dst)
    return ip[:10]+struct.pack("!H",checksum(ip))+ip[12:]+tcp

def next_line(proc, prefix, timeout=6):
    with selectors.DefaultSelector() as sel:
        sel.register(proc.stdout,selectors.EVENT_READ)
        end=time.monotonic()+timeout
        while time.monotonic()<end and sel.select(max(0,end-time.monotonic())):
            line=proc.stdout.readline().decode().strip()
            if not line:break
            if line.startswith(prefix):return line[len(prefix):]
    raise RuntimeError("missing " + prefix)

def getn(sock,size):
    out=b""
    while len(out)<size:
        b=sock.recv(size-len(out))
        if not b:raise RuntimeError("SOCKS endpoint closed early")
        out+=b
    return out

def socks(local, remote):
    s=socket.create_connection(("127.0.0.1",local),timeout=3)
    s.sendall(b"\x05\x01\x00")
    assert getn(s,2)==b"\x05\x00"
    s.sendall(b"\x05\x01\x00\x01"+socket.inet_aton("198.51.100.4")+struct.pack("!H",remote))
    return s

with tempfile.TemporaryDirectory(prefix="svpn-oc-") as tmp, contextlib.ExitStack() as stack:
    rendezvous=stack.enter_context(socket.socket(socket.AF_UNIX,socket.SOCK_STREAM))
    address=str(Path(tmp)/"gateway")
    rendezvous.bind(address);rendezvous.listen();rendezvous.settimeout(5)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1",0));port=probe.getsockname()[1]
    nonce=str(uuid.uuid4())
    source="on mark tcp.syn port 443 => mark-dscp 10\non deny tcp.syn port 2222 => drop\non incoming inbound.udp.open port 55000 => drop"
    settings=dict(client=str(fixture),proxy=ocproxy,port=port,nonce=nonce,authLength=len(b"fixture-cookie\n"),profile="fixture",kind="cisco",source=source)
    body=json.dumps(settings).encode()
    proc=subprocess.Popen([routecheck,"--ocproxy-supervise","--disable-dtls","--","vpn.fixture.invalid"],
                          stdin=subprocess.PIPE,stdout=subprocess.PIPE,env={**os.environ,"FIXTURE_SOCKET":address})
    def stop():
        if proc.poll() is None:proc.terminate()
        proc.wait(timeout=5)
    stack.callback(stop)
    proc.stdin.write(struct.pack("!I",len(body))+body+b"fixture-cookie\n");proc.stdin.flush()
    client,_=rendezvous.accept();stack.enter_context(client)
    _,anc,_,_=client.recvmsg(1,socket.CMSG_SPACE(4))
    fd=array.array("i");fd.frombytes(anc[0][2]);wire=stack.enter_context(socket.socket(fileno=fd[0]));wire.settimeout(3)
    next_line(proc,"SimpleVPN proxy ready "+nonce)
    stream=stack.enter_context(socks(port,443));syn=wire.recv(65535)
    assert syn[0]>>4==4 and syn[1]>>2==10 and syn[33]&2 and struct.unpack("!H",syn[22:24])[0]==443
    client_seq=struct.unpack("!I",syn[24:28])[0]+1
    wire.send(tcp_reply(syn,1000,client_seq,0x12))
    assert getn(stream,10)[:2]==b"\x05\x00"
    wire.send(tcp_reply(syn,1001,client_seq,0x18,b"hello"))
    assert getn(stream,5)==b"hello"
    deny=stack.enter_context(socks(port,2222))
    # A separate synthetic IPv4 UDP observation checks the inbound drop path.
    data=bytearray(28);data[0]=0x45;data[2:4]=struct.pack("!H",28);data[8:10]=bytes([64,17])
    data[12:20]=syn[16:20]+syn[12:16];data[20:28]=struct.pack("!HHHH",53,55000,8,0)
    data[10:12]=struct.pack("!H",checksum(bytes(data[:20])));wire.send(data)
    for i in range(10):
        proc.stdin.write(b"S");proc.stdin.flush();stats=json.loads(next_line(proc,"SimpleVPN proxy stats "+nonce+" "))
        if stats["outbound"]["droppedPackets"] and stats["inbound"]["droppedPackets"]:break
        time.sleep(.03)
    assert stats["outbound"]["editedPackets"] and stats["outbound"]["droppedPackets"] and stats["inbound"]["droppedPackets"],stats
    assert stats["inbound"]["forwardedPackets"]>=2 and stats["adapter"]=="openconnect-proxy",stats
    proc.stdin.close() # App exit or cancellation closes the control lease.
    assert proc.wait(timeout=4)==0
    assert socket.socket().connect_ex(("127.0.0.1",port))!=0
    print("Passed upstream ocproxy SOCKS5, bidirectional IP enforcement, private input, counters and teardown")

# Failures exercise the production supervisor and the same upstream ocproxy binary.
def start(frame, rendezvous):
    data = json.dumps(frame).encode()
    child = subprocess.Popen([routecheck, "--ocproxy-supervise", "--disable-dtls", "--", "vpn.fixture.invalid"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env={**os.environ, "FIXTURE_SOCKET": rendezvous})
    child.stdin.write(struct.pack("!I",len(data)) + data + b"fixture-cookie\n")
    child.stdin.flush()
    return child

with tempfile.TemporaryDirectory(prefix="svpn-negative-") as tmp, socket.socket(socket.AF_UNIX) as server:
    address = str(Path(tmp)/"gateway")
    server.bind(address); server.listen(); server.settimeout(3)
    child = start({**settings, "source":"unrecognized policy"}, address)
    assert child.wait(timeout=3) != 0
    assert b"proxy ready" not in child.stdout.read()
    with selectors.DefaultSelector() as watcher:
        watcher.register(server, selectors.EVENT_READ)
        assert not watcher.select(.1), "invalid policy launched client"

    # A listener owned by another process can never satisfy startup readiness.
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1",0)); occupied.listen()
        child = start({**settings, "port":occupied.getsockname()[1]}, address)
        with server.accept()[0] as claim:
            assert claim.recv(1)==b"V"
            assert child.wait(timeout=8) != 0
            assert b"proxy ready" not in child.stdout.read()
        with socket.create_connection(occupied.getsockname(), timeout=1), occupied.accept()[0]:
            pass

    # Exit while client is waiting for authentication, before any attach hook.
    blocked = Path(tmp)/"pending.py"
    blocked.write_text("#!/usr/bin/env python3\nimport os, socket\ns=socket.socket(socket.AF_UNIX)\ns.connect(os.environ['FIXTURE_SOCKET'])\ns.sendall(b'A')\ns.recv(1)\n")
    blocked.chmod(0o700)
    child = start({**settings, "client":str(blocked)}, address)
    with server.accept()[0] as claim:
        claim.settimeout(3)
        assert claim.recv(1)==b"A"
        child.stdin.close()
        assert child.wait(timeout=4)==0
        assert claim.recv(1)==b""
        assert b"proxy ready" not in child.stdout.read()
print("Passed invalid-program, occupied-port and authentication-abandonment cases")
