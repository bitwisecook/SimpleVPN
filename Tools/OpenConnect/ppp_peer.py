# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
"""Private Fortinet and F5 PPP peers for the member packet regression."""
import struct
from urllib.parse import parse_qs, urlsplit


def xml(peer, body):
    peer.sendall(f"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nConnection: close\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)


def fcs(data):
    value = 0xffff
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x8408 if value & 1 else 0)
    return value


def hdlc_packet(peer, read_exact):
    assert read_exact(peer, 1) == b"\x7e"
    frame = bytearray()
    while len(frame) < 2048:
        byte = read_exact(peer, 1)[0]
        if byte == 0x7e:
            assert fcs(frame) == 0xf0b8
            return bytes(frame[:-2])
        if byte == 0x7d:
            byte = read_exact(peer, 1)[0] ^ 0x20
        frame.append(byte)
    raise ValueError("PPP peer frame exceeds its fixture MTU")


def ppp(peer, read_exact, protocol, mode):
    hdlc = mode == "allow-hdlc"
    dual = mode == "allow-dual"
    """Complete both sides of LCP/IPCP; preserve exactly one packet per TLS envelope."""
    def outer(size):
        if protocol == "f5":
            return struct.pack("!HH", 0xf500, size)
        return struct.pack("!HHH", size + 6, 0x5050, size)

    def wrap(proto, body):
        payload = b"\xff\x03" + struct.pack("!H", proto) + body
        if hdlc:
            result = bytearray([0x7e])
            for byte in payload + struct.pack("<H", fcs(payload) ^ 0xffff):
                if byte < 0x20 or byte in (0x7d, 0x7e):
                    result.extend((0x7d, byte ^ 0x20))
                else:
                    result.append(byte)
            result.append(0x7e)
            return result
        return outer(len(payload)) + payload

    offered = set()
    sent = set()
    for _ in range(40):
        if hdlc:
            data = hdlc_packet(peer, read_exact)
        else:
            header = read_exact(peer, 4 if protocol == "f5" else 6)
            size = int.from_bytes(header[-2:], "big")
            assert header == outer(size) and 1 <= size <= 65535
            data = read_exact(peer, size)
        start = 2 if data.startswith(b"\xff\x03") else 0
        width = 1 if data[start] & 1 else 2
        proto = int.from_bytes(data[start:start + width], "big")
        payload = data[start + width:]
        if proto in (0x21, 0x57):
            assert offered == ({0xc021, 0x8021, 0x8057} if dual else {0xc021, 0x8021})
            reply = bytearray(payload)
            if proto == 0x21:
                assert len(payload) == 32 and payload[28:] == b"cstp"
                reply[12:16], reply[16:20] = reply[16:20], reply[12:16]
                reply[20:22], reply[22:24] = reply[22:24], reply[20:22]
            else:
                assert dual and len(payload) == 52 and payload[48:] == b"ipv6"
                reply[8:24], reply[24:40] = reply[24:40], reply[8:24]
                reply[40:42], reply[42:44] = reply[42:44], reply[40:42]
            peer.sendall(wrap(proto, reply))
            sent.add(proto)
            continue
        assert proto in (0xc021, 0x8021, 0x8057) and len(payload) >= 4
        if payload[0] == 5:  # Terminate-Request
            assert sent == ({0x21, 0x57} if dual else {0x21}) and proto == 0xc021
            peer.sendall(wrap(proto, bytes([6]) + payload[1:]))
            # The client closes its tunnel before it opens the separate logout
            # connection. Closing from the server here races an acknowledged
            # shutdown with a carrier failure in OpenConnect's read loop.
            assert not peer.recv(1)
            return
        if payload[0] == 1:  # Configure-Request
            peer.sendall(wrap(proto, b"\x02" + payload[1:]))
            if proto not in offered:
                offered.add(proto)
                opt = b"\x03\x06\xc6\x12\x1e\x09" if proto == 0x8021 else b""
                peer.sendall(wrap(proto, struct.pack("!BBH", 1, 27, len(opt) + 4) + opt))
    raise RuntimeError("PPP failed to establish")


def exchange(peer, method, target, headers, mode, protocol, read_exact):
    assert method == "GET"
    path = urlsplit(target)
    if protocol == "fortinet":
        assert headers["cookie"] == "SVPNCOOKIE=disposable-fixture"
        if path.path == "/remote/fortisslvpn_xml":
            split_dns = (b'<split-dns domains="internal.test" dnsserver1="198.18.30.53"/>'
                         if mode == "scoped-dns" else b'')
            xml(peer, b'<sslvpn-tunnel ver="2" dtls="0"><ipv4><assigned-addr ipv4="198.18.30.2"/>'
                      b'<dns ip="198.18.30.53"/><split-tunnel-info><addr ip="198.18.30.0" mask="255.255.255.0"/>'
                      b'</split-tunnel-info>' + split_dns + b'</ipv4></sslvpn-tunnel>')
            return False
        if path.path == "/remote/logout":
            xml(peer, b"logged out")
            return False
        assert path.path == "/remote/sslvpn-tunnel"
    else:
        if path.path != "/myvpn":
            assert headers["cookie"] == "MRHSession=disposable-fixture"
        if path.path == "/vdesk/vpn/index.php3":
            xml(peer, b'<favorites type="VPN"><favorite id="/Common/lab"><params>resourcename=/Common/lab</params></favorite></favorites>')
            return False
        if path.path == "/vdesk/vpn/connect.php3":
            assert parse_qs(path.query)["resourcename"] == ["/Common/lab"]
            dns = b"<DNS_SPLIT0>internal.test</DNS_SPLIT0>" if mode == "scoped-dns" else b""
            xml(peer, b"<favorite><object><ur_Z>z1</ur_Z><Session_ID>session</Session_ID><IPV4_0>1</IPV4_0>"
                      + (b"<IPV6_0>1</IPV6_0><UseDefaultGateway0>1</UseDefaultGateway0>" if mode == "allow-dual" else b"<IPV6_0>0</IPV6_0>")
                      + b"<DNS0>198.18.30.53</DNS0><LAN0>198.18.30.0/24</LAN0>" +
                      (b"<hdlc_framing>yes</hdlc_framing>" if mode == "allow-hdlc" else b"<hdlc_framing>no</hdlc_framing>") + dns + b"</object></favorite>")
            return False
        if path.path == "/vdesk/hangup.php3":
            xml(peer, b"logged out")
            return False
        assert path.path == "/myvpn" and parse_qs(path.query)["sess"] == ["session"]
        peer.sendall(b"HTTP/1.1 200 OK\r\nX-VPN-client-IP: 198.18.30.2\r\n" +
                     (b"X-VPN-client-IPv6: 2001:db8::22\r\n" if mode == "allow-dual" else b"") + b"\r\n")
    ppp(peer, read_exact, protocol, mode)
    return True
