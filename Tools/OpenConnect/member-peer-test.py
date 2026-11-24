# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise the shipping CSTP, GPST and PPP packet bridge against private TLS peers."""
import base64
import hashlib
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
from itertools import product
from urllib.parse import parse_qs, urlsplit
import tempfile
import threading
import ppp_peer


def read_exact(peer, length):
    result = bytearray()
    while len(result) < length:
        chunk = peer.recv(length - len(result))
        if not chunk:
            raise EOFError()
        result.extend(chunk)
    return bytes(result)


def request_headers(peer):
    raw = bytearray()
    while b"\r\n\r\n" not in raw and len(raw) < 32768:
        raw.extend(read_exact(peer, 1))
    first, *lines = raw.decode("ascii").split("\r\n")
    method, target, version = first.split(" ")
    assert version == "HTTP/1.1"
    headers = dict((k.lower(), v.strip()) for k, v in (row.split(":", 1) for row in lines if row))
    length = int(headers.get("content-length", 0))
    assert 0 <= length <= 32768
    return method, target, headers, read_exact(peer, length)


def globalprotect(peer, method, target, body):
    """The gateway returns config and HIP status, then switches to framed GPST."""
    path = urlsplit(target)
    if method == "GET":
        assert path.path == "/ssl-tunnel-connect.sslvpn" and parse_qs(path.query)["authcookie"] == ["disposable-fixture"]
        peer.sendall(b"START_TUNNEL")
        head = read_exact(peer, 16)
        assert head[:6] == bytes.fromhex("1a2b3c4d0800")
        return head, struct.unpack("!H", head[6:8])[0]
    assert method == "POST" and parse_qs(body.decode())["authcookie"] == ["disposable-fixture"]
    if path.path == "/ssl-vpn/getconfig.esp":
        xml = (b"<response><ip-address>198.18.30.2</ip-address><netmask>255.255.255.0</netmask>"
               b"<ip-address-v6>2001:db8::22</ip-address-v6><mtu>1360</mtu>"
               b"<ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url></response>")
    elif path.path == "/ssl-vpn/logout.esp":
        xml = b'<response status="success"></response>'
    else:
        assert path.path == "/ssl-vpn/hipreportcheck.esp"
        xml = b"<response><hip-report-needed>no</hip-report-needed></response>"
    peer.sendall(f"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nConnection: close\r\nContent-Length: {len(xml)}\r\n\r\n".encode() + xml)
    return None


def cstp(peer, method, target, headers, mode):
    assert (method, target) == ("CONNECT", "/CSCOSSLC/tunnel")
    assert headers["cookie"] == "webvpn=disposable-fixture"
    peer.sendall(b"HTTP/1.1 200 OK\r\nX-CSTP-Version: 1\r\nX-CSTP-Address: 198.18.30.2\r\n"
                 b"X-CSTP-Netmask: 255.255.255.0\r\nX-CSTP-Address-IP6: 2001:db8::22/64\r\n"
                 b"X-CSTP-MTU: 1360\r\nX-CSTP-Keepalive: 300\r\n" +
                 (b"X-CSTP-Split-Include: 10.0.0.0/not-a-prefix\r\n" if mode == "bad-route" else b"") + b"\r\n")
    if mode == "bad-route":
        return None
    head = read_exact(peer, 8)
    assert head[:4] == b"STF\x01" and head[6:] == b"\x00\x00"
    return head, struct.unpack("!H", head[4:6])[0]


def run(probe):
    subprocess.run([probe, "--fd-ownership"], check=True, stdin=subprocess.DEVNULL)
    name = "gateway.fixture.invalid"
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)

        def openssl(*args, data=None):
            return subprocess.run(["openssl", *args], cwd=root, input=data, capture_output=True, check=True).stdout

        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
                "-subj", "/CN=Disposable CSTP CA", "-days", "1", "-addext", "basicConstraints=critical,CA:TRUE")
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "key.pem", "-out", "server.csr", "-subj", f"/CN={name}")
        (root / "server.ext").write_text(f"basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:{name}\n")
        openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
                "-out", "cert.pem", "-days", "1", "-extfile", "server.ext")
        public = openssl("x509", "-pubkey", "-noout", "-in", "cert.pem")
        der = openssl("pkey", "-pubin", "-outform", "DER", data=public)
        pin = "pin-sha256:" + base64.b64encode(hashlib.sha256(der).digest()).decode()
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(root / "cert.pem", root / "key.pem")
        tls.set_servername_callback(lambda _conn, server_name, _ctx: None if server_name == name else ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)

        for protocol, mode in product(("anyconnect", "gp", "fortinet", "f5"), ("bad-pin", "short-pin", "bad-interface", "bad-host", "bad-route", "scoped-dns", "allow", "allow-hdlc", "allow-dual")):
            if mode in ("allow-hdlc", "allow-dual") and protocol != "f5":
                continue
            if (mode == "bad-route" and protocol != "anyconnect") or (mode == "scoped-dns" and protocol not in ("fortinet", "f5")):
                continue
            with socket.create_server(("127.0.0.1", 0)) as listener:
                listener.settimeout(1)
                done = threading.Event()
                errors = []
                connects = []
                requests = []
                packets = []

                def serve():
                    while not done.is_set():
                        try:
                            conn, _ = listener.accept()
                        except TimeoutError:
                            continue
                        connects.append(True)
                        try:
                            with conn, tls.wrap_socket(conn, server_side=True) as peer:
                                peer.settimeout(5)
                                method, target, headers, body = request_headers(peer)
                                requests.append((method, urlsplit(target).path))
                                if protocol in ("fortinet", "f5"):
                                    if ppp_peer.exchange(peer, method, target, headers, mode, protocol, read_exact):
                                        packets.append(True)
                                    continue
                                frame = (cstp(peer, method, target, headers, mode) if protocol == "anyconnect"
                                         else globalprotect(peer, method, target, body))
                                if frame is None:
                                    continue
                                head, length = frame
                                packet = bytearray(read_exact(peer, length))
                                assert len(packet) == 32 and packet[0] == 0x45 and packet[28:] == b"cstp"
                                packet[12:16], packet[16:20] = packet[16:20], packet[12:16]
                                packet[20:22], packet[22:24] = packet[22:24], packet[20:22]
                                peer.sendall(head + packet)
                                packets.append(True)
                                # The client closes this stream before submitting its GP logout.
                                peer.recv(1024)
                        except (ssl.SSLError, EOFError, ConnectionResetError):
                            # TLS peers may close an authenticated connection when
                            # switching from gateway configuration to a tunnel or
                            # performing logout. Required completed exchanges are
                            # asserted from the native probe and the trace below.
                            pass
                        except Exception as exc:
                            errors.append(exc)
                thread = threading.Thread(target=serve)
                thread.start()
                try:
                    supplied = {"bad-pin": "pin-sha256:" + "A" * 43 + "=", "short-pin": pin[:20]}.get(mode, pin)
                    subprocess.run([probe, str(listener.getsockname()[1]), str(root / "ca.pem"), supplied, mode, protocol],
                                   timeout=16, check=True)
                finally:
                    done.set()
                    thread.join(timeout=7)
                assert not errors and not thread.is_alive(), (mode, errors)
                assert bool(requests) == (mode in ("allow", "allow-hdlc", "allow-dual", "bad-route", "scoped-dns")) and bool(packets) == mode.startswith("allow"), mode
                assert bool(connects) == (mode not in ("bad-interface", "bad-host")), mode
                logout = {"gp": ("POST", "/ssl-vpn/logout.esp"), "f5": ("GET", "/vdesk/hangup.php3"),
                          "fortinet": ("GET", "/remote/logout")}
                if protocol in logout and mode.startswith("allow"):
                    assert logout[protocol] in requests, requests
                print(protocol, mode, "passed", flush=True)


if __name__ == "__main__":
    run(str(Path(sys.argv[1]).resolve()))
