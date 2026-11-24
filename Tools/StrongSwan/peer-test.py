# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise authenticated IKE/ESP across a private socketpair. No routes or listeners."""
import contextlib
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile


def certificates(folder):
    def openssl(*args):
        subprocess.run(["openssl", *args], check=True, cwd=folder, capture_output=True)

    for name in ("root", "untrusted"):
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", "/CN=Ephemeral " + name, "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", name+".key", "-out", name+".pem")
        openssl("x509", "-in", name+".pem", "-outform", "DER", "-out", name+".der")
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=gateway.test",
            "-keyout", "gateway.key", "-out", "gateway.csr")
    (folder / "usage").write_text("basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,1.3.6.1.5.5.8.2.2\n"
        "subjectAltName=DNS:gateway.test\n")
    openssl("x509", "-req", "-in", "gateway.csr", "-days", "2", "-CA", "root.pem",
            "-CAkey", "root.key", "-CAcreateserial", "-extfile", "usage", "-out", "gateway.pem")


def check_peer(binary, version, role, folder):
    with contextlib.ExitStack() as stack:
        def sockets():
            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            return stack.enter_context(left), stack.enter_context(right)

        def launch(argv, channels, **env):
            fds = {key: value.fileno() for key, value in channels.items()}
            child = subprocess.Popen(argv, pass_fds=list(fds.values()), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    env={**os.environ, **env, **{k: str(v) for k, v in fds.items()}})
            def stop():
                if child.poll() is None:
                    child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                child.stdout.close()
                child.stdin.close()
            stack.callback(stop)
            return child

        left, right = sockets()
        server_fds = {"PEER_FD": left}
        if version == "l2tp":
            lane, endpoint = sockets()
            server_fds["L2TP_FD"] = lane
            lns = launch([sys.argv[2], role], {"INNER_FD": endpoint})
        certs = dict(FIXTURE_CA=str(folder / "root.der"), FIXTURE_SERVER_CERT=str(folder / "gateway.pem"),
                     FIXTURE_SERVER_KEY=str(folder / "gateway.key"))
        server = launch([binary, "server", version], server_fds, **certs, **({"FIXTURE_WAIT_FOR_CLIENT": "1"} if role == "client" and version != "l2tp" else {}))
        with selectors.DefaultSelector() as sel:
            sel.register(server.stdout, selectors.EVENT_READ)
            line = server.stdout.readline().split() if sel.select(10) else []
            if len(line) != 2 or line[0] != b"READY" or not line[1].isdigit():
                raise RuntimeError("server startup failed")
        if role == "untrusted":
            certs["FIXTURE_CA"] = str(folder / "untrusted.der")
        client = launch([binary, role, version], {"PEER_FD": right}, FIXTURE_PORT=line[1].decode(), **certs)
        if client.wait(timeout=20):
            raise RuntimeError(f"{version} {role} failed")
        if version == "l2tp" and role in ("client", "wrong-user"):
            if lns.wait(timeout=5): raise RuntimeError("PPP reference endpoint failed")
        elif version != "l2tp" and role == "client":
            server.stdin.write(b"1")
            server.stdin.flush()
            if server.wait(timeout=20):
                raise RuntimeError("return-path check failed")
    print(f"Passed {version} {role}", flush=True)


with tempfile.TemporaryDirectory(prefix="simplevpn-ike-fixture-") as tmp:
    folder = Path(tmp)
    certificates(folder)
    modes = {
        "v2": ("client", "wrong", "wrong-id"),
        "v1": ("client", "wrong", "wrong-id"),
        "l2tp": ("client", "wrong", "wrong-id", "wrong-user", "no-ppp-auth"),
        "xauth": ("client", "wrong-user"),
        "eap": ("client", "wrong-user", "wrong-id", "untrusted"),
    }
    for version, roles in modes.items():
        for role in roles:
            check_peer(sys.argv[1], version, role, folder)
