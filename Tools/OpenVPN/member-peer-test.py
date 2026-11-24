# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise two real OpenVPN3 member bridges through an unprivileged upstream OpenVPN2 server."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


def run(server, probe):
    with tempfile.TemporaryDirectory(prefix="simplevpn-openvpn-members-") as temp:
        root = Path(temp)

        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=root, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
                "-subj", "/CN=Temporary VPN CA", "-days", "1", "-addext", "basicConstraints=critical,CA:TRUE")
        for name, purpose in [("server", "serverAuth"), ("clientA", "clientAuth"), ("clientB", "clientAuth")]:
            openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={name}", "-keyout", name + ".key", "-out", name + ".csr")
            (root / "profile.ext").write_text(f"basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage={purpose}\n")
            openssl("x509", "-req", "-in", name + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
                    "-out", name + ".pem", "-days", "1", "-extfile", "profile.ext")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ephemeral:
            ephemeral.bind(("127.0.0.1", 0))
            port = ephemeral.getsockname()[1]
        clients = []
        for name in ["clientA", "clientB"]:
            path = root / (name + ".ovpn")
            text = f"client\nproto udp\ndev tun\nremote 127.0.0.1 {port}\nremote-cert-tls server\nverify-x509-name server name\n"
            for tag, file in [("ca", "ca.pem"), ("cert", name + ".pem"), ("key", name + ".key")]:
                text += f"<{tag}>\n{(root / file).read_text()}</{tag}>\n"
            path.write_text(text)
            clients.append(str(path))
        # OpenVPN2 discards all decrypted packets for --dev null before its
        # client-to-client switch. Its documented AF_UNIX TUN backend needs
        # no privileges, host addresses, routes or external network access.
        sink = root / "private-tun"
        sink.write_text(f"#!{sys.executable}\nimport os, socket\n"
                        "s = socket.socket(fileno=int(os.environ['TUNTAP_SOCKET_FD']))\n"
                        "while s.recv(65536): pass\n")
        sink.chmod(0o700)
        args = [server, "--dev", "tun", "--dev-node", "unix:" + str(sink),
                "--ifconfig-noexec", "--route-noexec", "--script-security", "2",
                "--proto", "udp4", "--local", "127.0.0.1", "--port", str(port), "--disable-dco",
                "--topology", "subnet", "--server", "198.18.27.0", "255.255.255.0", "--client-to-client",
                "--ca", "ca.pem", "--cert", "server.pem", "--key", "server.key", "--dh", "none", "--verb", "3"]
        with (root / "server.log").open("w") as log:
            gateway = subprocess.Popen(args, cwd=root, stdout=log, stderr=subprocess.STDOUT)
            try:
                for _ in range(50):
                    if gateway.poll() is not None:
                        raise RuntimeError((root / "server.log").read_text())
                    if "Initialization Sequence Completed" in (root / "server.log").read_text():
                        break
                    time.sleep(0.1)
                try:
                    subprocess.run([probe, *clients], check=True, timeout=45)
                except subprocess.CalledProcessError:
                    print((root / "server.log").read_text()[-6000:], file=sys.stderr)
                    raise
            finally:
                if gateway.poll() is None:
                    gateway.terminate()
                gateway.wait(timeout=5)


if __name__ == "__main__":
    run(os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2]))
