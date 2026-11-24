# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
"""Verify the production nc/pulse/array member bridge on loopback without any tunnel devices."""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace

def module(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

fixture = Path(__file__).resolve().parent
read_exact = module(fixture / "member-peer-test.py").read_exact
source = Path(os.environ.get("OPENCONNECT_SOURCE",fixture.parents[1]/"build/openconnect-src"))
pulse_fixture = module(source/"tests/fake-pulse-server.py")
VIP = "198.18.30.2"
COOKIE = "disposable-fixture"

def read_headers(peer):
    raw = b""
    while not raw.endswith(b"\r\n\r\n"):
        if len(raw) > 32768: raise ValueError("long HTTP header")
        raw += read_exact(peer,1)
    first,*lines = raw.decode("ascii").strip().split("\r\n")
    fields = dict((k.lower(),v.strip()) for k,v in (row.split(":",1) for row in lines))
    return first.split(" ")[:2], fields

def reply_ip(packet):
    assert len(packet)==32 and packet[0]==0x45 and packet[28:]==b"cstp", packet.hex()
    return packet[:12]+packet[16:20]+packet[12:16]+packet[22:24]+packet[20:22]+packet[24:]

def array(peer, head, fields, mode):
    assert head == ["GET","/vpntunnel"] and fields["cookie"] == "ANsession="+COOKIE
    peer.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
    assert read_exact(peer,16)[0] == 0x50
    peer.sendall(bytes(16)+b'{"allow_speed_tunnel":0}')
    assert read_exact(peer,48)[0] == 0x54
    cfg = dict(client_ipv4=int.from_bytes(socket.inet_aton(VIP),"little"),client_ipv4_mask=16777215)
    if mode=="bad-route": cfg["include_network_resource"]={"ipv6":[{"ip":"2001:db8::1","mask":64}]}
    peer.sendall(bytes(16)+json.dumps(cfg).encode())
    if mode=="bad-route": return
    while True:
        header = read_exact(peer,20)
        payload = header + read_exact(peer,int.from_bytes(header[2:4],"big")-20)
        if header[9] == 0xff: continue
        peer.sendall(reply_ip(payload))
        return

def nc(peer, head, fields, mode):
    assert head == ["POST","/dana/js?prot=1&svc=4"] and "DSID="+COOKIE in fields["cookie"]
    peer.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
    def record(): return read_exact(peer, int.from_bytes(read_exact(peer,2),"little"))
    assert record()[0:2] == b"\0\x04"
    def tlv(key,value): return struct.pack(">HI",key,len(value))+value
    def kmp(key,value): return bytes(6)+struct.pack(">H",key)+b"\x01"+bytes(9)+struct.pack(">H",len(value))+value
    config = tlv(1,tlv(1,socket.inet_aton(VIP))+tlv(2,b"\xff\xff\xff\0"))+tlv(6,tlv(2,struct.pack(">I",1400)))
    if mode=="bad-route": config+=tlv(3,tlv(4,socket.inet_aton("10.0.0.0")+socket.inet_aton("255.0.0.0")))
    packet = kmp(301,config)
    peer.sendall(b"\x01\x00\x00")
    peer.sendall(len(packet).to_bytes(2,"little")+packet)
    if mode=="bad-route": return
    assert record()[6:8]==struct.pack(">H",303)
    data = record()
    assert data[6:8]==struct.pack(">H",300)
    packet = kmp(300,reply_ip(data[20:]))
    peer.sendall(len(packet).to_bytes(2,"little")+packet)

def pulse(peer, head, fields, mode):
    assert head[0]=="GET" and fields["upgrade"].lower()=="if-t/tls 1.0"
    pf=pulse_fixture
    with peer.makefile("rwb") as c:
        pf._send_ift_upgrade(c)
        pf._expect_ift(c,pf.VENDOR_TCG,1);pf._send_ift_version(c)
        pf._expect_ift(c,pf.VENDOR_JUNIPER,0x88);pf._send_ift_auth(c)
        pf._expect_ift(c,pf.VENDOR_TCG,6);pf._send_ift_auth_eap(c)
        auth=pf._expect_ift(c,pf.VENDOR_TCG,6)
        assert COOKIE.encode() in auth
        pf._send_ift_auth_cookie(c);pf._expect_ift(c,pf.VENDOR_TCG,6);pf._send_ift_success(c)
        cfg=io.BytesIO()
        pf._send_ift_config(SimpleNamespace(vpnnet=[VIP,"24"]),cfg)
        data=bytearray(cfg.getvalue())
        if mode=="bad-route":
            offset=data.index(bytes.fromhex("2e00000800000000"),44)
            data[offset:offset+8]=struct.pack(">HHBBBBIIII",0x2e00,24,1,0,0,0,0x07000010,65535,0xc6121e05,0xc6121e06)
            for pos in (8,40): struct.pack_into(">I",data,pos,struct.unpack_from(">I",data,pos)[0]+16)
        pf._send_ift(c,bytes(data))
        if mode=="bad-route": return
        pf._send_ift_config_end(c)
        while True:
            msg=pf._recv_ift(c)
            if struct.unpack(">II",msg[:8])==(pf.VENDOR_JUNIPER,4):
                frame=reply_ip(msg[16:])
                pf._send_ift_chunked(c,struct.pack(">IIII",pf.VENDOR_JUNIPER,4,len(frame)+16,0)+frame)
                return

def run(probe, protocols):
    with tempfile.TemporaryDirectory(prefix="simplevpn-legacy-tls-") as tmp:
        folder=Path(tmp)
        name="gateway.fixture.invalid"
        def openssl(*args, data=None):
            return subprocess.run(["openssl",*args],cwd=folder,input=data,capture_output=True,check=True).stdout
        openssl("req","-x509","-nodes","-newkey","rsa:2048","-keyout","key","-out","cert","-days","1","-subj","/CN="+name,
                "-addext","subjectAltName=DNS:"+name,"-addext","basicConstraints=critical,CA:TRUE")
        pub=openssl("x509","-noout","-pubkey","-in","cert")
        der=openssl("pkey","-pubin","-outform","DER",data=pub)
        pin="pin-sha256:"+base64.b64encode(hashlib.sha256(der).digest()).decode()
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(folder/"cert", folder/"key")
        tls.set_servername_callback(lambda _c,got,_ctx: None if got==name else ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
        for proto in protocols:
            for mode in ["bad-pin","bad-route","allow"]:
                with socket.create_server(("127.0.0.1",0)) as server:
                    server.settimeout(.2)
                    done=threading.Event(); failures=[]; packets=[]; headers=[]
                    def serve():
                        while not done.is_set():
                            try: conn,_=server.accept()
                            except TimeoutError:continue
                            try:
                                with conn, tls.wrap_socket(conn,server_side=True) as peer:
                                    peer.settimeout(6)
                                    head,fields=read_headers(peer)
                                    headers.append(head)
                                    if mode=="bad-pin":raise ValueError("authentication crossed the wrong pin")
                                    if head[1].startswith(("/dana-na/auth/logout.cgi", "/prx/000/http/localhost/logout")):
                                        peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");continue
                                    {"pulse":pulse,"nc":nc,"array":array}[proto](peer,head,fields,mode)
                                    if mode=="allow": packets.append(True)
                                    peer.recv(1024)
                            except (ssl.SSLError, EOFError, ConnectionResetError) as exc:
                                if mode=="allow" and not packets:failures.append(exc)
                            except Exception as exc:failures.append(exc)
                    t=threading.Thread(target=serve);t.start()
                    try:
                        proc=subprocess.run([probe,str(server.getsockname()[1]),str(folder/"cert"),pin if mode!="bad-pin" else "pin-sha256:"+"A"*43+"=", mode,proto],timeout=18)
                    finally:
                        done.set();t.join(8)
                    assert not t.is_alive() and not failures, (proto,mode,failures,headers)
                    assert proc.returncode==0 and bool(packets)==(mode=="allow"), (proto,mode,proc.returncode,headers)
                    print(proto,mode,"passed",flush=True)

if __name__=="__main__": run(str(Path(sys.argv[1]).resolve()), sys.argv[2:] or ["nc","pulse","array"])
