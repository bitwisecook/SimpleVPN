# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
"""Drive ocauth-helper with disposable credentials and verify its authenticated handoff."""
import base64
import hashlib
import json
from pathlib import Path
import runpy
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import xml.etree.ElementTree as ET
from urllib.parse import parse_qs, urlsplit

fixtures = runpy.run_path(str(Path(__file__).with_name("legacy-member-peer-test.py")))
read_headers, read_exact, pulse = (fixtures[k] for k in ("read_headers","read_exact","pulse_fixture"))
pw = "synthetic-password"
token = "disposable-fixture"

def response(peer,body=b"ok", headers=b""):
    peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n"+headers+
                 b"Content-Length: "+str(len(body)).encode()+b"\r\n\r\n"+body)

def authentication(peer,proto):
    head,fields=read_headers(peer)
    if proto=="pulse":
        with peer.makefile("rwb") as c:
            pulse._send_ift_upgrade(c); pulse._expect_ift(c,pulse.VENDOR_TCG,1);pulse._send_ift_version(c)
            pulse._expect_ift(c,pulse.VENDOR_JUNIPER,0x88);pulse._send_ift_auth(c)
            pulse._expect_ift(c,pulse.VENDOR_TCG,6);pulse._send_ift_auth_eap(c)
            pulse._expect_ift(c,pulse.VENDOR_TCG,6);pulse._send_ift_pass_req(c)
            answer=pulse._expect_ift(c,pulse.VENDOR_TCG,6)
            assert pw.encode() in answer and b"fixture-user" in answer
            pulse._send_ift_auth_cookie(c);pulse._expect_ift(c,pulse.VENDOR_TCG,6);pulse._send_ift_success(c)
        return
    if head[0]=="GET":
        if proto=="f5":
            response(peer,b'<html><body><form id="auth_form" method="post" action="/my.policy"><table><tr><td id="credentials_table_header">Fixture</td></tr></table><input type="text" name="username"/><input type="password" name="password"/></form></body></html>')
            return
        if proto=="fortinet":
            response(peer,b"login page")
            return
        assert proto=="nc", (head,proto)
        response(peer,b'<html><body><form name="frmLogin" method="post" action="/login"><input type="text" name="username"/><input type="password" name="password"/><input type="submit" name="btnSubmit" value="Sign In"/></form></body></html>')
        return
    payload=read_exact(peer,int(fields["content-length"]))
    if proto=="anyconnect":
        document=ET.fromstring(payload)
        assert document.tag=="config-auth"
        if document.get("type")=="init":
            response(peer,b'<config-auth client="vpn" type="auth-request" aggregate-auth-version="2"><auth id="main"><message>Login</message><form method="post" action="/"><input type="text" name="username" label="Username:"/><input type="password" name="password" label="Password:"/></form></auth></config-auth>')
        else:
            assert document.get("type")=="auth-reply" and document.findtext(".//username")=="fixture-user" and document.findtext(".//password")==pw
            response(peer,f'<config-auth client="vpn" type="complete" aggregate-auth-version="2"><session-id>1234</session-id><session-token>{token}</session-token><auth id="success"/><config/></config-auth>'.encode())
        return
    body=parse_qs(payload.decode())
    if proto=="gp":
        if head[1].startswith("/ssl-vpn/prelogin.esp"):
            response(peer,b'<prelogin-response><status>Success</status><authentication-message>Login</authentication-message><username-label>Username</username-label><password-label>Password</password-label><panos-version>1</panos-version><region>US</region></prelogin-response>')
        else:
            assert head[1]=="/ssl-vpn/login.esp" and body["user"]==["fixture-user"] and body["passwd"]==[pw], (head,list(body))
            args=["(null)",token,"PersistentCookie","test","fixture-user","TestAuth","vsys1","example","(null)","","","","tunnel","-1","4100","198.18.30.2","","",""]
            response(peer,("<jnlp><application-desc>"+"".join("<argument>"+v+"</argument>" for v in args)+"</application-desc></jnlp>").encode())
        return
    if proto=="fortinet":
        assert head[1]=="/remote/logincheck" and body["username"]==["fixture-user"] and body["credential"]==[pw]
        response(peer,b"ret=1,redir=/remote/fortisslvpn_xml",f"Set-Cookie: SVPNCOOKIE={token}; Path=/\r\n".encode())
        return
    if proto=="f5":
        assert head[1]=="/my.policy" and body["username"]==["fixture-user"] and body["password"]==[pw]
        response(peer,b"webtop",f"Set-Cookie: MRHSession={token}; Path=/\r\nSet-Cookie: F5_ST=fixture; Path=/\r\n".encode())
        return
    if proto=="array":
        assert head[1]=="/prx/000/http/localhost/login" and body["method"]==["staff"] and body["uname"]==["fixture-user"] and body["pwd"]==[pw], (head,list(body))
        name="ANsession"
    else:
        assert head[1]=="/login" and body["username"]==["fixture-user"] and body["password"]==[pw], (head,list(body))
        name="DSID"
    response(peer,b"<html>test webtop</html>",f"Set-Cookie: {name}={token}; Path=/\r\n".encode())

def run(helper, protocols):
    with tempfile.TemporaryDirectory(prefix="simplevpn-oc-auth-") as tmp:
        folder=Path(tmp)
        def openssl(*args,data=None):
            return subprocess.run(["openssl",*args],cwd=folder,input=data,capture_output=True,check=True).stdout
        openssl("req","-x509","-nodes","-newkey","rsa:2048","-keyout","key","-out","cert","-days","1","-subj","/CN=localhost",
                "-addext","subjectAltName=DNS:localhost,IP:127.0.0.1","-addext","basicConstraints=critical,CA:TRUE")
        der=openssl("pkey","-pubin","-outform","DER",data=openssl("x509","-pubkey","-noout","-in","cert"))
        pin="pin-sha256:"+base64.b64encode(hashlib.sha256(der).digest()).decode()
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(folder/"cert",folder/"key")
        for proto in protocols:
            for allowed in [False,True]:
                with socket.create_server(("127.0.0.1",0)) as server:
                    server.settimeout(.2);port=server.getsockname()[1];done=threading.Event();failures=[]; delivered=[]
                    def serve():
                        while not done.is_set():
                            try: c,_=server.accept()
                            except TimeoutError: continue
                            try:
                                with c,tls.wrap_socket(c,server_side=True) as peer:
                                    peer.settimeout(5);authentication(peer,proto)
                                    delivered.append(True)
                            except (EOFError,ssl.SSLError,ConnectionResetError) as e:
                                if allowed: failures.append(e)
                            except Exception as e:failures.append(e)
                    t=threading.Thread(target=serve);t.start()
                    try:
                        with subprocess.Popen([helper],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True) as child:
                            timer=threading.Timer(12,child.kill);timer.start()
                            def send(m): child.stdin.write(json.dumps(m)+"\n");child.stdin.flush()
                            desc=None
                            try:
                                path = "gateway" if proto=="gp" else ""
                                send({"start":{"protocol":proto,"server":f"https://localhost:{port}/{path}","params":{"cafile":str(folder/"cert"),"servercert":pin if allowed else "pin-sha256:"+"A"*43+"=","realm":"staff"}}})
                                for line in child.stdout:
                                    message=json.loads(line)
                                    if "form" in message:
                                        answers={}
                                        for field in message["form"]["fields"]:
                                            name=field["id"]
                                            if name=="method": answers[name]="staff"
                                            elif name in ("username","uname","user"):answers[name]="fixture-user"
                                            elif name in ("password","pwd","passwd","credential"):answers[name]=pw
                                            else:raise ValueError("unexpected field "+name)
                                        send({"answers":answers})
                                    elif "cert" in message: send({"accept":False})
                                    elif "done" in message: desc=message["done"];break
                                    elif "error" in message:
                                        if allowed: raise ValueError(message["error"])
                                        break
                            finally: timer.cancel()
                        assert bool(desc)==allowed
                        if desc:
                            cookie=desc["cookie"]
                            if proto=="gp":
                                assert parse_qs(cookie)["authcookie"]==[token] and parse_qs(cookie)["user"]==["fixture-user"]
                            elif proto=="anyconnect":
                                assert cookie==token or "webvpn="+token in [s.strip() for s in cookie.split(";")]
                            elif proto=="f5":
                                assert set(s.strip() for s in cookie.split(";"))=={"MRHSession="+token,"F5_ST=fixture"}
                            else:
                                wanted={"nc":"DSID="+token,"pulse":"c"*32,"array":"ANsession="+token,"fortinet":"SVPNCOOKIE="+token}[proto]
                                assert cookie==wanted
                            assert desc["servercert"]==pin
                            url=urlsplit(desc["connect-url"])
                            assert url.hostname=="localhost" and url.port==port and desc["resolve"]=={"host":"localhost","ip":"127.0.0.1"}, (url,desc.get("resolve"))
                    finally: done.set();t.join(6)
                    assert not failures and bool(delivered)==allowed, (proto,allowed,failures)
                    print(proto, "signed auth descriptor" if allowed else "wrong pin before submitting credentials", "passed",flush=True)

if __name__=="__main__":run(str(Path(sys.argv[1]).resolve()),sys.argv[2:] or ["anyconnect","gp","fortinet","f5","nc","pulse","array"])
