// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// proxy_test.go — the SOCKS5 / HTTP CONNECT / DNS-over-TCP handshakes against
// loopback test servers. No real network, no real proxy: every server here is a
// few lines of net.Listener that speaks just enough of the protocol to prove
// the client half is on-spec. These run in Tools/build-proxy-engine.sh, so a
// wire-format regression fails the build rather than a tunnel that connects and
// carries nothing.

package pxengine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestParseUpstream(t *testing.T) {
	cases := []struct {
		raw      string
		wantKind proxyKind
		wantAddr string
	}{
		{"socks5://host:1080", proxySOCKS5, "host:1080"},
		{"socks5://host", proxySOCKS5, "host:1080"},
		{"http://p:3128", proxyHTTPConnect, "p:3128"},
		{"http://p", proxyHTTPConnect, "p:8080"},
		{"https://secure.example", proxyHTTPSConnect, "secure.example:443"},
	}
	for _, c := range cases {
		up, err := parseUpstream(c.raw, "", "")
		if err != nil {
			t.Fatalf("%s: %v", c.raw, err)
		}
		if up.kind != c.wantKind || up.address != c.wantAddr {
			t.Errorf("%s: got kind=%d addr=%s", c.raw, up.kind, up.address)
		}
	}
	for _, bad := range []string{"", "ftp://x", "socks5://", "not a url", "://nohost"} {
		if _, err := parseUpstream(bad, "", ""); err == nil {
			t.Errorf("%q should have been rejected", bad)
		}
	}
}

func TestParseUpstreamCredentialsPrecedence(t *testing.T) {
	// Explicit credentials win over URL userinfo.
	up, err := parseUpstream("socks5://url-user:url-pass@host:1080", "opt-user", "opt-pass")
	if err != nil {
		t.Fatal(err)
	}
	if up.username != "opt-user" || up.password != "opt-pass" {
		t.Fatalf("explicit creds should win: %s/%s", up.username, up.password)
	}
	// Userinfo is the fallback when none supplied out of band.
	up, err = parseUpstream("socks5://url-user:url-pass@host:1080", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if up.username != "url-user" || up.password != "url-pass" {
		t.Fatalf("userinfo fallback failed: %s/%s", up.username, up.password)
	}
}

// --- SOCKS5 CONNECT ---------------------------------------------------------

// fakeSOCKS5 answers one CONNECT, records what it was asked to reach, and pipes
// the tunnelled stream to an echo. wantAuth selects the required auth method.
func fakeSOCKS5(t *testing.T, wantAuth bool, wantUser, wantPass string) (addr string, reached chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	reached = make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)

		// Greeting.
		hdr := make([]byte, 2)
		io.ReadFull(br, hdr)
		methods := make([]byte, hdr[1])
		io.ReadFull(br, methods)
		if wantAuth {
			conn.Write([]byte{0x05, socksUserPass})
			// RFC 1929 sub-negotiation.
			ver := make([]byte, 2)
			io.ReadFull(br, ver)
			u := make([]byte, ver[1])
			io.ReadFull(br, u)
			pl := make([]byte, 1)
			io.ReadFull(br, pl)
			p := make([]byte, pl[0])
			io.ReadFull(br, p)
			if string(u) != wantUser || string(p) != wantPass {
				conn.Write([]byte{0x01, 0x01}) // failure
				return
			}
			conn.Write([]byte{0x01, 0x00}) // success
		} else {
			conn.Write([]byte{0x05, socksNoAuth})
		}

		// Request.
		reqHdr := make([]byte, 4)
		io.ReadFull(br, reqHdr)
		var host string
		switch reqHdr[3] {
		case socksAtypIPv4:
			b := make([]byte, 4)
			io.ReadFull(br, b)
			host = net.IP(b).String()
		case socksAtypDomain:
			l := make([]byte, 1)
			io.ReadFull(br, l)
			b := make([]byte, l[0])
			io.ReadFull(br, b)
			host = string(b)
		case socksAtypIPv6:
			b := make([]byte, 16)
			io.ReadFull(br, b)
			host = net.IP(b).String()
		}
		pb := make([]byte, 2)
		io.ReadFull(br, pb)
		reached <- host

		// Success reply with a dummy bound address.
		conn.Write([]byte{0x05, 0x00, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0})

		// Echo the tunnelled stream.
		io.Copy(conn, br)
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), reached
}

func TestSOCKS5ConnectNoAuth(t *testing.T) {
	addr, reached := fakeSOCKS5(t, false, "", "")
	up, _ := parseUpstream("socks5://"+addr, "", "")
	conn, err := up.dialThrough(context.Background(), &net.Dialer{}, "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := <-reached; got != "example.com" {
		t.Fatalf("proxy asked to reach %q", got)
	}
	// The tunnel echoes.
	conn.Write([]byte("ping"))
	buf := make([]byte, 4)
	io.ReadFull(conn, buf)
	if string(buf) != "ping" {
		t.Fatalf("tunnel echo: %q", buf)
	}
}

func TestSOCKS5ConnectWithAuth(t *testing.T) {
	addr, reached := fakeSOCKS5(t, true, "alice", "s3cret")
	up, _ := parseUpstream("socks5://"+addr, "alice", "s3cret")
	conn, err := up.dialThrough(context.Background(), &net.Dialer{}, "10.0.0.1", 22)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := <-reached; got != "10.0.0.1" {
		t.Fatalf("proxy asked to reach %q", got)
	}
}

func TestSOCKS5AuthRejected(t *testing.T) {
	addr, _ := fakeSOCKS5(t, true, "alice", "right")
	up, _ := parseUpstream("socks5://"+addr, "alice", "wrong")
	if _, err := up.dialThrough(context.Background(), &net.Dialer{}, "x", 1); err == nil {
		t.Fatal("a wrong password must fail the dial")
	}
}

// --- HTTP CONNECT -----------------------------------------------------------

func fakeHTTPConnect(t *testing.T, wantAuth string) (addr string, reached chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	reached = make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if wantAuth != "" && req.Header.Get("Proxy-Authorization") != wantAuth {
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
			return
		}
		reached <- req.Host
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		io.Copy(conn, br) // echo tunnel
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), reached
}

func TestHTTPConnect(t *testing.T) {
	addr, reached := fakeHTTPConnect(t, "")
	up, _ := parseUpstream("http://"+addr, "", "")
	conn, err := up.dialThrough(context.Background(), &net.Dialer{}, "example.org", 443)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := <-reached; got != "example.org:443" {
		t.Fatalf("CONNECT target %q", got)
	}
	conn.Write([]byte("hi"))
	buf := make([]byte, 2)
	io.ReadFull(conn, buf)
	if string(buf) != "hi" {
		t.Fatalf("tunnel echo: %q", buf)
	}
}

func TestHTTPConnectBasicAuth(t *testing.T) {
	// base64("bob:pw") = Ym9iOnB3
	addr, reached := fakeHTTPConnect(t, "Basic Ym9iOnB3")
	up, _ := parseUpstream("http://"+addr, "bob", "pw")
	conn, err := up.dialThrough(context.Background(), &net.Dialer{}, "host", 80)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := <-reached; got != "host:80" {
		t.Fatalf("CONNECT target %q", got)
	}
}

func TestHTTPConnectRejected(t *testing.T) {
	addr, _ := fakeHTTPConnect(t, "Basic expected")
	up, _ := parseUpstream("http://"+addr, "bob", "wrong")
	if _, err := up.dialThrough(context.Background(), &net.Dialer{}, "host", 80); err == nil {
		t.Fatal("407 must fail the dial")
	}
}

// --- DNS-over-TCP ------------------------------------------------------------

// fakeDNSoverTCPProxy is an HTTP CONNECT proxy that, once tunnelled, speaks the
// server end of DNS-over-TCP: read one framed query, reply with a framed
// message that echoes the query id.
func fakeDNSoverTCPProxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				br := bufio.NewReader(conn)
				if _, err := http.ReadRequest(br); err != nil {
					return
				}
				conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				// DNS-over-TCP server side.
				var l [2]byte
				if _, err := io.ReadFull(br, l[:]); err != nil {
					return
				}
				n := binary.BigEndian.Uint16(l[:])
				q := make([]byte, n)
				io.ReadFull(br, q)
				// Reply: same length, flip QR bit region cosmetically; keep id.
				resp := make([]byte, n)
				copy(resp, q)
				out := make([]byte, 2+n)
				binary.BigEndian.PutUint16(out[:2], n)
				copy(out[2:], resp)
				conn.Write(out)
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func TestDNSOverTCP(t *testing.T) {
	addr := fakeDNSoverTCPProxy(t)
	up, _ := parseUpstream("http://"+addr, "", "")
	query := []byte{0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0} // minimal header
	resp, err := dnsOverTCP(context.Background(), up, &net.Dialer{}, "8.8.8.8", 53, query)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resp[:2], query[:2]) {
		t.Fatalf("response id %x should echo query id %x", resp[:2], query[:2])
	}
}

func TestDNSOverTCPRejectsOversize(t *testing.T) {
	up, _ := parseUpstream("http://127.0.0.1:1", "", "")
	if _, err := dnsOverTCP(context.Background(), up, &net.Dialer{}, "x", 53, make([]byte, maxDNSMessage+1)); err == nil {
		t.Fatal("an oversize query must be refused before any dial")
	}
}

// --- SOCKS UDP framing -------------------------------------------------------

func TestSOCKSUDPEncapDecapRoundTrip(t *testing.T) {
	payload := []byte("datagram")
	enc, err := socksUDPEncap("1.2.3.4", 53, payload)
	if err != nil {
		t.Fatal(err)
	}
	// Header: RSV RSV FRAG ATYP=1 + 4 addr + 2 port = 10 bytes.
	if len(enc) != 10+len(payload) {
		t.Fatalf("encap length %d", len(enc))
	}
	got, err := socksUDPDecap(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round trip lost payload: %q", got)
	}
}

func TestSOCKSUDPDecapRejectsFragment(t *testing.T) {
	enc, _ := socksUDPEncap("1.2.3.4", 53, []byte("x"))
	enc[2] = 0x01 // FRAG != 0
	if _, err := socksUDPDecap(enc); err == nil {
		t.Fatal("a fragmented datagram must be dropped")
	}
}

func TestSOCKSUDPEncapDomain(t *testing.T) {
	enc, err := socksUDPEncap("example.com", 443, []byte("d"))
	if err != nil {
		t.Fatal(err)
	}
	if enc[3] != socksAtypDomain || int(enc[4]) != len("example.com") {
		t.Fatalf("domain encap malformed: % x", enc[:6])
	}
}

// --- SOCKS UDP ASSOCIATE end to end -----------------------------------------

// fakeSOCKS5UDP grants UDP ASSOCIATE and echoes datagrams sent to its relay.
func fakeSOCKS5UDP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	relayPort := relay.LocalAddr().(*net.UDPAddr).Port
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		hdr := make([]byte, 2)
		io.ReadFull(br, hdr)
		methods := make([]byte, hdr[1])
		io.ReadFull(br, methods)
		conn.Write([]byte{0x05, socksNoAuth})
		// Request (UDP ASSOCIATE).
		reqHdr := make([]byte, 4)
		io.ReadFull(br, reqHdr)
		// DST 0.0.0.0:0 → 4 + 2 bytes.
		io.ReadFull(br, make([]byte, 6))
		// Reply with the relay address.
		reply := []byte{0x05, 0x00, 0x00, socksAtypIPv4, 127, 0, 0, 1,
			byte(relayPort >> 8), byte(relayPort & 0xFF)}
		conn.Write(reply)
		// Keep the control connection open until the client closes.
		io.Copy(io.Discard, br)
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := relay.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// Echo the whole SOCKS-UDP datagram straight back (header + payload).
			relay.WriteToUDP(append([]byte(nil), buf[:n]...), from)
		}
	}()
	t.Cleanup(func() { ln.Close(); relay.Close() })
	return ln.Addr().String()
}

func TestSOCKS5UDPAssociateGrant(t *testing.T) {
	// Exercise just the control-plane grant: negotiate + ASSOCIATE returns a
	// relay without error (the full data-plane relay needs the netstack, tested
	// via the contract of serveUDPviaSOCKS's error return).
	addr := fakeSOCKS5UDP(t)
	up, _ := parseUpstream("socks5://"+addr, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := up.dialProxyConn(ctx, &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := socks5Negotiate(conn, "", ""); err != nil {
		t.Fatal(err)
	}
	req, _ := socksRequest(socksCmdUDPAssoc, "0.0.0.0", 0)
	conn.Write(req)
	ip, port, err := readSocksReply(conn)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "127.0.0.1" || port == 0 {
		t.Fatalf("relay address %v:%d", ip, port)
	}
}

func TestSOCKS5CommandNotSupported(t *testing.T) {
	// A proxy that refuses UDP ASSOCIATE returns 0x07; readSocksReply must turn
	// that into an error so serveUDP falls back to DNS-over-TCP.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		hdr := make([]byte, 2)
		io.ReadFull(br, hdr)
		io.ReadFull(br, make([]byte, hdr[1]))
		conn.Write([]byte{0x05, socksNoAuth})
		io.ReadFull(br, make([]byte, 4+6))
		conn.Write([]byte{0x05, 0x07, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
	}()
	t.Cleanup(func() { ln.Close() })
	up, _ := parseUpstream("socks5://"+ln.Addr().String(), "", "")
	conn, _ := up.dialProxyConn(context.Background(), &net.Dialer{})
	defer conn.Close()
	socks5Negotiate(conn, "", "")
	req, _ := socksRequest(socksCmdUDPAssoc, "0.0.0.0", 0)
	conn.Write(req)
	if _, _, err := readSocksReply(conn); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("expected 'command not supported', got %v", err)
	}
}
