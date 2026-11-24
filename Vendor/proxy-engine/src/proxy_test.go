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
	"github.com/sagernet/sing/protocol/socks/socks5"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	socksAtypIPv4   = 1
	socksAtypDomain = 3
	socksAtypIPv6   = 4
	socksUserPass   = socks5.AuthTypeUsernamePassword
	socksNoAuth     = socks5.AuthTypeNotRequired
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

func TestSOCKSUDPHeader(t *testing.T) {
	for _, tc := range []struct {
		host string
		want []byte
	}{
		{"1.2.3.4", []byte{0, 0, 0, 1, 1, 2, 3, 4, 0, 53}},
		{"example.com", append(append([]byte{0, 0, 0, 3, 11}, []byte("example.com")...), 0, 53)},
	} {
		header, err := socksUDPHeader(tc.host, 53)
		if err != nil || !bytes.Equal(header, tc.want) {
			t.Errorf("%s: header %x, error %v", tc.host, header, err)
		}
	}
}

// --- SOCKS UDP ASSOCIATE end to end -----------------------------------------

// fakeSOCKS5UDP grants UDP ASSOCIATE and echoes datagrams sent to its relay.
func fakeSOCKS5UDP(t *testing.T, invalidFirst bool) string {
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
			if invalidFirst && n >= 10 && buf[3] == socksAtypIPv4 {
				foreign := append([]byte(nil), buf[:n]...)
				foreign[9] ^= 1
				copy(foreign[10:], "xx")
				_, _ = relay.WriteToUDP(foreign, from)
				foreign[9] ^= 1
				foreign[2] = 1
				_, _ = relay.WriteToUDP(foreign, from)
			}
			// Echo the whole SOCKS-UDP datagram straight back (header + payload).
			relay.WriteToUDP(append([]byte(nil), buf[:n]...), from)
		}
	}()
	t.Cleanup(func() { ln.Close(); relay.Close() })
	return ln.Addr().String()
}

func TestUDPCancellationClosesIdleAssociation(t *testing.T) {
	addr := fakeSOCKS5UDP(t, true)
	up, _ := parseUpstream("socks5://"+addr, "", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := &engineState{ctx: ctx, up: up, dialer: &net.Dialer{}}
	guest, app := net.Pipe()
	defer app.Close()
	done := make(chan error, 1)
	go func() { done <- st.serveUDPviaSOCKS(guest, "192.0.2.1", 1234) }()
	_ = app.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := app.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(app, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != "hi" || st.udpRelayRejected.Load() != 2 {
		t.Fatalf("cross-flow or fragmented data reached guest: %q (%d rejected)", reply, st.udpRelayRejected.Load())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("idle UDP relay was not closed")
	}
}

func TestSOCKS5UDPAssociateGrant(t *testing.T) {
	// Exercise just the control-plane grant: negotiate + ASSOCIATE returns a
	// relay without error (the full data-plane relay needs the netstack, tested
	// via the contract of serveUDPviaSOCKS's error return).
	addr := fakeSOCKS5UDP(t, false)
	up, _ := parseUpstream("socks5://"+addr, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := up.dialProxyConn(ctx, &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	relay, err := up.socksHandshake(conn, socks5.CommandUDPAssociate, "0.0.0.0", 0)
	if err != nil {
		t.Fatal(err)
	}
	if relay.Addr.String() != "127.0.0.1" || relay.Port == 0 {
		t.Fatalf("relay address %v", relay)
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
	if _, err := up.socksHandshake(conn, socks5.CommandUDPAssociate, "0.0.0.0", 0); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("expected 'command not supported', got %v", err)
	}
}

// A greeting can arrive in the same TCP segment as the proxy's reply.
// An unsuccessful response, on the other hand, must never drain a stalled body.
func TestConnectResponseBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, response, greeting string
		ok                       bool
	}{
		{"interim", "HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\n\r\nhello", "hello", true},
		{"greeting", "HTTP/1.1 200 OK\r\n\r\nSSH-2.0-fixture\r\n", "SSH-2.0-fixture\r\n", true},
		{"oversized", "HTTP/1.1 200 OK\r\nX: " + strings.Repeat("a", maxConnectHeaders) + "\r\n\r\n", "", false},
		{"unfinished error body", "HTTP/1.1 407 Denied\r\nContent-Length: 1000\r\n\r\n", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			go func() {
				_, _ = http.ReadRequest(bufio.NewReader(server))
				_, _ = io.WriteString(server, tc.response)
			}()
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := httpConnect(client, "example.test", 22, "", "")
				if tc.ok != (err == nil) {
					t.Errorf("unexpected handshake result: %v", err)
					return
				}
				if tc.ok {
					got := make([]byte, len(tc.greeting))
					if _, err := io.ReadFull(conn, got); err != nil || string(got) != tc.greeting {
						t.Errorf("greeting = %q, %v", got, err)
					}
				}
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				client.Close()
				<-done
				t.Fatal("handshake remained blocked")
			}
		})
	}
}

// Wait until a real loopback peer has received the request, then leave its
// response outstanding as the VPN disconnects.
func TestCancelledProxyExchangeReleasesSocket(t *testing.T) {
	for _, mode := range []string{"CONNECT", "UDP ASSOCIATE", "DNS response"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			up, err := parseUpstream("http://"+listener.Addr().String(), "", "")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				switch mode {
				case "CONNECT":
					conn, err := up.dialThrough(ctx, &net.Dialer{}, "example.test", 443)
					if conn != nil {
						conn.Close()
					}
					done <- err
				case "UDP ASSOCIATE":
					up.kind = proxySOCKS5
					guest, app := net.Pipe()
					defer app.Close()
					defer guest.Close()
					st := &engineState{ctx: ctx, up: up, dialer: &net.Dialer{}}
					done <- st.serveUDPviaSOCKS(guest, "192.0.2.1", 443)
				case "DNS response":
					_, err := dnsOverTCP(ctx, up, &net.Dialer{}, "192.0.2.53", 53, []byte{1, 2})
					done <- err
				}
			}()
			_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
			server, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(3 * time.Second))
			br := bufio.NewReader(server)
			switch mode {
			case "UDP ASSOCIATE":
				_, err = io.ReadFull(br, make([]byte, 3))
			default:
				_, err = http.ReadRequest(br)
				if err == nil && mode == "DNS response" {
					_, err = io.WriteString(server, "HTTP/1.1 200 OK\r\n\r\n")
					if err == nil {
						_, err = io.ReadFull(br, make([]byte, 4))
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled exchange succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("exchange did not exit on cancellation")
			}
			if _, err := br.ReadByte(); err != io.EOF {
				t.Fatalf("cancelled socket still open: %v", err)
			}
		})
	}
}

func TestHTTPSProxyVerifiesIdentityBeforeCONNECT(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1) }))
	defer server.Close()
	up, err := parseUpstream(server.URL, "user", "private")
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := up.dialThrough(context.Background(), &net.Dialer{}, "example.test", 443); err == nil {
		conn.Close()
		t.Fatal("accepted an untrusted proxy TLS identity")
	}
	if requests.Load() != 0 {
		t.Fatal("sent CONNECT credentials before proxy authentication")
	}
}

func TestSOCKSAuthenticationSelection(t *testing.T) {
	for _, tc := range []struct {
		user     string
		selected byte
	}{{"alice", socksNoAuth}, {"", socksUserPass}} {
		client, server := net.Pipe()
		result := make(chan error, 1)
		go func() {
			up := upstream{username: tc.user, password: "private"}
			_, err := up.socksHandshake(client, socks5.CommandConnect, "example.test", 80)
			client.Close()
			result <- err
		}()
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		var greeting [3]byte
		_, err := io.ReadFull(server, greeting[:])
		if err != nil || greeting[1] != 1 || greeting[2] == tc.selected {
			t.Fatalf("unexpected greeting %x %v", greeting, err)
		}
		if _, err = server.Write([]byte{5, tc.selected}); err != nil {
			t.Fatal(err)
		}
		var data [1]byte
		n, err := server.Read(data[:])
		server.Close()
		if n != 0 || err != io.EOF || <-result == nil {
			t.Fatalf("accepted unoffered method %d", tc.selected)
		}
	}
}

func TestProxyEndpointDiagnosticsDoNotEchoUserinfo(t *testing.T) {
	for _, raw := range []string{"https://user:private%zz@proxy.test", "http://proxy.test:99999", "https://proxy.test/path?private=true"} {
		_, err := parseUpstream(raw, "", "")
		if err == nil || strings.Contains(err.Error(), "private") {
			t.Fatal("endpoint error must reject invalid configuration and omit secrets")
		}
	}
}

func TestProxyStartAuthenticationContract(t *testing.T) {
	required, anonymous := true, false
	for _, scheme := range []string{"socks5", "socks5h", "http", "https"} {
		endpoint := scheme + "://127.0.0.1:1080"
		for _, fields := range [][2]string{{"", ""}, {"alice", ""}, {"", "secret"}} {
			cfg := startConfig{Upstream: authenticationPrefix + endpoint, RequiresAuth: &required, Username: fields[0], Password: fields[1]}
			if _, err := cfg.proxy(); err == nil {
				t.Errorf("%s admitted incomplete credentials", scheme)
			}
		}
		cfg := startConfig{Upstream: authenticationPrefix + endpoint, RequiresAuth: &required, Username: "alice", Password: "p:ass"}
		if _, err := cfg.proxy(); err != nil {
			t.Fatalf("%s rejected complete credentials: %v", scheme, err)
		}
		cfg.RequiresAuth = &anonymous
		if _, err := cfg.proxy(); err == nil {
			t.Errorf("%s stripped authentication requirement", scheme)
		}
		cfg.Upstream = endpoint
		if _, err := cfg.proxy(); err == nil {
			t.Errorf("%s retained unexpected credentials in anonymous mode", scheme)
		}
		cfg.Username, cfg.Password = "", ""
		if _, err := cfg.proxy(); err != nil {
			t.Errorf("%s rejected anonymous profile", scheme)
		}
	}
	for _, tc := range [][3]string{
		{"socks5", strings.Repeat("é", 128), "p"}, {"socks5", "u", strings.Repeat("é", 128)},
		{"http", "a:b", "p"}, {"https", "u", "p\r\n"}, {"http", "\x7fu", "p"}, {"https", "u", "\x00"},
	} {
		if _, err := parseUpstream(tc[0]+"://127.0.0.1", tc[1], tc[2]); err == nil {
			t.Errorf("%s admitted malformed credentials", tc[0])
		}
	}
	if _, err := parseUpstream("socks5://127.0.0.1", strings.Repeat("u", 255), strings.Repeat("p", 255)); err != nil {
		t.Fatal(err)
	}
}
