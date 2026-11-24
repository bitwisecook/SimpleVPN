// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"pxengine"
)

// An authenticated WireGuard device and a SOCKS5 UDP ASSOCIATE relay return
// independently through the same router and its single capture address.
func TestMixedWireGuardAndSOCKSProxyPorts(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		var greet [3]byte
		if _, err := io.ReadFull(c, greet[:]); err != nil || greet != [3]byte{5, 1, 0} {
			return
		}
		c.Write([]byte{5, 0})
		var request [10]byte
		if _, err := io.ReadFull(c, request[:]); err != nil || request[1] != 3 {
			return
		}
		resp := []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}
		binary.BigEndian.PutUint16(resp[8:], uint16(relay.LocalAddr().(*net.UDPAddr).Port))
		c.Write(resp)
		<-done
	}()
	const proxyTarget = "192.0.2.36"
	anonymous := false
	member := vrMember{ID: "proxy", Addresses: []string{"10.3.0.5/32"}, Allowed: []string{proxyTarget + "/32"},
		Proxy: &pxengine.RoutingPortConfig{Upstream: "socks5://" + listener.Addr().String(), RequiresAuth: &anonymous, MTU: 1280}}
	st, peers, host := newEncryptedVirtualSession(t, vrPolicy{Version: 1, Revision: 1, Default: "first", Rules: []vrRule{{Prefix: proxyTarget + "/32", Port: "proxy"}}}, member)
	if !st.router.Forward(wgTestIPv4UDP(t, testVirtualCapture, proxyTarget, "proxy hello")) {
		t.Fatal(st.router.Status())
	}
	relay.SetDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 1500)
	n, client, err := relay.ReadFromUDP(buffer)
	if err != nil || n < 10 || string(buffer[10:n]) != "proxy hello" {
		t.Fatalf("missing proxied packet (%d): %v", n, err)
	}
	if _, err = relay.WriteToUDP(append(bytes.Clone(buffer[:10]), []byte("proxy return")...), client); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-host:
		if len(p) < 28 || string(p[28:]) != "proxy return" || !bytes.Equal(p[16:20], net.ParseIP(testVirtualCapture).To4()) {
			t.Fatalf("incorrect proxy return: %x", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("missing return from SOCKS proxy", st.router.Status())
	}
	if !st.router.Forward(wgTestIPv4UDP(t, testVirtualCapture, wgTestPeerTunnelIP, "WG hello")) {
		t.Fatal(st.router.Status())
	}
	p := peers["first"].awaitPacket(5 * time.Second)
	if string(p[28:]) != "WG hello" {
		t.Fatal("incorrect wireguard egress")
	}
	reply := wgTestIPv4UDP(t, wgTestPeerTunnelIP, wgTestOurTunnelIP, "WG return")
	binary.BigEndian.PutUint16(reply[20:22], 51001)
	binary.BigEndian.PutUint16(reply[22:24], 51000)
	peers["first"].send(reply)
	select {
	case packet := <-host:
		if string(packet[28:]) != "WG return" {
			t.Fatalf("incorrect WG return: %x", packet)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("missing return from WireGuard")
	}
	if !st.stopPort("proxy") || !st.stopPort("proxy") || st.stopPort("unknown") {
		t.Fatal("stopping a configured proxy must be idempotent")
	}
	if status := st.retired["proxy"]; status.State != "stopped" || status.Endpoint != listener.Addr().String() {
		t.Fatal("stopping the proxy discarded its status or carrier exclusion", status)
	}
	if st.router.Forward(wgTestIPv4UDP(t, testVirtualCapture, proxyTarget, "stopped")) {
		t.Fatal("the withdrawn proxy claim fell through to WireGuard")
	}
	if !st.stopPort("first") || st.retired["first"].State != "stopped" || st.retired["first"].Endpoint == "" {
		t.Fatal("stopping WireGuard discarded its status or carrier exclusion", st.retired["first"])
	}
}

func TestMixedHTTPConnectPorts(t *testing.T) {
	// SetFallbackRoots is process-wide. Isolate the test trust anchor from the
	// host and every other test process. Production uses the system trust pool.
	mode := os.Getenv("SIMPLEVPN_CONNECT_TLS_FIXTURE")
	if mode == "" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		for _, trust := range []string{"trusted", "untrusted"} {
			cmd := exec.Command(exe, "-test.run=^TestMixedHTTPConnectPorts$", "-test.v")
			cmd.Env = append(os.Environ(), "SIMPLEVPN_CONNECT_TLS_FIXTURE="+trust, "GODEBUG=x509usefallbackroots=1")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s: %v: %s", trust, err, output)
			}
		}
		return
	}
	trusted := httptest.NewTLSServer(http.NotFoundHandler())
	pool := x509.NewCertPool()
	if mode == "trusted" {
		pool.AddCert(trusted.Certificate())
	}
	x509.SetFallbackRoots(pool)
	trusted.Close()
	for _, secure := range []bool{false, true} {
		if !secure && mode == "untrusted" {
			continue
		}
		t.Run(map[bool]string{false: "HTTP", true: "HTTPS"}[secure], func(t *testing.T) {
			query := []byte{0x12, 0x34, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}
			response := bytes.Clone(query)
			response[2] = 0x81
			var observed atomic.Int32
			done := make(chan struct{}, 1)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				observed.Add(1)
				if r.Method != "CONNECT" || r.Host != "192.0.2.53:53" || r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("tester:fixture-secret")) {
					http.Error(w, "Proxy credentials required", 407)
					return
				}
				c, buf, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				buf.WriteString("HTTP/1.1 200 OK\r\n\r\n")
				buf.Flush()
				frame := make([]byte, 2+len(query))
				if _, err = io.ReadFull(buf, frame); err != nil || !bytes.Equal(frame[2:], query) {
					return
				}
				copy(frame[2:], response)
				buf.Write(frame)
				buf.Flush()
			})
			server := httptest.NewUnstartedServer(handler)
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateClosed {
					select {
					case done <- struct{}{}:
					default:
					}
				}
			}

			if secure {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			required := true
			member := vrMember{ID: "proxy", Addresses: []string{"10.3.0.5/32"}, Allowed: []string{"192.0.2.53/32"},
				Proxy: &pxengine.RoutingPortConfig{Upstream: "auth-required-v1+" + server.URL, RequiresAuth: &required, Username: "tester", Password: "fixture-secret", MTU: 1280}}
			st, _, host := newEncryptedVirtualSession(t, vrPolicy{Version: 1, Revision: 1, Default: "first", Rules: []vrRule{{Prefix: "192.0.2.53/32", Port: "proxy"}}}, member)
			p := wgTestIPv4UDP(t, testVirtualCapture, "192.0.2.53", string(query))
			binary.BigEndian.PutUint16(p[22:24], 53)
			if !st.router.Forward(p) {
				t.Fatal("router refused DNS query")
			}
			if mode == "untrusted" {
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("untrusted TLS session did not close")
				}
				if observed.Load() != 0 {
					t.Fatal("CONNECT credentials reached an untrusted TLS server")
				}
				select {
				case <-host:
					t.Fatal("untrusted relay carried traffic")
				default:
				}
				return
			}
			select {
			case reply := <-host:
				if len(reply) < 28 || !bytes.Equal(reply[28:], response) {
					t.Fatal("unexpected DNS reply")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no DNS reply through CONNECT")
			}
		})
	}
}
