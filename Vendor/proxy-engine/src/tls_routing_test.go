// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package pxengine

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

type fixtureRouteDial func(ctx context.Context, host string, port int) (net.Conn, error)

func (f fixtureRouteDial) dial(ctx context.Context, _ *net.Dialer, host string, port int) (net.Conn, error) {
	return f(ctx, host, port)
}

func realClientRecord(t *testing.T, name string) []byte {
	t.Helper()
	peer, guest := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- tls.Client(guest, &tls.Config{ServerName: name}).Handshake() }()
	defer func() { peer.Close(); guest.Close(); <-done }()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	head := make([]byte, 5)
	if _, err := io.ReadFull(peer, head); err != nil {
		t.Fatal(err)
	}
	record := append(head, make([]byte, int(binary.BigEndian.Uint16(head[3:])))...)
	if _, err := io.ReadFull(peer, record[5:]); err != nil {
		t.Fatal(err)
	}
	return record
}

func TestGuardedProxyRequiresCompleteConfiguration(t *testing.T) {
	for _, text := range []string{"  ", "443 x.example host.example:443", "443 x.example [fe80::1%en0]:443", "0 x.example 127.0.0.1:443", "443 *.example 127.0.0.1:443", "443 x.example 127.0.0.1:443\n443 X.Example [::1]:443"} {
		if _, err := compileTLSRoutes(text); err == nil {
			t.Fatal("accepted invalid configuration", text)
		}
	}
	valid := "443 x.example 192.0.2.1:8443\n443 second.example [2001:db8::4]:443"
	checked, err := compileTLSRoutes(valid)
	if err != nil || len(checked[443]) != 2 || checked[443]["x.example"].Port() != 8443 {
		t.Fatal("invalid compiled routes", err)
	}
	const up = "socks5://192.0.2.1:1080"
	for _, cfg := range []startConfig{{Upstream: tlsRoutingPrefix + up}, {Upstream: up, TLSRoutes: valid}} {
		if _, err := cfg.proxy(); err == nil {
			t.Fatal("accepted incomplete version guard")
		}
	}
	if _, err := (startConfig{Upstream: tlsRoutingPrefix + up, TLSRoutes: valid}).proxy(); err != nil {
		t.Fatal(err)
	}
	if _, err := parseUpstream(tlsRoutingPrefix+up, "", ""); err == nil {
		t.Fatal("legacy upstream parser accepted guarded profile")
	}
}

func TestGuardedProxyDoesNotDialForTimeoutOrWrongName(t *testing.T) {
	wrong := realClientRecord(t, "other.example")
	for _, payload := range [][]byte{nil, wrong, wrong[:len(wrong)-1], []byte("GET / HTTP/1.0")} {
		dials := 0
		st := engineState{ctx: context.Background(), flowDial: fixtureRouteDial(func(context.Context, string, int) (net.Conn, error) { dials++; return nil, io.ErrUnexpectedEOF })}
		guest, peer := net.Pipe()
		done := make(chan error, 1)
		go func() {
			done <- st.dialGuarded(guest, tlsBackends{"expected.example": netip.MustParseAddrPort("192.0.2.1:443")}, 50*time.Millisecond)
		}()
		if len(payload) > 0 {
			go func() { _, _ = peer.Write(payload) }()
		}
		if err := <-done; err == nil || dials != 0 {
			t.Fatal("denied guest reached the proxy")
		}
		peer.Close()
		guest.Close()
	}
}

func TestGuardedProxyReplaysExactHandshakeAndRelaysAfterOneDial(t *testing.T) {
	record := realClientRecord(t, "portal.example")
	guest, peer := net.Pipe()
	proxy, backend := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); guest.Close(); peer.Close(); proxy.Close(); backend.Close() }()
	calls := 0
	st := engineState{ctx: ctx, flowDial: fixtureRouteDial(func(_ context.Context, host string, port int) (net.Conn, error) {
		calls++
		if host != "2001:db8::8" || port != 9443 {
			t.Errorf("unexpected backend %s:%d", host, port)
		}
		return proxy, nil
	})}
	done := make(chan error, 1)
	go func() {
		done <- st.dialGuarded(guest, tlsBackends{"portal.example": netip.MustParseAddrPort("[2001:db8::8]:9443")}, time.Second)
	}()
	backend.SetDeadline(time.Now().Add(2 * time.Second))
	peer.SetDeadline(time.Now().Add(2 * time.Second))
	go func() {
		peer.Write(record[:3])
		peer.Write(record[3:])
		peer.Write([]byte("following bytes"))
	}()
	want := append(bytes.Clone(record), []byte("following bytes")...)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(backend, got); err != nil || !bytes.Equal(got, want) {
		t.Fatal("TLS stream was changed", err)
	}
	if err := <-done; err != nil || calls != 1 {
		t.Fatal("incorrect dial count", calls, err)
	}
	go func() { backend.Write([]byte("reply")) }()
	if _, err := io.ReadFull(peer, got[:5]); err != nil || string(got[:5]) != "reply" {
		t.Fatal("return path failed", err)
	}
	cancel()
	st.relayWG.Wait()
}

func TestClientWithoutSNIHasNoDefaultBackend(t *testing.T) {
	// Go omits the SNI extension when the requested certificate name is an IP.
	record := realClientRecord(t, "127.0.0.1")
	guest, peer := net.Pipe()
	defer guest.Close()
	defer peer.Close()
	go func() { _, _ = peer.Write(record) }()
	_, _, err := readTLSRoute(guest, tlsBackends{"": netip.MustParseAddrPort("127.0.0.1:443")}, time.Second)
	if err == nil || err.Error() != "TLS ClientHello has no server name" {
		t.Fatal("missing SNI was not explicit", err)
	}
}
