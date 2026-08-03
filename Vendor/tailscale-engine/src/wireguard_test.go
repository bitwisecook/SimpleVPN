// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// wireguard_test.go — the JSON/uapi contract the plain-WireGuard shim
// (wireguard.go) promises Swift. Runs in Tools/build-tailscale-engine.sh, so a
// rename on either side of the boundary — or a uapi rendering bug, which is a
// tunnel that connects and authenticates nothing — fails the build.
//
// Deliberately no test brings a real device up against a peer: that needs a
// server. Everything up to the device boundary (config parse, key transcoding,
// endpoint resolution rules, uapi rendering, status whitelisting) is pure and
// pinned here.

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// Throwaway RFC-7748 test keys (base64 of 32 bytes) — not real key material.
const (
	testPriv = "QChaW1TIzE0uLQzfLpViB1BFyBSGGvPjJvhstBUFRUE="
	testPub  = "1Vzu4TQGEHVmHnDl35jRhc1vDBiUvIRWpuXW3wf3AWs="
	testPSK  = "u8LnGebbTJPitDkTRD1eDPFhbmg36pJqhLIJ8DKtcEE="
	// hex of testPriv / testPub / testPSK, for the uapi assertions
	testPrivHex = "40285a5b54c8cc4d2e2d0cdf2e9562075045c814861af3e326f86cb415054541"
	testPubHex  = "d55ceee134061075661e70e5df98d185cd6f0c1894bc8456a6e5d6df07f7016b"
	testPSKHex  = "bbc2e719e6db4c93e2b43913443d5e0cf1616e6837ea926a84b209f032ad7041"
)

func TestWGStartConfigKeys(t *testing.T) {
	// The exact JSON SimpleVPN's WireGuardStartConfig encoder emits.
	const in = `{
	  "privateKey": "` + testPriv + `",
	  "peerPublicKey": "` + testPub + `",
	  "presharedKey": "` + testPSK + `",
	  "endpoint": "vpn.example.com:51820",
	  "allowedIPs": ["0.0.0.0/0", "::/0"],
	  "persistentKeepalive": 25,
	  "listenPort": 0,
	  "mtu": 1420
	}`
	var cfg wgStartConfig
	if err := json.Unmarshal([]byte(in), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.PrivateKey != testPriv || cfg.PeerPublicKey != testPub || cfg.PresharedKey != testPSK ||
		cfg.Endpoint != "vpn.example.com:51820" || len(cfg.AllowedIPs) != 2 ||
		cfg.PersistentKeepalive != 25 || cfg.ListenPort != 0 || cfg.MTU != 1420 {
		t.Fatalf("field mismatch: %+v", cfg)
	}
}

func TestWGRenderUAPI(t *testing.T) {
	cfg := wgStartConfig{
		PrivateKey:          testPriv,
		PeerPublicKey:       testPub,
		PresharedKey:        testPSK,
		Endpoint:            "vpn.example.com:51820",
		AllowedIPs:          []string{"0.0.0.0/0", "10.44.0.0/16", "::/0"},
		PersistentKeepalive: 25,
		ListenPort:          51821,
	}
	uapi, err := renderWGUAPI(cfg, "192.0.2.7:51820")
	if err != nil {
		t.Fatal(err)
	}
	// Keys cross as HEX (base64 is the .conf spelling; uapi wants hex) and the
	// endpoint is the pre-resolved literal.
	for _, want := range []string{
		"private_key=" + testPrivHex + "\n",
		"listen_port=51821\n",
		"replace_peers=true\n",
		"public_key=" + testPubHex + "\n",
		"preshared_key=" + testPSKHex + "\n",
		"endpoint=192.0.2.7:51820\n",
		"persistent_keepalive_interval=25\n",
		"allowed_ip=0.0.0.0/0\n",
		"allowed_ip=10.44.0.0/16\n",
		"allowed_ip=::/0\n",
	} {
		if !strings.Contains(uapi, want) {
			t.Errorf("uapi missing %q:\n%s", want, uapi)
		}
	}
	// Interface keys must precede the peer section or IpcSet refuses the lot.
	if strings.Index(uapi, "private_key=") > strings.Index(uapi, "public_key=") {
		t.Error("private_key must come before the peer's public_key")
	}
	if strings.Index(uapi, "replace_peers=") > strings.Index(uapi, "public_key=") {
		t.Error("replace_peers must come before the peer's public_key")
	}
	// The base64 forms themselves must never appear (IpcSet would reject them,
	// but the invariant is worth its own line).
	if strings.Contains(uapi, testPriv) || strings.Contains(uapi, testPub) {
		t.Error("base64 key material leaked into the uapi string")
	}
}

func TestWGRenderUAPIOmitsOptionals(t *testing.T) {
	cfg := wgStartConfig{
		PrivateKey:    testPriv,
		PeerPublicKey: testPub,
		AllowedIPs:    []string{"10.0.0.0/8"},
	}
	uapi, err := renderWGUAPI(cfg, "192.0.2.7:51820")
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"preshared_key=", "persistent_keepalive_interval=", "listen_port="} {
		if strings.Contains(uapi, absent) {
			t.Errorf("optional %q must be omitted when unset:\n%s", absent, uapi)
		}
	}
}

func TestWGRenderUAPIRejections(t *testing.T) {
	good := wgStartConfig{
		PrivateKey:    testPriv,
		PeerPublicKey: testPub,
		AllowedIPs:    []string{"0.0.0.0/0"},
	}
	cases := []struct {
		name   string
		mutate func(*wgStartConfig)
	}{
		{"private key not base64", func(c *wgStartConfig) { c.PrivateKey = "not-base64!!" }},
		{"private key wrong length", func(c *wgStartConfig) { c.PrivateKey = "QUJD" }}, // 3 bytes
		{"peer key missing", func(c *wgStartConfig) { c.PeerPublicKey = "" }},
		{"preshared key not base64", func(c *wgStartConfig) { c.PresharedKey = "???" }},
		{"allowed ip with host bits", func(c *wgStartConfig) { c.AllowedIPs = []string{"10.0.0.1/8"} }},
		{"allowed ip malformed", func(c *wgStartConfig) { c.AllowedIPs = []string{"banana"} }},
		{"no allowed ips at all", func(c *wgStartConfig) { c.AllowedIPs = nil }},
		{"listen port out of range", func(c *wgStartConfig) { c.ListenPort = 70000 }},
	}
	for _, tc := range cases {
		cfg := good
		tc.mutate(&cfg)
		if _, err := renderWGUAPI(cfg, "192.0.2.7:51820"); err == nil {
			t.Errorf("%s: should have been rejected", tc.name)
		}
	}
}

func TestWGResolveEndpointLiterals(t *testing.T) {
	// IP literals pass through with no DNS (and v6 keeps its brackets).
	if got, err := wgResolveEndpoint("192.0.2.1:51820"); err != nil || got != "192.0.2.1:51820" {
		t.Fatalf("v4 literal: got %q %v", got, err)
	}
	if got, err := wgResolveEndpoint("[2001:db8::1]:51820"); err != nil || got != "[2001:db8::1]:51820" {
		t.Fatalf("v6 literal: got %q %v", got, err)
	}
	for _, bad := range []string{"", "host-with-no-port", "192.0.2.1", "host:notaport", "host:99999"} {
		if _, err := wgResolveEndpoint(bad); err == nil {
			t.Errorf("%q should have been rejected", bad)
		}
	}
}

func TestWGStatusParseIsAWhitelist(t *testing.T) {
	// Real IpcGet output carries the private/preshared keys — the parse must
	// pass counters through and drop every key line.
	ipc := strings.Join([]string{
		"private_key=" + testPrivHex,
		"listen_port=51821",
		"public_key=" + testPubHex,
		"preshared_key=" + testPSKHex,
		"endpoint=192.0.2.7:51820",
		"last_handshake_time_sec=1700000000",
		"last_handshake_time_nsec=123",
		"tx_bytes=1000",
		"rx_bytes=2000",
		"persistent_keepalive_interval=25",
		// A hypothetical second peer: counters sum, newest handshake wins.
		"public_key=" + testPubHex,
		"endpoint=192.0.2.8:51820",
		"last_handshake_time_sec=1600000000",
		"tx_bytes=10",
		"rx_bytes=20",
		"",
	}, "\n")
	got := parseWGIpcStatus(ipc)
	if got.RxBytes != 2020 || got.TxBytes != 1010 {
		t.Errorf("byte counters should sum across peers: %+v", got)
	}
	if got.LastHandshake != 1700000000 {
		t.Errorf("newest handshake should win: %+v", got)
	}
	if got.Endpoint != "192.0.2.8:51820" || got.ListenPort != 51821 {
		t.Errorf("endpoint/listen port: %+v", got)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), testPrivHex) || strings.Contains(string(b), testPSKHex) {
		t.Fatalf("key material leaked into the status payload: %s", b)
	}
}

func TestWGStartResponseShape(t *testing.T) {
	b, err := json.Marshal(wgStartResponse{OK: true, Endpoint: "192.0.2.7:51820"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"ok":true,"endpoint":"192.0.2.7:51820"}` {
		t.Fatalf("ok envelope drifted: %s", b)
	}
	b, _ = json.Marshal(wgStartResponse{Error: &shimError{Kind: "endpoint", Message: "cannot resolve"}})
	if string(b) != `{"error":{"kind":"endpoint","message":"cannot resolve"}}` {
		t.Fatalf("error envelope drifted: %s", b)
	}
}
