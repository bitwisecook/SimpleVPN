// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// contract_test.go — the JSON contract this shim promises Swift. These run in
// Tools/build-tailscale-engine.sh, so a rename on either side of the boundary
// fails the build rather than silently producing a tunnel with no routes.
//
// Deliberately no test brings the real stack up: that needs a tailnet.

package main

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/net/dns"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine/router"
)

func TestStartConfigKeys(t *testing.T) {
	// The exact JSON SimpleVPN's TailscaleEngineConfig encoder emits.
	const in = `{
	  "controlURL": "https://headscale.example.com",
	  "hostname": "Jims-Mac",
	  "authKey": "tskey-auth-secret",
	  "stateDir": "/Library/Application Support/SimpleVPN/tailscale/abc",
	  "acceptRoutes": true,
	  "acceptDNS": true,
	  "useExitNode": true,
	  "exitNode": "100.64.0.7",
	  "exitNodeAllowLANAccess": true,
	  "advertiseRoutes": ["192.168.7.0/24"],
	  "mtu": 1280
	}`
	var cfg startConfig
	if err := json.Unmarshal([]byte(in), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.ControlURL != "https://headscale.example.com" || cfg.Hostname != "Jims-Mac" ||
		cfg.AuthKey != "tskey-auth-secret" || !cfg.AcceptRoutes || !cfg.AcceptDNS ||
		!cfg.UseExitNode || cfg.ExitNode != "100.64.0.7" || !cfg.ExitNodeAllowLANAccess ||
		len(cfg.AdvertiseRoutes) != 1 || cfg.MTU != 1280 ||
		!strings.HasSuffix(cfg.StateDir, "/abc") {
		t.Fatalf("field mismatch: %+v", cfg)
	}
}

func TestValidateControlURL(t *testing.T) {
	if got, err := validateControlURL(""); err != nil || got != ipn.DefaultControlURL {
		t.Fatalf("empty should mean Tailscale's own control plane, got %q %v", got, err)
	}
	if got, err := validateControlURL("https://hs.example.com/"); err != nil || got != "https://hs.example.com" {
		t.Fatalf("headscale URL: got %q %v", got, err)
	}
	for _, bad := range []string{"http://hs.example.com", "hs.example.com", "https://", "ftp://x", "not a url at all"} {
		if _, err := validateControlURL(bad); err == nil {
			t.Errorf("%q should have been rejected", bad)
		}
	}
}

func TestParseRoutes(t *testing.T) {
	got, err := parseRoutes([]string{"10.0.0.0/8", " ", "fd00::/8"})
	if err != nil || len(got) != 2 {
		t.Fatalf("got %v %v", got, err)
	}
	for _, bad := range []string{"10.0.0.1/8", "banana", "10.0.0.0/33", "10.0.0.0"} {
		if _, err := parseRoutes([]string{bad}); err == nil {
			t.Errorf("%q should have been rejected", bad)
		}
	}
}

func TestApplyExitNode(t *testing.T) {
	p := ipn.NewPrefs()
	applyExitNode(p, true, "100.64.0.7")
	if p.ExitNodeIP.String() != "100.64.0.7" || p.ExitNodeID != "" {
		t.Fatalf("IP form: %+v", p)
	}
	applyExitNode(p, true, "nodeidCNTRL")
	if p.ExitNodeID != "nodeidCNTRL" || p.ExitNodeIP.IsValid() {
		t.Fatalf("stable-id form: %+v", p)
	}
	// Turning the toggle off must CLEAR, not merely stop offering.
	applyExitNode(p, false, "100.64.0.7")
	if p.ExitNodeID != "" || p.ExitNodeIP.IsValid() {
		t.Fatalf("off should clear: %+v", p)
	}
}

func TestPublishConfigShape(t *testing.T) {
	st := &engineState{}
	var seen *tunnelConfig
	// publishConfig writes lastConfig and emits; with no callback registered
	// the emit is a no-op, so assert on the stored copy.
	st.publishConfig(&router.Config{
		LocalAddrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32"), netip.MustParsePrefix("fd7a:115c:a1e0::1/128")},
		Routes:     []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		NewMTU:     1280,
	}, &dns.OSConfig{
		Nameservers:   []netip.Addr{netip.MustParseAddr("100.100.100.100")},
		SearchDomains: []dnsname.FQDN{dnsname.FQDN("tail1234.ts.net.")},
		MatchDomains:  []dnsname.FQDN{dnsname.FQDN("tail1234.ts.net.")},
	}, 1400)
	st.cfgMu.Lock()
	seen = st.lastConfig
	st.cfgMu.Unlock()

	b, err := json.Marshal(seen)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"localAddrs", "routes", "localRoutes", "subnetRoutes", "mtu", "dns"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("missing key %q in netmapChanged payload: %s", k, b)
		}
	}
	if seen.MTU != 1280 {
		t.Errorf("NewMTU should win over the fallback, got %d", seen.MTU)
	}
	if seen.LocalAddrs[0] != "100.64.0.1/32" || seen.Routes[0] != "0.0.0.0/0" {
		t.Errorf("prefix rendering: %+v", seen)
	}
	// Trailing dots must be gone — NEDNSSettings wants bare suffixes.
	if seen.DNS.SearchDomains[0] != "tail1234.ts.net" || seen.DNS.MatchDomains[0] != "tail1234.ts.net" {
		t.Errorf("FQDN rendering: %+v", seen.DNS)
	}
}

func TestPublishConfigIgnoresNilRouterConfig(t *testing.T) {
	st := &engineState{}
	st.publishConfig(nil, nil, 1280)
	st.cfgMu.Lock()
	defer st.cfgMu.Unlock()
	if st.lastConfig != nil {
		t.Fatal("a nil router config (Close) must not publish empty settings")
	}
}

func TestCallbackTUNBounds(t *testing.T) {
	d := newCallbackTUN(1280, nil)
	defer d.Close()

	// A packet larger than the destination buffer is dropped, not truncated,
	// and does not wedge the reader.
	if !d.push(make([]byte, 4000)) {
		t.Fatal("push should have queued")
	}
	if !d.push([]byte{0x45, 0, 0, 20}) {
		t.Fatal("push should have queued")
	}
	bufs := [][]byte{make([]byte, 100)}
	sizes := make([]int, 1)
	n, err := d.Read(bufs, sizes, 10)
	if err != nil || n != 1 || sizes[0] != 4 {
		t.Fatalf("expected the oversized packet dropped and the small one read: n=%d sizes=%v err=%v", n, sizes, err)
	}
	if d.dropped.Load() != 1 {
		t.Fatalf("drop counter: %d", d.dropped.Load())
	}
}

func TestCallbackTUNQueueIsBounded(t *testing.T) {
	d := newCallbackTUN(1280, nil)
	defer d.Close()
	accepted := 0
	for i := 0; i < inboundQueueDepth*2; i++ {
		if d.push([]byte{0x45}) {
			accepted++
		}
	}
	if accepted != inboundQueueDepth {
		t.Fatalf("queue should saturate at %d, accepted %d", inboundQueueDepth, accepted)
	}
	if d.dropped.Load() != int64(inboundQueueDepth) {
		t.Fatalf("every overflow must be counted, got %d", d.dropped.Load())
	}
}

func TestCallbackTUNClosedReadReturnsError(t *testing.T) {
	d := newCallbackTUN(1280, nil)
	d.Close()
	d.Close() // idempotent — stopTunnel may race a failed start
	if _, err := d.Read([][]byte{make([]byte, 100)}, make([]int, 1), 0); err == nil {
		t.Fatal("read on a closed device must error so wireguard-go stops its reader")
	}
	if d.push([]byte{0x45}) {
		t.Fatal("push on a closed device must fail")
	}
}

func TestCallbackTUNIsNotAFakeTun(t *testing.T) {
	// tsd.System sniffs for IsFakeTun() and would silently switch the node to
	// netstack-only (no packet path) if our device grew that method.
	var d any = newCallbackTUN(1280, nil)
	if _, bad := d.(interface{ IsFakeTun() bool }); bad {
		t.Fatal("callbackTUN must not implement IsFakeTun")
	}
}

func TestStatusPayloadEncodesEmptyCollections(t *testing.T) {
	// Swift decodes these non-optionally; nil slices would encode as null.
	b, err := json.Marshal(statusPayload{State: "NoState", SelfIPs: []string{}, ExitNodes: []peerSummary{}})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"selfIPs":[]`) || !strings.Contains(s, `"exitNodes":[]`) {
		t.Fatalf("empty collections must encode as [], got %s", s)
	}
}

func TestPrefsPatchOmittedFieldsStayNil(t *testing.T) {
	var p prefsPatch
	if err := json.Unmarshal([]byte(`{"acceptDNS":false}`), &p); err != nil {
		t.Fatal(err)
	}
	if p.AcceptDNS == nil || *p.AcceptDNS {
		t.Fatal("acceptDNS should have decoded as an explicit false")
	}
	if p.AcceptRoutes != nil || p.AdvertiseRoutes != nil || p.ExitNode != nil {
		t.Fatal("absent fields must stay nil so they are left alone")
	}
}

func TestErrorEnvelope(t *testing.T) {
	b, err := json.Marshal(okResponse{Error: &shimError{Kind: "badRequest", Message: "bad"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"error":{"kind":"badRequest","message":"bad"}}` {
		t.Fatalf("error envelope drifted: %s", b)
	}
	b, _ = json.Marshal(okResponse{OK: true})
	if string(b) != `{"ok":true}` {
		t.Fatalf("ok envelope drifted: %s", b)
	}
}
