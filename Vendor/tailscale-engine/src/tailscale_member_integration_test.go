//go:build darwin && tailscale_scoped

// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"pxengine/packetrouter"

	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// The local coordination fixture implements Tailscale's control protocol and
// a real DERP relay. The two authenticated nodes use separate callback TUNs.
func TestVirtualTailscaleControlAndReturn(t *testing.T) {
	iface, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	relay := derpserver.New(key.NewNode(), logger.Discard)
	server := httptest.NewTLSServer(derpserver.Handler(relay))
	defer server.Close()
	defer relay.Close()
	control := &testcontrol.Server{Logf: logger.Discard, RequireAuthKey: "tskey-auth-fixture", DERPMap: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
		1: {RegionID: 1, RegionCode: "local", Nodes: []*tailcfg.DERPNode{{Name: "local", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", STUNPort: -1, DERPPort: server.Listener.Addr().(*net.TCPAddr).Port, InsecureForTests: true}}},
	}}}
	coord := httptest.NewServer(control)
	defer coord.Close()
	packets := [2]chan []byte{make(chan []byte, 32), make(chan []byte, 32)}
	var nodes [2]*engineState
	for i, name := range []string{"member", "remote"} {
		callbacks := tsCallbacks{packet: func(p []byte) {
			select {
			case packets[i] <- bytes.Clone(p):
			default:
			}
		}, state: func(statePayload) {}, browse: func(string) {}, netmap: func(*tunnelConfig) {}, logf: t.Logf}
		cfg := startConfig{Hostname: name, AuthKey: control.RequireAuthKey, StateDir: t.TempDir(), UserKeychainState: true, UnderlayInterfaceIndex: uint32(iface.Index)}
		nodes[i], err = buildEngineWithCallbacks(cfg, coord.URL, nil, 1280, callbacks)
		if err != nil {
			t.Fatal(err)
		}
		defer stopTSState(nodes[i])
	}
	var local, remote netip.Addr
	deadline := time.Now().Add(18 * time.Second)
	for time.Now().Before(deadline) {
		ipv4 := func(n *engineState) netip.Addr {
			n.cfgMu.Lock()
			defer n.cfgMu.Unlock()
			if n.lastConfig != nil {
				for _, ip := range n.lastConfig.LocalAddrs {
					if p, e := netip.ParsePrefix(ip); e == nil && p.Addr().Is4() {
						return p.Addr()
					}
				}
			}
			return netip.Addr{}
		}
		local, remote = ipv4(nodes[0]), ipv4(nodes[1])
		if local.IsValid() && remote.IsValid() && nodes[0].backendState() == "Running" && nodes[1].backendState() == "Running" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !local.IsValid() || !remote.IsValid() || local == remote {
		t.Fatalf("node negotiation failed: %v %v (%s/%s)", local, remote, nodes[0].backendState(), nodes[1].backendState())
	}
	const host = "198.19.255.1"
	member := vrMember{ID: "tailnet", MTU: 1280, Addresses: []string{local.String()}, Allowed: []string{remote.String() + "/32"}, External: &vrDriverConfig{Adapter: "tailscale-node", Generation: 7}}
	destination := vrPolicy{Version: 1, Revision: 1, Rules: []vrRule{{Prefix: remote.String() + "/32", Port: member.ID}}}
	source := vrPolicy{Version: 1, Revision: 1, SourceRules: []packetrouter.SourceRule{{Source: "app", Port: member.ID}}}
	for _, tt := range []struct {
		name   string
		policy vrPolicy
	}{{"destination", destination}, {"source", source}} {
		t.Run(tt.name, func(t *testing.T) {
			received := make(chan []byte, 16)
			st, err := createVRWithDrivers(vrConfig{Version: 3, Underlay: uint32(iface.Index), Capture: []string{host}, Members: []vrMember{member}, Policy: tt.policy},
				func(p []byte) { received <- bytes.Clone(p) }, nil, func(slot uint32, generation uint64, p []byte) bool { return nodes[0].tundev.push(p) })
			if err != nil {
				t.Fatal(err)
			}
			defer st.stop()
			origin := wgTestIPv4UDP(t, host, remote.String(), "simplevpn request")
			if tt.policy.SourceRules != nil {
				if st.router.Forward(origin) || st.router.ForwardWithSource(origin, "unknown", 123) {
					t.Fatal("unattributed packet reached the node")
				}
				binary.BigEndian.PutUint16(origin[20:22], 4521)
			}
			reply := wgTestIPv4UDP(t, remote.String(), local.String(), "simplevpn reply")
			binary.BigEndian.PutUint16(reply[20:22], binary.BigEndian.Uint16(origin[22:24]))
			binary.BigEndian.PutUint16(reply[22:24], binary.BigEndian.Uint16(origin[20:22]))
			resend := time.NewTicker(200 * time.Millisecond)
			defer resend.Stop()
			limit := time.NewTimer(15 * time.Second)
			defer limit.Stop()
			for {
				select {
				case <-resend.C:
					var sent bool
					if tt.policy.SourceRules != nil {
						sent = st.router.ForwardWithSource(origin, "app", 123)
					} else {
						sent = st.router.Forward(origin)
					}
					if !sent {
						t.Fatal(st.router.Status())
					}
				case p := <-packets[1]:
					if bytes.HasSuffix(p, []byte("simplevpn request")) && netip.AddrFrom4([4]byte(p[12:16])) == local {
						nodes[1].tundev.push(bytes.Clone(reply))
					}
				case p := <-packets[0]:
					st.returnDriver(0, 7, p)
				case p := <-received:
					if bytes.HasSuffix(p, []byte("simplevpn reply")) && netip.AddrFrom4([4]byte(p[16:20])).String() == host {
						return
					}
				case <-limit.C:
					t.Fatalf("no routed peer round trip: %v, node states %s/%s, roster %d", st.router.Status(), nodes[0].backendState(), nodes[1].backendState(), control.NumNodes())
				}
			}
		})
	}
}
