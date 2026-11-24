// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"encoding/binary"
	"pxengine/routelang/catalog"
	"testing"
	"time"
)

func TestExternalPacketPortLifecycle(t *testing.T) {
	const capture, assigned, dst = "198.19.255.1", "10.10.3.1", "192.0.2.53"
	for _, row := range catalog.Adapters() {
		if !row.PacketPolicy() || row.ID == "wireguard-shared" {
			continue
		}
		t.Run(row.ID, func(t *testing.T) {
			member := vrMember{ID: "office", MTU: 1280, Addresses: []string{assigned + "/32"}, Allowed: []string{"0.0.0.0/0"}, External: &vrDriverConfig{Adapter: row.ID, Generation: 327}}
			cfg := vrConfig{Version: 3, Underlay: 1, Capture: []string{capture}, Members: []vrMember{member}, Policy: vrPolicy{Version: 1, Revision: 1, Default: "office"}}
			var delivered, submitted []byte
			var seenEpoch uint64
			st, err := createVRWithDrivers(cfg, func(p []byte) { delivered = bytes.Clone(p) }, nil, func(slot uint32, epoch uint64, p []byte) bool {
				if slot != 0 {
					return false
				}
				submitted = bytes.Clone(p)
				seenEpoch = epoch
				return true
			})
			if err != nil {
				t.Fatal(err)
			}
			defer st.stop()
			makePacket := func(from, to string, sport, dport uint16) []byte {
				p := wgTestIPv4UDP(t, from, to, "routed")
				binary.BigEndian.PutUint16(p[20:22], sport)
				binary.BigEndian.PutUint16(p[22:24], dport)
				return p
			}
			query := makePacket(capture, dst, 3250, 53)
			reply := makePacket(dst, assigned, 53, 3250)
			if !st.router.Forward(query) || seenEpoch != 327 || !bytes.Equal(submitted, makePacket(assigned, dst, 3250, 53)) {
				t.Fatal("routed transmit", st.router.Status())
			}
			if st.returnDriver(1, 327, reply) || st.returnDriver(0, 328, reply) || delivered != nil {
				t.Fatal("wrong origin admitted")
			}
			if !st.returnDriver(0, 327, reply) || !bytes.Equal(delivered, makePacket(dst, capture, 53, 3250)) {
				t.Fatal("return", st.router.Status())
			}
			if meters := st.memberPolicy[0].Status(); meters.Outbound.ForwardedPackets != 1 || meters.Inbound.ForwardedPackets != 1 || len(meters.Rules) != 0 {
				t.Fatal("unfiltered virtual port counters", meters)
			}
			if st.revokeDriver(0, 328) || !st.revokeDriver(0, 327) || st.router.Forward(query) || st.returnDriver(0, 327, reply) {
				t.Fatal("revoked generation remained active")
			}
			if st.replaceDriver(0, 327, member) {
				t.Fatal("reused generation")
			}
			member.External = &vrDriverConfig{Adapter: row.ID, Generation: 328}
			member.Allowed = []string{dst + "/32"}
			if st.replaceDriver(0, 327, member) {
				t.Fatal("narrowed carrier inherited default")
			}
			member.Allowed = []string{"0.0.0.0/0"}
			member.MTU++
			if st.replaceDriver(0, 327, member) {
				t.Fatal("changed MTU without capture negotiation")
			}
			member.MTU--
			if !st.replaceDriver(0, 327, member) || st.router.Forward(query) || st.returnDriver(0, 327, reply) {
				t.Fatal("old flow crossed a generation")
			}
			if !st.router.Forward(makePacket(capture, dst, 3251, 53)) || seenEpoch != 328 || !st.returnDriver(0, 328, makePacket(dst, assigned, 53, 3251)) {
				t.Fatal("new incarnation", st.router.Status())
			}
			st.stop()
			if st.returnDriver(0, 328, reply) || st.router.Forward(query) {
				t.Fatal("closed session admitted traffic")
			}
		})
	}
}
func TestExternalRevocationDrainsWrites(t *testing.T) {
	started, release, revoked := make(chan struct{}), make(chan struct{}), make(chan bool, 1)
	p := vrDriverPort{id: "office", active: true, generation: 2, write: func(uint32, uint64, []byte) bool { close(started); <-release; return true }}
	go p.send(2, []byte{1})
	<-started
	go func() { revoked <- p.revoke(2) }()
	select {
	case <-revoked:
		t.Fatal("live driver write escaped revocation")
	case <-time.After(5 * time.Millisecond):
	}
	close(release)
	if !<-revoked || p.send(2, []byte{1}) {
		t.Fatal("revoked driver writable", p.status())
	}
}

func TestRoutedExitNodeUsesOnlyTheNamedAuthenticatedDriver(t *testing.T) {
	const capture, target = "198.19.255.1", "192.0.2.53"
	const source = `on chosen: route.select { route.exit_node("nSecond"); }
on checked: inbound.ip.packet { if !flow.has_exit_node || flow.exit_node != "nSecond" { drop(); } }`
	members := []vrMember{
		{ID: "office", MTU: 1280, Addresses: []string{"100.64.1.1/32"}, Allowed: []string{"0.0.0.0/0"},
			External: &vrDriverConfig{Adapter: "tailscale-node", Generation: 2}, ExitNodeID: "nFirst"},
		{ID: "remote", MTU: 1280, Addresses: []string{"100.64.1.2/32"}, Allowed: []string{"0.0.0.0/0"},
			External: &vrDriverConfig{Adapter: "tailscale-node", Generation: 8}, ExitNodeID: "nSecond"},
	}
	cfg := vrConfig{Version: 3, Underlay: 1, Capture: []string{capture}, Members: members,
		Policy: vrPolicy{Version: 2, Revision: 1, Default: "office", EventSource: source}}
	var delivered []byte
	var slot uint32
	var sent uint64
	st, err := createVRWithDrivers(cfg, func(p []byte) { delivered = bytes.Clone(p) }, nil, func(s uint32, epoch uint64, _ []byte) bool {
		slot, sent = s, epoch
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	defer st.stop()
	query := wgTestIPv4UDP(t, capture, target, "query")
	if !st.router.Forward(query) || slot != 1 || sent != 8 {
		t.Fatal("selector did not use the second driver", slot, sent, st.router.Status())
	}
	reply := wgTestIPv4UDP(t, target, "100.64.1.2", "reply")
	binary.BigEndian.PutUint16(reply[20:22], binary.BigEndian.Uint16(query[22:24]))
	binary.BigEndian.PutUint16(reply[22:24], binary.BigEndian.Uint16(query[20:22]))
	if st.returnDriver(0, 2, reply) || !st.returnDriver(1, 8, reply) || len(delivered) == 0 {
		t.Fatal("reply did not match the selected generation and confirmed exit", st.router.Status())
	}
	if !st.revokeDriver(1, 8) {
		t.Fatal("could not revoke the selected generation")
	}
	binary.BigEndian.PutUint16(query[20:22], 45000)
	if st.router.Forward(query) || st.router.Status().Drops["exit node is unavailable for this destination"] != 1 {
		t.Fatal("unavailable exit silently used the default driver", st.router.Status())
	}
	members[1].External = &vrDriverConfig{Adapter: "wireguard", Generation: 8}
	if forged, err := createVRWithDrivers(cfg, func([]byte) {}, nil, func(uint32, uint64, []byte) bool { return true }); err == nil {
		forged.stop()
		t.Fatal("a non-tailnet driver could claim an exit node")
	}
}

func TestVirtualMemberPreservesPolicyInBothDirections(t *testing.T) {
	const host, assigned, peer = "198.19.255.1", "10.6.0.8", "192.0.2.9"
	const policy = "on deny: udp.datagram { if port.dst == 25 { drop(); } }\non reply: inbound.ip.packet { if flow.profile == \"office\" { ip.dscp = 22; } }"
	member := vrMember{ID: "office", Addresses: []string{assigned}, Allowed: []string{"0.0.0.0/0"}, MTU: 1280, Adapter: "openvpn3", VPNKind: "openvpn", EventSource: policy, External: &vrDriverConfig{Adapter: "openvpn3", Generation: 10}}
	cfg := vrConfig{Version: 3, Underlay: 1, Capture: []string{host}, Members: []vrMember{member}, Policy: vrPolicy{Version: 1, Revision: 1, Default: "office"}}
	cfg.Policy.Version = 2
	cfg.Policy.EventSource = `on verify: udp.datagram { if flow.member != "office" || flow.profile != "office" || vpn.kind != "openvpn" || flow.generation < 10 { drop(); } }
on verify_return: inbound.udp.datagram { if flow.member != "office" || vpn.kind != "openvpn" || flow.generation != 10 { drop(); } }`
	var delivered []byte
	sent := 0
	open := func() (*vrState, error) {
		return createVRWithDrivers(cfg, func(p []byte) { delivered = bytes.Clone(p) }, nil, func(uint32, uint64, []byte) bool { sent++; return true })
	}
	st, err := open()
	if err != nil {
		t.Fatal(err)
	}
	defer st.stop()
	query := wgTestIPv4UDP(t, host, peer, "hello")
	binary.BigEndian.PutUint16(query[22:24], 25)
	if st.router.Forward(query) || sent != 0 || st.router.Status().Flows != 0 {
		t.Fatal("member drop leaked or established a return mapping")
	}
	binary.BigEndian.PutUint16(query[22:24], 53)
	if !st.router.Forward(query) || sent != 1 {
		t.Fatal("admitted member send", st.router.Status())
	}
	reply := wgTestIPv4UDP(t, peer, assigned, "hello")
	binary.BigEndian.PutUint16(reply[22:24], binary.BigEndian.Uint16(query[20:22]))
	binary.BigEndian.PutUint16(reply[20:22], 53)
	if !st.returnDriver(0, 10, reply) || len(delivered) == 0 || delivered[1]>>2 != 22 {
		t.Fatal("member policy missing on return", st.router.Status())
	}
	if rules := st.memberPolicy[0].Status().Rules; len(rules) != 2 {
		t.Fatal("member rules absent from inspector")
	}
	if !st.revokeDriver(0, 10) {
		t.Fatal("revoke failed")
	}
	member.External = &vrDriverConfig{Adapter: "openvpn3", Generation: 11}
	if !st.replaceDriver(0, 10, member) {
		t.Fatal("revoked member did not reauthenticate")
	}
	binary.BigEndian.PutUint16(query[22:24], 25)
	if st.router.Forward(query) || sent != 1 {
		t.Fatal("reconnecting discarded the member policy")
	}
	cfg.Members[0].Adapter = "tailscale-node"
	if bad, err := open(); err == nil {
		bad.stop()
		t.Fatal("different policy schema accepted")
	}
}
