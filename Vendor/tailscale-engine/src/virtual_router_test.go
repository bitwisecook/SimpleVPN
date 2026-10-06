// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/conn"
)

// Two real encrypted peers deliberately use identical private addresses. The
// production session, not two host interfaces, owns capture and reverse NAT.
func TestVirtualSessionPinsFlowsAcrossTwoEncryptedVPNs(t *testing.T) {
	const capture = "198.19.255.1"
	var members []vrMember
	peers := make(map[string]*wgTestDevice)
	publicKeys := make(map[string]string)
	for _, id := range []string{"first", "second"} {
		private, public := wgTestKeyPair()
		peerPrivate, peerPublic := wgTestKeyPair()
		peer := newWGTestDevice(t, id)
		peer.up(strings.Join([]string{"private_key=" + wgTestHex(t, peerPrivate), "replace_peers=true",
			"public_key=" + wgTestHex(t, public), "allowed_ip=" + wgTestOurTunnelIP + "/32", "allowed_ip=fd7a:115c:a1e0::2/128", ""}, "\n"))
		peers[id], publicKeys[id] = peer, public
		members = append(members, vrMember{ID: id, Addresses: []string{wgTestOurTunnelIP + "/32", "fd7a:115c:a1e0::2/128"}, WireGuard: wgStartConfig{
			PrivateKey: private, PeerPublicKey: peerPublic, AllowedIPs: []string{"0.0.0.0/0", "::/0"}, MTU: 1280,
			Endpoint: fmt.Sprintf("127.0.0.1:%d", peer.listenPort()),
		}})
	}
	host := make(chan []byte, 32)
	st, err := createVRState(vrConfig{Version: 1, Capture: []string{capture, "fd6e:7853:ffff::1"}, Members: members,
		Policy: vrPolicy{Version: 1, Revision: 1, Default: "first"}},
		func(p []byte) { host <- bytes.Clone(p) }, func(string) conn.Bind {
			iface, err := net.InterfaceByName("lo0")
			if err != nil {
				t.Fatal(err)
			}
			return newPhysicalBind(uint32(iface.Index))
		})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.stop)
	for id, peer := range peers {
		engine, ok := wgInstances.Get(st.engines[id])
		if !ok {
			t.Fatal("session did not retain its own port")
		}
		ours := &wgTestDevice{t: t, name: id, dev: engine.dev, tun: engine.tundev}
		peer.apply(strings.Join([]string{"public_key=" + wgTestHex(t, publicKeys[id]), "update_only=true",
			fmt.Sprintf("endpoint=127.0.0.1:%d", ours.listenPort()), ""}, "\n"))
	}
	exchange := func(id, message string, sourcePort uint16) {
		t.Helper()
		out := wgTestIPv4UDP(t, capture, wgTestPeerTunnelIP, message)
		binary.BigEndian.PutUint16(out[20:22], sourcePort)
		if !st.router.Forward(out) {
			t.Fatal("capture rejected", st.router.Status())
		}
		translated := peers[id].awaitPacket(5 * time.Second)
		want := wgTestIPv4UDP(t, wgTestOurTunnelIP, wgTestPeerTunnelIP, message)
		binary.BigEndian.PutUint16(want[20:22], sourcePort)
		if !bytes.Equal(translated, want) {
			t.Fatalf("wrong translated packet on %s: %x", id, translated)
		}
		in := wgTestIPv4UDP(t, wgTestPeerTunnelIP, wgTestOurTunnelIP, message+" return")
		binary.BigEndian.PutUint16(in[20:22], 51001)
		binary.BigEndian.PutUint16(in[22:24], sourcePort)
		peers[id].send(in)
		select {
		case got := <-host:
			want := wgTestIPv4UDP(t, wgTestPeerTunnelIP, capture, message+" return")
			binary.BigEndian.PutUint16(want[20:22], 51001)
			binary.BigEndian.PutUint16(want[22:24], sourcePort)
			if !bytes.Equal(got, want) {
				t.Fatalf("return crossed a VPN or retained its private source: %x", got)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no packet returned to virtual interface", st.router.Status())
		}
	}
	exchangeTransport := func(id string, ipv6 bool, protocol byte, sourcePort uint16) {
		t.Helper()
		src, dst, assigned := capture, wgTestPeerTunnelIP, wgTestOurTunnelIP
		if ipv6 {
			src, dst, assigned = "fd6e:7853:ffff::1", "fd7a:115c:a1e0::1", "fd7a:115c:a1e0::2"
		}
		raw := vrTestTransport(src, dst, sourcePort, 443, protocol, false)
		if !st.router.Forward(raw) {
			t.Fatal("transport rejected", st.router.Status())
		}
		translated := peers[id].awaitPacket(5 * time.Second)
		if want := vrTestTransport(assigned, dst, sourcePort, 443, protocol, false); !bytes.Equal(translated, want) {
			t.Fatalf("translated IPv6=%v protocol=%d packet differed: %x", ipv6, protocol, translated)
		}
		peers[id].send(vrTestTransport(dst, assigned, 443, sourcePort, protocol, true))
		select {
		case got := <-host:
			if want := vrTestTransport(dst, src, 443, sourcePort, protocol, true); !bytes.Equal(got, want) {
				t.Fatalf("wrong returned IPv6=%v protocol=%d packet: %x", ipv6, protocol, got)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no transport return", st.router.Status())
		}
	}
	for i, protocol := range []byte{6, 17} {
		exchangeTransport("first", false, protocol, uint16(51100+i))
		exchangeTransport("first", true, protocol, uint16(51200+i))
	}

	exchange("first", "initial", 51000)
	policy, _ := (vrPolicy{Version: 1, Revision: 2, Default: "second"}).compile()
	if err := st.router.Apply(policy); err != nil {
		t.Fatal(err)
	}
	for i, protocol := range []byte{6, 17} {
		exchangeTransport("first", false, protocol, uint16(51100+i))
		exchangeTransport("first", true, protocol, uint16(51200+i))
		exchangeTransport("second", false, protocol, uint16(51300+i))
		exchangeTransport("second", true, protocol, uint16(51400+i))
	}

	exchange("first", "pinned", 51000)
	exchange("second", "new flow", 51002)
	st.router.RemovePort("first")
	if st.router.Forward(wgTestIPv4UDP(t, capture, wgTestPeerTunnelIP, "must not escape")) {
		t.Fatal("established flow escaped its stopped VPN")
	}
	exchange("second", "survives", 51002)
	st.stop()
	if st.router.Forward(wgTestIPv4UDP(t, capture, wgTestPeerTunnelIP, "stopped")) {
		t.Fatal("stopped virtual interface accepted a packet")
	}
}

// Complete transport checksums exercise production NAT, not UDP's IPv4 zero-
// checksum exception. TCP SYN/SYN-ACK exchange also proves return flow matching.
func vrTestTransport(src, dst string, source, target uint16, protocol byte, reply bool) []byte {
	s, d := netip.MustParseAddr(src), netip.MustParseAddr(dst)
	header, length := 20, 8
	if s.Is6() {
		header = 40
	}
	if protocol == 6 {
		length = 20
	}
	raw := make([]byte, header+length)
	if s.Is4() {
		raw[0], raw[8], raw[9] = 0x45, 64, protocol
		binary.BigEndian.PutUint16(raw[2:], uint16(len(raw)))
		copy(raw[12:], s.AsSlice())
		copy(raw[16:], d.AsSlice())
		binary.BigEndian.PutUint16(raw[10:], wgTestOnesComplementSum(raw[:20]))
	} else {
		raw[0], raw[6], raw[7] = 0x60, protocol, 64
		binary.BigEndian.PutUint16(raw[4:], uint16(length))
		copy(raw[8:], s.AsSlice())
		copy(raw[24:], d.AsSlice())
	}
	l4 := raw[header:]
	binary.BigEndian.PutUint16(l4, source)
	binary.BigEndian.PutUint16(l4[2:], target)
	checksumAt := 6
	if protocol == 6 {
		l4[12], l4[13], checksumAt = 0x50, 2, 16
		binary.BigEndian.PutUint32(l4[4:], 1234)
		if reply {
			l4[13] = 0x12
			binary.BigEndian.PutUint32(l4[8:], 1235)
		}
		binary.BigEndian.PutUint16(l4[14:], 65535)
	} else {
		binary.BigEndian.PutUint16(l4[4:], uint16(length))
	}
	pseudo := append(append([]byte(nil), s.AsSlice()...), d.AsSlice()...)
	if s.Is4() {
		pseudo = append(pseudo, 0, protocol, byte(length>>8), byte(length))
	} else {
		pseudo = append(pseudo, 0, 0, byte(length>>8), byte(length), 0, 0, 0, protocol)
	}
	checksum := wgTestOnesComplementSum(append(pseudo, l4...))
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(l4[checksumAt:], checksum)
	return raw
}
