// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package packetrouter

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func bigDatagram(t *testing.T, source, target string, sourcePort, targetPort uint16) packet {
	t.Helper()
	raw := testDatagram(source, target, sourcePort, 17)
	p, err := parse(raw, false)
	if err != nil {
		t.Fatal(err)
	}
	p.raw = append(raw, bytes.Repeat([]byte{42}, 3000)...)
	if p.src.Is4() {
		binary.BigEndian.PutUint16(p.raw[2:], uint16(len(p.raw)))
	} else {
		binary.BigEndian.PutUint16(p.raw[4:], uint16(len(p.raw)-40))
	}
	binary.BigEndian.PutUint16(p.raw[p.transport+2:], targetPort)
	binary.BigEndian.PutUint16(p.raw[p.transport+4:], uint16(len(p.raw)-p.transport))
	p.fixIPChecksum()
	p.fixTransportChecksum()
	return p
}

func TestFragmentedDatagramsAreReassembledTranslatedAndReturned(t *testing.T) {
	for _, addresses := range [][3]string{
		{"198.19.255.1", "10.0.0.2", "10.0.0.3"},
		{"fd6e:7853:ffff::1", "fd42::2", "fd42::3"},
	} {
		var fragments [][]byte
		var returned []byte
		port := Port{ID: "vpn", Generation: 7, MTU: 1280,
			Addresses: []netip.Addr{netip.MustParseAddr(addresses[1])},
			Allowed:   []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
			Send:      func(p []byte) bool { fragments = append(fragments, p); return true }}
		r, err := New([]netip.Addr{netip.MustParseAddr(addresses[0])}, []Port{port}, Policy{Revision: 1, Default: "vpn"}, func(p []byte) { returned = p })
		if err != nil {
			t.Fatal(err)
		}
		p := bigDatagram(t, addresses[0], addresses[2], 40000, 443)
		var meta *fragmentMeta
		if p.src.Is6() {
			meta = &fragmentMeta{true, 123, 40, 6, 17}
		}
		parts, err := fragmentPacket(p, 1280, meta)
		if err != nil || len(parts) < 2 {
			t.Fatal("test did not fragment")
		}
		for at := len(parts) - 1; at >= 0; at-- {
			if !r.Forward(parts[at]) {
				t.Fatalf("fragment refused: %v", r.Status())
			}
		}
		if len(fragments) != len(parts) {
			t.Fatalf("wrong outgoing fragment count: %d", len(fragments))
		}
		var receiver reassembler
		var whole []byte
		for _, part := range fragments {
			data, _, pending, err := receiver.accept(part, "peer")
			if err != nil {
				t.Fatal(err)
			}
			if !pending {
				whole = data
			}
		}
		assertChecksums(t, whole)
		translated, err := parse(whole, false)
		if err != nil || translated.src.String() != addresses[1] {
			t.Fatal("bad reassembled translation")
		}
		reply := bigDatagram(t, addresses[2], addresses[1], 443, 40000)
		parts, err = fragmentPacket(reply, 1280, meta)
		if err != nil {
			t.Fatal(err)
		}
		for at := len(parts) - 1; at >= 0; at-- {
			if !r.Return("vpn", 7, parts[at]) {
				t.Fatalf("return fragment refused: %v", r.Status())
			}
		}
		assertChecksums(t, returned)
		back, err := parse(returned, false)
		if err != nil || back.dst.String() != addresses[0] {
			t.Fatal("bad return fragment translation")
		}
		r.Close()
		if r.Forward(parts[0]) || r.Return("vpn", 7, parts[0]) {
			t.Fatal("closed router accepted fragments")
		}
	}
}

func TestOverlappingFragmentsKillTheWholeDatagram(t *testing.T) {
	p := bigDatagram(t, "198.19.255.1", "10.0.0.3", 40000, 443)
	parts, err := fragmentPacket(p, 1280, nil)
	if err != nil {
		t.Fatal(err)
	}
	var a reassembler
	if _, _, pending, err := a.accept(parts[0], "capture"); !pending || err != nil {
		t.Fatal("first fragment")
	}
	if _, _, _, err := a.accept(parts[0], "capture"); err == nil {
		t.Fatal("overlap was accepted")
	}
	for _, part := range parts[1:] {
		if _, _, _, err := a.accept(part, "capture"); err == nil {
			t.Fatal("overlapping group resumed")
		}
	}
	if a.bytes != 0 {
		t.Fatal("overlap retained fragment storage")
	}
}

func TestUnfragmentedIPv6GetsUsablePacketTooBigFeedback(t *testing.T) {
	var feedback []byte
	port := Port{ID: "vpn", Generation: 1, MTU: 1280,
		Addresses: []netip.Addr{netip.MustParseAddr("fd42::2")},
		Allowed:   []netip.Prefix{netip.MustParsePrefix("::/0")}, Send: func([]byte) bool { t.Fatal("oversized IPv6 was forwarded"); return false }}
	r, err := New([]netip.Addr{netip.MustParseAddr("fd6e:7853:ffff::1")}, []Port{port}, Policy{Revision: 1, Default: "vpn"}, func(p []byte) { feedback = p })
	if err != nil {
		t.Fatal(err)
	}
	p := bigDatagram(t, "fd6e:7853:ffff::1", "fd42::3", 40000, 443)
	if r.Forward(p.raw) {
		t.Fatal("oversized IPv6 accepted")
	}
	assertChecksums(t, feedback)
	if len(feedback) > 1280 || feedback[40] != 2 || binary.BigEndian.Uint32(feedback[44:]) != 1280 {
		t.Fatal("invalid PTB feedback")
	}
}
