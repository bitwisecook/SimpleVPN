// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package packetrouter

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestSourceAdmissionAndTupleQuarantine(t *testing.T) {
	for _, proto := range []byte{6, 17} {
		for _, network := range [][4]string{
			{"198.19.255.1", "10.1.0.2", "10.8.0.7", "10.8.0.0/16"},
			{"fd6e:7853:ffff::1", "fd42::2", "fd01::7", "fd01::/64"},
		} {
			capture, assigned, dest := network[0], network[1], network[2]
			var sent, received int
			port := Port{ID: "work", Generation: 4, MTU: 1280, Addresses: []netip.Addr{netip.MustParseAddr(assigned)},
				Allowed: []netip.Prefix{netip.MustParsePrefix(network[3])}, Send: func([]byte) bool { sent++; return true }}
			policy := Policy{Revision: 1, SourceRules: []SourceRule{{Source: "9-APP", Port: "work"}, {Source: "temp", Port: "work"}}}
			r, err := New([]netip.Addr{netip.MustParseAddr(capture)}, []Port{port}, policy, func([]byte) { received++ })
			if err != nil {
				t.Fatal(err)
			}
			pkt := testDatagram(capture, dest, 40000, proto)
			if r.Forward(pkt) || r.ForwardWithSource(pkt, "missing", 10) || r.ForwardWithSource(pkt, "9-APP", 0) {
				t.Fatal("unattributed capture accepted")
			}
			if r.ForwardWithSource(testDatagram(capture, capture, 40000, proto), "9-APP", 10) {
				t.Fatal("source rule exceeded AllowedIPs")
			}
			if !r.ForwardWithSource(pkt, "9-APP", 10) || !r.ForwardWithSource(pkt, "9-APP", 10) {
				t.Fatal(r.Status())
			}
			reply := testDatagram(dest, assigned, 443, proto)
			q, err := parse(reply, false)
			if err != nil {
				t.Fatal(err)
			}
			binary.BigEndian.PutUint16(q.raw[q.transport+2:], 40000)
			q.fixTransportChecksum()
			if !r.Return("work", 4, reply) {
				t.Fatal("trusted reverse path failed")
			}
			// Same alias, distinct process incarnation. A fresh TCP sequence, like
			// a UDP tuple or retransmission, cannot silently replace that owner.
			newPacket := append([]byte(nil), pkt...)
			if proto == 6 {
				p, err := parse(newPacket, false)
				if err != nil {
					t.Fatal(err)
				}
				binary.BigEndian.PutUint32(p.raw[p.transport+4:], 123)
				p.fixTransportChecksum()
			}
			if r.ForwardWithSource(newPacket, "9-APP", 11) || r.Return("work", 4, reply) || r.ForwardWithSource(pkt, "9-APP", 10) {
				t.Fatal("contested tuple accepted an owner or return packet")
			}
			fresh := testDatagram(capture, dest, 40001, proto)
			if !r.ForwardWithSource(fresh, "temp", 11) {
				t.Fatal("unrelated temporary process flow lost")
			}
			if err := r.Apply(Policy{Revision: 2, SourceRules: []SourceRule{{Source: "9-APP", Port: "work"}}}); err != nil {
				t.Fatal(err)
			}
			if r.ForwardWithSource(fresh, "temp", 11) {
				t.Fatal("removed source still flows")
			}
			if err := r.Apply(Policy{Revision: 3, SourceRules: []SourceRule{}}); err != nil {
				t.Fatal(err)
			}
			if r.ForwardWithSource(testDatagram(capture, dest, 40002, proto), "9-APP", 10) {
				t.Fatal("empty source policy did not block")
			}
			if err := r.Apply(Policy{Revision: 4}); err == nil {
				t.Fatal("source mode silently disabled")
			}
			if sent != 3 || received != 1 {
				t.Fatal("unexpected data-plane activity", sent, received)
			}
		}
	}
}

func TestSourceFragmentsNeverCrossProcessIncarnations(t *testing.T) {
	const capture, remote = "198.19.255.1", "10.1.0.7"
	var sent int
	port := Port{ID: "vpn", Generation: 1, MTU: 65535, Addresses: []netip.Addr{netip.MustParseAddr("10.1.0.2")},
		Allowed: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/24")}, Send: func([]byte) bool { sent++; return true }}
	r, err := New([]netip.Addr{netip.MustParseAddr(capture)}, []Port{port}, Policy{Revision: 1, SourceRules: []SourceRule{{Source: "signed", Port: "vpn"}}}, func([]byte) {})
	if err != nil {
		t.Fatal(err)
	}
	parts, err := fragmentPacket(bigDatagram(t, capture, remote, 30000, 443), 1280, nil)
	if err != nil || len(parts) < 2 {
		t.Fatal(err)
	}
	if r.Forward(parts[0]) {
		t.Fatal("buffered unattributed fragment")
	}
	if !r.ForwardWithSource(parts[0], "signed", 3) {
		t.Fatal("first fragment rejected")
	}
	for _, part := range parts[1:] {
		if !r.ForwardWithSource(part, "signed", 4) {
			t.Fatal("second owner's fragments rejected")
		}
	}
	if sent != 0 {
		t.Fatal("mixed-owner fragments escaped")
	}
	for _, part := range parts[1:] {
		if !r.ForwardWithSource(part, "signed", 3) {
			t.Fatal("same owner's fragments rejected")
		}
	}
	if sent != 1 {
		t.Fatal("owned datagram was not forwarded")
	}
}

// Destination choices are evaluated once at admission. A revision can edit
// the base or override for new connections without moving an existing one.
func TestPerSourceDestinationsPinExistingFlows(t *testing.T) {
	const capture, inside = "198.19.255.1", "10.42.0.5"
	host := netip.MustParsePrefix(inside + "/32")
	subnet := netip.MustParsePrefix("10.42.0.0/24")
	all := netip.MustParsePrefix("0.0.0.0/0")
	var egress []string
	makePort := func(id string, gen uint64, allowed netip.Prefix) Port {
		return Port{ID: id, Generation: gen, MTU: 1280, Allowed: []netip.Prefix{allowed},
			Addresses: []netip.Addr{netip.MustParseAddr("10.200.2.2")}, Send: func([]byte) bool { egress = append(egress, id); return true }}
	}
	ports := []Port{makePort("base", 1, all), makePort("subnet", 2, subnet), makePort("specific", 3, host)}
	policy := Policy{Revision: 1, SourceRules: []SourceRule{
		{Source: "app", Port: "base", Destinations: []Rule{{subnet, "subnet"}, {host, "specific"}}},
		{Source: "process", Port: "base"},
	}}
	r, err := New([]netip.Addr{netip.MustParseAddr(capture)}, ports, policy, func([]byte) {})
	if err != nil {
		t.Fatal(err)
	}
	check := func(alias string, owner uint64, dst string, srcPort uint16, want string) {
		t.Helper()
		before := len(egress)
		ok := r.ForwardWithSource(testDatagram(capture, dst, srcPort, 17), alias, owner)
		if want == "" {
			if ok || len(egress) != before {
				t.Fatal("unexpected fallback", alias, dst, egress)
			}
			return
		}
		if !ok || len(egress) != before+1 || egress[before] != want {
			t.Fatal("wrong selected VPN", alias, dst, want, egress, r.Status())
		}
	}
	check("app", 101, inside, 40000, "specific")
	check("app", 101, "10.42.0.6", 40001, "subnet")
	check("app", 101, "192.0.2.4", 40002, "base")
	check("process", 102, inside, 40003, "base")
	check("unknown", 102, inside, 40004, "")
	policy.Revision++
	policy.SourceRules[0].Port = "subnet"
	policy.SourceRules[0].Destinations = []Rule{{subnet, "base"}, {netip.MustParsePrefix("192.0.2.0/24"), "specific"}}
	if err := r.Apply(policy); err != nil {
		t.Fatal(err)
	}
	check("app", 101, inside, 40000, "specific")
	check("app", 101, inside, 40005, "base")
	check("app", 101, "192.0.2.5", 40006, "") // Selected port's actual AllowedIPs still gate the packet.
	r.RemovePort("specific")
	check("app", 101, inside, 40000, "")
	check("app", 101, inside, 40007, "base")
}
