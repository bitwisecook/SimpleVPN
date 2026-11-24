// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package packetrouter

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func TestEvidenceOnlyMatchesPriorDNSInTheSameScope(t *testing.T) {
	now := time.Now()
	r := &Router{now: time.Now}
	r.renewEvidenceLocked(now)
	defer r.stopEvidenceLocked()
	e := r.evidence
	server := &flow{port: "first", generation: 1, owner: 100, source: "app", lastSeen: now}
	target := netip.MustParseAddr("192.0.2.15")
	newFlow := func(port, source string, owner, generation uint64) *flow {
		f := &flow{port: port, generation: generation, owner: owner, source: source, lastSeen: now}
		e.open(f, target, now)
		return f
	}
	dns := func(name string, question bool) {
		msg := fixtureDNS(t, name, !question, target.As4(), 5)
		p := packet{protocol: 17, raw: append(make([]byte, 8), msg...)}
		if question {
			p.dstPort = 53
			e.outbound(server, p, now)
		} else {
			p.srcPort = 53
			e.inbound(server, p, now)
		}
	}
	before := newFlow("first", "app", 100, 1)
	dns("unasked.example", false)
	dns("service.example", true)
	dns("mismatch.example", false)
	if len(e.addresses) != 0 {
		t.Fatal("accepted unsolicited/mismatched answer")
	}
	dns("service.example", false)
	first := newFlow("first", "app", 100, 1)
	if name, _ := e.names(first, target, now); name != "service.example" {
		t.Fatal("lost prior DNS correlation")
	}
	for _, other := range []*flow{before, newFlow("second", "app", 100, 1), newFlow("first", "app", 100, 2), newFlow("first", "app", 101, 1), newFlow("first", "other", 100, 1)} {
		if name, _ := e.names(other, target, now); name != "" {
			t.Fatal("leaked evidence across time/member/generation/source")
		}
	}
	now = now.Add(time.Second)
	dns("shared.example", true)
	dns("shared.example", false)
	if name, _ := e.names(first, target, now); name != "" {
		t.Fatal("displayed ambiguous shared address")
	}
	now = now.Add(5 * time.Second)
	if name, _ := e.names(first, target, now); name != "" {
		t.Fatal("displayed stale evidence")
	}
}

func TestEvidenceLeaseAndSegmentedClientHelloOnRouter(t *testing.T) {
	const client = "198.19.255.1"
	const remote = "192.0.2.15"
	p := Port{ID: "vpn", Generation: 1, Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.2")}, Allowed: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, MTU: 1500, Send: func([]byte) bool { return true }}
	r, err := New([]netip.Addr{netip.MustParseAddr(client)}, []Port{p}, Policy{Revision: 1, Default: "vpn"}, func([]byte) {})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	now := time.Now()
	r.now = func() time.Time { return now }
	send := func(port uint16, seq uint32, flags byte, data []byte) {
		raw := sizedDatagram(client, remote, port, 6, data)
		p, err := parse(raw, false)
		if err != nil {
			t.Fatal(err)
		}
		binary.BigEndian.PutUint32(raw[p.transport+4:], seq)
		raw[p.transport+13] = flags
		p.fixTransportChecksum()
		if !r.Forward(raw) {
			t.Fatal("router dropped valid TLS fixture")
		}
	}
	const syn = 77
	send(40000, syn, 2, nil)
	if r.evidence != nil {
		t.Fatal("inspection allocated during ordinary routing")
	}
	r.mu.Lock()
	r.renewEvidenceLocked(now)
	r.mu.Unlock()
	hello := fixtureRecord(fixtureHello("portal.example", false))
	send(40000, syn+1, 16, hello)
	send(40001, syn, 2, nil)
	send(40001, syn+1, 16, hello[:10])
	send(40001, syn+1, 16, hello[:10]) // identical retry
	send(40001, syn+9, 16, hello[8:])  // partial overlap with new bytes
	send(40002, syn, 2, nil)
	send(40002, syn+5, 16, hello[4:]) // missed first bytes
	for tuple, f := range r.flows {
		_, name := r.evidence.names(f, tuple.dst, now)
		if (name == "portal.example") != (tuple.srcPort == 40001) {
			t.Fatal("unexpected SNI for port", tuple.srcPort, name)
		}
	}
	if r.evidence.buffers != 0 {
		t.Fatal("kept raw bytes after completing the hello")
	}
	now = now.Add(evidenceLease)
	for tuple, f := range r.flows {
		if dns, sni := r.evidence.names(f, tuple.dst, now); dns != "" || sni != "" {
			t.Fatal("returned expired evidence")
		}
	}
	r.mu.Lock()
	r.renewEvidenceLocked(now)
	r.mu.Unlock()
	if len(r.evidence.notes) != 0 {
		t.Fatal("renewal revived old names")
	}
}

func TestEvidenceLimitsPartialHellosAndClearsIdleLease(t *testing.T) {
	now := time.Now()
	r := &Router{now: func() time.Time { return now.Add(evidenceLease) }}
	r.renewEvidenceLocked(now)
	defer func() { r.mu.Lock(); defer r.mu.Unlock(); r.stopEvidenceLocked() }()
	dst := netip.MustParseAddr("192.0.2.20")
	tcp := make([]byte, 26)
	tcp[12], tcp[13] = 0x50, 0x10
	binary.BigEndian.PutUint32(tcp[4:], 1)
	copy(tcp[20:], []byte{22, 3, 1, 0, 255, 1})
	for i := 0; i < 128; i++ {
		f := &flow{lastSeen: now}
		f.reverse.tuple.protocol = 6
		r.evidence.open(f, dst, now)
		r.evidence.outbound(f, packet{raw: tcp, protocol: 6}, now)
	}
	if r.evidence.buffers != 32 {
		t.Fatal("unbounded or missing handshake buffers", r.evidence.buffers)
	}
	r.evidence.sweep(now.Add(4 * time.Second))
	if r.evidence.buffers != 0 {
		t.Fatal("retained incomplete payloads")
	}
	r.mu.Lock()
	r.evidence.timer.Reset(time.Millisecond)
	r.mu.Unlock()
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		r.mu.Lock()
		stopped := r.evidence == nil
		r.mu.Unlock()
		if stopped {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("idle lease did not release DNS names and payloads")
}
