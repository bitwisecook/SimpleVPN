// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package packetrouter

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func rawFixture(t *testing.T, source string) *RawPacketPolicy {
	t.Helper()
	s, err := NewRawPacketPolicy("wireguard", "personal", "wireguard", source)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}
func TestRawPolicyDisabledDirectionsAndSessionLifetime(t *testing.T) {
	s := rawFixture(t, "")
	if s.NeedsPackets(Inbound) != 0 || s.NeedsPackets(Outbound) != 0 {
		t.Fatal("empty plan entered evaluator")
	}
	s.Observe(Outbound, 6, 999)
	s.Apply(Inbound, []byte{0xff})
	s.Observe(Inbound, 1, 7)
	stats := s.Status()
	if stats.Outbound.ForwardedPackets != 6 || stats.Outbound.ReceivedBytes != 999 || stats.Inbound.EvaluatedPackets != 0 || stats.Inbound.ForwardedBytes != 8 || len(stats.Rules) != 0 || stats.SessionID == "" {
		t.Fatal(stats)
	}
	if s.Status().SessionID == rawFixture(t, "").Status().SessionID {
		t.Fatal("session id reused")
	}
	s.Close()
	if s.NeedsPackets(Inbound) != -1 || s.Apply(Inbound, []byte{0}) {
		t.Fatal("closed policy forwarded")
	}
	for _, sample := range []struct{ id, source string }{
		{"wireguard", "on x tcp.syn source browser => drop"}, {"wireguard", "on x:tcp.syn {if flow.source==\"browser\" {drop();}}"},
		{"apple-personal", ""}, {"wireguard", "on x tcp.syn => count\non x inbound.tcp.syn => count"},
	} {
		if p, e := CompileAdapterEvents(sample.id, sample.source); e == nil {
			p.Close()
			t.Fatalf("accepted %+v", sample)
		}
	}
}

func TestIndependentUDPDirectionAndObservedEdits(t *testing.T) {
	for _, source := range []string{
		"on old udp.open => mark-dscp 12\non incoming inbound.udp.open => mark-dscp 22",
		`on old:udp.open { if flow.direction=="outbound" && flow.adapter=="wireguard" {ip.dscp=12;} }
          on incoming:inbound.udp.open {if flow.direction=="inbound" {ip.dscp=22;}}`,
	} {
		s := rawFixture(t, source)
		now := s.epoch
		s.now = func() time.Time { return now }
		var octets uint64
		for _, pair := range [][2]string{{"192.0.2.3", "198.51.100.7"}, {"2001:db8::a", "2001:db8:2::2"}} {
			for _, d := range []Direction{Outbound, Inbound} {
				for i, want := range []byte{12, 0} {
					if d == Inbound && i == 0 {
						want = 22
					}
					pkt := testDatagram(pair[0], pair[1], 4096, 17)
					if d == Outbound {
						octets += uint64(len(pkt))
					}
					if !s.Apply(d, pkt) {
						t.Fatal("denied", i)
					}
					p, e := parse(pkt, false)
					if e != nil {
						t.Fatal(e)
					}
					h := packetEventHost{packet: &p}
					v, _ := h.Read("ip.dscp")
					if byte(v.AsInt()) != want {
						t.Fatalf("direction %d packet %d DSCP=%d want %d", d, i, v.AsInt(), want)
					}
				}
			}
		}
		before := s.Status()
		if before.Inbound.EditedPackets != 2 || before.Outbound.EditedPackets != 2 || before.Inbound.RuleHits != 2 || before.Inbound.ReceivedPackets != 4 || before.Inbound.ForwardedBytes != octets || before.Outbound.ReceivedBytes != octets || before.Outbound.ForwardedPackets != 4 || before.Inbound.ReceivedBytes != octets {
			t.Fatal(before)
		}
		now = now.Add(2 * time.Minute)
		pkt := testDatagram("192.0.2.3", "198.51.100.7", 4096, 17)
		s.Apply(Outbound, pkt)
		if pkt[1]>>2 != 12 {
			t.Fatal("stale generation after expiry")
		}
	}
	drop := rawFixture(t, "on deny inbound.udp.open => drop")
	for range 2 {
		if drop.Apply(Inbound, testDatagram("192.0.2.3", "198.51.100.7", 9, 17)) {
			t.Fatal("denied first packet created a UDP binding")
		}
	}
	if drop.Status().Inbound.DroppedPackets != 2 || drop.Status().Rules[0].Drops != 2 {
		t.Fatal(drop.Status())
	}
}
func TestRawOpaqueAndFragmentsRespectPolicyScope(t *testing.T) {
	all := rawFixture(t, `on ip:ip.packet {ip.dscp=17;}`)
	transport := rawFixture(t, `on udp:udp.datagram {count();}`)
	base := testDatagram("192.0.2.1", "198.51.100.1", 1, 17)
	frame := bytes.Clone(base)
	frame[9] = 47
	binary.BigEndian.PutUint16(frame[10:], 0)
	binary.BigEndian.PutUint16(frame[10:], ^sum(frame[:20]))
	if !all.Apply(Outbound, frame) || frame[1]>>2 != 17 || !transport.Apply(Outbound, frame) {
		t.Fatal("opaque protocol did not traverse + run IP policy")
	}
	frag := append([]byte(nil), base[:28]...)
	binary.BigEndian.PutUint16(frag[2:], 28)
	binary.BigEndian.PutUint16(frag[6:], 0x2000)
	binary.BigEndian.PutUint16(frag[10:], 0)
	binary.BigEndian.PutUint16(frag[10:], ^sum(frag[:20]))
	if !all.Apply(Outbound, frag) || frag[1]>>2 != 17 || transport.Apply(Outbound, frag) {
		t.Fatal("IPv4 fragment concealed an active transport hook")
	}
	v6 := make([]byte, 56)
	v6[0], v6[6], v6[7], v6[40] = 0x60, 44, 64, 17
	binary.BigEndian.PutUint16(v6[4:], 16)
	v6[43] = 1
	if !all.Apply(Outbound, v6) || transport.Apply(Outbound, v6) {
		t.Fatal("IPv6 fragment policy")
	}
	broken := append([]byte(nil), base...)
	broken[10] ^= 1
	if all.Apply(Outbound, broken) {
		t.Fatal("bad checksum accepted")
	}
	if transport.NeedsPackets(Inbound) != 0 || !transport.Apply(Inbound, broken) {
		t.Fatal("outbound rule affected inbound pass-through")
	}
}

func TestSharedIngressBeforeCaptureAndMatchedMember(t *testing.T) {
	const policy = `on received:inbound.udp.open {if flow.member=="office" && flow.generation==7 && flow.adapter=="wireguard-shared" && flow.direction=="inbound" {ip.dscp=18;}}`
	var sent, delivered []byte
	port := Port{ID: "office", Generation: 7, Addresses: []netip.Addr{netip.MustParseAddr("10.7.0.1")}, Allowed: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, MTU: 1500, Send: func(p []byte) bool { sent = bytes.Clone(p); return true }}
	r, e := New([]netip.Addr{netip.MustParseAddr("192.0.2.20")}, []Port{port}, Policy{Revision: 1, Default: "office", EventSource: policy}, func(p []byte) { delivered = bytes.Clone(p) })
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(r.Close)
	if !r.Forward(testDatagram("192.0.2.20", "198.51.100.4", 40500, 17)) {
		t.Fatal(r.Status())
	}
	request, e := parse(sent, false)
	if e != nil {
		t.Fatal(e)
	}
	packetReply(&request)
	if r.Return("office", 6, bytes.Clone(request.raw)) {
		t.Fatal("stale generation")
	}
	for i := range 2 {
		if !r.Return("office", 7, bytes.Clone(request.raw)) {
			t.Fatal(r.Status())
		}
		want := byte(0)
		if i == 0 {
			want = 18
		}
		p, e := parse(delivered, false)
		if e != nil || p.dst.String() != "192.0.2.20" || delivered[1]>>2 != want {
			t.Fatal(i, p.dst, e)
		}
	}
	stats := r.PacketPolicyStatus()
	if stats.Inbound.ReceivedPackets != 3 || stats.Inbound.DroppedPackets != 1 || stats.Inbound.ForwardedPackets != 2 || stats.Inbound.RuleHits != 1 || stats.Inbound.EditedPackets != 1 || stats.Outbound.ForwardedPackets != 1 || stats.Rules[0].PacketsIn != 1 {
		t.Fatal(stats)
	}
}
func TestRawProfileAndProtocolSource(t *testing.T) {
	const program = `on open:udp.open { if flow.profile=="personal" && vpn.kind=="wireguard" {ip.dscp=11;} }`
	buf := testDatagram("192.0.2.3", "198.51.100.7", 512, 17)
	if !rawFixture(t, program).Apply(Outbound, buf) || buf[1]>>2 != 11 {
		t.Fatal("verified profile metadata did not reach the handler")
	}
	p, err := NewRawPacketPolicy("wireguard", "", "", program)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.Apply(Outbound, buf) || p.Status().Outbound.DroppedPackets != 1 {
		t.Fatal("absent profile read succeeded")
	}
	q, err := CompileAdapterEvents("wireguard-shared", program)
	if err != nil {
		t.Fatal(err)
	}
	q.Close()
}

func TestRawIPv6Extensions(t *testing.T) {
	s := rawFixture(t, `on rx:inbound.udp.datagram {ip.dscp=7;}`)
	base := testDatagram("2001:db8::a", "2001:db8::c", 512, 17)
	withOptions := append(bytes.Clone(base[:40]), make([]byte, 8)...)
	withOptions = append(withOptions, base[40:]...)
	binary.BigEndian.PutUint16(withOptions[4:], uint16(len(withOptions)-40))
	withOptions[40] = 17
	for _, next := range []byte{0, 60} {
		pkt := bytes.Clone(withOptions)
		pkt[6] = next
		if !s.Apply(Inbound, pkt) {
			t.Fatalf("did not dispatch past padding-only header %d", next)
		}
		if pkt[0]&15 != 1 || pkt[1]>>4 != 12 {
			t.Fatal("wrong IPv6 traffic class")
		}
	}
	for _, next := range []byte{43, 51, 135, 139, 140} {
		pkt := bytes.Clone(withOptions)
		pkt[6] = next
		if s.Apply(Inbound, pkt) {
			t.Fatalf("unsupported next header %d concealed UDP", next)
		}
	}
	withOptions[6], withOptions[42] = 60, 0xc9
	if s.Apply(Inbound, withOptions) {
		t.Fatal("unknown destination option accepted")
	}
	stats := s.Status().Inbound
	if stats.ReceivedPackets != 8 || stats.DroppedPackets != 6 || stats.EditedPackets != 2 || stats.RuleHits != 2 {
		t.Fatal(stats)
	}
}

func packetReply(p *packet) {
	l4 := p.raw[p.transport:]
	binary.BigEndian.PutUint16(l4, p.dstPort)
	binary.BigEndian.PutUint16(l4[2:], p.srcPort)
	src, dst := p.src, p.dst
	p.replaceAddress(true, dst)
	p.replaceAddress(false, src)
	p.fixTransportChecksum()
}
