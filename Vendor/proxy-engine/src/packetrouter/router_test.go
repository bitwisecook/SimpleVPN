// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package packetrouter

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

func testDatagram(src, dst string, sourcePort uint16, protocol byte) []byte {
	source, target := netip.MustParseAddr(src), netip.MustParseAddr(dst)
	headerLength, transportLength := 20, 8
	if source.Is6() {
		headerLength = 40
	}
	if protocol == 6 {
		transportLength = 20
	}
	data := make([]byte, headerLength+transportLength+5)
	if source.Is4() {
		data[0], data[8], data[9] = 0x45, 64, protocol
		binary.BigEndian.PutUint16(data[2:], uint16(len(data)))
		copy(data[12:], source.AsSlice())
		copy(data[16:], target.AsSlice())
		binary.BigEndian.PutUint16(data[10:], ^checksum.Checksum(data[:20], 0))
	} else {
		data[0], data[6], data[7] = 0x60, protocol, 64
		binary.BigEndian.PutUint16(data[4:], uint16(len(data)-40))
		copy(data[8:], source.AsSlice())
		copy(data[24:], target.AsSlice())
	}
	l4 := data[headerLength:]
	checksumAt := 6
	switch protocol {
	case 6:
		binary.BigEndian.PutUint16(l4, sourcePort)
		binary.BigEndian.PutUint16(l4[2:], 443)
		l4[12], l4[13], checksumAt = 0x50, 2, 16
	case 17:
		binary.BigEndian.PutUint16(l4, sourcePort)
		binary.BigEndian.PutUint16(l4[2:], 443)
		binary.BigEndian.PutUint16(l4[4:], uint16(len(l4)))
	case 1, 58:
		l4[0], checksumAt = 8, 2
		if protocol == 58 {
			l4[0] = 128
		}
		binary.BigEndian.PutUint16(l4[4:], sourcePort)
	}
	copy(l4[transportLength:], []byte("hello"))
	var pseudo []byte
	if protocol != 1 {
		pseudo = append(pseudo, source.AsSlice()...)
		pseudo = append(pseudo, target.AsSlice()...)
		if source.Is4() {
			pseudo = append(pseudo, 0, protocol)
			pseudo = binary.BigEndian.AppendUint16(pseudo, uint16(len(l4)))
		} else {
			pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(len(l4)))
			pseudo = append(pseudo, 0, 0, 0, protocol)
		}
	}
	binary.BigEndian.PutUint16(l4[checksumAt:], ^checksum.Checksum(l4, checksum.Checksum(pseudo, 0)))
	return data
}

func assertChecksums(t *testing.T, raw []byte) {
	t.Helper()
	ipHeader := 20
	if raw[0]>>4 == 6 {
		ipHeader = 40
	} else if checksum.Checksum(raw[:20], 0) != 0xffff {
		t.Fatal("bad translated IPv4 checksum")
	}
	protocol := raw[9]
	src, dst := raw[12:16], raw[16:20]
	if ipHeader == 40 {
		protocol, src, dst = raw[6], raw[8:24], raw[24:40]
	}
	l4 := raw[ipHeader:]
	var pseudo []byte
	if protocol != 1 {
		pseudo = append(pseudo, src...)
		pseudo = append(pseudo, dst...)
		if ipHeader == 20 {
			pseudo = append(pseudo, 0, protocol)
			pseudo = binary.BigEndian.AppendUint16(pseudo, uint16(len(l4)))
		} else {
			pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(len(l4)))
			pseudo = append(pseudo, 0, 0, 0, protocol)
		}
	}
	if checksum.Checksum(l4, checksum.Checksum(pseudo, 0)) != 0xffff {
		t.Fatal("bad complete transport checksum")
	}
}

func TestTranslationPreservesPayloadAndCompleteChecksums(t *testing.T) {
	for _, addresses := range [][3]string{
		{"198.19.255.1", "10.0.0.2", "10.0.0.3"},
		{"fd6e:7853:ffff::1", "fd42::2", "fd42::3"},
	} {
		for _, proto := range []byte{6, 17, 1, 58} {
			if (proto == 1 && addresses[0][0] == 'f') || (proto == 58 && addresses[0][0] != 'f') {
				continue
			}
			t.Run(addresses[0]+"/"+string(rune(proto)), func(t *testing.T) {
				var outbound, inbound []byte
				port := Port{ID: "vpn", Generation: 1, Addresses: []netip.Addr{netip.MustParseAddr(addresses[1])},
					Allowed: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}, MTU: 1280,
					Send: func(p []byte) bool { outbound = bytes.Clone(p); return true }}
				r, err := New([]netip.Addr{netip.MustParseAddr(addresses[0])}, []Port{port}, Policy{Revision: 1, Default: "vpn"}, func(p []byte) { inbound = p })
				if err != nil {
					t.Fatal(err)
				}
				original := testDatagram(addresses[0], addresses[2], 40000, proto)
				if !r.Forward(original) {
					t.Fatalf("forward refused: %v", r.Status())
				}
				assertChecksums(t, outbound)
				p, err := parse(outbound, false)
				if err != nil || p.src.String() != addresses[1] || !bytes.Equal(p.raw[len(p.raw)-5:], []byte("hello")) {
					t.Fatal("incorrect source translation")
				}
				reply := testDatagram(addresses[2], addresses[1], 443, proto)
				q, err := parse(reply, false)
				if err != nil {
					t.Fatal(err)
				}
				if q.echo {
					binary.BigEndian.PutUint16(reply[q.transport+4:], 40000)
					if proto == 1 {
						reply[q.transport] = 0
					} else {
						reply[q.transport] = 129
					}
				} else {
					binary.BigEndian.PutUint16(reply[q.transport+2:], 40000)
				}
				q.fixTransportChecksum()
				if !r.Return("vpn", 1, reply) {
					t.Fatalf("return refused: %v", r.Status())
				}
				assertChecksums(t, inbound)
				q, err = parse(inbound, false)
				if err != nil || q.dst.String() != addresses[0] {
					t.Fatal("incorrect return translation")
				}
			})
		}
	}
}

func TestPoliciesPinExistingFlowsAndDoNotFallbackAfterLoss(t *testing.T) {
	capture := netip.MustParseAddr("198.19.255.1")
	var through []string
	ports := []Port{}
	for _, id := range []string{"a", "b"} {
		ports = append(ports, Port{ID: id, Generation: 1, Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.2")},
			Allowed: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, MTU: 1280,
			Send: func([]byte) bool { through = append(through, id); return true }})
	}
	r, err := New([]netip.Addr{capture}, ports, Policy{Revision: 1, Default: "a"}, func([]byte) {})
	if err != nil {
		t.Fatal(err)
	}
	old := testDatagram(capture.String(), "10.0.0.3", 40000, 17)
	if !r.Forward(old) {
		t.Fatal("initial forward")
	}
	if err := r.Apply(Policy{Revision: 2, Default: "b"}); err != nil {
		t.Fatal(err)
	}
	if !r.Forward(old) || !r.Forward(testDatagram(capture.String(), "10.0.0.3", 40001, 17)) {
		t.Fatal("policy forward")
	}
	if len(through) != 3 || through[0] != "a" || through[1] != "a" || through[2] != "b" {
		t.Fatalf("flow moved: %v", through)
	}
	r.RemovePort("a")
	if r.Forward(old) {
		t.Fatal("pinned flow escaped after VPN loss")
	}
	if r.Return("b", 99, old) {
		t.Fatal("stale callback accepted")
	}
	if err := r.Apply(Policy{Revision: 3, Rules: []Rule{{netip.MustParsePrefix("::/0"), "b"}}}); err == nil {
		t.Fatal("unauthorized IPv6 policy accepted")
	}
	if r.Status().Revision != 2 {
		t.Fatal("rejected policy replaced current revision")
	}
}

func TestHalfDefaultsAreAuthorizedOnlyAsCompleteCoverage(t *testing.T) {
	all := netip.MustParsePrefix("0.0.0.0/0")
	allowed := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
	if !covers(all, allowed) || covers(all, allowed[:1]) {
		t.Fatal("incorrect paired default coverage")
	}
}

func FuzzPacketParser(f *testing.F) {
	f.Add(testDatagram("198.19.255.1", "10.0.0.2", 40000, 17))
	f.Add(testDatagram("fd6e:7853:ffff::1", "fd42::2", 40000, 6))
	f.Fuzz(func(t *testing.T, raw []byte) {
		for _, quote := range []bool{false, true} {
			p, err := parse(bytes.Clone(raw), quote)
			if err == nil && !p.icmpError {
				address := netip.MustParseAddr("10.42.0.2")
				if p.src.Is6() {
					address = netip.MustParseAddr("fd42::99")
				}
				p.replaceAddress(true, address)
				if !quote {
					p.fixTransportChecksum()
				}
			}
		}
	})
}

func TestIPv6AddressDependentOptionsCannotBypassTranslation(t *testing.T) {
	for _, test := range []struct {
		name    string
		options []byte
		valid   bool
	}{
		{"Pad1", []byte{0, 0, 0, 0, 0, 0}, true},
		{"PadN", []byte{1, 4, 0, 0, 0, 0}, true},
		{"HomeAddress", []byte{0xc9, 4, 0, 0, 0, 0}, false},
		{"Unknown", []byte{2, 4, 0, 0, 0, 0}, false},
		{"TruncatedPadding", []byte{1, 7, 0, 0, 0, 0}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := testDatagram("fd6e:7853:ffff::1", "fd42::2", 40000, 17)
			raw := append(bytes.Clone(original[:40]), append([]byte{17, 0}, test.options...)...)
			raw = append(raw, original[40:]...)
			raw[6] = 0
			binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-40))
			_, err := parse(raw, false)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v, parse=%v", test.valid, err)
			}
		})
	}
}

func TestTCPRetransmitNewConnectionAndClosedFlowLifetime(t *testing.T) {
	capture := netip.MustParseAddr("198.19.255.1")
	var through []string
	var ports []Port
	for _, id := range []string{"a", "b"} {
		ports = append(ports, Port{ID: id, Generation: 1, Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.2")}, Allowed: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, MTU: 1280, Send: func([]byte) bool { through = append(through, id); return true }})
	}
	r, err := New([]netip.Addr{capture}, ports, Policy{Revision: 1, Default: "a"}, func([]byte) {})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r.now = func() time.Time { return now }
	opening := testDatagram(capture.String(), "10.0.0.3", 40000, 6)
	if !r.Forward(opening) {
		t.Fatal("opening SYN refused")
	}
	if err = r.Apply(Policy{Revision: 2, Default: "b"}); err != nil {
		t.Fatal(err)
	}
	if !r.Forward(opening) {
		t.Fatal("retransmitted SYN refused")
	}
	newConnection := bytes.Clone(opening)
	p, _ := parse(newConnection, false)
	binary.BigEndian.PutUint32(newConnection[p.transport+4:], 123)
	p.fixTransportChecksum()
	if !r.Forward(newConnection) {
		t.Fatal("new connection refused")
	}
	if strings.Join(through, ",") != "a,a,b" {
		t.Fatal("TCP policy decisions", through)
	}
	reset := bytes.Clone(newConnection)
	p, _ = parse(reset, false)
	reset[p.transport+13] = 4
	p.fixTransportChecksum()
	if !r.Forward(reset) {
		t.Fatal("reset refused")
	}
	now = now.Add(3 * time.Minute)
	r.mu.Lock()
	r.expire()
	r.mu.Unlock()
	if r.Status().Flows != 0 {
		t.Fatal("closed flow retained")
	}
}
