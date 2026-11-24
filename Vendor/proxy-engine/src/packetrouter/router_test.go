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
	return sizedDatagram(src, dst, sourcePort, protocol, []byte("hello"))
}

func sizedDatagram(src, dst string, sourcePort uint16, protocol byte, payload []byte) []byte {
	source, target := netip.MustParseAddr(src), netip.MustParseAddr(dst)
	headerLength, transportLength := 20, 8
	if source.Is6() {
		headerLength = 40
	}
	if protocol == 6 {
		transportLength = 20
	}
	data := make([]byte, headerLength+transportLength+len(payload))
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
	copy(l4[transportLength:], payload)
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
					Send: func(p []byte) bool { outbound = p; return true }}
				r, err := New([]netip.Addr{netip.MustParseAddr(addresses[0])}, []Port{port}, Policy{Revision: 1, Default: "vpn"}, func(p []byte) { inbound = p })
				if err != nil {
					t.Fatal(err)
				}
				original := testDatagram(addresses[0], addresses[2], 40000, proto)
				if !r.Forward(original) {
					t.Fatalf("forward refused: %v", r.Status())
				}
				// The capture buffer can be recycled immediately after Forward.
				clear(original)
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
				clear(reply)
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

// Reapplying a plan after member loss must retain its more-specific decision
// for both new flows and the flows pinned to it before it stopped.
func TestStoppedMemberClaimsSurviveReapply(t *testing.T) {
	for _, family := range []struct {
		capture, assigned, private, other, claim, all string
	}{
		{"198.19.255.1", "10.0.0.2", "10.2.0.8", "192.0.2.8", "10.2.0.0/16", "0.0.0.0/0"},
		{"fd6e:7853:ffff::1", "fd01::2", "fd02::8", "2001:db8::8", "fd02::/64", "::/0"},
	} {
		t.Run(family.claim, func(t *testing.T) {
			privatePrefix := netip.MustParsePrefix(family.claim)
			fullPrefix := netip.MustParsePrefix(family.all)
			addresses := []netip.Addr{netip.MustParseAddr(family.assigned)}
			var privateSends, otherSends int
			ports := []Port{
				{ID: "private", Generation: 7, Addresses: addresses, MTU: 1280,
					Allowed: []netip.Prefix{privatePrefix}, Send: func([]byte) bool { privateSends++; return true }},
				{ID: "full", Generation: 11, Addresses: addresses, MTU: 1280,
					Allowed: []netip.Prefix{fullPrefix}, Send: func([]byte) bool { otherSends++; return true }},
			}
			// The second VPN also claims the same subnet at lower precedence.
			policy := Policy{Revision: 1, Default: "full", Rules: []Rule{{privatePrefix, "private"}, {privatePrefix, "full"}}}
			r, err := New([]netip.Addr{netip.MustParseAddr(family.capture)}, ports, policy, func([]byte) {})
			if err != nil {
				t.Fatal(err)
			}
			pinned := testDatagram(family.capture, family.private, 40000, 17)
			if !r.Forward(pinned) || privateSends != 1 {
				t.Fatal("initial member selection", r.Status())
			}
			r.RemovePort("private")
			policy.Revision++
			if err := r.Check(policy); err != nil {
				t.Fatal(err)
			}
			if err := r.Apply(policy); err != nil {
				t.Fatal(err)
			}
			if r.Forward(pinned) || r.Forward(testDatagram(family.capture, family.private, 40001, 17)) {
				t.Fatal("stopped member's destination leaked to surviving VPN")
			}
			if !r.Forward(testDatagram(family.capture, family.other, 40001, 17)) || privateSends != 1 || otherSends != 1 {
				t.Fatal("unrelated default traffic affected", r.Status())
			}
			if r.Return("private", 7, pinned) || r.Status().Drops["stale VPN packet"] == 0 {
				t.Fatal("detached port still accepts callbacks")
			}
			if err := r.Check(Policy{Revision: 3, Rules: []Rule{{fullPrefix, "private"}}}); err == nil {
				t.Fatal("stopped member gained authority outside its original prefixes")
			}
		})
	}
}

func TestHalfDefaultsAreAuthorizedOnlyAsCompleteCoverage(t *testing.T) {
	all := netip.MustParsePrefix("0.0.0.0/0")
	allowed := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
	if !covers(all, allowed) || covers(all, allowed[:1]) {
		t.Fatal("incorrect paired default coverage")
	}
}

func TestReplacementMustCoverCurrentClaims(t *testing.T) {
	capture := netip.MustParseAddr("198.19.255.1")
	claim := netip.MustParsePrefix("10.2.0.0/16")
	port := Port{ID: "office", Generation: 1, MTU: 1280,
		Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.2")}, Allowed: []netip.Prefix{claim},
		Send: func([]byte) bool { return true }}
	rules := []Rule{{claim, port.ID}}
	r, err := New([]netip.Addr{capture}, []Port{port}, Policy{Revision: 1, Rules: rules}, func([]byte) {})
	if err != nil {
		t.Fatal(err)
	}
	rules[0].Prefix = netip.MustParsePrefix("10.2.0.0/24")
	r.RemovePort(port.ID)
	port.Generation++
	port.Allowed = []netip.Prefix{rules[0].Prefix}
	if err := r.ReplacePort(1, port); err == nil {
		t.Fatal("replacement inherited a wider active route")
	}
	if err := r.Apply(Policy{Revision: 2, Rules: rules}); err != nil {
		t.Fatal(err)
	}
	if err := r.ReplacePort(1, port); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultLossBetweenPolicyCheckAndCommitRetainsCapture(t *testing.T) {
	capture := netip.MustParseAddr("198.19.255.1")
	port := Port{ID: "office", Generation: 1, MTU: 1280,
		Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.2")}, Allowed: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		Send: func([]byte) bool { return true }}
	r, err := New([]netip.Addr{capture}, []Port{port}, Policy{Revision: 1}, func([]byte) {})
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{Revision: 2, Default: port.ID}
	if err := r.Check(policy); err != nil {
		t.Fatal(err)
	}
	r.RemovePort(port.ID)
	if err := r.Apply(policy); err != nil {
		t.Fatal(err)
	}
	if r.Forward(testDatagram(capture.String(), "192.0.2.20", 40000, 17)) || r.Status().Drops["selected VPN unavailable"] != 1 {
		t.Fatal("traffic did not retain the unavailable disposition", r.Status())
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
	r.expire(r.now())
	r.mu.Unlock()
	if r.Status().Flows != 0 {
		t.Fatal("closed flow retained")
	}
}

// Exercise complete steady-state routing in both directions, including source
// translation, checksum validation, flow pinning, and generation-scoped return.
func TestRejectedSubmissionCannotCreateReturnState(t *testing.T) {
	const capture, vip, peer = "198.19.255.1", "10.0.0.2", "10.0.0.3"
	port := Port{ID: "vpn", Generation: 1, Addresses: []netip.Addr{netip.MustParseAddr(vip)},
		Allowed: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, MTU: 1280, Send: func([]byte) bool { return false }}
	r, err := New([]netip.Addr{netip.MustParseAddr(capture)}, []Port{port}, Policy{Revision: 1, Default: "vpn"}, func([]byte) { t.Error("delivered unsolicited reply") })
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Forward(testDatagram(capture, peer, 443, 17)) || r.Status().Flows != 0 {
		t.Fatal("rejected submission created a flow")
	}
	if r.Return("vpn", 1, testDatagram(peer, vip, 443, 17)) {
		t.Fatal("accepted reply without an admitted send")
	}
}

func BenchmarkRouteQUICRoundTrip(b *testing.B) {
	for _, addresses := range [][3]string{
		{"198.19.255.1", "10.0.0.2", "10.0.0.3"},
		{"fd6e:7853:ffff::1", "fd42::2", "fd42::3"},
	} {
		b.Run(addresses[0], func(b *testing.B) {
			payload := make([]byte, 1200)
			for i := range payload {
				payload[i] = byte(i)
			}
			port := Port{ID: "work", Generation: 7, Addresses: []netip.Addr{netip.MustParseAddr(addresses[1])},
				Allowed: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
				MTU:     1280, Send: func([]byte) bool { return true }}
			router, err := New([]netip.Addr{netip.MustParseAddr(addresses[0])}, []Port{port},
				Policy{Revision: 1, Default: port.ID}, func([]byte) {})
			if err != nil {
				b.Fatal(err)
			}
			out := sizedDatagram(addresses[0], addresses[2], 40000, 17, payload)
			reply := sizedDatagram(addresses[2], addresses[1], 443, 17, payload)
			q, err := parse(reply, false)
			if err != nil {
				b.Fatal(err)
			}
			binary.BigEndian.PutUint16(reply[q.transport+2:], 40000)
			q.fixTransportChecksum()
			b.SetBytes(int64(len(out) + len(reply)))
			b.ReportAllocs()
			for b.Loop() {
				if !router.Forward(out) || !router.Return(port.ID, port.Generation, reply) {
					b.Fatal(router.Status())
				}
			}
		})
	}
}

func TestAllowedHostIndexPreservesMixedFamilyBoundaries(t *testing.T) {
	allowed := []netip.Prefix{
		netip.MustParsePrefix("10.3.0.0/25"), netip.MustParsePrefix("10.3.0.128/25"),
		netip.MustParsePrefix("fd02:1234::/48"), netip.MustParsePrefix("fd03::7/128"),
	}
	// Exercise the direct small-list check and the large-list index.
	for _, count := range []int{4, 32} {
		for len(allowed) < count {
			addr := netip.AddrFrom4([4]byte{192, 0, 2, byte(len(allowed))})
			allowed = append(allowed, netip.PrefixFrom(addr, 32))
		}
		port := clonePort(Port{Allowed: allowed})
		for _, tc := range []struct {
			address string
			want    bool
		}{
			{"10.2.255.255", false}, {"10.3.0.0", true}, {"10.3.0.127", true},
			{"10.3.0.128", true}, {"10.3.0.255", true}, {"10.3.1.0", false},
			{"fd02:1234:0:ffff::", true}, {"fd02:1234:1::", false}, {"fd03::7", true},
			{"fd03::8", false}, {"::ffff:10.3.0.10", false},
		} {
			addr := netip.MustParseAddr(tc.address)
			if got := port.allowsHost(addr); got != tc.want {
				t.Errorf("allowed count %d, address %s: got %t, want %t", count, addr, got, tc.want)
			}
		}
	}
}

// Admit new TCP SYNs distributed across 4096 routed hosts. The decision index
// and traffic are identical; only the WireGuard port's allowed IPs differ.
func BenchmarkNewTCPFlowAllowedIPs(b *testing.B) {
	const hosts = 4096
	capture := netip.MustParseAddr("198.19.255.1")
	rules := make([]Rule, hosts)
	allowedHosts := make([]netip.Prefix, hosts)
	packets := make([][]byte, hosts)
	for i := range packets {
		address := netip.AddrFrom4([4]byte{10, 4, byte(i >> 8), byte(i)})
		allowedHosts[i] = netip.PrefixFrom(address, 32)
		rules[i] = Rule{Prefix: allowedHosts[i], Port: "work"}
		packets[i] = sizedDatagram(capture.String(), address.String(), uint16(40000+i), 6, nil)
	}
	for _, tc := range []struct {
		name    string
		allowed []netip.Prefix
	}{
		{"one_subnet", []netip.Prefix{netip.MustParsePrefix("10.4.0.0/16")}},
		{"4096_hosts", allowedHosts},
	} {
		b.Run(tc.name, func(b *testing.B) {
			port := Port{ID: "work", Generation: 1, MTU: 1280, Addresses: []netip.Addr{netip.MustParseAddr("10.90.0.1")}, Allowed: tc.allowed, Send: func([]byte) bool { return true }}
			r, err := New([]netip.Addr{capture}, []Port{port}, Policy{Revision: 1, Rules: rules}, func([]byte) {})
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			index := 0
			for b.Loop() {
				if !r.Forward(packets[index]) {
					b.Fatal(r.Status())
				}
				index = (index + 257) % hosts
				if index == 0 {
					clear(r.flows)
					clear(r.reverse)
				}
			}
		})
	}
}
