// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// sshflow_test.go — the two behaviours an SSH-backed tunnel changes about the
// UDP and DNS paths, driven through the REAL netstack rather than around it.
//
// The UDP test injects an actual IPv4/UDP packet: the point is not only that the
// flow is refused and counted, but that `st.up` being nil for this upstream does
// not nil-dereference on the first UDP packet of every SSH tunnel. A hand-rolled
// unit test of the decision would have missed exactly that.

package pxengine

import (
	"net"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// udpPacketV4 builds a complete, checksummed IPv4/UDP datagram — what the host
// stack would hand the utun.
func udpPacketV4(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) []byte {
	const ipHdrLen = header.IPv4MinimumSize
	udpLen := header.UDPMinimumSize + len(payload)
	buf := make([]byte, ipHdrLen+udpLen)

	src := tcpip.AddrFromSlice(net.ParseIP(srcIP).To4())
	dst := tcpip.AddrFromSlice(net.ParseIP(dstIP).To4())

	udp := header.UDP(buf[ipHdrLen:])
	udp.Encode(&header.UDPFields{
		SrcPort: srcPort, DstPort: dstPort, Length: uint16(udpLen),
	})
	copy(buf[ipHdrLen+header.UDPMinimumSize:], payload)
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, src, dst, uint16(udpLen))
	xsum = checksum.Checksum(payload, xsum)
	udp.SetChecksum(^udp.CalculateChecksum(xsum))

	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(buf)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	return buf
}

func TestServeUDPRefusesNonDNSWithoutSOCKS(t *testing.T) {
	// An extension-dialled (ssh://) upstream: st.up is NIL. SSH has no UDP
	// channel type, so every non-DNS UDP flow must be refused — counted, not
	// black-holed — and the nil upstream must not be dereferenced getting there.
	up, err := parseUpstream("ssh://alice@gateway.example", "", "")
	if err != nil {
		t.Fatal(err)
	}
	st, err := buildEngine(up, 1500)
	if err != nil {
		t.Fatalf("buildEngine: %v", err)
	}
	defer func() { st.cancel(); st.ep.Close(); st.stack.Close(); st.stack.Wait() }()
	if st.up != nil {
		t.Fatal("precondition: st.up must be nil for this upstream")
	}

	// UDP/443 — QUIC, the flow this tunnel genuinely cannot carry.
	pkt := udpPacketV4("198.18.0.9", "203.0.113.7", 51234, 443, []byte("quic-ish"))
	injectIPv4(t, st, pkt)

	deadline := time.Now().Add(3 * time.Second)
	for st.udpRefused.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := st.udpRefused.Load(); got != 1 {
		t.Fatalf("udpRefused = %d, want 1 (a refused UDP flow must be counted, not only logged)", got)
	}
	// lastError must name the cause; it is what the connection panel shows.
	st.lastErrMu.Lock()
	msg := st.lastErr
	st.lastErrMu.Unlock()
	if !contains(msg, "only TCP") {
		t.Errorf("lastError should explain the refusal, got %q", msg)
	}
	// And the flow must not be left counted as active.
	deadline = time.Now().Add(3 * time.Second)
	for st.activeFlows.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := st.activeFlows.Load(); got != 0 {
		t.Errorf("activeFlows = %d after a refused flow, want 0", got)
	}
}

// injectIPv4 pushes a raw IPv4 packet in the way PXPacketIn does, without cgo.
func injectIPv4(t *testing.T, st *engineState, raw []byte) {
	t.Helper()
	if raw[0]>>4 != 4 {
		t.Fatal("test packet is not IPv4")
	}
	pkt := newInboundPacket(raw)
	st.ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
	pkt.DecRef()
}

func TestDNSSentinelRewrite(t *testing.T) {
	st := &engineState{}

	// No sentinel configured: everything passes through untouched. This is the
	// proxy-tunnel behaviour and must not change.
	if h, p := st.resolveDNSTarget("8.8.8.8", 53); h != "8.8.8.8" || p != 53 {
		t.Fatalf("no sentinel: got %s:%d", h, p)
	}

	st.dnsSentinel = "198.18.0.53"
	st.dnsUpstream = "127.0.0.1:53"

	// The sentinel is re-aimed — this is the "resolve at the far end" case that
	// no SOCKS request can express.
	if h, p := st.resolveDNSTarget("198.18.0.53", 53); h != "127.0.0.1" || p != 53 {
		t.Fatalf("sentinel: got %s:%d, want 127.0.0.1:53", h, p)
	}
	// A non-sentinel resolver is still honoured verbatim: a user who lists a real
	// resolver as well must reach THAT one.
	if h, p := st.resolveDNSTarget("10.0.0.53", 53); h != "10.0.0.53" || p != 53 {
		t.Fatalf("non-sentinel: got %s:%d", h, p)
	}
	// A non-53 port to the sentinel is still re-aimed (a stub resolver may use a
	// different port), but the UPSTREAM's port wins — that is the address that
	// actually has a resolver on it.
	if h, p := st.resolveDNSTarget("198.18.0.53", 5353); h != "127.0.0.1" || p != 53 {
		t.Fatalf("sentinel alt port: got %s:%d", h, p)
	}

	// A bare host upstream (no port) keeps the guest's port rather than guessing.
	st.dnsUpstream = "resolver.internal"
	if h, p := st.resolveDNSTarget("198.18.0.53", 53); h != "resolver.internal" || p != 53 {
		t.Fatalf("bare-host upstream: got %s:%d", h, p)
	}

	// A nonsense port is ignored rather than sending the query to port 0.
	st.dnsUpstream = "127.0.0.1:0"
	if h, p := st.resolveDNSTarget("198.18.0.53", 53); h != "127.0.0.1" || p != 53 {
		t.Fatalf("bad upstream port: got %s:%d, want the guest's port kept", h, p)
	}

	// IPv6 upstreams round-trip through SplitHostPort's bracket form.
	st.dnsSentinel = "fd6e:7853::53"
	st.dnsUpstream = "[::1]:53"
	if h, p := st.resolveDNSTarget("fd6e:7853::53", 53); h != "::1" || p != 53 {
		t.Fatalf("ipv6 sentinel: got %s:%d, want ::1:53", h, p)
	}
}

func TestStartConfigCarriesTheDNSSentinel(t *testing.T) {
	// The exact JSON SSHNetworkTunnelStartConfig emits for a far-side resolver.
	const in = `{"dnsSentinel":"198.18.0.53","dnsUpstream":"127.0.0.1:53",` +
		`"mtu":1500,"password":"","upstream":"ssh://alice@gw.example:22","username":"alice"}`
	cfg, err := decodeStartConfig(in)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.DNSSentinel != "198.18.0.53" || cfg.DNSUpstream != "127.0.0.1:53" {
		t.Fatalf("sentinel fields did not decode: %+v", cfg)
	}
	if cfg.Upstream != "ssh://alice@gw.example:22" || cfg.Username != "alice" || cfg.MTU != 1500 {
		t.Fatalf("field mismatch: %+v", cfg)
	}
}

func TestStatusReportsUDPRefused(t *testing.T) {
	// The counter must be in the payload under the exact key Swift decodes.
	b := marshalStatus(statusPayload{State: "running", Scheme: "ssh", UDPRefused: 7})
	if !contains(b, `"udpRefused":7`) {
		t.Fatalf("status must carry udpRefused: %s", b)
	}
	// …and still leak nothing about the session.
	for _, leak := range []string{"gateway", "alice", "hunter2"} {
		if contains(b, leak) {
			t.Fatalf("status leaked %q: %s", leak, b)
		}
	}
}
