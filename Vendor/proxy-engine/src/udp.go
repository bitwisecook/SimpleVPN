// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// udp.go — the UDP flow handler and its two upstream strategies.
//
// UDP over a proxy is fundamentally limited by what the proxy grants:
//
//   SOCKS5 with UDP ASSOCIATE — real UDP. We open a control connection, ask for
//     an association, and relay the guest's datagrams to the granted relay,
//     wrapping each in the RFC 1928 UDP request header. If the proxy refuses
//     UDP ASSOCIATE we fail this flow gracefully (drop) — except DNS, which
//     falls back to DNS-over-TCP so name resolution keeps working.
//
//   HTTP(S) CONNECT — TCP only. All UDP is dropped EXCEPT DNS (port 53), which
//     is carried as DNS-over-TCP to the query's own resolver (see dns.go).
//
// v1 keeps this simple: one datagram in, one datagram out, torn down on idle.

package pxengine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// udpIdleTimeout tears down a UDP flow after this long with no traffic. UDP
	// has no close, so an idle timer is the only way to reclaim the flow.
	udpIdleTimeout = 60 * time.Second
	// dnsPort is the one UDP port a CONNECT proxy will still carry (as TCP).
	dnsPort = 53
)

// handleUDP is the udp.Forwarder handler. Like TCP, ID().LocalAddress:LocalPort
// is the destination the guest addressed.
func (st *engineState) handleUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	dstHost := addrFromTCPIP(id.LocalAddress)
	dstPort := int(id.LocalPort)

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		st.setLastError("udp accept %s:%d failed: %s", dstHost, dstPort, tcpErr)
		return true
	}
	guest := gonet.NewUDPConn(&wq, ep)
	st.udpFlows.Add(1)
	st.activeFlows.Add(1)
	go st.serveUDP(guest, dstHost, dstPort)
	return true
}

// serveUDP routes one UDP flow to whichever strategy the proxy supports.
func (st *engineState) serveUDP(guest *gonet.UDPConn, dstHost string, dstPort int) {
	defer st.activeFlows.Add(-1)
	defer guest.Close()

	// st.up is NIL when the flows are dialled by the extension (an SSH session):
	// there is no SOCKS proxy in this process to ask for a UDP association, and
	// SSH has no UDP channel type at all. Without this guard that read is a nil
	// dereference on the first UDP packet of every SSH tunnel.
	if st.up != nil && st.up.kind == proxySOCKS5 {
		if err := st.serveUDPviaSOCKS(guest, dstHost, dstPort); err != nil {
			// SOCKS UDP unavailable: DNS still deserves to work.
			if dstPort == dnsPort {
				st.serveDNSoverTCP(guest, dstHost, dstPort)
				return
			}
			st.udpRefused.Add(1)
			st.setLastError("udp %s:%d dropped: %v", dstHost, dstPort, err)
		}
		return
	}
	// TCP-only upstream (a CONNECT proxy, or an SSH session): DNS only.
	if dstPort == dnsPort {
		st.serveDNSoverTCP(guest, dstHost, dstPort)
		return
	}
	// Refused, not black-holed, and COUNTED — see statusPayload.UDPRefused. This
	// is where QUIC (UDP/443) lands: an app that can fall back to TCP does so
	// after its own timeout, and one that cannot simply does not work through
	// this tunnel. The count is what makes that visible.
	st.udpRefused.Add(1)
	st.setLastError("udp %s:%d refused: this tunnel carries only TCP (and DNS)", dstHost, dstPort)
}

// serveDNSoverTCP answers the guest's DNS queries by tunnelling each as
// DNS-over-TCP to the resolver the guest addressed. One flow may carry several
// queries (a stub resolver reusing the socket), so it loops until idle.
func (st *engineState) serveDNSoverTCP(guest *gonet.UDPConn, resolverHost string, resolverPort int) {
	// ONE substitution, at the head: a query addressed to the configured sentinel
	// is re-aimed at the resolver that sentinel stands for, resolved at the far
	// end of the session. Everything below is unchanged by it.
	resolverHost, resolverPort = st.resolveDNSTarget(resolverHost, resolverPort)
	buf := make([]byte, maxDNSMessage)
	for {
		_ = guest.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, err := guest.Read(buf)
		if err != nil {
			return
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		st.dnsQueries.Add(1)
		st.bytesUp.Add(int64(n))

		ctx, cancel := context.WithTimeout(st.ctx, dialTimeout)
		resp, derr := dnsOverTCP(ctx, st.up, st.dialer, resolverHost, resolverPort, query)
		cancel()
		if derr != nil {
			st.setLastError("dns %s failed: %v", resolverAddress(resolverHost, resolverPort), derr)
			continue
		}
		if _, werr := guest.Write(resp); werr != nil {
			return
		}
		st.bytesDown.Add(int64(len(resp)))
	}
}

// ---- SOCKS5 UDP ASSOCIATE ---------------------------------------------------

// serveUDPviaSOCKS sets up an association and relays the flow. It returns an
// error (without having relayed anything) when the proxy will not grant UDP, so
// the caller can fall back for DNS. Once relaying begins it runs until idle.
func (st *engineState) serveUDPviaSOCKS(guest *gonet.UDPConn, dstHost string, dstPort int) error {
	// Control connection: negotiate, then UDP ASSOCIATE. It must stay open for
	// the lifetime of the association (the proxy tears the relay down when it
	// closes).
	ctx, cancel := context.WithTimeout(st.ctx, dialTimeout)
	ctrl, err := st.up.dialProxyConn(ctx, st.dialer)
	cancel()
	if err != nil {
		return err
	}
	closeCtrl := func() { ctrl.Close() }

	_ = ctrl.SetDeadline(time.Now().Add(dialTimeout))
	if err := socks5Negotiate(ctrl, st.up.username, st.up.password); err != nil {
		closeCtrl()
		return err
	}
	// DST in a UDP ASSOCIATE is the address the CLIENT will send from; 0.0.0.0:0
	// means "I don't know yet", which every compliant proxy accepts.
	req, err := socksRequest(socksCmdUDPAssoc, "0.0.0.0", 0)
	if err != nil {
		closeCtrl()
		return err
	}
	if _, err := ctrl.Write(req); err != nil {
		closeCtrl()
		return err
	}
	relayIP, relayPort, err := readSocksReply(ctrl)
	if err != nil {
		closeCtrl()
		return err // e.g. "command not supported" ⇒ caller falls back for DNS
	}
	_ = ctrl.SetDeadline(time.Time{})

	// A 0.0.0.0 (or absent) relay address means "use the proxy's own address".
	relayHost := ""
	if relayIP != nil && !relayIP.IsUnspecified() {
		relayHost = relayIP.String()
	}
	if relayHost == "" {
		h, _, _ := net.SplitHostPort(st.up.address)
		relayHost = h
	}
	relayAddr := net.JoinHostPort(relayHost, fmt.Sprintf("%d", relayPort))

	// The relay socket is a real OS UDP socket to the proxy's relay endpoint.
	relayConn, err := st.dialer.DialContext(st.ctx, "udp", relayAddr)
	if err != nil {
		closeCtrl()
		return fmt.Errorf("cannot reach SOCKS UDP relay %s: %w", relayAddr, err)
	}

	// From here the flow is live; tear down control + relay together on exit.
	done := make(chan struct{})
	var once bool
	closeAll := func() {
		if once {
			return
		}
		once = true
		close(done)
		relayConn.Close()
		closeCtrl()
	}
	defer closeAll()

	// The control connection carries no data, but if the proxy closes it the
	// association is dead — watch for that and tear down.
	go func() {
		var b [1]byte
		_ = ctrl.SetReadDeadline(time.Time{})
		_, _ = ctrl.Read(b[:]) // blocks until EOF/error
		closeAll()
	}()

	// relay -> guest: strip the SOCKS UDP header, deliver the payload.
	go func() {
		buf := make([]byte, maxPacketSize)
		for {
			_ = relayConn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			n, rerr := relayConn.Read(buf)
			if rerr != nil {
				closeAll()
				return
			}
			payload, derr := socksUDPDecap(buf[:n])
			if derr != nil {
				continue
			}
			if _, werr := guest.Write(payload); werr != nil {
				closeAll()
				return
			}
			st.bytesDown.Add(int64(len(payload)))
		}
	}()

	// guest -> relay: wrap each datagram in the SOCKS UDP request header aimed
	// at the original destination.
	buf := make([]byte, maxPacketSize)
	for {
		_ = guest.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, rerr := guest.Read(buf)
		if rerr != nil {
			return nil
		}
		encap, eerr := socksUDPEncap(dstHost, dstPort, buf[:n])
		if eerr != nil {
			continue
		}
		if _, werr := relayConn.Write(encap); werr != nil {
			return nil
		}
		st.bytesUp.Add(int64(n))
		select {
		case <-done:
			return nil
		default:
		}
	}
}

// socksUDPEncap builds a SOCKS5 UDP request datagram: RSV(2) FRAG(1)=0 ATYP
// DST.ADDR DST.PORT DATA.
func socksUDPEncap(host string, port int, data []byte) ([]byte, error) {
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("socks udp: port %d out of range", port)
	}
	out := []byte{0x00, 0x00, 0x00} // RSV RSV FRAG
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, socksAtypIPv4)
			out = append(out, v4...)
		} else {
			out = append(out, socksAtypIPv6)
			out = append(out, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("socks udp: hostname exceeds 255 bytes")
		}
		out = append(out, socksAtypDomain, byte(len(host)))
		out = append(out, host...)
	}
	out = append(out, byte(port>>8), byte(port&0xFF))
	out = append(out, data...)
	return out, nil
}

// socksUDPDecap strips the SOCKS5 UDP header and returns the payload. FRAG != 0
// (fragmented datagrams) is rejected — we do not reassemble, per RFC 1928's
// permission to drop fragments.
func socksUDPDecap(pkt []byte) ([]byte, error) {
	if len(pkt) < 4 {
		return nil, errors.New("socks udp: short datagram")
	}
	if pkt[2] != 0x00 {
		return nil, errors.New("socks udp: fragmented datagram dropped")
	}
	off := 4
	switch pkt[3] {
	case socksAtypIPv4:
		off += 4
	case socksAtypIPv6:
		off += 16
	case socksAtypDomain:
		if len(pkt) < 5 {
			return nil, errors.New("socks udp: short domain")
		}
		off += 1 + int(pkt[4])
	default:
		return nil, fmt.Errorf("socks udp: unknown address type 0x%02x", pkt[3])
	}
	off += 2 // port
	if off > len(pkt) {
		return nil, errors.New("socks udp: header longer than datagram")
	}
	return pkt[off:], nil
}

// io is imported for its error sentinels used across the UDP path.
var _ = io.EOF
