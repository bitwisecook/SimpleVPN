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
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks/socks5"
	"net"
	"sync"
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
	if st.tlsRoutes[dstPort] != nil {
		st.udpRefused.Add(1)
		return true
	}

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
			if st.ctx.Err() != nil {
				return
			}
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
		query := buf[:n]
		st.dnsQueries.Add(1)
		st.bytesUp.Add(int64(n))

		ctx, cancel := context.WithTimeout(st.ctx, dialTimeout)
		resp, derr := dnsOverTCP(ctx, st.flowDial, st.dialer, resolverHost, resolverPort, query)
		cancel()
		if derr != nil {
			if st.ctx.Err() != nil {
				return
			}
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
func (st *engineState) serveUDPviaSOCKS(guest net.Conn, dstHost string, dstPort int) error {
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
	stopHandshake := context.AfterFunc(st.ctx, closeCtrl)
	defer stopHandshake()

	_ = ctrl.SetDeadline(time.Now().Add(dialTimeout))
	relay, err := st.up.socksHandshake(ctrl, socks5.CommandUDPAssociate, "0.0.0.0", 0)
	if err != nil {
		closeCtrl()
		return err
	}
	_ = ctrl.SetDeadline(time.Time{})
	if !relay.IsValid() || relay.Port == 0 {
		closeCtrl()
		return errors.New("SOCKS proxy returned an invalid relay endpoint")
	}
	if relay.Addr.IsUnspecified() {
		// Use the connected peer: a second resolution can pick another server.
		peer, ok := ctrl.RemoteAddr().(*net.TCPAddr)
		if !ok {
			closeCtrl()
			return errors.New("SOCKS proxy peer is unavailable")
		}
		relay.Addr = peer.AddrPort().Addr().Unmap()
	}
	relayAddr := relay.String()
	header, err := socksUDPHeader(dstHost, dstPort)
	if err != nil {
		closeCtrl()
		return err
	}

	// The relay socket is a real OS UDP socket to the proxy's relay endpoint.
	relayConn, err := st.dialer.DialContext(st.ctx, "udp", relayAddr)
	if err != nil {
		closeCtrl()
		return fmt.Errorf("cannot reach SOCKS UDP relay %s: %w", relayAddr, err)
	}

	// From here the flow is live; tear down control + relay together on exit.
	done := make(chan struct{})
	closeAll := sync.OnceFunc(func() {
		close(done)
		relayConn.Close()
		closeCtrl()
		guest.Close()
	})
	stopHandshake()
	stopCancel := context.AfterFunc(st.ctx, closeAll)
	defer stopCancel()
	var workers sync.WaitGroup
	workers.Add(2)
	defer workers.Wait()
	defer closeAll()

	// The control connection carries no data, but if the proxy closes it the
	// association is dead — watch for that and tear down.
	go func() {
		defer workers.Done()
		var b [1]byte
		_ = ctrl.SetReadDeadline(time.Time{})
		_, _ = ctrl.Read(b[:]) // blocks until EOF/error
		closeAll()
	}()

	// relay -> guest: strip the SOCKS UDP header, deliver the payload.
	go func() {
		defer workers.Done()
		buf := make([]byte, maxPacketSize)
		for {
			_ = relayConn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			n, rerr := relayConn.Read(buf)
			if rerr != nil {
				closeAll()
				return
			}
			payload, matches := bytes.CutPrefix(buf[:n], header)
			if !matches {
				st.udpRelayRejected.Add(1)
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
	buf := make([]byte, len(header)+maxPacketSize)
	copy(buf, header)
	for {
		_ = guest.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, rerr := guest.Read(buf[len(header):])
		if rerr != nil {
			return nil
		}
		if _, werr := relayConn.Write(buf[:len(header)+n]); werr != nil {
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

// One association belongs to one connected guest flow. Reuse its wire header
// in both directions to enforce the peer IP and port and reject fragments.
func socksUDPHeader(host string, port int) ([]byte, error) {
	if len(host) == 0 || len(host) > 255 || port < 1 || port > 65535 {
		return nil, errors.New("invalid SOCKS UDP destination")
	}
	destination := metadata.ParseSocksaddrHostPort(host, uint16(port))
	var header bytes.Buffer
	header.Grow(3 + metadata.SocksaddrSerializer.AddrPortLen(destination))
	header.Write([]byte{0, 0, 0})
	err := metadata.SocksaddrSerializer.WriteAddrPort(&header, destination)
	return header.Bytes(), err
}
