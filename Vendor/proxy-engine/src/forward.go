// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// forward.go — the TCP flow handler. gVisor's TCP forwarder calls handleTCP
// once per inbound guest connection; we accept it, dial the original
// destination through the upstream proxy, and splice the two together.

package pxengine

import (
	"context"
	"io"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// copyBufSize is the per-direction copy buffer. 32 KiB is io.Copy's own default
// and a good balance for a proxied stream.
const copyBufSize = 32 * 1024

// copyCounted copies src->dst and returns the byte count. A dedicated helper
// (rather than io.Copy) so the byte total feeds the status counters directly.
func copyCounted(dst io.Writer, src io.Reader) int64 {
	buf := make([]byte, copyBufSize)
	var total int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			w, werr := dst.Write(buf[:n])
			total += int64(w)
			if werr != nil {
				return total
			}
		}
		if err != nil {
			return total
		}
	}
}

// handleTCP is the tcp.Forwarder handler. The forwarder has already matched an
// inbound SYN; ID().LocalAddress:LocalPort is the address the guest dialled
// (the original destination), which is exactly what we dial through the proxy.
func (st *engineState) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	targetHost := addrFromTCPIP(id.LocalAddress)
	targetPort := int(id.LocalPort)

	st.totalFlows.Add(1)

	// Dial the proxy FIRST, before accepting the guest endpoint. If the proxy
	// dial fails we reset the guest connection (sendReset=true) so the app sees
	// a refused connection immediately rather than a black hole.
	ctx, cancel := context.WithTimeout(st.ctx, dialTimeout)
	proxyConn, err := st.up.dialThrough(ctx, st.dialer, targetHost, targetPort)
	cancel()
	if err != nil {
		st.failedFlows.Add(1)
		st.setLastError("tcp %s:%d via proxy failed: %v", targetHost, targetPort, err)
		r.Complete(true) // send RST
		return
	}

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		st.failedFlows.Add(1)
		st.setLastError("tcp accept %s:%d failed: %s", targetHost, targetPort, tcpErr)
		proxyConn.Close()
		r.Complete(true)
		return
	}
	// Endpoint created: the handshake completes. Do NOT sendReset now.
	r.Complete(false)

	guestConn := gonet.NewTCPConn(&wq, ep)
	st.activeFlows.Add(1)
	go st.pipe(guestConn, proxyConn)
}

// dialTargetThroughProxy is used by the UDP/DNS path too: a plain net.Conn to
// targetHost:targetPort tunnelled through the configured proxy.
func (st *engineState) dialTargetThroughProxy(ctx context.Context, host string, port int) (net.Conn, error) {
	return st.up.dialThrough(ctx, st.dialer, host, port)
}
