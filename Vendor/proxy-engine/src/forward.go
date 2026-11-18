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
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// copyBufSize is the per-direction copy buffer. 32 KiB is io.Copy's own default
// and a good balance for a proxied stream.
const copyBufSize = 32 * 1024

// Count each completed write so live throughput includes long-lived flows.
func copyCounted(dst io.Writer, src io.Reader, counter *atomic.Int64) error {
	buf := make([]byte, copyBufSize)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			w, writeErr := dst.Write(buf[:n])
			counter.Add(int64(w))
			if writeErr != nil {
				return writeErr
			}
			if w != n {
				return io.ErrShortWrite
			}
		}
		if err != nil {
			return err
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

	// Dial the upstream FIRST, before accepting the guest endpoint. If the dial
	// fails we reset the guest connection (sendReset=true) so the app sees a
	// refused connection immediately rather than a black hole. This is also what
	// makes "the SSH session is down" a fast failure rather than a queue: the
	// extension dialler refuses (-3) and the guest gets its RST here.
	ctx, cancel := context.WithTimeout(st.ctx, dialTimeout)
	proxyConn, err := st.flowDial.dial(ctx, st.dialer, targetHost, targetPort)
	cancel()
	if err != nil {
		st.failedFlows.Add(1)
		st.setLastError("tcp %s:%d upstream failed: %v", targetHost, targetPort, err)
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
	st.startRelay(guestConn, proxyConn)
}
