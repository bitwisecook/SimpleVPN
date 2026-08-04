// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// flowdial.go — the "someone else dials this flow" upstream.
//
// The proxy-tunnel engine normally dials each flow itself (proxy.go: SOCKS5 or
// HTTP CONNECT over a real OS socket). SimpleVPN's SSH Network Tunnel kind needs
// the opposite arrangement: the transport is an SSH session that lives on the
// SWIFT side (libssh, in the packet-tunnel extension), so the netstack must ask
// Swift to open each flow and then treat the result as an ordinary net.Conn.
//
// THE HANDOFF IS A FILE DESCRIPTOR, not a byte-pump callback family. Swift makes
// a socketpair, keeps one end and pumps it against an SSH `direct-tcpip`
// channel, and returns the OTHER end's fd across the C boundary. That is the
// same shape the OpenVPN 3 and OpenConnect bridges already use for their tun
// handoff (OpenVPN3Bridge.mm / OpenConnectBridge.mm), and it buys three things a
// callback family cannot:
//
//   - Go keeps a real *net.TCPConn, so pipe()/copyCounted()/CloseWrite() and the
//     byte counters in engine.go work with no special-casing at all;
//   - backpressure is the KERNEL's (the socket buffer), not a queue we invent;
//   - no polling. A callback pump would have to be woken somehow, and the only
//     mechanism available across a C boundary is a timer — which is exactly the
//     3ms/20ms spin the subprocess-era SSH engine used and that this path must
//     not reintroduce.
//
// REFUSALS. A negative return is a refusal, and the code says why so the guest
// gets an immediate RST with a diagnosable reason rather than a black hole:
//
//	-1  generic failure
//	-2  no upstream (no SSH session configured at all)
//	-3  session down (reconnecting) — flows FAIL FAST, they are never queued
//	-4  the server refused the forward (administratively prohibited, etc.)
//	-5  the dial timed out
//
// Anything else negative reads as generic. Zero and positive values are fds.

package pxengine

/*
#include <stdlib.h>

// Swift → engine flow dial. Returns a socket file descriptor the engine adopts
// (and closes when the flow ends), or a NEGATIVE refusal code. `host` is
// borrowed for the duration of the call only.
typedef int (*PXFlowDialCallback)(const char *host, int port);

static int pxCallFlowDial(PXFlowDialCallback f, const char *host, int port) {
	if (f == NULL) return -2;
	return f(host, port);
}
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"unsafe"
)

// flowDialer is "whatever opens one flow to host:port". Both the in-process
// proxy dialers (*upstream) and the extension's SSH session (extensionDialer)
// satisfy it, which is what lets handleTCP and dnsOverTCP stay upstream-agnostic.
//
// `base` is the real OS dialer. A proxy upstream needs it (that is how it reaches
// the proxy); an extension dialer ignores it (the session's socket is not ours).
type flowDialer interface {
	dial(ctx context.Context, base *net.Dialer, host string, port int) (net.Conn, error)
}

// dial satisfies flowDialer for the in-process proxy upstreams. Named separately
// from dialThrough so the interface method and the concrete SOCKS/CONNECT helper
// can be documented (and tested) independently.
func (up *upstream) dial(ctx context.Context, base *net.Dialer, host string, port int) (net.Conn, error) {
	return up.dialThrough(ctx, base, host, port)
}

// ---- Refusal codes ----------------------------------------------------------

// Flow-dial refusal codes. Mirrored in Swift by
// SSHNetworkTunnelEngine.FlowRefusal — a value added on one side without the
// other becomes a "generic failure" here, never a misreported cause.
const (
	flowRefuseGeneric     = -1
	flowRefuseNoUpstream  = -2
	flowRefuseSessionDown = -3
	flowRefuseServer      = -4
	flowRefuseTimeout     = -5
)

// errFlowRefused sentinels, one per code, so callers (and tests) can compare
// rather than string-match. handleTCP only needs "an error", but the message is
// what lands in PXStatus.lastError and therefore in the connection panel.
var (
	errNoUpstream  = errors.New("no SSH session is configured for this tunnel")
	errSessionDown = errors.New("the SSH session is down (reconnecting) — this connection was refused rather than queued")
	errServerRefus = errors.New("the SSH server refused to open the forward")
	errDialTimeout = errors.New("the SSH server did not open the forward in time")
)

// refusalError maps a negative callback return to prose. Unknown negatives are
// reported as generic WITH their code, so a future Swift-side addition shows up
// as an honest "code -7" rather than being silently attributed to a cause it is
// not.
func refusalError(code int) error {
	switch code {
	case flowRefuseNoUpstream:
		return errNoUpstream
	case flowRefuseSessionDown:
		return errSessionDown
	case flowRefuseServer:
		return errServerRefus
	case flowRefuseTimeout:
		return errDialTimeout
	case flowRefuseGeneric:
		return errors.New("the SSH session could not open this connection")
	default:
		return fmt.Errorf("the SSH session refused this connection (code %d)", code)
	}
}

// ---- The callback registry --------------------------------------------------

// The flow-dial function pointer, in an atomic like the other three callbacks:
// every TCP flow reads it, and it must never contend with a PXStatus call.
var cbFlowDial atomic.Pointer[C.PXFlowDialCallback]

// Register the flow dialler. Call before PXStart when the upstream URL is
// `ssh://…`; a NULL pointer (or no call at all) makes every such flow refuse
// with -2 rather than hang. Fires on arbitrary Go goroutines — one per flow —
// so the Swift implementation must be thread-safe, and must return promptly
// (its budget is under the engine's own dialTimeout so the RST is ours).
//
//export PXSetFlowDialCallback
func PXSetFlowDialCallback(dial C.PXFlowDialCallback) {
	cbFlowDial.Store(&dial)
}

// hasFlowDialCallback reports whether a dialler has been registered. PXStart
// uses it to refuse an `ssh://` upstream up front, which turns "every flow is
// refused and nobody knows why" into one settings error at connect.
func hasFlowDialCallback() bool {
	p := cbFlowDial.Load()
	return p != nil && *p != nil
}

// ---- The dialer ------------------------------------------------------------

// extensionDialer asks Swift for a socket per flow. Stateless: the session it
// speaks for lives entirely on the other side of the C boundary.
type extensionDialer struct{}

// dial calls into Swift and adopts the descriptor it returns.
//
// ADOPTION IS EXACT, and the order matters. net.FileConn DUPLICATES the
// descriptor it is given and the returned Conn owns the duplicate — so the
// os.File wrapper must be closed IMMEDIATELY afterwards or every flow leaks the
// original fd for the lifetime of the tunnel. On the failure path the same close
// is what returns the descriptor Swift already handed over; dropping it there
// would leak a socket AND leave Swift's SSH channel pumping into a peer nobody
// reads.
func (extensionDialer) dial(ctx context.Context, _ *net.Dialer, host string, port int) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p := cbFlowDial.Load()
	if p == nil || *p == nil {
		return nil, errNoUpstream
	}
	chost := C.CString(host)
	fd := int(C.pxCallFlowDial(*p, chost, C.int(port)))
	C.free(unsafe.Pointer(chost))
	if fd < 0 {
		return nil, refusalError(fd)
	}

	// os.NewFile takes ownership of fd; FileConn dups it; closing the file hands
	// the original back. Anything else leaks one descriptor per flow.
	file := os.NewFile(uintptr(fd), fmt.Sprintf("sshflow:%s:%d", host, port))
	conn, err := net.FileConn(file)
	closeErr := file.Close()
	if err != nil {
		return nil, fmt.Errorf("adopting the SSH flow socket failed: %w", err)
	}
	if closeErr != nil {
		// The dup succeeded, so the flow is usable; the original descriptor is
		// what we failed to hand back. Report it rather than hiding a leak.
		logf("flow dial: releasing the handed-over descriptor failed: %v", closeErr)
	}
	return conn, nil
}
