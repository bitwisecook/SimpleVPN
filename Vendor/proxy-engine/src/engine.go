// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// engine.go — cgo shim exporting a tun2socks-style "proxy tunnel" to Swift as
// part of a C static archive, for SimpleVPN's Proxy Tunnel VPN kind.
//
// WHAT THIS IS: the packet-tunnel system extension presents a utun with routes;
// this engine terminates every TCP (and DNS-carrying UDP) flow on that utun in
// a userspace TCP/IP stack (gVisor netstack) and re-dials it through an upstream
// SOCKS5 or HTTP(S) CONNECT proxy. No subprocess, no system-proxy setting, no
// per-app configuration — the routes decide what enters the tunnel and every
// flow that does is proxied in-process.
//
//	NEPacketTunnelFlow (Swift)  <->  channel.Endpoint (gVisor)  <->  netstack
//	     raw IP packets                InjectInbound / ReadContext     TCP/UDP
//	                                                                     |
//	                                                            forwarder handlers
//	                                                                     |
//	                                                       SOCKS5 / CONNECT dialer
//	                                                                     |
//	                                                        real net.Dialer (physical NIC)
//
// PACKET FORMAT: raw IP packets on the C boundary, both ways — NO 4-byte PF
// header (that is an openvpn3-only quirk; see AGENTS.md). The Swift side reads
// the IP version nibble to tell NEPacketTunnelFlow which protocol number to
// carry alongside each engine->app packet.
//
// C contract (all returned strings are UTF-8 JSON, malloc'd by Go, freed by
// PXFree):
//
//	PXSetCallbacks(packetOut, stateChanged, logLine)
//	  Register the three C function pointers. Call ONCE before PXStart; any may
//	  be NULL. Callbacks fire on arbitrary Go goroutines: the Swift
//	  implementations must be thread-safe and must not block (packetOut is on
//	  the data path).
//
//	PXStart(configJSON) -> responseJSON
//	  request:  {"upstream":"socks5://host:1080","username":"","password":"",
//	             "mtu":1500}
//	  response: {"ok":true} or {"error":{"kind":"…","message":"…"}}
//	  kinds: badRequest | alreadyRunning | engine | other
//	  Synchronous: there is no control-plane handshake. On {"ok":true} the
//	  stack is up and the routes/DNS the Swift side advertises are immediately
//	  live; per-flow proxy failures are surfaced as status counters and log
//	  lines, never as a start failure.
//
//	PXStop() -> responseJSON     ({"ok":true}; idempotent)
//	PXStatus() -> statusJSON     (state, lastError, flow counters, byte counters)
//	PXPacketIn(bytes,len) -> int flow->engine; 1 = injected, 0 = dropped
//	PXFree(p) — free any string returned above.
//
// SECRETS: username/password arrive in the PXStart JSON, live only in the
// upstream struct in memory, and are never logged nor echoed by PXStatus. The
// upstream URL in providerConfiguration never carries them (the Swift side
// keeps them out); a URL that does carry userinfo is accepted as a fallback.
//
// Go runtime note: as a c-archive the runtime starts lazily, does not take over
// host signal handling, and never calls exit() — safe inside a
// NEPacketTunnelProvider.
package pxengine

/*
#include <stdlib.h>
#include <string.h>

// Callback types crossing to Swift. `packetOut` borrows its buffer for the
// duration of the call only — Swift must copy before returning.
typedef void (*PXPacketCallback)(const unsigned char *bytes, int len);
typedef void (*PXStringCallback)(const char *text);

// Go cannot call a C function pointer directly; these thin trampolines keep the
// nil check in one place.
static void pxCallPacket(PXPacketCallback f, const unsigned char *b, int n) { if (f != NULL) f(b, n); }
static void pxCallString(PXStringCallback f, const char *s) { if (f != NULL) f(s); }
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// ---- Tunables ---------------------------------------------------------------

const (
	// nicID is the single NIC our channel endpoint is attached to.
	nicID tcpip.NICID = 1

	// defaultMTU matches a common utun default; the Swift side sends the real
	// one in the config.
	defaultMTU = 1500

	// tcpReceiveBufferSize / tcpMaxInFlight bound the TCP forwarder. maxInFlight
	// is how many half-open guest connections netstack will track at once.
	tcpReceiveBufferSize = 0 // 0 ⇒ let netstack pick its default window
	tcpMaxInFlight       = 2048

	// maxPacketSize caps a packet accepted from either direction. Anything
	// larger than a jumbo-ish frame is a bug or an attack, not a packet.
	maxPacketSize = 65535
)

// ---- Wire types -------------------------------------------------------------

type startConfig struct {
	Upstream string `json:"upstream"`
	Username string `json:"username"`
	Password string `json:"password"`
	MTU      int    `json:"mtu"`
}

type shimError struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

type okResponse struct {
	OK    bool       `json:"ok,omitempty"`
	Error *shimError `json:"error,omitempty"`
}

// statusPayload is what PXStatus returns. It carries NO secrets and NO upstream
// address (only the scheme, which is not sensitive) — the credentials and the
// exact proxy host stay inside the engine.
type statusPayload struct {
	State         string `json:"state"`
	Scheme        string `json:"scheme"`
	LastError     string `json:"lastError,omitempty"`
	ActiveFlows   int64  `json:"activeFlows"`
	TotalFlows    int64  `json:"totalFlows"`
	FailedFlows   int64  `json:"failedFlows"`
	UDPFlows      int64  `json:"udpFlows"`
	DNSQueries    int64  `json:"dnsQueries"`
	BytesUp       int64  `json:"bytesUp"`
	BytesDown     int64  `json:"bytesDown"`
	PacketsInDrop int64  `json:"packetsInDropped"`
}

// ---- Callback registry ------------------------------------------------------
//
// Function pointers live in atomics: the packet path reads packetOut for every
// outbound packet and must never contend with a PXStatus call.

var (
	cbPacketOut atomic.Pointer[C.PXPacketCallback]
	cbState     atomic.Pointer[C.PXStringCallback]
	cbLog       atomic.Pointer[C.PXStringCallback]
)

func loadStringCB(p *atomic.Pointer[C.PXStringCallback]) C.PXStringCallback {
	if v := p.Load(); v != nil {
		return *v
	}
	return nil
}

func emitString(p *atomic.Pointer[C.PXStringCallback], s string) {
	f := loadStringCB(p)
	if f == nil {
		return
	}
	cs := C.CString(s)
	defer C.free(unsafe.Pointer(cs))
	C.pxCallString(f, cs)
}

func logf(format string, args ...any) {
	if loadStringCB(&cbLog) == nil {
		return
	}
	emitString(&cbLog, fmt.Sprintf(format, args...))
}

func emitState(state, message string) {
	b, err := json.Marshal(map[string]string{"state": state, "message": message})
	if err != nil {
		return
	}
	emitString(&cbState, string(b))
}

//export PXSetCallbacks
func PXSetCallbacks(packetOut C.PXPacketCallback, stateChanged C.PXStringCallback, logLine C.PXStringCallback) {
	cbPacketOut.Store(&packetOut)
	cbState.Store(&stateChanged)
	cbLog.Store(&logLine)
}

// ---- Engine state -----------------------------------------------------------

type engineState struct {
	stack  *stack.Stack
	ep     *channel.Endpoint
	up     *upstream
	dialer *net.Dialer
	ctx    context.Context
	cancel context.CancelFunc
	pumpWG sync.WaitGroup

	// Counters (atomics: read by PXStatus off the data path).
	activeFlows   atomic.Int64
	totalFlows    atomic.Int64
	failedFlows   atomic.Int64
	udpFlows      atomic.Int64
	dnsQueries    atomic.Int64
	bytesUp       atomic.Int64 // guest -> proxy
	bytesDown     atomic.Int64 // proxy -> guest
	packetsInDrop atomic.Int64

	lastErrMu sync.Mutex
	lastErr   string
}

func (st *engineState) setLastError(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	st.lastErrMu.Lock()
	st.lastErr = msg
	st.lastErrMu.Unlock()
	logf("%s", msg)
}

var (
	mu      sync.Mutex // serialises PXStart / PXStop
	current atomic.Pointer[engineState]
)

func fail(kind, format string, args ...any) *C.char {
	return cJSON(okResponse{Error: &shimError{Kind: kind, Message: fmt.Sprintf(format, args...)}})
}

func cJSON(v any) *C.char {
	b, err := json.Marshal(v)
	if err != nil {
		return C.CString(`{"error":{"kind":"other","message":"marshal failed"}}`)
	}
	return C.CString(string(b))
}

//export PXFree
func PXFree(p *C.char) {
	if p != nil {
		C.free(unsafe.Pointer(p))
	}
}

// ---- Start ------------------------------------------------------------------

//export PXStart
func PXStart(cfgJSON *C.char) *C.char {
	mu.Lock()
	defer mu.Unlock()

	if current.Load() != nil {
		return fail("alreadyRunning", "a proxy tunnel is already running")
	}
	if cfgJSON == nil {
		return fail("badRequest", "missing configuration")
	}
	var cfg startConfig
	if err := json.Unmarshal([]byte(C.GoString(cfgJSON)), &cfg); err != nil {
		return fail("badRequest", "configuration is not valid JSON: %v", err)
	}
	up, err := parseUpstream(cfg.Upstream, cfg.Username, cfg.Password)
	if err != nil {
		return fail("badRequest", "%v", err)
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}

	st, err := buildEngine(up, mtu)
	if err != nil {
		return fail("engine", "%v", err)
	}
	current.Store(st)
	emitState("running", "")
	logf("proxy tunnel up: scheme=%s mtu=%d", schemeName(up.kind), mtu)
	return cJSON(okResponse{OK: true})
}

func buildEngine(up *upstream, mtu int) (*engineState, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol, ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol, udp.NewProtocol,
		},
		HandleLocal: false,
	})

	ep := channel.New(512, uint32(mtu), "")
	if err := s.CreateNICWithOptions(nicID, ep, stack.NICOptions{Name: "proxy0"}); err != nil {
		s.Close()
		return nil, fmt.Errorf("create NIC: %s", err)
	}
	// Promiscuous + spoofing: this NIC must accept packets addressed to ANY
	// destination (we intercept every flow the routes send us, whatever its
	// address) and originate replies from those same addresses. Without both,
	// netstack would drop everything that is not addressed to a local address.
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		s.Close()
		return nil, fmt.Errorf("promiscuous mode: %s", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		s.Close()
		return nil, fmt.Errorf("spoofing: %s", err)
	}
	// Catch-all routes: everything on this NIC. The OS routing table (via NE's
	// includedRoutes) already decided what reaches the utun; inside netstack we
	// just accept it all.
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	ctx, cancel := context.WithCancel(context.Background())
	st := &engineState{
		stack:  s,
		ep:     ep,
		up:     up,
		ctx:    ctx,
		cancel: cancel,
		// The real OS dialer for reaching the proxy. KeepAlive keeps a busy
		// proxy connection healthy; the timeout is per-dial (also bounded by the
		// per-flow context).
		dialer: &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second},
	}

	// Forwarders: one per transport. Each inbound flow becomes a handler call.
	tcpFwd := tcp.NewForwarder(s, tcpReceiveBufferSize, tcpMaxInFlight, st.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, st.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	st.startOutboundPump()
	return st, nil
}

// startOutboundPump drains packets netstack produces (TCP ACKs, resets, our DNS
// replies) and hands them to Swift for the utun. It blocks on ReadContext so it
// carries no busy-loop; it exits when the context is cancelled at stop.
func (st *engineState) startOutboundPump() {
	st.pumpWG.Add(1)
	go func() {
		defer st.pumpWG.Done()
		for {
			pkt := st.ep.ReadContext(st.ctx)
			if pkt == nil {
				return // context cancelled (stop) or endpoint closed
			}
			view := pkt.ToView()
			pkt.DecRef()
			data := view.AsSlice()
			if len(data) == 0 || len(data) > maxPacketSize {
				continue
			}
			f := cbPacketOut.Load()
			if f == nil {
				continue
			}
			C.pxCallPacket(*f, (*C.uchar)(unsafe.Pointer(&data[0])), C.int(len(data)))
		}
	}()
}

// ---- Packet ingress ---------------------------------------------------------

//export PXPacketIn
func PXPacketIn(bytes unsafe.Pointer, length C.int) C.int {
	if bytes == nil || length <= 0 || length > maxPacketSize {
		return 0
	}
	st := current.Load()
	if st == nil {
		return 0
	}
	// C.GoBytes copies — the Swift buffer is not ours to keep.
	raw := C.GoBytes(bytes, length)
	var proto tcpip.NetworkProtocolNumber
	switch raw[0] >> 4 {
	case 4:
		proto = header.IPv4ProtocolNumber
	case 6:
		proto = header.IPv6ProtocolNumber
	default:
		st.packetsInDrop.Add(1)
		return 0
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(raw),
	})
	st.ep.InjectInbound(proto, pkt)
	pkt.DecRef()
	return 1
}

// ---- TCP forwarding ---------------------------------------------------------

// pipe copies between the guest connection and the proxy connection, counting
// bytes each way, and closes both when either side ends. This is the whole data
// path of a proxied TCP flow.
func (st *engineState) pipe(guest, proxy net.Conn) {
	defer st.activeFlows.Add(-1)
	defer guest.Close()
	defer proxy.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	// guest -> proxy
	go func() {
		defer wg.Done()
		n := copyCounted(proxy, guest)
		st.bytesUp.Add(n)
		// Half-close so the peer sees EOF but the other direction can drain.
		if cw, ok := proxy.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	// proxy -> guest
	go func() {
		defer wg.Done()
		n := copyCounted(guest, proxy)
		st.bytesDown.Add(n)
		if cw, ok := guest.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
}

// addrFromTCPIP renders a netstack address as a dialable host string. IPv4 and
// IPv6 both come back in the form net.ParseIP understands.
func addrFromTCPIP(a tcpip.Address) string {
	return net.IP(a.AsSlice()).String()
}

func schemeName(k proxyKind) string {
	switch k {
	case proxySOCKS5:
		return "socks5"
	case proxyHTTPConnect:
		return "http"
	case proxyHTTPSConnect:
		return "https"
	default:
		return "unknown"
	}
}

// ---- Status -----------------------------------------------------------------

//export PXStatus
func PXStatus() *C.char {
	st := current.Load()
	if st == nil {
		return cJSON(statusPayload{State: "stopped"})
	}
	st.lastErrMu.Lock()
	lastErr := st.lastErr
	st.lastErrMu.Unlock()
	return cJSON(statusPayload{
		State:         "running",
		Scheme:        schemeName(st.up.kind),
		LastError:     lastErr,
		ActiveFlows:   st.activeFlows.Load(),
		TotalFlows:    st.totalFlows.Load(),
		FailedFlows:   st.failedFlows.Load(),
		UDPFlows:      st.udpFlows.Load(),
		DNSQueries:    st.dnsQueries.Load(),
		BytesUp:       st.bytesUp.Load(),
		BytesDown:     st.bytesDown.Load(),
		PacketsInDrop: st.packetsInDrop.Load(),
	})
}

// ---- Stop -------------------------------------------------------------------

//export PXStop
func PXStop() *C.char {
	mu.Lock()
	defer mu.Unlock()
	st := current.Load()
	if st == nil {
		return cJSON(okResponse{OK: true}) // idempotent
	}
	current.Store(nil)

	// Cancel first so the outbound pump and every in-flight per-flow context
	// unwind, then close the stack (which closes the channel endpoint and every
	// gonet endpoint riding on it).
	st.cancel()
	st.ep.Close()
	st.stack.Close()

	// Bound the wait so a wedged pump cannot hang stopTunnel forever.
	done := make(chan struct{})
	go func() { st.pumpWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		logf("outbound pump did not exit within 5s")
	}
	// Reap the netstack's own goroutines so they do not accumulate across
	// reconnects in this long-lived extension process.
	st.stack.Wait()
	emitState("stopped", "")
	return cJSON(okResponse{OK: true})
}
