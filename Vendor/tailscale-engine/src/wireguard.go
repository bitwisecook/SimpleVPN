// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// wireguard.go — cgo shim exporting a PLAIN WireGuard engine (wireguard-go's
// device package, no control plane) to Swift, the third c-archive family in
// this ONE archive alongside TS* (the Tailscale node) and the folded-in PX*
// (the proxy tunnel). Two Go c-archives cannot be linked into one binary, and
// PacketTunnel already links this one — so the plain-WireGuard exports live
// here, in the same Go module that already pins wireguard-go for Tailscale.
//
// WHAT THIS IS NOT: the Tailscale engine. TSStart composes a whole node
// (control client, netmap, MagicDNS); WGStart drives device.NewDevice directly
// with a static uapi config — one interface, one peer, the classic wg-quick
// client shape. Multi-peer configs round-trip through the editor but only the
// first peer is driven here (the common client case; the editor says so).
//
// PACKET FORMAT: raw IP packets on the C boundary, both ways — NO 4-byte PF
// header (that is an openvpn3-only quirk; see AGENTS.md). The TUN handed to
// wireguard-go is the same callbackTUN the Tailscale node uses (main.go),
// emitting to the WG packetOut callback instead of the TS one.
//
// CHECKSUM INVARIANT (the kernel-panic class documented at length in
// pxengine's buildEngine): every packet handed to Swift is written verbatim to
// the utun via NEPacketTunnelFlow, so it must carry COMPLETE checksums — no
// offload, no partial (pseudo-header-only) sums. This path is safe by
// construction: callbackTUN advertises BatchSize()==1 and implements none of
// the offload/virtio-header interfaces, so wireguard-go's GSO/checksum-offload
// paths (linux-only) never engage; decapsulated packets pass through with the
// checksums their origin computed, and outbound packets already carry full
// sums from the host stack (the utun has no offload). Do NOT give callbackTUN
// offload capabilities.
//
// C contract (all returned strings are UTF-8 JSON, malloc'd by Go, freed by
// WGFree):
//
//	WGSetCallbacks(packetOut, logLine)
//	  Register the two C function pointers. Call ONCE before WGStart; either
//	  may be NULL. Callbacks fire on arbitrary Go goroutines: the Swift
//	  implementations must be thread-safe and must not block (packetOut is on
//	  the data path).
//
//	WGStart(configJSON) -> responseJSON
//	  request:  {"privateKey":"<base64>","peerPublicKey":"<base64>",
//	             "presharedKey":"<base64 or empty>","endpoint":"host:port",
//	             "allowedIPs":["0.0.0.0/0","::/0"],"persistentKeepalive":25,
//	             "listenPort":0,"mtu":1420}
//	  response: {"ok":true,"endpoint":"<resolved ip:port>"} or
//	            {"error":{"kind":"…","message":"…"}}
//	  kinds: badRequest | alreadyRunning | endpoint | engine | other
//	  The resolved endpoint is returned so Swift can pin it as the tunnel's
//	  remote address (NE then routes the encrypted UDP around the tunnel).
//	  Synchronous: the device is up when this returns; the handshake itself is
//	  lazy (first packet / keepalive) and its progress is visible via WGStatus.
//
//	WGStop() -> responseJSON     ({"ok":true}; idempotent)
//	WGStatus() -> statusJSON     (state, rx/tx bytes, last handshake time,
//	                              current endpoint, listen port; NEVER any key)
//	WGPacketIn(bytes,len) -> int flow→engine; 1 = queued, 0 = dropped
//	WGFree(p) — free any string returned above.
//
// SECRETS: the private key (and preshared key) arrive in the WGStart JSON —
// which reached Swift via startTunnel(options:) in memory, never
// providerConfiguration — are handed to device.IpcSet, and are never logged
// (wireguard-go's own logger prints peer publics only) nor echoed by WGStatus
// (its IpcGet parse is a strict whitelist).
package main

/*
#include <stdlib.h>
#include <string.h>

// Callback types crossing to Swift. `packetOut` borrows its buffer for the
// duration of the call only — Swift must copy before returning.
typedef void (*WGPacketCallback)(const unsigned char *bytes, int len);
typedef void (*WGStringCallback)(const char *text);

// Go cannot call a C function pointer directly; thin trampolines keep the nil
// check in one place.
static void wgCallPacket(WGPacketCallback f, const unsigned char *b, int n) { if (f != NULL) f(b, n); }
static void wgCallString(WGStringCallback f, const char *s) { if (f != NULL) f(s); }
*/
import "C"

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
)

// wgDefaultMTU is the wg-quick default: 1500 minus WireGuard's 80-byte
// worst-case (IPv6) encapsulation overhead.
const wgDefaultMTU = 1420

// ---- Wire types ---------------------------------------------------------------

// wgStartConfig is exactly the JSON WireGuardStartConfig (Shared/
// WireGuardConfig.swift) encodes. Field names are load-bearing — pinned by
// TestWGStartConfigKeys here and WireGuardConfigTests on the Swift side.
type wgStartConfig struct {
	PrivateKey          string   `json:"privateKey"`
	PeerPublicKey       string   `json:"peerPublicKey"`
	PresharedKey        string   `json:"presharedKey"`
	Endpoint            string   `json:"endpoint"`
	AllowedIPs          []string `json:"allowedIPs"`
	PersistentKeepalive int      `json:"persistentKeepalive"`
	ListenPort          int      `json:"listenPort"`
	MTU                 int      `json:"mtu"`
}

// wgStartResponse is okResponse plus the resolved endpoint (ip:port) on
// success — Swift pins it as NE's tunnelRemoteAddress so the encrypted UDP to
// the server is routed around the tunnel it carries.
type wgStartResponse struct {
	OK       bool       `json:"ok,omitempty"`
	Endpoint string     `json:"endpoint,omitempty"`
	Error    *shimError `json:"error,omitempty"`
}

// wgStatusPayload is what WGStatus returns. A strict whitelist over IpcGet —
// key material never crosses here.
type wgStatusPayload struct {
	State          string `json:"state"`
	Endpoint       string `json:"endpoint,omitempty"`
	ListenPort     int    `json:"listenPort"`
	RxBytes        int64  `json:"rxBytes"`
	TxBytes        int64  `json:"txBytes"`
	LastHandshake  int64  `json:"lastHandshake"` // unix seconds; 0 = never
	PacketsDropped int64  `json:"packetsDropped"`
}

// ---- Callback registry ----------------------------------------------------

var (
	wgCbPacketOut atomic.Pointer[C.WGPacketCallback]
	wgCbLog       atomic.Pointer[C.WGStringCallback]
)

func wgLogf(format string, args ...any) {
	f := wgCbLog.Load()
	if f == nil || *f == nil {
		return
	}
	cs := C.CString(fmt.Sprintf(format, args...))
	defer C.free(unsafe.Pointer(cs))
	C.wgCallString(*f, cs)
}

// emitWGPacket is the plain-WireGuard engine's engine→flow delivery (the
// callbackTUN `emit` seam — see main.go).
func emitWGPacket(p []byte) {
	f := wgCbPacketOut.Load()
	if f == nil {
		return
	}
	C.wgCallPacket(*f, (*C.uchar)(unsafe.Pointer(&p[0])), C.int(len(p)))
}

//export WGSetCallbacks
func WGSetCallbacks(packetOut C.WGPacketCallback, logLine C.WGStringCallback) {
	wgCbPacketOut.Store(&packetOut)
	wgCbLog.Store(&logLine)
}

// ---- Engine state -----------------------------------------------------------

type wgState struct {
	dev      *device.Device
	tundev   *callbackTUN
	endpoint string // resolved ip:port, for status
}

var (
	wgMu      sync.Mutex // serialises WGStart / WGStop
	wgCurrent atomic.Pointer[wgState]
)

func wgFail(kind, format string, args ...any) *C.char {
	return cJSON(wgStartResponse{Error: &shimError{Kind: kind, Message: fmt.Sprintf(format, args...)}})
}

//export WGFree
func WGFree(p *C.char) {
	if p != nil {
		C.free(unsafe.Pointer(p))
	}
}

// ---- Config → uapi ----------------------------------------------------------

// wgDecodeKey turns a standard base64 WireGuard key into the lowercase hex the
// uapi wants. The two encodings are how the same 32 bytes are spelled in
// wg-quick files vs. `wg set` — mixing them up is a silent auth failure, so
// the length is enforced here.
func wgDecodeKey(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", fmt.Errorf("not valid base64: %v", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("a WireGuard key is 32 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// wgResolveEndpoint turns the config's host:port into the literal ip:port the
// uapi's endpoint= line requires (StdNetBind.ParseEndpoint is
// netip.ParseAddrPort — it does no DNS). Resolution happens ONCE at start,
// like wg-quick; a roaming server needs a reconnect.
func wgResolveEndpoint(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("no endpoint given")
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf("endpoint must be host:port (like vpn.example.com:51820)")
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", fmt.Errorf("%q is not a valid port", port)
	}
	// Already a literal? Normalise through netip so "[::1]:51820" round-trips.
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.String(), nil
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return "", fmt.Errorf("cannot resolve %q: %v", host, err)
	}
	ap := addr.AddrPort()
	if !ap.IsValid() {
		return "", fmt.Errorf("cannot resolve %q", host)
	}
	return ap.String(), nil
}

// renderWGUAPI renders the device.IpcSet configuration string. Pure (the
// endpoint arrives pre-resolved) so the contract tests can pin it without a
// device or a network.
func renderWGUAPI(cfg wgStartConfig, resolvedEndpoint string) (string, error) {
	priv, err := wgDecodeKey(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("private key: %v", err)
	}
	pub, err := wgDecodeKey(cfg.PeerPublicKey)
	if err != nil {
		return "", fmt.Errorf("peer public key: %v", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	if cfg.ListenPort > 0 {
		if cfg.ListenPort > 65535 {
			return "", fmt.Errorf("listen port %d is out of range", cfg.ListenPort)
		}
		fmt.Fprintf(&b, "listen_port=%d\n", cfg.ListenPort)
	}
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", pub)
	if strings.TrimSpace(cfg.PresharedKey) != "" {
		psk, err := wgDecodeKey(cfg.PresharedKey)
		if err != nil {
			return "", fmt.Errorf("preshared key: %v", err)
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", psk)
	}
	fmt.Fprintf(&b, "endpoint=%s\n", resolvedEndpoint)
	if cfg.PersistentKeepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", cfg.PersistentKeepalive)
	}
	// Cryptokey routing: at least one allowed IP or the peer can carry
	// nothing — a tunnel that connects and drops every packet.
	prefixes, err := parseRoutes(cfg.AllowedIPs) // shared with the TS shim; same CIDR rules
	if err != nil {
		return "", fmt.Errorf("allowed IPs: %v", err)
	}
	if len(prefixes) == 0 {
		return "", fmt.Errorf("no allowed IPs — the peer would carry no traffic")
	}
	for _, p := range prefixes {
		fmt.Fprintf(&b, "allowed_ip=%s\n", p.String())
	}
	return b.String(), nil
}

// ---- Start ------------------------------------------------------------------

//export WGStart
func WGStart(cfgJSON *C.char) *C.char {
	wgMu.Lock()
	defer wgMu.Unlock()

	if wgCurrent.Load() != nil {
		return wgFail("alreadyRunning", "a WireGuard tunnel is already running")
	}
	if cfgJSON == nil {
		return wgFail("badRequest", "missing configuration")
	}
	var cfg wgStartConfig
	if err := json.Unmarshal([]byte(C.GoString(cfgJSON)), &cfg); err != nil {
		return wgFail("badRequest", "configuration is not valid JSON: %v", err)
	}
	endpoint, err := wgResolveEndpoint(cfg.Endpoint)
	if err != nil {
		return wgFail("endpoint", "%v", err)
	}
	uapi, err := renderWGUAPI(cfg, endpoint)
	if err != nil {
		return wgFail("badRequest", "%v", err)
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = wgDefaultMTU
	}

	tundev := newCallbackTUN(mtu, emitWGPacket)
	logger := &device.Logger{Verbosef: wgLogf, Errorf: wgLogf}
	dev := device.NewDevice(tundev, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close() // closes the tun too
		return wgFail("engine", "configuration was refused: %v", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return wgFail("engine", "device would not come up: %v", err)
	}

	wgCurrent.Store(&wgState{dev: dev, tundev: tundev, endpoint: endpoint})
	wgLogf("wireguard up: endpoint=%s mtu=%d", endpoint, mtu)
	return cJSON(wgStartResponse{OK: true, Endpoint: endpoint})
}

// ---- Packet ingress -----------------------------------------------------------

//export WGPacketIn
func WGPacketIn(bytes unsafe.Pointer, length C.int) C.int {
	if bytes == nil || length <= 0 || length > maxPacketSize {
		return 0
	}
	st := wgCurrent.Load()
	if st == nil {
		return 0
	}
	// C.GoBytes copies — the Swift buffer is not ours to keep.
	if st.tundev.push(C.GoBytes(bytes, length)) {
		return 1
	}
	return 0
}

// ---- Status -------------------------------------------------------------------

// parseWGIpcStatus distils device.IpcGet output into the status payload. A
// STRICT WHITELIST: IpcGet includes private_key/preshared_key lines, and this
// is the one place that guarantees they never reach Swift. Multi-peer output
// (not produced by our single-peer config, but cheap to be right about) sums
// the byte counters and keeps the most recent handshake.
func parseWGIpcStatus(ipc string) wgStatusPayload {
	out := wgStatusPayload{State: "running"}
	for _, line := range strings.Split(ipc, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "rx_bytes":
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				out.RxBytes += n
			}
		case "tx_bytes":
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				out.TxBytes += n
			}
		case "last_handshake_time_sec":
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > out.LastHandshake {
				out.LastHandshake = n
			}
		case "endpoint":
			out.Endpoint = v
		case "listen_port":
			if n, err := strconv.Atoi(v); err == nil {
				out.ListenPort = n
			}
		}
	}
	return out
}

//export WGStatus
func WGStatus() *C.char {
	st := wgCurrent.Load()
	if st == nil {
		return cJSON(wgStatusPayload{State: "stopped"})
	}
	ipc, err := st.dev.IpcGet()
	if err != nil {
		return cJSON(wgStatusPayload{State: "running", Endpoint: st.endpoint,
			PacketsDropped: st.tundev.dropped.Load()})
	}
	out := parseWGIpcStatus(ipc)
	if out.Endpoint == "" {
		out.Endpoint = st.endpoint
	}
	out.PacketsDropped = st.tundev.dropped.Load()
	return cJSON(out)
}

// ---- Stop -----------------------------------------------------------------------

//export WGStop
func WGStop() *C.char {
	wgMu.Lock()
	defer wgMu.Unlock()
	st := wgCurrent.Load()
	if st == nil {
		return cJSON(okResponse{OK: true}) // idempotent
	}
	wgCurrent.Store(nil)
	// device.Close() tears down the peers, the bind and the TUN (it calls
	// tun.Close itself); the extra Close is idempotent belt-and-braces so a
	// future wireguard-go bump that stops closing the tun cannot leak our
	// reader goroutine into this long-lived extension process.
	st.dev.Close()
	st.tundev.Close()
	wgLogf("wireguard stopped")
	return cJSON(okResponse{OK: true})
}
