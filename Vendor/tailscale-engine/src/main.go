// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// main.go — cgo shim exporting the open-source Tailscale client stack
// (tailscale.com, BSD-3-Clause) to Swift as a C static archive
// (-buildmode=c-archive), for SimpleVPN's Tailscale / Headscale VPN kind.
//
// WHY THIS SHAPE, NOT tsnet: tsnet gives a dial-only netstack — good for an app
// that wants to *speak* to a tailnet, useless for a system-wide VPN. SimpleVPN
// is a real NEPacketTunnelProvider, so this embeds the same composition
// tailscaled uses (tsd.System + wgengine + ipnlocal.LocalBackend) but replaces
// the two pieces that assume they own the machine:
//
//   - the TUN: a callbackTUN whose Read/Write cross the C boundary, so packets
//     move between NEPacketTunnelFlow (Swift) and wireguard-go (Go) instead of
//     a /dev/utun fd. NetworkExtension already owns the utun.
//   - the router + DNS configurator: router.CallbackRouter (Tailscale's own
//     shim for exactly this case — "Mac, iOS, Android") reports the desired
//     routes/addresses/DNS instead of running `route`/`scutil`; Swift turns
//     that into NEPacketTunnelNetworkSettings. A sandboxed extension must not
//     mutate the host network stack behind NE's back.
//
// PACKET FORMAT: everything on this boundary is a RAW IP packet. There is no
// 4-byte PF header on either side here (unlike the openvpn3 socketpair pump —
// see AGENTS.md); the Swift side strips/adds nothing, it only has to pass
// NEPacketTunnelFlow's separately-carried protocol number back and forth.
//
// C contract (all strings are UTF-8 JSON, malloc'd by Go, freed via TSFree):
//
//	TSSetCallbacks(packetOut, stateChanged, browseToURL, netmapChanged, logLine)
//	  Registers the five C function pointers. Call ONCE before TSStart; passing
//	  NULL for any of them disables that callback. Callbacks fire on arbitrary
//	  Go goroutines — the Swift implementations must be thread-safe and must
//	  not block (they are on the packet path).
//
//	TSStart(configJSON) -> responseJSON
//	  request:  {"controlURL": "<https:// … or empty for Tailscale's own>",
//	             "hostname": "…", "authKey": "<may be empty ⇒ browser sign-in>",
//	             "stateDir": "/abs/path", "acceptRoutes": bool,
//	             "acceptDNS": bool, "useExitNode": bool,
//	             "exitNode": "<Tailscale IP or stable node id, may be empty>",
//	             "exitNodeAllowLANAccess": bool,
//	             "advertiseRoutes": ["10.0.0.0/24", …], "mtu": 1280}
//	  response: {"ok": true} or {"error": {"kind": "…", "message": "…"}}
//	  kinds: badRequest | alreadyRunning | stateDir | engine | backend | other
//
//	TSStop() -> responseJSON     ({"ok":true}; idempotent)
//	TSStatus() -> statusJSON     (see statusPayload below; {"state":"NoState"}
//	                              when nothing is running)
//	TSUpdatePrefs(prefsJSON) -> responseJSON
//	  Live edit of the three user-visible toggles + exit node without a
//	  reconnect: {"acceptRoutes":bool,"acceptDNS":bool,"useExitNode":bool,
//	              "exitNode":"…","exitNodeAllowLANAccess":bool,
//	              "advertiseRoutes":[…]} — every field optional; only the
//	  present ones are applied (mirrors ipn.MaskedPrefs).
//
//	TSPacketIn(bytes, len) -> int   flow→engine; 1 = queued, 0 = dropped
//	  (queue full, engine stopped, or a bad length). Never blocks.
//
//	TSFree(p) — free any string returned above.
//
// SECRETS: authKey arrives in the TSStart JSON, is handed straight to
// ipn.Options.AuthKey and is never logged, never written to disk by this shim,
// and never echoed back in TSStatus. The node key that the control plane issues
// IS persisted — that is the point of stateDir — under 0700, by Tailscale's own
// file state store.
//
// Go runtime note: as a c-archive the runtime starts lazily on first call, does
// not take over host signal handling, and never calls exit(). Safe to embed in
// a NEPacketTunnelProvider.
package main

/*
#include <stdlib.h>
#include <string.h>

// Callback types crossing to Swift. `packetOut` borrows its buffer for the
// duration of the call only — Swift must copy before returning.
typedef void (*TSPacketCallback)(const unsigned char *bytes, int len);
typedef void (*TSStringCallback)(const char *text);

// Go cannot call a C function pointer directly; these thin trampolines exist
// so the nil check lives in one place.
static void tsCallPacket(TSPacketCallback f, const unsigned char *b, int n) { if (f != NULL) f(b, n); }
static void tsCallString(TSStringCallback f, const char *s) { if (f != NULL) f(s); }
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/control/controlclient"
	_ "tailscale.com/feature/condregister" // registers portmapper, captive-portal detection, …
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
)

// ---- Wire types -------------------------------------------------------------

type startConfig struct {
	ControlURL             string   `json:"controlURL"`
	Hostname               string   `json:"hostname"`
	AuthKey                string   `json:"authKey"`
	StateDir               string   `json:"stateDir"`
	AcceptRoutes           bool     `json:"acceptRoutes"`
	AcceptDNS              bool     `json:"acceptDNS"`
	UseExitNode            bool     `json:"useExitNode"`
	ExitNode               string   `json:"exitNode"`
	ExitNodeAllowLANAccess bool     `json:"exitNodeAllowLANAccess"`
	AdvertiseRoutes        []string `json:"advertiseRoutes"`
	MTU                    int      `json:"mtu"`
}

// prefsPatch mirrors ipn.MaskedPrefs for the fields SimpleVPN exposes: a nil
// pointer means "leave alone", so the app can flip one toggle without having to
// resend (and possibly stale-overwrite) the others.
type prefsPatch struct {
	AcceptRoutes           *bool     `json:"acceptRoutes"`
	AcceptDNS              *bool     `json:"acceptDNS"`
	UseExitNode            *bool     `json:"useExitNode"`
	ExitNode               *string   `json:"exitNode"`
	ExitNodeAllowLANAccess *bool     `json:"exitNodeAllowLANAccess"`
	AdvertiseRoutes        *[]string `json:"advertiseRoutes"`
}

type shimError struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

type okResponse struct {
	OK    bool       `json:"ok,omitempty"`
	Error *shimError `json:"error,omitempty"`
}

// tunnelConfig is the netmapChanged payload: everything Swift needs to build
// NEPacketTunnelNetworkSettings, and nothing else. It is derived from
// router.Config + dns.OSConfig — i.e. from what the Tailscale engine actually
// decided, not from a re-derivation of the netmap on the Swift side.
type tunnelConfig struct {
	LocalAddrs   []string   `json:"localAddrs"`
	Routes       []string   `json:"routes"`
	LocalRoutes  []string   `json:"localRoutes"`
	SubnetRoutes []string   `json:"subnetRoutes"`
	MTU          int        `json:"mtu"`
	DNS          dnsPayload `json:"dns"`
}

type dnsPayload struct {
	Nameservers   []string `json:"nameservers"`
	SearchDomains []string `json:"searchDomains"`
	MatchDomains  []string `json:"matchDomains"`
}

type statePayload struct {
	State   string `json:"state"`
	AuthURL string `json:"authURL,omitempty"`
	Message string `json:"message,omitempty"`
}

type peerSummary struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	HostName string   `json:"hostName"`
	IPs      []string `json:"ips"`
	Online   bool     `json:"online"`
	Active   bool     `json:"active"`
	Country  string   `json:"country,omitempty"`
	City     string   `json:"city,omitempty"`
}

type statusPayload struct {
	State          string        `json:"state"`
	AuthURL        string        `json:"authURL,omitempty"`
	HaveNodeKey    bool          `json:"haveNodeKey"`
	SelfIPs        []string      `json:"selfIPs"`
	SelfDNSName    string        `json:"selfDNSName,omitempty"`
	SelfHostName   string        `json:"selfHostName,omitempty"`
	MagicDNSSuffix string        `json:"magicDNSSuffix,omitempty"`
	Tailnet        string        `json:"tailnet,omitempty"`
	PeerCount      int           `json:"peerCount"`
	PeersOnline    int           `json:"peersOnline"`
	ExitNodes      []peerSummary `json:"exitNodes"`
	ExitNodeID     string        `json:"exitNodeID,omitempty"`
	ExitNodeName   string        `json:"exitNodeName,omitempty"`
	RxBytes        int64         `json:"rxBytes"`
	TxBytes        int64         `json:"txBytes"`
	Health         []string      `json:"health,omitempty"`
	Config         *tunnelConfig `json:"config,omitempty"`
	PacketsDropped int64         `json:"packetsDropped"`
}

// ---- Callback registry ------------------------------------------------------
//
// Function pointers live in atomics rather than under the engine mutex: the
// packet path reads packetOut for every packet and must never contend with a
// TSStatus call.

var (
	cbPacketOut atomic.Pointer[C.TSPacketCallback]
	cbState     atomic.Pointer[C.TSStringCallback]
	cbBrowse    atomic.Pointer[C.TSStringCallback]
	cbNetmap    atomic.Pointer[C.TSStringCallback]
	cbLog       atomic.Pointer[C.TSStringCallback]
)

func loadCB(p *atomic.Pointer[C.TSStringCallback]) C.TSStringCallback {
	if v := p.Load(); v != nil {
		return *v
	}
	return nil
}

func emitString(p *atomic.Pointer[C.TSStringCallback], s string) {
	f := loadCB(p)
	if f == nil {
		return
	}
	cs := C.CString(s)
	defer C.free(unsafe.Pointer(cs))
	C.tsCallString(f, cs)
}

func emitJSON(p *atomic.Pointer[C.TSStringCallback], v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	emitString(p, string(b))
}

func logf(format string, args ...any) {
	if loadCB(&cbLog) == nil {
		return
	}
	emitString(&cbLog, fmt.Sprintf(format, args...))
}

//export TSSetCallbacks
func TSSetCallbacks(packetOut C.TSPacketCallback, stateChanged C.TSStringCallback,
	browseToURL C.TSStringCallback, netmapChanged C.TSStringCallback, logLine C.TSStringCallback) {
	cbPacketOut.Store(&packetOut)
	cbState.Store(&stateChanged)
	cbBrowse.Store(&browseToURL)
	cbNetmap.Store(&netmapChanged)
	cbLog.Store(&logLine)
}

// ---- The TUN device ---------------------------------------------------------

// inboundQueueDepth bounds flow→engine buffering. A VPN must drop, never block:
// TSPacketIn is called from the extension's packet-read handler, and stalling it
// would stall every flow on the machine. One full 1500-byte-ish burst of ~512
// packets is roughly a 750 KB ceiling.
const inboundQueueDepth = 512

// maxPacketSize caps what we will accept from either direction. Anything larger
// than a jumbo-ish frame is a bug or an attack, not a packet.
const maxPacketSize = 65535

// defaultMTU matches Tailscale's own default TUN MTU.
const defaultMTU = 1280

// callbackTUN is a tun.Device whose two directions cross the C boundary:
// Read() hands wireguard-go packets that Swift pushed in with TSPacketIn, and
// Write() hands Swift the decrypted packets via the packetOut callback.
//
// It deliberately does NOT implement IsFakeTun() — tsd.System sniffs for that
// method and would switch the whole node into netstack-only mode.
type callbackTUN struct {
	events    chan tun.Event
	inbound   chan []byte
	closeOnce sync.Once
	closed    chan struct{}
	mtu       atomic.Int64
	dropped   atomic.Int64
}

func newCallbackTUN(mtu int) *callbackTUN {
	t := &callbackTUN{
		events:  make(chan tun.Event, 4),
		inbound: make(chan []byte, inboundQueueDepth),
		closed:  make(chan struct{}),
	}
	t.mtu.Store(int64(mtu))
	t.events <- tun.EventUp
	return t
}

// File is only ever called by the plan9 router; nil is correct here.
func (t *callbackTUN) File() *os.File { return nil }

func (t *callbackTUN) Name() (string, error) { return "SimpleVPN", nil }

func (t *callbackTUN) MTU() (int, error) { return int(t.mtu.Load()), nil }

func (t *callbackTUN) Events() <-chan tun.Event { return t.events }

// BatchSize 1: NEPacketTunnelFlow has no vectorised write worth the extra
// buffering here, and a batch of one keeps the C boundary trivially bounded.
func (t *callbackTUN) BatchSize() int { return 1 }

func (t *callbackTUN) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}

// Read blocks until Swift pushes a packet or the device closes. wireguard-go
// treats a returned error as fatal for its reader goroutine, which is what we
// want on close.
func (t *callbackTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) == 0 {
		return 0, nil
	}
	for {
		select {
		case <-t.closed:
			return 0, os.ErrClosed
		case pkt, ok := <-t.inbound:
			if !ok {
				return 0, os.ErrClosed
			}
			// Bounds check before the copy: a packet that cannot fit is
			// dropped rather than truncated — a truncated IP packet is
			// worse than a missing one.
			if offset < 0 || offset > len(bufs[0]) || len(pkt) > len(bufs[0])-offset {
				t.dropped.Add(1)
				continue
			}
			n := copy(bufs[0][offset:], pkt)
			sizes[0] = n
			return 1, nil
		}
	}
}

// Write delivers engine→flow packets. Each buffer is handed to Swift for the
// duration of the callback only; Swift copies it into NEPacketTunnelFlow.
func (t *callbackTUN) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	default:
	}
	f := cbPacketOut.Load()
	if f == nil {
		return len(bufs), nil
	}
	for _, b := range bufs {
		if offset < 0 || offset > len(b) {
			t.dropped.Add(1)
			continue
		}
		p := b[offset:]
		if len(p) == 0 || len(p) > maxPacketSize {
			t.dropped.Add(1)
			continue
		}
		C.tsCallPacket(*f, (*C.uchar)(unsafe.Pointer(&p[0])), C.int(len(p)))
	}
	return len(bufs), nil
}

// push queues a flow→engine packet. Returns false when the queue is full or the
// device is closed — the caller drops, never blocks.
func (t *callbackTUN) push(pkt []byte) bool {
	select {
	case <-t.closed:
		return false
	default:
	}
	select {
	case t.inbound <- pkt:
		return true
	default:
		t.dropped.Add(1)
		return false
	}
}

// ---- Engine state -----------------------------------------------------------

type engineState struct {
	sys      *tsd.System
	lb       *ipnlocal.LocalBackend
	tundev   *callbackTUN
	netMon   *netmon.Monitor
	dialer   *tsdial.Dialer
	netstack *netstack.Impl
	cancel   context.CancelFunc
	watchWG  sync.WaitGroup

	// lastConfig is the most recent router+DNS config, kept so TSStatus can
	// report what the tunnel is actually configured with even between
	// netmapChanged callbacks.
	cfgMu      sync.Mutex
	lastConfig *tunnelConfig
}

var (
	mu      sync.Mutex // serialises TSStart/TSStop/TSUpdatePrefs
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

//export TSFree
func TSFree(p *C.char) {
	if p != nil {
		C.free(unsafe.Pointer(p))
	}
}

//export TSPacketIn
func TSPacketIn(bytes unsafe.Pointer, length C.int) C.int {
	if bytes == nil || length <= 0 || length > maxPacketSize {
		return 0
	}
	st := current.Load()
	if st == nil {
		return 0
	}
	// C.GoBytes copies — the Swift buffer is not ours to keep.
	if st.tundev.push(C.GoBytes(bytes, length)) {
		return 1
	}
	return 0
}

// ---- Start ------------------------------------------------------------------

// validateControlURL enforces the same rule as the Swift editor: empty means
// Tailscale's own control plane, otherwise it must be an https URL with a host.
// Headscale deployments just put their own https URL here — there is no second
// code path for them.
func validateControlURL(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return ipn.DefaultControlURL, nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("not a URL: %v", err)
	}
	if u.Scheme != "https" {
		return "", errors.New("control server URL must start with https://")
	}
	if u.Host == "" {
		return "", errors.New("control server URL has no host")
	}
	return strings.TrimSuffix(s, "/"), nil
}

func parseRoutes(in []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%q is not a valid CIDR", s)
		}
		if p.Addr() != p.Masked().Addr() {
			return nil, fmt.Errorf("%q has host bits set (did you mean %v?)", s, p.Masked())
		}
		out = append(out, p)
	}
	return out, nil
}

//export TSStart
func TSStart(cfgJSON *C.char) *C.char {
	mu.Lock()
	defer mu.Unlock()

	if current.Load() != nil {
		return fail("alreadyRunning", "a Tailscale session is already running")
	}
	if cfgJSON == nil {
		return fail("badRequest", "missing configuration")
	}
	var cfg startConfig
	if err := json.Unmarshal([]byte(C.GoString(cfgJSON)), &cfg); err != nil {
		return fail("badRequest", "configuration is not valid JSON: %v", err)
	}

	controlURL, err := validateControlURL(cfg.ControlURL)
	if err != nil {
		return fail("badRequest", "%v", err)
	}
	advRoutes, err := parseRoutes(cfg.AdvertiseRoutes)
	if err != nil {
		return fail("badRequest", "%v", err)
	}
	if strings.TrimSpace(cfg.StateDir) == "" {
		return fail("badRequest", "no state directory given")
	}
	if err := os.MkdirAll(cfg.StateDir, 0700); err != nil {
		return fail("stateDir", "cannot create %s: %v", cfg.StateDir, err)
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}

	st, err := buildEngine(cfg, controlURL, advRoutes, mtu)
	if err != nil {
		return fail(kindOf(err), "%v", err)
	}
	current.Store(st)
	return cJSON(okResponse{OK: true})
}

// startError carries the kind through buildEngine's single error return so the
// Swift side can distinguish "your config is wrong" from "the stack failed".
type startError struct {
	kind string
	err  error
}

func (e startError) Error() string { return e.err.Error() }
func (e startError) Unwrap() error { return e.err }

func kindOf(err error) string {
	var se startError
	if errors.As(err, &se) {
		return se.kind
	}
	return "other"
}

func buildEngine(cfg startConfig, controlURL string, advRoutes []netip.Prefix, mtu int) (*engineState, error) {
	st := &engineState{}
	// Anything created before the first error return has to be torn down by
	// hand — there is no defer-until-success helper worth the indirection for
	// five objects, but every early return below MUST unwind.
	sys := tsd.NewSystem()
	st.sys = sys

	netMon, err := netmon.New(sys.Bus.Get(), logf)
	if err != nil {
		return nil, startError{"engine", fmt.Errorf("network monitor: %w", err)}
	}
	st.netMon = netMon
	sys.Set(netMon)

	dialer := &tsdial.Dialer{Logf: logf}
	dialer.SetBus(sys.Bus.Get())
	st.dialer = dialer

	tundev := newCallbackTUN(mtu)
	st.tundev = tundev

	// One object is both Router and dns.OSConfigurator: Tailscale hands us the
	// complete desired network state in a single call, which is precisely the
	// shape NEPacketTunnelNetworkSettings wants (it is applied atomically too).
	// SplitDNS=true: NEDNSSettings.matchDomains is real split DNS on macOS, so
	// a tailnet with restricted-search DNS does not hijack the whole resolver.
	cbRouter := &router.CallbackRouter{
		SplitDNS:   true,
		InitialMTU: uint32(mtu),
	}
	cbRouter.SetBoth = func(rcfg *router.Config, dcfg *dns.OSConfig) error {
		st.publishConfig(rcfg, dcfg, mtu)
		return nil
	}

	eng, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		Tun:           tundev,
		Router:        cbRouter,
		DNS:           cbRouter,
		NetMon:        netMon,
		Dialer:        dialer,
		SetSubsystem:  sys.Set,
		ControlKnobs:  sys.ControlKnobs(),
		HealthTracker: sys.HealthTracker.Get(),
		Metrics:       sys.UserMetricsRegistry(),
		EventBus:      sys.Bus.Get(),
		// ListenPort 0: let magicsock pick. A fixed port would collide with a
		// real Tailscale.app on the same Mac.
		ListenPort: 0,
	})
	if err != nil {
		tundev.Close()
		netMon.Close()
		return nil, startError{"engine", fmt.Errorf("wireguard engine: %w", err)}
	}
	sys.Set(eng)
	sys.Set(cbRouter)
	sys.HealthTracker.Get().SetMetricsRegistry(sys.UserMetricsRegistry())

	// netstack handles the traffic this node terminates itself (peerapi) and,
	// on darwin, forwarding for any subnet routes we advertise — the OS-level
	// forwarding tailscaled would use is not available to a sandboxed
	// extension. ProcessSubnets follows whether we actually advertise anything.
	ns, err := netstack.Create(logf, sys.Tun.Get(), eng, sys.MagicSock.Get(), dialer, sys.DNSManager.Get(), sys.ProxyMapper())
	if err != nil {
		eng.Close()
		netMon.Close()
		return nil, startError{"engine", fmt.Errorf("netstack: %w", err)}
	}
	ns.ProcessLocalIPs = false // the real TUN carries our own addresses
	ns.ProcessSubnets = len(advRoutes) > 0
	ns.CheckLocalTransportEndpoints = true
	st.netstack = ns
	sys.Set(ns)
	// From here on every failure has the same unwind, and forgetting one leaks
	// a gVisor stack plus an engine thread into a process that outlives the
	// tunnel. One closure, used by all of them.
	unwind := func() {
		ns.Close()
		eng.Close()
		netMon.Close()
	}
	sys.NetstackRouter.Set(len(advRoutes) > 0)
	sys.Tun.Get().Start()

	stateFile := filepath.Join(cfg.StateDir, "tailscaled.state")
	stateStore, err := store.New(logf, stateFile)
	if err != nil {
		unwind()
		return nil, startError{"stateDir", fmt.Errorf("state store %s: %w", stateFile, err)}
	}
	sys.Set(stateStore)

	// logid zero value ⇒ no logtail. SimpleVPN never uploads logs to Tailscale;
	// diagnostics go to the extension's os_log via the logLine callback.
	lb, err := ipnlocal.NewLocalBackend(logf, logid.PublicID{}, sys, controlclient.LoginDefault)
	if err != nil {
		unwind()
		return nil, startError{"backend", fmt.Errorf("local backend: %w", err)}
	}
	st.lb = lb
	lb.SetVarRoot(cfg.StateDir)
	if err := ns.Start(lb); err != nil {
		lb.Shutdown()
		unwind()
		return nil, startError{"engine", fmt.Errorf("netstack start: %w", err)}
	}

	prefs := ipn.NewPrefs()
	prefs.ControlURL = controlURL
	prefs.Hostname = cfg.Hostname
	prefs.WantRunning = true
	prefs.RouteAll = cfg.AcceptRoutes
	prefs.CorpDNS = cfg.AcceptDNS
	prefs.AdvertiseRoutes = advRoutes
	prefs.ExitNodeAllowLANAccess = cfg.ExitNodeAllowLANAccess
	applyExitNode(prefs, cfg.UseExitNode, cfg.ExitNode)

	ctx, cancel := context.WithCancel(context.Background())
	st.cancel = cancel
	st.startWatch(ctx, cfg.AuthKey == "")

	if err := lb.Start(ipn.Options{UpdatePrefs: prefs, AuthKey: cfg.AuthKey}); err != nil {
		cancel()
		lb.Shutdown()
		unwind()
		return nil, startError{"backend", fmt.Errorf("start: %w", err)}
	}
	return st, nil
}

// applyExitNode encodes the one rule the UI needs: turning the toggle off must
// CLEAR the exit node, not merely stop offering it, or the tunnel keeps
// defaulting every packet through a peer the user just deselected.
func applyExitNode(prefs *ipn.Prefs, use bool, id string) {
	prefs.ExitNodeID = ""
	prefs.ExitNodeIP = netip.Addr{}
	id = strings.TrimSpace(id)
	if !use || id == "" {
		return
	}
	if ip, err := netip.ParseAddr(id); err == nil {
		prefs.ExitNodeIP = ip
		return
	}
	prefs.ExitNodeID = tailcfg.StableNodeID(id)
}

// ---- Notification watch -----------------------------------------------------

func (st *engineState) startWatch(ctx context.Context, interactive bool) {
	st.watchWG.Add(1)
	go func() {
		defer st.watchWG.Done()
		var loginStarted bool
		mask := ipn.NotifyInitialState | ipn.NotifyInitialPrefs | ipn.NotifyInitialHealthState
		st.lb.WatchNotifications(ctx, mask, func() {}, func(n *ipn.Notify) bool {
			if n.BrowseToURL != nil && *n.BrowseToURL != "" {
				emitString(&cbBrowse, *n.BrowseToURL)
			}
			if n.ErrMessage != nil && *n.ErrMessage != "" {
				emitJSON(&cbState, statePayload{State: st.backendState(), Message: *n.ErrMessage})
			}
			if n.State != nil {
				s := *n.State
				emitJSON(&cbState, statePayload{State: s.String(), AuthURL: st.authURL()})
				// No auth key ⇒ the node has to be authorized in a browser.
				// LocalBackend does not start that itself: it waits for a
				// client to ask, which is what a `tailscale up` would do.
				if interactive && s == ipn.NeedsLogin && !loginStarted {
					loginStarted = true
					go func() {
						if err := st.lb.StartLoginInteractive(ctx); err != nil {
							logf("interactive login failed: %v", err)
						}
					}()
				}
			}
			return true
		})
	}()
}

func (st *engineState) backendState() string {
	if st.lb == nil {
		return ipn.NoState.String()
	}
	return st.lb.StatusWithoutPeers().BackendState
}

func (st *engineState) authURL() string {
	if st.lb == nil {
		return ""
	}
	return st.lb.StatusWithoutPeers().AuthURL
}

// publishConfig converts Tailscale's router+DNS decision into the JSON Swift
// re-applies as NEPacketTunnelNetworkSettings. A nil rcfg (Close) publishes
// nothing — tearing down settings is NE's job, not ours.
func (st *engineState) publishConfig(rcfg *router.Config, dcfg *dns.OSConfig, fallbackMTU int) {
	if rcfg == nil {
		return
	}
	tc := &tunnelConfig{
		LocalAddrs:   prefixStrings(rcfg.LocalAddrs),
		Routes:       prefixStrings(rcfg.Routes),
		LocalRoutes:  prefixStrings(rcfg.LocalRoutes),
		SubnetRoutes: prefixStrings(rcfg.SubnetRoutes),
		MTU:          fallbackMTU,
	}
	if rcfg.NewMTU > 0 {
		tc.MTU = rcfg.NewMTU
	}
	if dcfg != nil {
		tc.DNS = dnsPayload{
			Nameservers:   addrStrings(dcfg.Nameservers),
			SearchDomains: fqdnStrings(dcfg.SearchDomains),
			MatchDomains:  fqdnStrings(dcfg.MatchDomains),
		}
	}
	st.cfgMu.Lock()
	st.lastConfig = tc
	st.cfgMu.Unlock()
	emitJSON(&cbNetmap, tc)
}

func prefixStrings(in []netip.Prefix) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, p.String())
	}
	return out
}

func addrStrings(in []netip.Addr) []string {
	out := make([]string, 0, len(in))
	for _, a := range in {
		out = append(out, a.String())
	}
	return out
}

func fqdnStrings(in []dnsname.FQDN) []string {
	out := make([]string, 0, len(in))
	for _, f := range in {
		out = append(out, strings.TrimSuffix(f.WithoutTrailingDot(), "."))
	}
	return out
}

// ---- Status -----------------------------------------------------------------

//export TSStatus
func TSStatus() *C.char {
	st := current.Load()
	if st == nil {
		return cJSON(statusPayload{State: ipn.NoState.String(), SelfIPs: []string{}, ExitNodes: []peerSummary{}})
	}
	s := st.lb.Status()
	out := statusPayload{
		State:       s.BackendState,
		AuthURL:     s.AuthURL,
		HaveNodeKey: s.HaveNodeKey,
		SelfIPs:     addrStrings(s.TailscaleIPs),
		ExitNodes:   []peerSummary{},
		Health:      s.Health,
	}
	if out.SelfIPs == nil {
		out.SelfIPs = []string{}
	}
	if s.Self != nil {
		out.SelfDNSName = strings.TrimSuffix(s.Self.DNSName, ".")
		out.SelfHostName = s.Self.HostName
	}
	if s.CurrentTailnet != nil {
		out.MagicDNSSuffix = s.CurrentTailnet.MagicDNSSuffix
		out.Tailnet = s.CurrentTailnet.Name
	} else {
		out.MagicDNSSuffix = s.MagicDNSSuffix
	}
	for _, p := range s.Peer {
		out.PeerCount++
		if p.Online {
			out.PeersOnline++
		}
		out.RxBytes += p.RxBytes
		out.TxBytes += p.TxBytes
		if p.ExitNodeOption {
			out.ExitNodes = append(out.ExitNodes, summarisePeer(p))
		}
		if p.ExitNode {
			out.ExitNodeID = string(p.ID)
			out.ExitNodeName = peerName(p)
		}
	}
	if s.ExitNodeStatus != nil && out.ExitNodeID == "" {
		out.ExitNodeID = string(s.ExitNodeStatus.ID)
	}
	st.cfgMu.Lock()
	out.Config = st.lastConfig
	st.cfgMu.Unlock()
	out.PacketsDropped = st.tundev.dropped.Load()
	return cJSON(out)
}

func peerName(p *ipnstate.PeerStatus) string {
	if n := strings.TrimSuffix(p.DNSName, "."); n != "" {
		// The leading label is the machine name; the rest is the tailnet
		// suffix, which is noise in a picker.
		if i := strings.Index(n, "."); i > 0 {
			return n[:i]
		}
		return n
	}
	return p.HostName
}

func summarisePeer(p *ipnstate.PeerStatus) peerSummary {
	ps := peerSummary{
		ID:       string(p.ID),
		Name:     peerName(p),
		HostName: p.HostName,
		IPs:      addrStrings(p.TailscaleIPs),
		Online:   p.Online,
		Active:   p.ExitNode,
	}
	if p.Location != nil {
		ps.Country = p.Location.Country
		ps.City = p.Location.City
	}
	return ps
}

// ---- Live prefs -------------------------------------------------------------

//export TSUpdatePrefs
func TSUpdatePrefs(patchJSON *C.char) *C.char {
	mu.Lock()
	defer mu.Unlock()
	st := current.Load()
	if st == nil {
		return fail("badRequest", "no Tailscale session is running")
	}
	if patchJSON == nil {
		return fail("badRequest", "missing prefs")
	}
	var p prefsPatch
	if err := json.Unmarshal([]byte(C.GoString(patchJSON)), &p); err != nil {
		return fail("badRequest", "prefs are not valid JSON: %v", err)
	}

	mp := &ipn.MaskedPrefs{}
	if p.AcceptRoutes != nil {
		mp.RouteAll = *p.AcceptRoutes
		mp.RouteAllSet = true
	}
	if p.AcceptDNS != nil {
		mp.CorpDNS = *p.AcceptDNS
		mp.CorpDNSSet = true
	}
	if p.ExitNodeAllowLANAccess != nil {
		mp.ExitNodeAllowLANAccess = *p.ExitNodeAllowLANAccess
		mp.ExitNodeAllowLANAccessSet = true
	}
	if p.AdvertiseRoutes != nil {
		routes, err := parseRoutes(*p.AdvertiseRoutes)
		if err != nil {
			return fail("badRequest", "%v", err)
		}
		mp.AdvertiseRoutes = routes
		mp.AdvertiseRoutesSet = true
	}
	if p.UseExitNode != nil || p.ExitNode != nil {
		use := true
		if p.UseExitNode != nil {
			use = *p.UseExitNode
		}
		id := ""
		if p.ExitNode != nil {
			id = *p.ExitNode
		}
		applyExitNode(&mp.Prefs, use, id)
		mp.ExitNodeIDSet = true
		mp.ExitNodeIPSet = true
	}
	if _, err := st.lb.EditPrefs(mp); err != nil {
		return fail("backend", "%v", err)
	}
	return cJSON(okResponse{OK: true})
}

// ---- Stop -------------------------------------------------------------------

//export TSStop
func TSStop() *C.char {
	mu.Lock()
	defer mu.Unlock()
	st := current.Load()
	if st == nil {
		return cJSON(okResponse{OK: true}) // idempotent
	}
	current.Store(nil)

	st.cancel()
	// Order matters: stop the backend (which stops talking to control and
	// tears the wg config down) before closing the engine that owns the TUN,
	// or the engine's reconfigure can race a closed device.
	st.lb.Shutdown()
	if eng, ok := st.sys.Engine.GetOK(); ok {
		eng.Close()
	}
	// netstack owns gVisor goroutines of its own; without this they would
	// accumulate across every reconnect in this (long-lived) extension process.
	if st.netstack != nil {
		st.netstack.Close()
	}
	st.tundev.Close()
	if st.netMon != nil {
		st.netMon.Close()
	}
	if st.dialer != nil {
		st.dialer.Close()
	}
	// The watcher exits when its context is cancelled; bound the wait so a
	// wedged notification loop cannot hang stopTunnel forever.
	done := make(chan struct{})
	go func() { st.watchWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		logf("watch goroutine did not exit within 5s")
	}
	return cJSON(okResponse{OK: true})
}

// unused, but c-archive builds need a main.
func main() {}

var _ logger.Logf = logf
