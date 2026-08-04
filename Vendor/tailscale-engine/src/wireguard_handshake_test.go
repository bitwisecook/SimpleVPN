// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// wireguard_handshake_test.go — OUR uapi text completing a REAL WireGuard
// handshake, with no server, no peer and no hardware.
//
// wireguard_test.go pins the shape of what renderWGUAPI writes. That is not the
// same as proving it WORKS: a wrong key encoding, a missing allowed_ip or a
// malformed endpoint line all render perfectly and then authenticate nothing.
// "WireGuard first handshake" was on the needs-a-live-peer list for that reason
// — but the live peer is unnecessary. This file stands up TWO wireguard-go
// devices in-process over loopback UDP and drives one of them with the exact
// text WGStart hands device.IpcSet, so the handshake, the data path and
// cryptokey routing are all proven here, in the build gate
// (Tools/build-tailscale-engine.sh runs `go test`).
//
// THE FAR END IS HAND-WRITTEN ON PURPOSE. The responder's uapi is assembled
// here from an independent base64→hex transcode, never from renderWGUAPI or
// wgDecodeKey: if both ends of a handshake came out of the code under test, a
// symmetric bug (say, both sides spelling keys in base64) would cancel out and
// the test would pass on a config no real server would accept.
// TestWGUAPIWithBase64KeysIsRefusedByARealDevice closes that loop from the
// other side by proving a real device rejects the wrong spelling.
//
// NOTHING LEAVES THE MACHINE. The Bind here is loopback-only (127.0.0.1), not
// conn.NewDefaultBind's wildcard socket — same discipline as the proxy engine's
// loopback tests, and it keeps the run off every other interface (and out of
// the macOS firewall's way).
//
// WHAT STILL NEEDS A REAL SERVER: that a particular VPN provider's peer accepts
// our handshake (their key, their allowed_ips, their MTU), DNS/route
// installation by NetworkExtension, and roaming/endpoint re-resolution. The
// protocol-level claims — our config is accepted, it handshakes, it carries
// packets, and it drops what allowed_ips excludes — are no longer among them.

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"tailscale.com/types/key"
)

// The two ends' tunnel addresses, plus the two addresses cryptokey routing must
// refuse: one outside our peer's allowed_ips (outbound), one forged as a source
// the peer is not allowed to claim (inbound).
const (
	wgTestOurTunnelIP    = "10.55.0.1"
	wgTestPeerTunnelIP   = "10.55.0.2"
	wgTestOffRouteIP     = "198.51.100.9"
	wgTestForgedSourceIP = "10.55.0.99"
)

// ---- A loopback-only conn.Bind -------------------------------------------------

// loopbackBind is a conn.Bind over ONE UDP socket on 127.0.0.1. wireguard-go's
// own StdNetBind binds the wildcard address on every interface, which a test has
// no business doing on a developer's machine; this reaches the other device in
// the same process and nothing else.
type loopbackBind struct {
	mu   sync.Mutex
	sock *net.UDPConn
}

func (b *loopbackBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sock != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.sock = sock
	actual := uint16(sock.LocalAddr().(*net.UDPAddr).Port)
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, ap, err := sock.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = &conn.StdNetEndpoint{AddrPort: ap}
		return 1, nil
	}
	return []conn.ReceiveFunc{recv}, actual, nil
}

func (b *loopbackBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sock == nil {
		return nil
	}
	err := b.sock.Close()
	b.sock = nil
	return err
}

func (b *loopbackBind) SetMark(uint32) error { return nil }

func (b *loopbackBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	dst, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	sock := b.sock
	b.mu.Unlock()
	if sock == nil {
		return net.ErrClosed
	}
	for _, buf := range bufs {
		if _, err := sock.WriteToUDPAddrPort(buf[offset:], dst.AddrPort); err != nil {
			return err
		}
	}
	return nil
}

// ParseEndpoint is the seam our `endpoint=` line lands on — the reason
// wgResolveEndpoint must hand IpcSet a literal ip:port and never a hostname.
func (b *loopbackBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &conn.StdNetEndpoint{AddrPort: ap}, nil
}

func (b *loopbackBind) BatchSize() int { return 1 }

// ---- Test devices --------------------------------------------------------------

// wgTestDevice is one wireguard-go device wired to a callbackTUN — the same TUN
// the shipping engine uses (wireguard.go), with its emit callback delivering
// into a channel instead of across the C boundary.
type wgTestDevice struct {
	t    *testing.T
	name string
	dev  *device.Device
	tun  *callbackTUN
	rx   chan []byte
}

func newWGTestDevice(t *testing.T, name string) *wgTestDevice {
	return newWGTestDeviceLogging(t, name, device.LogLevelError)
}

func newWGTestDeviceLogging(t *testing.T, name string, logLevel int) *wgTestDevice {
	t.Helper()
	d := &wgTestDevice{t: t, name: name, rx: make(chan []byte, 32)}
	d.tun = newCallbackTUN(wgDefaultMTU, func(p []byte) {
		// emit BORROWS its buffer for the duration of the call (the C contract
		// Swift honours) — copy before queueing, exactly as Swift must.
		d.rx <- bytes.Clone(p)
	})
	// LogLevelError, not t.Logf: the device's goroutines outlive the test
	// function body, and logging into a finished *testing.T panics.
	d.dev = device.NewDevice(d.tun, &loopbackBind{},
		device.NewLogger(logLevel, "wg-"+name+" "))
	t.Cleanup(func() {
		d.dev.Close()
		d.tun.Close()
	})
	return d
}

// apply hands a uapi configuration to IpcSet and fails the test if it is
// refused — the boundary WGStart's rendered text has to survive.
func (d *wgTestDevice) apply(uapi string) {
	d.t.Helper()
	if err := d.dev.IpcSet(uapi); err != nil {
		d.t.Fatalf("%s: IpcSet refused the configuration: %v\n%s", d.name, err, uapi)
	}
}

// up applies a uapi configuration and brings the device up, in the same order
// WGStart does (NewDevice → IpcSet → Up).
func (d *wgTestDevice) up(uapi string) {
	d.t.Helper()
	d.apply(uapi)
	if err := d.dev.Up(); err != nil {
		d.t.Fatalf("%s: device would not come up: %v", d.name, err)
	}
}

func (d *wgTestDevice) status() wgStatusPayload {
	d.t.Helper()
	ipc, err := d.dev.IpcGet()
	if err != nil {
		d.t.Fatalf("%s: IpcGet failed: %v", d.name, err)
	}
	return parseWGIpcStatus(ipc)
}

func (d *wgTestDevice) listenPort() int {
	d.t.Helper()
	port := d.status().ListenPort
	if port == 0 {
		d.t.Fatalf("%s: no listen port after Up()", d.name)
	}
	return port
}

// awaitHandshake polls the status the app itself reads (parseWGIpcStatus over
// IpcGet) for a non-zero last_handshake_time_sec — the field WGStatus surfaces
// and the only in-band proof that the noise exchange actually completed.
func (d *wgTestDevice) awaitHandshake(within time.Duration) int64 {
	d.t.Helper()
	deadline := time.Now().Add(within)
	for {
		if hs := d.status().LastHandshake; hs != 0 {
			return hs
		}
		if time.Now().After(deadline) {
			return 0
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// send pushes a packet in flow→engine, the direction WGPacketIn drives.
func (d *wgTestDevice) send(pkt []byte) {
	d.t.Helper()
	if !d.tun.push(pkt) {
		d.t.Fatalf("%s: the TUN refused the packet", d.name)
	}
}

func (d *wgTestDevice) awaitPacket(within time.Duration) []byte {
	select {
	case p := <-d.rx:
		return p
	case <-time.After(within):
		return nil
	}
}

func (d *wgTestDevice) expectNoPacket(within time.Duration, why string) {
	d.t.Helper()
	if p := d.awaitPacket(within); p != nil {
		d.t.Errorf("%s: %s — but a %d-byte packet arrived: % x", d.name, why, len(p), p)
	}
}

// ---- Key material --------------------------------------------------------------

// wgTestKeyPair returns a real Curve25519 keypair as the base64 a wg-quick
// .conf (and SimpleVPN's WireGuardStartConfig) spells keys in. key.NewNode
// applies the same clamping WireGuard does, so the pair is one a device agrees
// with — which is what makes a handshake possible at all.
func wgTestKeyPair() (privB64, pubB64 string) {
	k := key.NewNode()
	priv := k.Raw32()
	pub := k.Public().Raw32()
	return base64.StdEncoding.EncodeToString(priv[:]),
		base64.StdEncoding.EncodeToString(pub[:])
}

func wgTestPSK(t *testing.T) string {
	t.Helper()
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatalf("random preshared key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw[:])
}

// wgTestHex transcodes base64→hex INDEPENDENTLY of wgDecodeKey, so the
// responder's configuration cannot inherit a transcoding bug from the code
// under test.
func wgTestHex(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 32 {
		t.Fatalf("test key %q is not 32 base64 bytes: %v", b64, err)
	}
	return hex.EncodeToString(raw)
}

// ---- Packets -------------------------------------------------------------------

// wgTestIPv4UDP builds a well-formed IPv4/UDP packet. The IP total-length field
// and header checksum are real: wireguard-go trims an inbound packet to the
// declared total length and drops anything shorter than a header, so a sloppy
// packet would fail for reasons that have nothing to do with the tunnel.
//
// The UDP checksum is left zero — legal for UDP over IPv4 (RFC 768). The
// CHECKSUM INVARIANT documented in wireguard.go is about packets handed to
// SWIFT for a utun write; nothing here crosses that boundary.
func wgTestIPv4UDP(t *testing.T, src, dst, payload string) []byte {
	t.Helper()
	s, err := netip.ParseAddr(src)
	if err != nil {
		t.Fatalf("bad test source %q: %v", src, err)
	}
	d, err := netip.ParseAddr(dst)
	if err != nil {
		t.Fatalf("bad test destination %q: %v", dst, err)
	}
	total := 20 + 8 + len(payload)
	p := make([]byte, total)
	p[0] = 0x45 // IPv4, 20-byte header
	binary.BigEndian.PutUint16(p[2:4], uint16(total))
	binary.BigEndian.PutUint16(p[4:6], 0x2b1c) // identification
	p[8] = 64                                  // TTL
	p[9] = 17                                  // UDP
	s4, d4 := s.As4(), d.As4()
	copy(p[12:16], s4[:])
	copy(p[16:20], d4[:])
	binary.BigEndian.PutUint16(p[10:12], wgTestOnesComplementSum(p[:20]))
	binary.BigEndian.PutUint16(p[20:22], 51000) // source port
	binary.BigEndian.PutUint16(p[22:24], 51001) // destination port
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
}

func wgTestOnesComplementSum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ---- The pair ------------------------------------------------------------------

// wgTestPair brings up the responder first (its listen port has to exist before
// our `endpoint=` line can name it), then OUR device from renderWGUAPI's output.
//
// ourPSK/peerPSK are separate parameters so a mismatch can be tested: a
// preshared key that renders but is not actually applied would be a silent
// downgrade of the tunnel's security.
func wgTestPair(t *testing.T, ourAllowedIPs []string, ourPSK, peerAllowedIP, peerPSK string) (ours, peer *wgTestDevice) {
	t.Helper()
	ourPriv, ourPub := wgTestKeyPair()
	peerPriv, peerPub := wgTestKeyPair()

	peer = newWGTestDevice(t, "responder")
	responderLines := []string{
		"private_key=" + wgTestHex(t, peerPriv),
		"replace_peers=true",
		"public_key=" + wgTestHex(t, ourPub),
	}
	if peerPSK != "" {
		responderLines = append(responderLines, "preshared_key="+wgTestHex(t, peerPSK))
	}
	responderLines = append(responderLines, "allowed_ip="+peerAllowedIP, "")
	peer.up(strings.Join(responderLines, "\n"))

	remote := fmt.Sprintf("127.0.0.1:%d", peer.listenPort())
	// wgResolveEndpoint is the shipping path from the config's host:port to the
	// literal the uapi needs; use it rather than hand-formatting the line.
	resolved, err := wgResolveEndpoint(remote)
	if err != nil {
		t.Fatalf("wgResolveEndpoint(%q): %v", remote, err)
	}
	cfg := wgStartConfig{
		PrivateKey:          ourPriv,
		PeerPublicKey:       peerPub,
		PresharedKey:        ourPSK,
		Endpoint:            remote,
		AllowedIPs:          ourAllowedIPs,
		PersistentKeepalive: 25,
		MTU:                 wgDefaultMTU,
	}
	uapi, err := renderWGUAPI(cfg, resolved)
	if err != nil {
		t.Fatalf("renderWGUAPI: %v", err)
	}
	ours = newWGTestDevice(t, "ours")
	ours.up(uapi) // the first assertion: IpcSet ACCEPTS the text we generate

	// THE FORK DOES NOT ROAM. Upstream wireguard-go learns a peer's endpoint from
	// the packets it receives; tailscale/wireguard-go has that removed (Tailscale
	// picks endpoints itself in magicsock), so a peer with no `endpoint=` can
	// receive an initiation and then fail to answer it — "no known endpoint for
	// peer". That is exactly why renderWGUAPI ALWAYS writes an endpoint line, and
	// why the responder needs ours told to it here rather than inferred. A real
	// server runs stock WireGuard and does roam.
	peer.apply(strings.Join([]string{
		"public_key=" + wgTestHex(t, ourPub),
		"update_only=true",
		fmt.Sprintf("endpoint=127.0.0.1:%d", ours.listenPort()),
		"",
	}, "\n"))
	return ours, peer
}

// ---- The tests -----------------------------------------------------------------

// The whole envelope in one pass: our rendered config is accepted, it completes
// a real noise handshake with a preshared key in play, and packets cross in both
// directions byte-for-byte.
func TestWGRenderedConfigCompletesARealHandshake(t *testing.T) {
	psk := wgTestPSK(t)
	ours, peer := wgTestPair(t,
		[]string{wgTestPeerTunnelIP + "/32"}, psk,
		wgTestOurTunnelIP+"/32", psk)

	// The handshake is lazy (wireguard.go says so): the first outbound packet
	// triggers it, and wireguard-go stages the packet until the keypair exists.
	outbound := wgTestIPv4UDP(t, wgTestOurTunnelIP, wgTestPeerTunnelIP, "simplevpn out")
	ours.send(outbound)

	got := peer.awaitPacket(10 * time.Second)
	if got == nil {
		t.Fatal("the packet never reached the far device — the handshake did not complete " +
			"(a wrong key encoding, a bad endpoint line or a missing allowed_ip all look like this)")
	}
	if !bytes.Equal(got, outbound) {
		t.Errorf("the tunnel altered the packet:\n sent % x\n got  % x", outbound, got)
	}

	// The handshake time is what WGStatus reports and what the UI calls the
	// connection being real; it must be non-zero at BOTH ends.
	if hs := ours.awaitHandshake(5 * time.Second); hs == 0 {
		t.Error("our side never recorded a handshake (last_handshake_time_sec stayed 0)")
	}
	if hs := peer.awaitHandshake(5 * time.Second); hs == 0 {
		t.Error("the far side never recorded a handshake")
	}

	// Return path: the responder replies to the endpoint it learned.
	inbound := wgTestIPv4UDP(t, wgTestPeerTunnelIP, wgTestOurTunnelIP, "simplevpn back")
	peer.send(inbound)
	back := ours.awaitPacket(10 * time.Second)
	if back == nil {
		t.Fatal("nothing came back through the tunnel")
	}
	if !bytes.Equal(back, inbound) {
		t.Errorf("the return packet was altered:\n sent % x\n got  % x", inbound, back)
	}
}

// Cryptokey routing, the property the docs claim and the reason renderWGUAPI
// refuses a peer with no allowed_ips: allowed_ips is a filter in BOTH
// directions, not a route table.
func TestWGCryptokeyRoutingDropsWhatAllowedIPsExclude(t *testing.T) {
	psk := wgTestPSK(t)
	ours, peer := wgTestPair(t,
		[]string{wgTestPeerTunnelIP + "/32"}, psk,
		wgTestOurTunnelIP+"/32", psk)

	// Establish first, so a later silence is a DROP and not an unbuilt tunnel.
	ours.send(wgTestIPv4UDP(t, wgTestOurTunnelIP, wgTestPeerTunnelIP, "establish"))
	if peer.awaitPacket(10*time.Second) == nil {
		t.Fatal("the tunnel never came up, so nothing below would mean anything")
	}

	// OUTBOUND: no peer covers 198.51.100.9, so there is nothing to encrypt to.
	ours.send(wgTestIPv4UDP(t, wgTestOurTunnelIP, wgTestOffRouteIP, "off route"))
	peer.expectNoPacket(750*time.Millisecond,
		"a destination outside the peer's allowed_ips must not be sent")

	// INBOUND: the peer is allowed to claim 10.55.0.2 and nothing else, so a
	// packet it sources from 10.55.0.99 must be dropped after decryption.
	peer.send(wgTestIPv4UDP(t, wgTestForgedSourceIP, wgTestOurTunnelIP, "forged source"))
	ours.expectNoPacket(750*time.Millisecond,
		"a source address outside the peer's allowed_ips must be dropped after decryption")

	// The control that makes both silences meaningful: the tunnel is still alive.
	alive := wgTestIPv4UDP(t, wgTestOurTunnelIP, wgTestPeerTunnelIP, "still alive")
	ours.send(alive)
	got := peer.awaitPacket(10 * time.Second)
	if got == nil {
		t.Fatal("the tunnel stopped carrying allowed traffic — the drops above prove nothing")
	}
	if !bytes.Equal(got, alive) {
		t.Errorf("the control packet was altered:\n sent % x\n got  % x", alive, got)
	}
}

// The preshared key is APPLIED, not merely rendered. With a PSK on one side only
// the noise exchange cannot complete, so neither end ever records a handshake —
// which is what proves the `preshared_key=` line reached the crypto.
func TestWGPresharedKeyMismatchNeverHandshakes(t *testing.T) {
	ours, peer := wgTestPair(t,
		[]string{wgTestPeerTunnelIP + "/32"}, wgTestPSK(t),
		wgTestOurTunnelIP+"/32", wgTestPSK(t))

	ours.send(wgTestIPv4UDP(t, wgTestOurTunnelIP, wgTestPeerTunnelIP, "should not arrive"))

	// 3 s covers the initiation and at least part of one retry (wireguard-go
	// re-initiates every 5 s); a handshake that works at all works in
	// milliseconds over loopback — the positive test above measures that.
	if hs := ours.awaitHandshake(3 * time.Second); hs != 0 {
		t.Error("our side completed a handshake despite a preshared-key mismatch")
	}
	if hs := peer.status().LastHandshake; hs != 0 {
		t.Error("the far side completed a handshake despite a preshared-key mismatch")
	}
	peer.expectNoPacket(250*time.Millisecond, "no packet can cross without a handshake")
}

// Why wgDecodeKey exists. A real device REFUSES the base64 spelling a wg-quick
// .conf uses, so the base64→hex transcode in renderWGUAPI is load-bearing and
// not decoration — and if it ever regressed, WGStart would fail loudly at
// IpcSet rather than bring up a tunnel that authenticates nothing.
func TestWGUAPIWithBase64KeysIsRefusedByARealDevice(t *testing.T) {
	privB64, pubB64 := wgTestKeyPair()
	// Silent: the IPC rejection this test WANTS is logged as an error, and a
	// gate's log should not carry an alarming line from a passing test.
	d := newWGTestDeviceLogging(t, "strict", device.LogLevelSilent)
	wrong := strings.Join([]string{
		"private_key=" + privB64,
		"replace_peers=true",
		"public_key=" + pubB64,
		"endpoint=127.0.0.1:51820",
		"allowed_ip=0.0.0.0/0",
		"",
	}, "\n")
	if err := d.dev.IpcSet(wrong); err == nil {
		t.Fatal("wireguard-go accepted base64 key material — then nothing here would " +
			"catch renderWGUAPI forgetting to transcode to hex")
	}
}
