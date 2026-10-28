package teleport

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pion/stun"
)

type candidate struct {
	Type string `json:"type"`
	Addr string `json:"addr"`
}

type networkFamily uint8

const (
	familyDual networkFamily = iota
	familyIPv4
	familyIPv6
)

func (f networkFamily) String() string {
	switch f {
	case familyIPv4:
		return "ipv4"
	case familyIPv6:
		return "ipv6"
	default:
		return "dual-stack"
	}
}

type peerDesc struct {
	Candidates []candidate `json:"candidates"`
	IceConfig  []iceServer `json:"ice_config,omitempty"`
	IsMaster   bool        `json:"is_master"`
}

func listenPort() int {
	b := []byte{0, 0}
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return 49152 + int(binary.BigEndian.Uint16(b))%16384
}

func localCandidates(port int, family networkFamily) []candidate {
	ifaces, _ := net.Interfaces()
	seen := map[string]bool{}
	var out []candidate
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ip := interfaceAddrIP(a)
			if ip == nil || !isRoutableCandidateIP(ip, family) {
				continue
			}
			addr := net.JoinHostPort(ip.String(), fmt.Sprint(port))
			if !seen[addr] {
				seen[addr] = true
				out = append(out, candidate{Type: "iface", Addr: addr})
			}
		}
	}
	return out
}

// isRoutableCandidateIP reports whether ip is usable as a WAN candidate for
// family: globally routable, not an IPv6 ULA (fc00::/7), and matching the
// requested address family.
func isRoutableCandidateIP(ip net.IP, family networkFamily) bool {
	if !ip.IsGlobalUnicast() {
		return false
	}
	isV4 := ip.To4() != nil
	if !isV4 && ip.IsPrivate() {
		return false
	}
	if family == familyIPv4 && !isV4 {
		return false
	}
	if family == familyIPv6 && isV4 {
		return false
	}
	return true
}

func interfaceAddrIP(addr net.Addr) net.IP {
	switch value := addr.(type) {
	case *net.IPNet:
		return value.IP
	case *net.IPAddr:
		return value.IP
	default:
		return nil
	}
}

// The Teleport peer that advertises is_master=true drives nomination. Its
// authenticated Binding Requests carry these DATA values in order; the slave
// only answers them. This sequence comes from the successful shared-Go
// capture, not from generic ICE behaviour.
var nominationWaitSequence = []int{2000, 1000, 500, 250, 125}

// nominationTracker keeps the master-driven Teleport nomination state per
// remote UDP tuple. The slave must not invent or transmit wait requests:
// doing so reverses the protocol role and prevents the console from activating
// WireGuard. It only records the authenticated DATA requests it receives.
type nominationTracker struct {
	mu         sync.Mutex
	pairs      map[string]*nominationPair
	active     bool
	selected   string
	selectedCh chan struct{}
}

type nominationPair struct {
	nextWait int
}

func newNominationTracker() *nominationTracker {
	return &nominationTracker{
		pairs:      make(map[string]*nominationPair),
		selectedCh: make(chan struct{}),
	}
}

// observe records a master nomination request and returns whether it completed
// the exact wait sequence for this remote tuple.
func (t *nominationTracker) observe(addr string, waitMs int) (selected bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.pairs[addr]
	if p == nil {
		p = &nominationPair{}
		t.pairs[addr] = p
	}
	if t.selected != "" || p.nextWait >= len(nominationWaitSequence) {
		return false
	}
	if waitMs != nominationWaitSequence[p.nextWait] {
		return false
	}
	p.nextWait++
	if p.nextWait == len(nominationWaitSequence) {
		if !t.active {
			return false
		}
		t.selected = addr
		close(t.selectedCh)
		return true
	}
	return false
}

// activate allows a completed master nomination sequence to select an
// endpoint. Progress observed before activation is retained.
func (t *nominationTracker) activate() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.active {
		return
	}
	t.active = true
	// The console can complete the master-driven wait sequence before our
	// CONNECT polling loop observes CONNECT_RESPONSE. Preserve that verified
	// pre-response work and select it now instead of waiting another 40 seconds.
	for addr, p := range t.pairs {
		if p.nextWait == len(nominationWaitSequence) {
			t.selected = addr
			close(t.selectedCh)
			return
		}
	}
}

func (t *nominationTracker) selectedEndpoint() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.selected
}

func (t *nominationTracker) waitForSelection(ctx context.Context, timeout time.Duration) string {
	if selected := t.selectedEndpoint(); selected != "" {
		return selected
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-t.selectedCh:
		return t.selectedEndpoint()
	case <-timer.C:
		return ""
	case <-ctx.Done():
		return ""
	}
}

// stunBindingProbe is the initial, authenticated connectivity check sent to a
// peer candidate. Unlike nomination requests it deliberately has no DATA
// attribute: the console is the master and supplies the wait countdown.
//
// This is particularly important on IPv4. A STUN query to the public STUN
// server establishes a mapping for that server, but a symmetric or
// address-dependent NAT may still drop the console's first packet until we
// send a packet to the console's exact IP:port tuple.
func stunBindingProbe(secret string) ([]byte, [12]byte) {
	var setters []stun.Setter
	setters = append(setters, stun.TransactionID, stun.BindingRequest)
	if secret != "" {
		setters = append(setters, stun.NewShortTermIntegrity(secret))
	}
	msg := stun.MustBuild(setters...)
	var tx [12]byte
	copy(tx[:], msg.TransactionID[:])
	return msg.Raw, tx
}

// startPeerCandidateProbes creates tuple-specific NAT state before the
// console's master-driven nomination reaches us, then keeps pinging at a
// slower cadence until stop() is called so a slow nomination doesn't let the
// NAT/relay mapping go stale before an endpoint is finally selected.
func startPeerCandidateProbes(s *udpSockets, candidates []candidate, secret string) func() {
	done := make(chan struct{})
	var stopOnce sync.Once
	var wg sync.WaitGroup
	stop := func() {
		stopOnce.Do(func() { close(done) })
		wg.Wait()
	}
	if s == nil || len(candidates) == 0 {
		return stop
	}

	send := func() {
		for _, candidate := range candidates {
			sendPeerCandidateProbe(s, candidate.Addr, secret)
		}
	}

	send()
	wg.Add(1)
	go func() {
		defer wg.Done()
		burstTicker := time.NewTicker(400 * time.Millisecond)
		burstDeadline := time.NewTimer(5 * time.Second)
	burst:
		for {
			select {
			case <-done:
				burstTicker.Stop()
				burstDeadline.Stop()
				return
			case <-burstDeadline.C:
				break burst
			case <-burstTicker.C:
				send()
			}
		}
		burstTicker.Stop()
		burstDeadline.Stop()
		keepAlive := time.NewTicker(5 * time.Second)
		defer keepAlive.Stop()
		for {
			select {
			case <-done:
				return
			case <-keepAlive.C:
				send()
			}
		}
	}()
	return stop
}

// sendPeerCandidateProbe refreshes the candidate's exact NAT/relay tuple and
// gives the console another authenticated STUN packet to answer before a
// WireGuard handshake is attempted on that endpoint.
func sendPeerCandidateProbe(s *udpSockets, addr, secret string) bool {
	if s == nil {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	conn, network := s.V6, "udp6"
	if ip.To4() != nil {
		conn, network = s.V4, "udp4"
	}
	if conn == nil {
		return false
	}
	remote, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return false
	}
	probe, _ := stunBindingProbe(secret)
	if _, err := conn.WriteToUDP(probe, remote); err != nil {
		appLog.Debug("candidate STUN probe failed", "candidate", addr, "network", network, "error", err)
		return false
	}
	appLog.Debug("sent candidate STUN probe", "candidate", addr, "network", network)
	return true
}

// setUDPReadDeadline applies t to both sockets, ignoring nils.
func setUDPReadDeadline(s *udpSockets, t time.Time) {
	if s.V4 != nil {
		_ = s.V4.SetReadDeadline(t)
	}
	if s.V6 != nil {
		_ = s.V6.SetReadDeadline(t)
	}
}

// readUDPPacket reads one datagram from conn, returning ok=false if done has
// fired or the read errored (e.g. from a deadline set by udpReadStopper.Stop).
func readUDPPacket(conn *net.UDPConn, done <-chan struct{}, buf []byte) (n int, addr *net.UDPAddr, ok bool) {
	select {
	case <-done:
		return 0, nil, false
	default:
	}
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return 0, nil, false
	}
	return n, addr, true
}

// udpReadStopper coordinates goroutines reading from up to two UDP sockets:
// Stop unblocks any goroutine parked in ReadFromUDP and waits for all of them
// to exit before returning, so they don't keep stealing packets from
// whichever reader (WireGuard's netstack, or the fallback probe) uses these
// sockets next. Safe to call more than once.
type udpReadStopper struct {
	sockets  *udpSockets
	done     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

func newUDPReadStopper(sockets *udpSockets) *udpReadStopper {
	return &udpReadStopper{sockets: sockets, done: make(chan struct{})}
}

// start launches fn as a tracked goroutine reading conn; a nil conn is a no-op.
func (u *udpReadStopper) start(conn *net.UDPConn, fn func(conn *net.UDPConn, done <-chan struct{})) {
	if conn == nil {
		return
	}
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		fn(conn, u.done)
	}()
}

func (u *udpReadStopper) Stop() {
	u.stopOnce.Do(func() {
		close(u.done)
		setUDPReadDeadline(u.sockets, time.Now())
		u.wg.Wait()
		setUDPReadDeadline(u.sockets, time.Time{})
	})
}

// earlyNominationListener answers the console's authenticated STUN Binding
// Requests as soon as they arrive on the outer UDP sockets, which may be well
// before CONNECT_RESPONSE: the console can complete its nomination wait
// sequence before the CONNECT poll loop even observes a response.
type earlyNominationListener struct {
	sockets    *udpSockets
	stunSecret string
	nomination *nominationTracker

	mu   sync.Mutex
	logs []packetLog

	allowed map[string]struct{}

	stop *udpReadStopper
}

func newEarlyNominationListener(sockets *udpSockets, stunSecret string, nomination *nominationTracker) *earlyNominationListener {
	return &earlyNominationListener{
		sockets:    sockets,
		stunSecret: stunSecret,
		nomination: nomination,
		stop:       newUDPReadStopper(sockets),
	}
}

// restrictToCandidates makes the listener ignore nomination traffic from
// every tuple except the supplied candidates. It must be called before Start.
// TURN-only mode uses this after CONNECT_RESPONSE reveals the relay tuples so
// a direct console candidate cannot win master nomination.
func (l *earlyNominationListener) restrictToCandidates(candidates []candidate) {
	l.allowed = make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		l.allowed[c.Addr] = struct{}{}
	}
}

func (l *earlyNominationListener) allows(addr string) bool {
	if l.allowed == nil {
		return true
	}
	_, ok := l.allowed[addr]
	return ok
}

// Start begins reading from every open outer socket. Each listener is
// single-shot: create a new one per connection attempt rather than
// restarting one that has been Stopped.
func (l *earlyNominationListener) Start() {
	l.stop.start(l.sockets.V4, l.readLoop)
	l.stop.start(l.sockets.V6, l.readLoop)
}

func (l *earlyNominationListener) readLoop(conn *net.UDPConn, done <-chan struct{}) {
	buf := make([]byte, 1500)
	for {
		n, addr, ok := readUDPPacket(conn, done, buf)
		if !ok {
			return
		}
		data := append([]byte(nil), buf[:n]...)
		if !l.allows(addr.String()) {
			appLog.Debug("ignored nomination from disallowed candidate", "remote", addr.String())
			continue
		}
		l.appendLog(logPacket("in", addr, data))
		msg, ok := parseStunMessage(data)
		if !ok || msg.Type != stun.BindingRequest {
			continue
		}
		resp, accepted := respondToStunBindingRequest(conn, msg, addr, l.stunSecret, l.nomination)
		if !accepted {
			continue
		}
		if resp != nil {
			l.appendLog(logPacket("out", addr, resp))
		}
	}
}

// maxEarlyNominationLogs bounds the packet log so a connection attempt stuck
// retrying candidates for a long time can't grow this without limit; the
// oldest entries are dropped first.
const maxEarlyNominationLogs = 500

func (l *earlyNominationListener) appendLog(p packetLog) {
	l.mu.Lock()
	if len(l.logs) >= maxEarlyNominationLogs {
		l.logs = l.logs[1:]
	}
	l.logs = append(l.logs, p)
	l.mu.Unlock()
}

// Stop unblocks any goroutine parked in ReadFromUDP and waits for it to exit
// before returning, so it doesn't keep stealing packets from whichever reader
// (WireGuard's netstack, or the fallback probe) uses these sockets next. Safe
// to call more than once.
func (l *earlyNominationListener) Stop() {
	l.stop.Stop()
}

// Logs returns a snapshot of packets observed so far.
func (l *earlyNominationListener) Logs() []packetLog {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]packetLog(nil), l.logs...)
}

func stunNominationWait(msg *stun.Message) (int, bool) {
	raw, err := msg.Get(stun.AttrData)
	if err != nil {
		return 0, false
	}
	var payload struct {
		Wait int `json:"wait"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return 0, false
	}
	return payload.Wait, true
}

func rankCandidates(c []candidate) []candidate {
	out := append([]candidate(nil), c...)
	score := func(c candidate) int {
		ap, _ := netip.ParseAddrPort(c.Addr)
		s := 100
		switch c.Type {
		case "iface":
			s = 0
		case "reflex":
			s = 10
		case "turn":
			s = 20
		}
		if ap.Addr().Is6() {
			s -= 2
		}
		return s
	}
	sort.SliceStable(out, func(i, j int) bool { return score(out[i]) < score(out[j]) })
	return out
}

func probeCandidates(s *udpSockets, cands []candidate, sessionSecret string, local []candidate) string {
	ordered := compatibleCandidates(s, cands, local)
	appLog.Debug("fallback probe starting", "candidates", len(ordered))
	if s == nil || len(ordered) == 0 {
		return guessCandidate(ordered)
	}

	type target struct {
		addr   string
		remote *net.UDPAddr
		conn   *net.UDPConn
	}
	var targets []target
	rankByRemote := make(map[string]int, len(ordered))
	for _, c := range ordered {
		ap, err := netip.ParseAddrPort(c.Addr)
		if err != nil {
			continue
		}
		conn := s.V4
		if ap.Addr().Is6() {
			conn = s.V6
		}
		if conn == nil {
			continue
		}
		remote := net.UDPAddrFromAddrPort(ap)
		targets = append(targets, target{addr: c.Addr, remote: remote, conn: conn})
		rankByRemote[remote.String()] = len(targets) - 1
	}

	if len(targets) == 0 {
		return guessCandidate(ordered)
	}

	type responsePacket struct {
		remote *net.UDPAddr
	}
	responses := make(chan responsePacket, len(targets)+4)
	readResponses := func(conn *net.UDPConn, done <-chan struct{}) {
		buf := make([]byte, 1500)
		for {
			_, addr, ok := readUDPPacket(conn, done, buf)
			if !ok {
				return
			}
			select {
			case responses <- responsePacket{remote: addr}:
			case <-done:
				return
			}
		}
	}
	reader := newUDPReadStopper(s)
	reader.start(s.V4, readResponses)
	reader.start(s.V6, readResponses)
	defer reader.Stop()

	for _, t := range targets {
		req, _ := stunBindingProbe(sessionSecret)
		_, _ = t.conn.WriteToUDP(req, t.remote)
		appLog.Debug("fallback probe sent", "candidate", t.addr)
	}

	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()

	bestRank := -1
	var graceTimer *time.Timer
	var graceCh <-chan time.Time
	selectBest := func() (string, bool) {
		if bestRank >= 0 {
			return targets[bestRank].addr, true
		}
		return "", false
	}

	for {
		select {
		case resp := <-responses:
			if rank, ok := rankByRemote[resp.remote.String()]; ok {
				matchedAddr := targets[rank].addr
				if rank == 0 {
					// Top-ranked candidate answered; nothing can beat it.
					appLog.Debug("fallback probe result", "candidate", matchedAddr, "matched", true, "rank", 0)
					return matchedAddr
				}
				if bestRank == -1 || rank < bestRank {
					bestRank = rank
					appLog.Debug("fallback probe candidate responded", "candidate", matchedAddr, "rank", rank)
					if graceTimer == nil {
						graceTimer = time.NewTimer(60 * time.Millisecond)
						defer graceTimer.Stop()
						graceCh = graceTimer.C
					}
				}
			}
		case <-graceCh:
			if selected, ok := selectBest(); ok {
				appLog.Debug("fallback probe result after grace period", "candidate", selected, "matched", true, "rank", bestRank)
				return selected
			}
		case <-timer.C:
			if selected, ok := selectBest(); ok {
				appLog.Debug("fallback probe result", "candidate", selected, "matched", true, "rank", bestRank)
				return selected
			}
			appLog.Debug("fallback probe timed out; falling back to guess")
			return guessCandidate(ordered)
		}
	}
}

func guessCandidate(ordered []candidate) string {
	// Nothing answered; guess. Prefer a publicly routable candidate
	// (reflex/turn) over a private/loopback/link-local iface address,
	// which is almost certainly unreachable unless we share the peer's LAN.
	for _, c := range ordered {
		if isPubliclyRoutableCandidateAddr(c.Addr) {
			return c.Addr
		}
	}
	if len(ordered) > 0 {
		return ordered[0].Addr
	}
	return ""
}

func isPubliclyRoutableCandidateAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate()
}

// compatibleCandidates drops peer candidates that cannot be reached through
// one of our open sockets, or whose family we never found a real local
// candidate for -- an open socket alone doesn't mean that family actually
// routes anywhere (e.g. dual-stack opens a v6 socket even on an IPv4-only
// host). In particular, a -4 run must never fall back to an IPv6 candidate
// merely because IPv6 has a higher generic ranking.
func compatibleCandidates(s *udpSockets, cands []candidate, local []candidate) []candidate {
	if s == nil {
		return nil
	}
	haveLocalV4, haveLocalV6 := localCandidateFamilies(local)
	var compatible []candidate
	for _, c := range cands {
		host, _, err := net.SplitHostPort(c.Addr)
		if err != nil {
			continue
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip == nil {
			continue
		}
		if ip.To4() != nil && s.V4 != nil && haveLocalV4 || ip.To4() == nil && s.V6 != nil && haveLocalV6 {
			compatible = append(compatible, c)
		}
	}
	return rankCandidates(compatible)
}

func localCandidateFamilies(local []candidate) (haveV4, haveV6 bool) {
	for _, c := range local {
		if haveV4 && haveV6 {
			return
		}
		host, _, err := net.SplitHostPort(c.Addr)
		if err != nil {
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			haveV4 = true
		} else {
			haveV6 = true
		}
	}
	return
}
