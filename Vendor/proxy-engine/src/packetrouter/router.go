// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

// Package packetrouter routes a stable capture interface to independent raw-IP
// VPN ports. It never opens a physical socket or falls back to Direct. Existing
// flows retain their policy decision and port generation until they expire.
package packetrouter

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"
)

type Port struct {
	ID         string
	Generation uint64
	Addresses  []netip.Addr
	Allowed    []netip.Prefix
	MTU        int
	Send       func([]byte) bool
}

type Rule struct {
	Prefix netip.Prefix
	Port   string
}
type Policy struct {
	Revision uint64
	Rules    []Rule
	Default  string
}
type Status struct {
	Revision   uint64            `json:"revision"`
	Flows      int               `json:"flows"`
	PacketsOut uint64            `json:"packetsOut"`
	PacketsIn  uint64            `json:"packetsIn"`
	Drops      map[string]uint64 `json:"drops"`
}

type tuple struct {
	src, dst         netip.Addr
	srcPort, dstPort uint16
	protocol         uint8
}
type reverseKey struct {
	tuple      tuple
	port       string
	generation uint64
}
type flow struct {
	key        tuple
	reverse    reverseKey
	port       string
	generation uint64
	translated netip.Addr
	lastSeen   time.Time
	syn        uint32
	fin        uint8
	closingAt  time.Time
}

type Router struct {
	mu        sync.Mutex
	capture   map[netip.Addr]bool
	ports     map[string]Port
	policy    Policy
	flows     map[tuple]*flow
	reverse   map[reverseKey]*flow
	output    func([]byte)
	now       func() time.Time
	maxFlows  int
	lastGC    time.Time
	fragments reassembler
	closed    bool
	stats     Status
}

func New(capture []netip.Addr, ports []Port, policy Policy, output func([]byte)) (*Router, error) {
	if output == nil || len(capture) == 0 {
		return nil, errors.New("capture addresses and packet output are required")
	}
	r := &Router{capture: make(map[netip.Addr]bool), ports: make(map[string]Port),
		flows: make(map[tuple]*flow), reverse: make(map[reverseKey]*flow), output: output,
		now: time.Now, maxFlows: 8192, stats: Status{Drops: make(map[string]uint64)}}
	for _, address := range capture {
		if !address.IsGlobalUnicast() || address.Is4In6() {
			return nil, errors.New("invalid capture address")
		}
		r.capture[address] = true
	}
	for _, port := range ports {
		if _, duplicate := r.ports[port.ID]; duplicate {
			return nil, errors.New("duplicate VPN port")
		}
		if err := r.validatePort(port); err != nil {
			return nil, err
		}
		r.ports[port.ID] = clonePort(port)
	}
	if err := r.compile(policy); err != nil {
		return nil, err
	}
	return r, nil
}

func clonePort(p Port) Port {
	p.Addresses = append([]netip.Addr(nil), p.Addresses...)
	p.Allowed = append([]netip.Prefix(nil), p.Allowed...)
	return p
}

func (r *Router) validatePort(p Port) error {
	if p.ID == "" || p.Generation == 0 || p.Send == nil || len(p.Addresses) == 0 || p.MTU < 576 || p.MTU > 65535 {
		return errors.New("invalid VPN port")
	}
	for _, address := range p.Addresses {
		if !address.IsGlobalUnicast() || address.Is4In6() || r.capture[address] || address.Is6() && p.MTU < 1280 {
			return fmt.Errorf("invalid or conflicting assigned address for VPN %s", p.ID)
		}
	}
	for _, prefix := range p.Allowed {
		if !prefix.IsValid() || prefix != prefix.Masked() {
			return errors.New("invalid allowed prefix")
		}
	}
	return nil
}

// Coverage includes paired /1 defaults without authorizing a prefix the peer
// cannot carry. Recursion visits only branches overlapping an allowed prefix.
func covers(prefix netip.Prefix, allowed []netip.Prefix) bool {
	var overlaps []netip.Prefix
	for _, candidate := range allowed {
		if candidate.Addr().BitLen() != prefix.Addr().BitLen() {
			continue
		}
		if candidate.Bits() <= prefix.Bits() && candidate.Contains(prefix.Addr()) {
			return true
		}
		if candidate.Overlaps(prefix) {
			overlaps = append(overlaps, candidate)
		}
	}
	if len(overlaps) == 0 || prefix.Bits() == prefix.Addr().BitLen() {
		return false
	}
	b := append([]byte(nil), prefix.Addr().AsSlice()...)
	bit := prefix.Bits()
	b[bit/8] |= 1 << (7 - bit%8)
	other, _ := netip.AddrFromSlice(b)
	return covers(netip.PrefixFrom(prefix.Addr(), bit+1), overlaps) && covers(netip.PrefixFrom(other, bit+1), overlaps)
}

func (r *Router) compile(policy Policy) error {
	if policy.Revision == 0 || policy.Revision <= r.policy.Revision || len(policy.Rules) > 4096 {
		return errors.New("invalid or stale routing policy revision")
	}
	if policy.Default != "" {
		port, ok := r.ports[policy.Default]
		if !ok {
			return errors.New("default VPN is unavailable")
		}
		if !covers(netip.MustParsePrefix("0.0.0.0/0"), port.Allowed) && !covers(netip.MustParsePrefix("::/0"), port.Allowed) {
			return errors.New("default VPN cannot carry a default route")
		}
	}
	policy.Rules = append([]Rule(nil), policy.Rules...)
	for _, rule := range policy.Rules {
		port, ok := r.ports[rule.Port]
		if !ok || !rule.Prefix.IsValid() || rule.Prefix != rule.Prefix.Masked() || !covers(rule.Prefix, port.Allowed) {
			return fmt.Errorf("route is outside VPN %s's authorized prefixes", rule.Port)
		}
	}
	// Stable ties preserve the caller's deliberate precedence for overlap.
	sort.SliceStable(policy.Rules, func(i, j int) bool { return policy.Rules[i].Prefix.Bits() > policy.Rules[j].Prefix.Bits() })
	r.policy = policy
	return nil
}

func (r *Router) Apply(policy Policy) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("routing session stopped")
	}
	return r.compile(policy)
}

// Check validates a proposed revision without publishing it. The capture owner
// uses this before installing OS settings, then publishes after the OS ack.
func (r *Router) Check(policy Policy) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("routing session stopped")
	}
	trial := &Router{ports: r.ports, policy: r.policy}
	return trial.compile(policy)
}

func (r *Router) RemovePort(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.ports, id)
	// Keep tombstones for established flows: removing their decision would let
	// a retransmission escape through a newly selected VPN.
}

func (r *Router) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.fragments.close()
	r.ports = make(map[string]Port)
	r.flows = make(map[tuple]*flow)
	r.reverse = make(map[reverseKey]*flow)
}

func (r *Router) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.stats
	out.Revision, out.Flows = r.policy.Revision, len(r.flows)
	out.Drops = make(map[string]uint64)
	for reason, count := range r.stats.Drops {
		out.Drops[reason] = count
	}
	return out
}

func (r *Router) drop(reason string) bool { r.stats.Drops[reason]++; return false }
func key(p packet) tuple                  { return tuple{p.src, p.dst, p.srcPort, p.dstPort, p.protocol} }
func flipped(k tuple) tuple               { return tuple{k.dst, k.src, k.dstPort, k.srcPort, k.protocol} }

func (r *Router) expire() {
	now := r.now()
	if now.Sub(r.lastGC) < time.Second {
		return
	}
	r.lastGC = now
	for k, f := range r.flows {
		ttl := 2 * time.Minute
		if k.protocol == 6 {
			ttl = 30 * time.Minute
		}
		if now.Sub(f.lastSeen) > ttl || (!f.closingAt.IsZero() && now.Sub(f.closingAt) > 2*time.Minute) {
			delete(r.flows, k)
			delete(r.reverse, f.reverse)
		}
	}
}

// Forward accepts only the session's capture sources. A missing decision,
// unavailable/unsupported egress, bad packet or queue pressure drops explicitly.
func (r *Router) Forward(raw []byte) bool {
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return false
	}
	normalized, original, pending, normalizationError := r.fragments.accept(raw, "capture")
	if pending {
		return true
	}
	p, err := parse(bytes.Clone(normalized), false)
	if normalizationError != nil {
		err = normalizationError
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return false
	}
	if err != nil {
		result := r.drop(err.Error())
		r.mu.Unlock()
		return result
	}
	if !r.capture[p.src] {
		result := r.drop("unknown capture source")
		r.mu.Unlock()
		return result
	}
	if p.icmpError {
		return r.forwardError(p)
	}
	r.expire()
	k := key(p)
	f := r.flows[k]
	// A retransmitted SYN belongs to the existing flow. A different initial
	// sequence number starts a new connection and gets today's policy.
	if f != nil && p.protocol == 6 && p.raw[p.transport+13]&0x12 == 0x02 && binary.BigEndian.Uint32(p.raw[p.transport+4:]) != f.syn {
		delete(r.flows, k)
		delete(r.reverse, f.reverse)
		f = nil
	}
	if f == nil {
		if p.protocol == 6 && p.raw[p.transport+13]&0x12 != 0x02 {
			result := r.drop("TCP flow has no opening SYN")
			r.mu.Unlock()
			return result
		}
		if len(r.flows) >= r.maxFlows {
			result := r.drop("flow table full")
			r.mu.Unlock()
			return result
		}
		id := r.policy.Default
		for _, rule := range r.policy.Rules {
			if rule.Prefix.Contains(p.dst) {
				id = rule.Port
				break
			}
		}
		port, ok := r.ports[id]
		if !ok {
			result := r.drop("selected VPN unavailable")
			r.mu.Unlock()
			return result
		}
		var source netip.Addr
		for _, address := range port.Addresses {
			if address.Is4() == p.src.Is4() {
				source = address
				break
			}
		}
		if !source.IsValid() || !covers(netip.PrefixFrom(p.dst, p.dst.BitLen()), port.Allowed) {
			result := r.drop("selected VPN cannot carry this destination")
			r.mu.Unlock()
			return result
		}
		translatedKey := k
		translatedKey.src = source
		f = &flow{key: k, port: id, generation: port.Generation, translated: source,
			reverse: reverseKey{flipped(translatedKey), id, port.Generation}}
		if _, collision := r.reverse[f.reverse]; collision {
			result := r.drop("translated tuple collision")
			r.mu.Unlock()
			return result
		}
		if p.protocol == 6 {
			f.syn = binary.BigEndian.Uint32(p.raw[p.transport+4:])
		}
		r.flows[k], r.reverse[f.reverse] = f, f
	}
	port, ok := r.ports[f.port]
	if !ok || port.Generation != f.generation {
		result := r.drop("pinned VPN stopped")
		r.mu.Unlock()
		return result
	}
	f.lastSeen = r.now()
	f.observeTCP(p, 1, r.now())
	// Build feedback from the original capture addresses, before translating.
	var tooBig []byte
	if len(p.raw) > port.MTU {
		tooBig = mtuError(p, port.MTU)
	}
	p.replaceAddress(true, f.translated)
	p.fixTransportChecksum()
	packets, fragmentationError := fragmentPacket(p, port.MTU, original)
	if fragmentationError != nil {
		r.drop("packet exceeds VPN MTU")
		r.mu.Unlock()
		r.output(tooBig)
		return false
	}
	r.mu.Unlock()
	accepted := true
	for _, packet := range packets {
		if !port.Send(packet) {
			accepted = false
		}
	}
	r.mu.Lock()
	if accepted {
		r.stats.PacketsOut++
	} else {
		r.drop("VPN packet queue full")
	}
	r.mu.Unlock()
	return accepted
}

// Return's port and generation are mandatory. Identical remote addresses and
// translated tuples in two VPNs must never share a reverse mapping.
func (r *Router) Return(id string, generation uint64, raw []byte) bool {
	r.mu.Lock()
	port, active := r.ports[id]
	if r.closed || !active || port.Generation != generation {
		result := r.drop("stale VPN packet")
		r.mu.Unlock()
		return result
	}
	r.mu.Unlock()
	normalized, _, pending, normalizationError := r.fragments.accept(raw, fmt.Sprintf("VPN:%d:%s:%d", len(id), id, generation))
	if pending {
		return true
	}
	p, err := parse(bytes.Clone(normalized), false)
	if normalizationError != nil {
		err = normalizationError
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return false
	}
	port, active = r.ports[id]
	if !active || port.Generation != generation {
		result := r.drop("stale VPN packet")
		r.mu.Unlock()
		return result
	}
	if err != nil {
		result := r.drop(err.Error())
		r.mu.Unlock()
		return result
	}
	r.expire()
	if p.icmpError {
		return r.returnError(id, generation, p)
	}
	f := r.reverse[reverseKey{key(p), id, generation}]
	if f == nil {
		result := r.drop("unsolicited VPN packet")
		r.mu.Unlock()
		return result
	}
	f.lastSeen = r.now()
	f.observeTCP(p, 2, r.now())
	p.replaceAddress(false, f.key.src)
	p.fixTransportChecksum()
	r.stats.PacketsIn++
	r.mu.Unlock()
	r.output(p.raw)
	return true
}

// Both helpers enter with mu held and release it on every path. ICMP errors
// route by the quoted established flow, never by the ICMP sender's address.
func (r *Router) returnError(id string, generation uint64, outer packet) bool {
	quoted, err := parse(outer.raw[outer.transport+8:], true)
	if err != nil {
		result := r.drop("invalid ICMP quote")
		r.mu.Unlock()
		return result
	}
	f := r.reverse[reverseKey{flipped(key(quoted)), id, generation}]
	if f == nil || outer.dst != f.translated {
		result := r.drop("unmatched ICMP quote")
		r.mu.Unlock()
		return result
	}
	quoted.replaceAddress(true, f.key.src)
	outer.replaceAddress(false, f.key.src)
	outer.fixTransportChecksum()
	r.stats.PacketsIn++
	r.mu.Unlock()
	r.output(outer.raw)
	return true
}

func (r *Router) forwardError(outer packet) bool {
	quoted, err := parse(outer.raw[outer.transport+8:], true)
	if err != nil {
		result := r.drop("invalid ICMP quote")
		r.mu.Unlock()
		return result
	}
	f := r.flows[flipped(key(quoted))]
	if f == nil {
		result := r.drop("unmatched ICMP quote")
		r.mu.Unlock()
		return result
	}
	port, ok := r.ports[f.port]
	if !ok || port.Generation != f.generation {
		result := r.drop("pinned VPN stopped")
		r.mu.Unlock()
		return result
	}
	quoted.replaceAddress(false, f.translated)
	outer.replaceAddress(true, f.translated)
	outer.fixTransportChecksum()
	if len(outer.raw) > port.MTU {
		result := r.drop("ICMP error exceeds VPN MTU")
		r.mu.Unlock()
		return result
	}
	f.lastSeen = r.now()
	r.mu.Unlock()
	accepted := port.Send(outer.raw)
	r.mu.Lock()
	if accepted {
		r.stats.PacketsOut++
	} else {
		r.drop("VPN packet queue full")
	}
	r.mu.Unlock()
	return accepted
}

func (f *flow) observeTCP(p packet, direction uint8, now time.Time) {
	if p.protocol != 6 {
		return
	}
	flags := p.raw[p.transport+13]
	if flags&1 != 0 {
		f.fin |= direction
	}
	if (flags&4 != 0 || f.fin == 3) && f.closingAt.IsZero() {
		f.closingAt = now
	}
}
