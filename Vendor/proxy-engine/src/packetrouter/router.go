// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

// Package packetrouter routes a stable capture interface to independent raw-IP
// VPN ports. It never opens a physical socket or falls back to Direct. Existing
// flows retain their policy decision and port generation until they expire.
package packetrouter

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"pxengine/routelang"
)

type Port struct {
	Kind string
	// Optional profile-local policy attaches immediately inside the carrier boundary.
	Policy     *RawPacketPolicy
	ID         string
	Generation uint64
	ExitNodeID string
	Addresses  []netip.Addr
	Allowed    []netip.Prefix
	MTU        int
	// Send receives an owned packet and may retain it after returning.
	Send         func([]byte) bool
	allowedHosts *DestinationTable
}

func (p Port) eventContext(d Direction, source observed[string]) packetContext {
	return packetContext{direction: d, source: source, member: p.ID, profile: p.ID, kind: p.Kind, generation: p.Generation}
}

// An exit carries traffic using the tailnet default. More-specific peers or
// subnet routes can carry other traffic on the same authenticated member.
func (p Port) exitFor(destination netip.Addr) string {
	if p.ExitNodeID == "" {
		return ""
	}
	if p.allowedHosts != nil {
		if matched, ok := p.allowedHosts.Lookup(destination); ok && matched.Prefix.Bits() == 0 {
			return p.ExitNodeID
		}
		return ""
	}
	hasDefault := false
	for _, prefix := range p.Allowed {
		if prefix.Contains(destination) {
			if prefix.Bits() > 0 {
				return ""
			}
			hasDefault = true
		}
	}
	if hasDefault {
		return p.ExitNodeID
	}
	return ""
}

type exitSelection struct {
	router       *Router
	baseline     Port
	destination  netip.Addr
	sourceScoped bool
	chosen       Port
	failure      string
}

func (s *exitSelection) choose(id string) error {
	if s.chosen.ID != "" {
		if s.chosen.ExitNodeID == id {
			return nil
		}
		return errors.New("conflicting exit nodes selected")
	}
	if s.baseline.Send == nil || !s.baseline.allowsHost(s.destination) {
		return errors.New("the captured destination has no authorized VPN")
	}
	if s.sourceScoped {
		if s.baseline.exitFor(s.destination) != id {
			return errors.New("the application's route does not authorize this exit node")
		}
		s.chosen = s.baseline
		return nil
	}
	var selected Port
	for _, port := range s.router.ports {
		if port.Send == nil || port.ExitNodeID != id || port.exitFor(s.destination) != id {
			continue
		}
		if selected.ID != "" {
			return errors.New("exit node matches multiple connected VPNs")
		}
		selected = port
	}
	if selected.ID == "" {
		return errors.New("exit node is unavailable for this destination")
	}
	s.chosen = selected
	return nil
}

type Rule struct {
	Prefix netip.Prefix `json:"prefix"`
	Port   string       `json:"port"`
}
type SourceRule struct {
	Source       string `json:"source"`
	Port         string `json:"port"`
	Destinations []Rule `json:"destinations,omitempty"`
}

type sourceSelection struct {
	base      string
	overrides DestinationTable
}

type Policy struct {
	Revision    uint64
	EventSource string
	SourceRules []SourceRule // nil for destination capture; an empty list denies all sources.
	Rules       []Rule
	Default     string
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
	submissions    uint32
	seenInboundUDP bool
	id, revision   uint64
	firstSeen      time.Time
	rule           *ruleCounter
	counts         TrafficCounters
	captureSource  netip.Addr
	reverse        reverseKey
	port           string
	exitNode       string
	generation     uint64
	translated     netip.Addr
	lastSeen       time.Time
	syn            uint32
	fin            uint8
	blocked        bool
	closingAt      time.Time
	owner          uint64
	source         string
}

type Router struct {
	packetMetrics             packetMetrics
	events                    *EventProgram
	evidence                  *inspectorEvidence
	ruleCounters              map[ruleKey]*ruleCounter
	nextRule, nextFlow        uint64
	unmatched, defaultCounter *ruleCounter
	mu                        sync.Mutex
	capture                   map[netip.Addr]bool
	ports                     map[string]Port
	policy                    Policy
	destinations              DestinationTable
	sources                   map[string]*sourceSelection
	flows                     map[tuple]*flow
	reverse                   map[reverseKey]*flow
	output                    func([]byte)
	now                       func() time.Time
	maxFlows                  int
	lastGC                    time.Time
	fragments                 reassembler
	closed                    bool
	stats                     Status
}

func New(capture []netip.Addr, ports []Port, policy Policy, output func([]byte)) (*Router, error) {
	if output == nil || len(capture) == 0 {
		return nil, errors.New("capture addresses and packet output are required")
	}
	r := &Router{packetMetrics: packetMetrics{session: rand.Text()}, capture: make(map[netip.Addr]bool), ports: make(map[string]Port),
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
	if len(p.Allowed) > linearPrefixLimit {
		rules := make([]Rule, len(p.Allowed))
		for i, prefix := range p.Allowed {
			rules[i].Prefix = prefix
		}
		index := CompileDestinations(rules)
		p.allowedHosts = &index
	}
	return p
}

// Host admission only needs membership. Whole routes still require covers to
// prove that the union of allowed prefixes includes every address in the route.
func (p *Port) allowsHost(address netip.Addr) bool {
	if p.allowedHosts != nil {
		_, allowed := p.allowedHosts.Lookup(address)
		return allowed
	}
	for _, prefix := range p.Allowed {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
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
	if p.ExitNodeID != "" {
		if p.Kind != "tailscale" || !routelang.ValidExitNodeID(p.ExitNodeID) {
			return errors.New("invalid exit node on VPN port")
		}
		hasDefault := false
		for _, prefix := range p.Allowed {
			hasDefault = hasDefault || prefix.Bits() == 0
		}
		if !hasDefault {
			return errors.New("exit node VPN has no authenticated default route")
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
	if policy.Revision == 0 || policy.Revision <= r.policy.Revision || len(policy.Rules)+len(policy.SourceRules) > 4096 {
		return errors.New("invalid or stale routing policy revision")
	}
	if r.policy.Revision != 0 && (r.sources != nil) != (policy.SourceRules != nil) {
		return errors.New("cannot change the capture attribution mode of a running session")
	}
	var sources map[string]*sourceSelection
	if policy.SourceRules != nil {
		if policy.Default != "" || len(policy.Rules) != 0 {
			return errors.New("source capture does not accept a destination fallback")
		}
		sources = make(map[string]*sourceSelection, len(policy.SourceRules))
		count := len(policy.SourceRules)
		for _, rule := range policy.SourceRules {
			if _, known := r.ports[rule.Port]; !known || rule.Source == "" || len(rule.Source) > 256 {
				return errors.New("invalid source rule or unknown VPN")
			}
			if _, duplicate := sources[rule.Source]; duplicate {
				return errors.New("duplicate source rule")
			}
			count += len(rule.Destinations)
			if count > 4096 {
				return errors.New("source policy exceeds 4096 rules")
			}
			seen := make(map[netip.Prefix]bool, len(rule.Destinations))
			for _, override := range rule.Destinations {
				prefix := override.Prefix
				if _, known := r.ports[override.Port]; !known || !prefix.IsValid() || prefix.Addr().Is4In6() || prefix != prefix.Masked() || seen[prefix] {
					return errors.New("invalid or duplicate source destination override")
				}
				seen[prefix] = true
			}
			sources[rule.Source] = &sourceSelection{base: rule.Port, overrides: CompileDestinations(rule.Destinations)}
		}
	}
	if policy.Default != "" {
		// A known, stopped default keeps its capture claim. Forward still requires
		// an active port, so losing it between Check and Apply cannot release capture.
		port, ok := r.ports[policy.Default]
		if !ok {
			return errors.New("default VPN is unknown")
		}
		if !covers(netip.MustParsePrefix("0.0.0.0/0"), port.Allowed) && !covers(netip.MustParsePrefix("::/0"), port.Allowed) {
			return errors.New("default VPN cannot carry a default route")
		}
	}
	for _, rule := range policy.Rules {
		port, ok := r.ports[rule.Port]
		if !ok || !rule.Prefix.IsValid() || rule.Prefix.Addr().Is4In6() || rule.Prefix != rule.Prefix.Masked() || !covers(rule.Prefix, port.Allowed) {
			return fmt.Errorf("route is outside VPN %s's authorized prefixes", rule.Port)
		}
	}
	events := r.events
	if r.policy.Revision == 0 || policy.EventSource != r.policy.EventSource {
		var err error
		events, err = CompileEvents(policy.EventSource)
		if err != nil {
			return err
		}
		// Carry matched handler totals across a program replacement when its
		// stable handler ID remains present in the incoming program.
		if r.events != nil {
			for _, ev := range r.events.InspectionCounters() {
				if row := r.ruleCounters[ruleKey{kind: "event", event: ev.ID}]; row != nil {
					row.PacketsOut += ev.PacketsOut
					row.PacketsIn += ev.PacketsIn
					row.BytesOut += ev.BytesOut
					row.BytesIn += ev.BytesIn
					row.Drops += ev.Drops
				}
			}
		}
	}
	r.publishRuleCounters(policy, events)
	r.events = events
	if sources != nil {
		// Keep reverse reservations as tombstones. A late reply to a revoked
		// mapping must not become a reply to a different process.
		for _, f := range r.flows {
			if sources[f.source] == nil {
				f.blocked = true
			}
		}
	}
	r.sources = sources
	policy.SourceRules = nil
	r.destinations = CompileDestinations(policy.Rules)
	policy.Rules = append([]Rule(nil), policy.Rules...) // Revalidate every declared claim on port replacement.
	r.policy = policy
	return nil
}

func (r *Router) Apply(policy Policy) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("routing session stopped")
	}
	previous := r.events
	err := r.compile(policy)
	if r.events != previous {
		previous.Close()
	}
	return err
}

// Check validates a proposed revision without publishing it. The capture owner
// uses this before installing OS settings, then publishes after the OS ack.
func (r *Router) Check(policy Policy) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("routing session stopped")
	}
	trial := &Router{ports: r.ports, policy: r.policy, sources: r.sources, events: r.events}
	err := trial.compile(policy)
	if trial.events != r.events {
		trial.events.Close()
	}
	return err
}

// Call with mu held. A stopped member retains its authorized prefix claims for
// policy validation but releases its engine callback immediately.
func (r *Router) activePort(id string) (Port, bool) {
	port := r.ports[id]
	return port, port.Send != nil
}

func (r *Router) RemovePort(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if port, ok := r.ports[id]; ok {
		port.Send = nil
		port.allowedHosts = nil
		r.ports[id] = port
	}
}

// ReplacePort installs a newly authenticated generation after explicit revocation.
// Existing NAT entries remain bound to the old generation until they expire.
func (r *Router) ReplacePort(oldGeneration uint64, next Port) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	old, ok := r.ports[next.ID]
	if r.closed || !ok || old.Send != nil || old.Generation != oldGeneration || next.Generation <= oldGeneration {
		return errors.New("VPN port generation is not eligible for replacement")
	}
	if next.MTU != old.MTU {
		return errors.New("reconnect capture before changing the VPN port MTU")
	}
	next.Policy, next.Kind = old.Policy, old.Kind
	if err := r.validatePort(next); err != nil {
		return err
	}
	if r.policy.Default == next.ID && !covers(netip.MustParsePrefix("0.0.0.0/0"), next.Allowed) && !covers(netip.MustParsePrefix("::/0"), next.Allowed) {
		return errors.New("negotiated VPN cannot carry the active default route")
	}
	for _, rule := range r.policy.Rules {
		if rule.Port == next.ID && !covers(rule.Prefix, next.Allowed) {
			return errors.New("negotiated VPN cannot carry the active prefix")
		}
	}
	r.ports[next.ID] = clonePort(next)
	return nil
}

func (r *Router) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.events.Close()
	r.stopEvidenceLocked()
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

func (r *Router) drop(reason string) bool { return r.reject(reason, nil, nil) }
func key(p packet) tuple                  { return tuple{p.src, p.dst, p.srcPort, p.dstPort, p.protocol} }
func flipped(k tuple) tuple               { return tuple{k.dst, k.src, k.dstPort, k.srcPort, k.protocol} }

func (r *Router) expire(now time.Time) {
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
	return r.forward(raw, "", 0, false)
}

// ForwardWithSource accepts only a trusted alias resolved by the capture owner
// from this packet's OS metadata. owner is the kernel process incarnation.
func (r *Router) ForwardWithSource(raw []byte, source string, owner uint64) bool {
	return r.forward(raw, source, owner, true)
}

func (r *Router) forward(raw []byte, source string, owner uint64, requiresSource bool) (allowed bool) {
	defer func() {
		if !allowed {
			r.recordRawDrop(Outbound, len(raw))
		}
	}()
	r.mu.Lock()
	r.packetMetrics.dirs[Outbound].received(len(raw))
	closed := r.closed
	sourceScoped := r.sources != nil
	unauthorized := sourceScoped && (owner == 0 || r.sources[source] == nil)
	r.mu.Unlock()
	if closed {
		return false
	}
	if requiresSource && !sourceScoped {
		return false
	}
	// A capture fragment must only reassemble with fragments from the same
	// process and verified alias, including across policy edits.
	normalized := raw
	var original *fragmentMeta
	var normalizationError error
	if !unauthorized {
		var pending bool
		normalized, original, pending, normalizationError = r.fragments.accept(raw, fragmentScope{owner: owner, source: source})
		if pending {
			return true
		}
	}
	var p packet
	err := normalizationError
	if err == nil {
		p, err = parse(normalized, false)
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
	if unauthorized && owner != 0 && r.sources[source] != nil {
		result := r.drop("source authorization changed during admission")
		r.mu.Unlock()
		return result
	}
	if !r.capture[p.src] {
		result := r.drop("unknown capture source")
		r.mu.Unlock()
		return result
	}
	if p.icmpError {
		return r.forwardError(p, source, owner)
	}
	now := r.now()
	r.expire(now)
	k := key(p)
	f := r.flows[k]
	var selected *sourceSelection
	if sourceScoped {
		selected = r.sources[source]
		if f != nil && (f.owner != owner || f.blocked || selected == nil) {
			f.blocked = true
			result := r.reject("source flow ownership conflict", nil, f)
			r.mu.Unlock()
			return result
		}
		if owner == 0 || selected == nil {
			result := r.drop("unattributed or unauthorized source")
			r.mu.Unlock()
			return result
		}
	}
	// A retransmitted SYN belongs to the existing flow. A different initial
	// sequence number starts a new connection and gets today's policy.
	if f != nil && p.protocol == 6 && p.raw[p.transport+13]&0x12 == 0x02 && binary.BigEndian.Uint32(p.raw[p.transport+4:]) != f.syn {
		delete(r.flows, k)
		delete(r.reverse, f.reverse)
		f = nil
	}
	var decision *ruleCounter
	if f != nil {
		decision = f.rule
	} else if sourceScoped {
		key := ruleKey{kind: "source", source: source, port: selected.base}
		if hit, found := selected.overrides.Lookup(p.dst); found {
			key.kind, key.port, key.prefix = "override", hit.Port, hit.Prefix
		}
		decision = r.ruleCounters[key]
	} else if hit, found := r.destinations.Lookup(p.dst); found {
		decision = r.ruleCounters[ruleKey{kind: "destination", prefix: hit.Prefix, port: hit.Port}]
	} else {
		decision = r.defaultCounter
	}

	if f == nil {
		if p.protocol == 6 && p.raw[p.transport+13]&0x12 != 0x02 {
			result := r.reject("TCP flow has no opening SYN", decision, nil)
			r.mu.Unlock()
			return result
		}
		if len(r.flows) >= r.maxFlows {
			result := r.reject("flow table full", decision, nil)
			r.mu.Unlock()
			return result
		}
	}
	var portOverride string
	if r.events != nil && r.events.enabled[Outbound] {
		portID := decision.key.port
		if f != nil {
			portID = f.port
		}
		port := r.ports[portID]
		ctx := port.eventContext(Outbound, observed[string]{source, sourceScoped})
		if f != nil {
			ctx.exitNode = f.exitNode
		} else {
			ctx.exitNode = port.exitFor(p.dst)
			if r.events.selectExit {
				ctx.selection = &exitSelection{router: r, baseline: port, destination: p.dst, sourceScoped: sourceScoped}
			}
		}
		if !r.events.dispatch(&p, f == nil, ctx, &r.packetMetrics.dirs[Outbound]) {
			reason := "event policy drop"
			if ctx.selection != nil && ctx.selection.failure != "" {
				reason = ctx.selection.failure
			}
			result := r.reject(reason, decision, f)
			r.mu.Unlock()
			return result
		}
		if ctx.selection != nil && ctx.selection.chosen.ID != "" {
			portOverride = ctx.selection.chosen.ID
		}
	}
	if f == nil {
		id := decision.key.port
		if portOverride != "" {
			id = portOverride
		}
		port, ok := r.activePort(id)
		if !ok {
			result := r.reject("selected VPN unavailable", decision, nil)
			r.mu.Unlock()
			return result
		}
		var sourceIP netip.Addr
		for _, address := range port.Addresses {
			if address.Is4() == p.src.Is4() {
				sourceIP = address
				break
			}
		}
		if !sourceIP.IsValid() || !port.allowsHost(p.dst) {
			result := r.reject("selected VPN cannot carry this destination", decision, nil)
			r.mu.Unlock()
			return result
		}
		translatedKey := k
		translatedKey.src = sourceIP
		f = &flow{captureSource: k.src, owner: owner, source: source, port: id, generation: port.Generation, translated: sourceIP,
			exitNode: port.exitFor(p.dst),
			reverse:  reverseKey{flipped(translatedKey), id, port.Generation}}
		if _, collision := r.reverse[f.reverse]; collision {
			result := r.reject("translated tuple collision", decision, nil)
			r.mu.Unlock()
			return result
		}
		if p.protocol == 6 {
			f.syn = binary.BigEndian.Uint32(p.raw[p.transport+4:])
		}
		r.nextFlow++
		f.id, f.revision, f.firstSeen, f.rule = r.nextFlow, r.policy.Revision, now, decision
		r.flows[k], r.reverse[f.reverse] = f, f
		if r.evidence != nil {
			r.evidence.open(f, p.dst, now)
		}
	}
	port, ok := r.activePort(f.port)
	if !ok || port.Generation != f.generation {
		result := r.reject("pinned VPN stopped", nil, f)
		r.mu.Unlock()
		return result
	}
	f.lastSeen = now
	f.observeTCP(p, 1, now)
	// Build feedback from the original capture addresses, before translating.
	var tooBig []byte
	if len(p.raw) > port.MTU {
		tooBig = mtuError(p, port.MTU)
	}
	p.replaceAddress(true, f.translated)
	if port.Policy != nil && !port.Policy.Apply(Outbound, p.raw) {
		r.forgetUnsent(k, f)
		result := r.reject("member event policy drop", nil, f)
		r.mu.Unlock()
		return result
	}
	packets := [][]byte{p.raw}
	if len(p.raw) > port.MTU {
		var err error
		packets, err = fragmentPacket(p, port.MTU, original)
		if err != nil {
			r.reject("packet exceeds VPN MTU", nil, f)
			r.forgetUnsent(k, f)
			// Local PMTU feedback enters the capture endpoint without an inbound
			// member. Its destination policy runs before exposing the packet.
			inbound := &r.packetMetrics.dirs[Inbound]
			allowFeedback := true
			if r.events != nil && r.events.enabled[Inbound] {
				feedback, parseErr := parse(tooBig, false)
				allowFeedback = parseErr == nil && r.events.dispatch(&feedback, false, packetContext{direction: Inbound}, inbound)
			}
			inbound.finish(len(tooBig), allowFeedback)
			r.mu.Unlock()
			if allowFeedback {
				r.output(tooBig)
			}
			return false
		}
	}
	if r.evidence != nil {
		r.evidence.outbound(f, p, now)
	}
	f.submissions++
	r.mu.Unlock()
	var sent, bytes uint64
	for _, packet := range packets {
		if port.Send(packet) {
			sent++
			bytes += uint64(len(packet))
		}
	}
	r.mu.Lock()
	f.submissions--
	r.packetMetrics.dirs[Outbound].forward(sent, bytes)
	f.outbound(sent, bytes)
	if sent == 0 {
		r.forgetUnsent(k, f)
	}
	accepted := int(sent) == len(packets)
	if accepted {
		r.stats.PacketsOut++
	} else {
		for n := int(sent); n < len(packets); n++ {
			r.reject("VPN packet queue full", nil, f)
		}
	}
	r.mu.Unlock()
	return accepted
}

// A queue refusal or local policy/MTU rejection cannot authorize return traffic.
// An inline reply can arrive while the adapter is still submitting the packet.
func (r *Router) forgetUnsent(k tuple, f *flow) {
	if f.counts.PacketsOut != 0 || f.submissions != 0 || r.flows[k] != f {
		return
	}
	delete(r.flows, k)
	delete(r.reverse, f.reverse)
	if r.evidence != nil {
		delete(r.evidence.notes, f)
	}
}

// Return's port and generation are mandatory. Identical remote addresses and
// translated tuples in two VPNs must never share a reverse mapping.
func (r *Router) Return(id string, generation uint64, raw []byte) (allowed bool) {
	defer func() {
		if !allowed {
			r.recordRawDrop(Inbound, len(raw))
		}
	}()
	r.mu.Lock()
	r.packetMetrics.dirs[Inbound].received(len(raw))
	port, active := r.activePort(id)
	if r.closed || !active || port.Generation != generation {
		result := r.drop("stale VPN packet")
		r.mu.Unlock()
		return result
	}
	r.mu.Unlock()
	normalized, _, pending, normalizationError := r.fragments.accept(raw, fragmentScope{port: id, generation: generation})
	if pending {
		return true
	}
	var p packet
	err := normalizationError
	if err == nil {
		p, err = parse(normalized, false)
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return false
	}
	port, active = r.activePort(id)
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
	now := r.now()
	r.expire(now)
	if port.Policy != nil && !port.Policy.Apply(Inbound, p.raw) {
		result := r.drop("member event policy drop")
		r.mu.Unlock()
		return result
	}
	if p.icmpError {
		return r.returnError(id, generation, p)
	}
	f := r.reverse[reverseKey{key(p), id, generation}]
	if f == nil || f.blocked {
		result := r.reject("unsolicited VPN packet", nil, f)
		r.mu.Unlock()
		return result
	}
	if !r.inboundPolicy(&p, f) {
		result := r.reject("event policy drop", nil, f)
		r.mu.Unlock()
		return result
	}
	if p.protocol == 17 {
		f.seenInboundUDP = true
	}
	f.lastSeen = now
	f.observeTCP(p, 2, now)
	if r.evidence != nil {
		r.evidence.inbound(f, p, now)
	}
	p.replaceAddress(false, f.captureSource)
	r.packetMetrics.dirs[Inbound].finish(len(p.raw), true)
	f.inbound(len(p.raw))
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
	if f == nil || f.blocked || outer.dst != f.translated {
		result := r.reject("unmatched ICMP quote", nil, f)
		r.mu.Unlock()
		return result
	}
	if !r.inboundPolicy(&outer, f) {
		result := r.reject("event policy drop", nil, f)
		r.mu.Unlock()
		return result
	}
	quoted.replaceAddress(true, f.captureSource)
	outer.replaceAddress(false, f.captureSource)
	outer.fixTransportChecksum()
	f.lastSeen = r.now()
	r.packetMetrics.dirs[Inbound].finish(len(outer.raw), true)
	f.inbound(len(outer.raw))
	r.stats.PacketsIn++
	r.mu.Unlock()
	r.output(outer.raw)
	return true
}

func (r *Router) forwardError(outer packet, source string, owner uint64) bool {
	quoted, err := parse(outer.raw[outer.transport+8:], true)
	if err != nil {
		result := r.drop("invalid ICMP quote")
		r.mu.Unlock()
		return result
	}
	f := r.flows[flipped(key(quoted))]
	if f == nil || f.blocked || (r.sources != nil && (owner == 0 || f.owner != owner || r.sources[source] == nil)) {
		result := r.reject("unmatched ICMP quote", nil, f)
		r.mu.Unlock()
		return result
	}
	port, ok := r.activePort(f.port)
	if !ok || port.Generation != f.generation {
		result := r.reject("pinned VPN stopped", nil, f)
		r.mu.Unlock()
		return result
	}
	if r.events != nil && r.events.enabled[Outbound] && !r.events.dispatch(&outer, false, port.eventContext(Outbound, observed[string]{source, f.owner != 0}), &r.packetMetrics.dirs[Outbound]) {
		result := r.reject("event policy drop", nil, f)
		r.mu.Unlock()
		return result
	}
	quoted.replaceAddress(false, f.translated)
	outer.replaceAddress(true, f.translated)
	outer.fixTransportChecksum()
	if port.Policy != nil && !port.Policy.Apply(Outbound, outer.raw) {
		result := r.reject("member event policy drop", nil, f)
		r.mu.Unlock()
		return result
	}
	if len(outer.raw) > port.MTU {
		result := r.reject("ICMP error exceeds VPN MTU", nil, f)
		r.mu.Unlock()
		return result
	}
	f.lastSeen = r.now()
	r.mu.Unlock()
	accepted := port.Send(outer.raw)
	r.mu.Lock()
	if accepted {
		r.packetMetrics.dirs[Outbound].finish(len(outer.raw), true)
		f.outbound(1, uint64(len(outer.raw)))
		r.stats.PacketsOut++
	} else {
		r.reject("VPN packet queue full", nil, f)
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

func (r *Router) inboundPolicy(p *packet, f *flow) bool {
	if r.events == nil || !r.events.enabled[Inbound] {
		return true
	}
	ctx := r.ports[f.port].eventContext(Inbound, observed[string]{f.source, f.owner != 0})
	ctx.exitNode = f.exitNode
	return r.events.dispatch(p, p.protocol == 17 && !f.seenInboundUDP, ctx, &r.packetMetrics.dirs[Inbound])
}
func (r *Router) recordRawDrop(d Direction, size int) {
	r.mu.Lock()
	r.packetMetrics.dirs[d].finish(size, false)
	r.mu.Unlock()
}
func (r *Router) PacketPolicyStatus() PacketPolicyStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	status := r.packetMetrics.snapshot("wireguard-shared", r.events)
	for i, cur := range status.Rules {
		if prior := r.ruleCounters[ruleKey{kind: "event", event: cur.ID}]; prior != nil {
			row := &status.Rules[i]
			row.PacketsIn += prior.PacketsIn
			row.PacketsOut += prior.PacketsOut
			row.BytesIn += prior.BytesIn
			row.BytesOut += prior.BytesOut
			row.Drops += prior.Drops
		}
	}
	return status
}
