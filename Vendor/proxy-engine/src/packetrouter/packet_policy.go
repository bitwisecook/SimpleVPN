// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package packetrouter

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"pxengine/routelang/catalog"
)

type Direction uint8

const (
	Outbound Direction = iota
	Inbound
)

var packetHooks = catalog.PacketHooks()
var inboundNames = func() map[string]string {
	m := make(map[string]string, len(packetHooks))
	for _, name := range packetHooks {
		m[name] = "inbound." + name
	}
	return m
}()

func CompileAdapterEvents(adapter, source string) (*EventProgram, error) {
	if source == "" {
		a, ok := catalog.AdapterByID(adapter)
		if !ok || !a.PacketPolicy() {
			return nil, fmt.Errorf("adapter %q does not support raw packet policies", adapter)
		}
		return nil, nil
	}
	schema, ok := catalog.PacketForAdapter(adapter)
	if !ok {
		return nil, fmt.Errorf("adapter %q does not support raw packet policies", adapter)
	}
	if len(source) > 32768 || strings.IndexByte(source, 0) >= 0 || !utf8.ValidString(source) {
		return nil, errors.New("event program must be UTF-8, at most 32 KiB and free of NUL bytes")
	}
	if isRichProgram(source) {
		p, err := compileRichPackets(source, schema)
		if err != nil || p == nil {
			return p, err
		}
		p.adapter = adapter
		for _, d := range []Direction{Outbound, Inbound} {
			for _, name := range packetHooks {
				event := name
				if d == Inbound {
					event = inboundNames[name]
				}
				if p.rich.code.Handles(event) {
					p.enabled[d] = true
					if name == "udp.open" {
						p.trackUDP[d] = true
					}
					if name != "ip.packet" && name != "ipv4.packet" && name != "ipv6.packet" {
						p.needsTransport[d] = true
					}
				}
			}
		}
		p.selectExit = p.rich.code.Handles(catalog.ExitSelectionEvent)
		p.enabled[Outbound] = p.enabled[Outbound] || p.selectExit
		return p, nil
	}
	var parts [2]strings.Builder
	ids := map[string]bool{}
	for i, line := range strings.Split(source, "\n") {
		if i != 0 {
			parts[0].WriteByte('\n')
			parts[1].WriteByte('\n')
		}
		words := strings.Fields(strings.SplitN(line, "#", 2)[0])
		d := Outbound
		if len(words) >= 3 && words[0] == "on" {
			if ids[words[1]] || len(ids) >= 128 {
				return nil, fmt.Errorf("line %d: expected unique ID and at most 128 rules", i+1)
			}
			ids[words[1]] = true
			if strings.HasPrefix(words[2], "inbound.") {
				d = Inbound
				words[2] = strings.TrimPrefix(words[2], "inbound.")
				line = strings.Join(words, " ")
			}
			if adapter != "wireguard-shared" {
				for j := 3; j < len(words) && words[j] != "=>"; j += 2 {
					if words[j] == "source" {
						return nil, fmt.Errorf("line %d: source attribution unavailable on %s", i+1, adapter)
					}
				}
			}
		}
		parts[d].WriteString(line)
	}
	out, err := compileCompact(parts[0].String())
	if err != nil {
		return nil, err
	}
	in, err := compileCompact(parts[1].String())
	if err != nil {
		out.Close()
		return nil, err
	}
	if in == nil && out == nil {
		return nil, nil
	}
	if out == nil {
		out = new(EventProgram)
	} else {
		out.enabled[Outbound] = true
	}
	out.incoming = in
	out.adapter = adapter
	out.enabled[Inbound] = in != nil
	for d, part := range []*EventProgram{out, in} {
		if part != nil {
			t := part.table[udpOpen]
			out.trackUDP[d] = len(t.ports) > 0 || t.allPorts.mask != (candidateBits{})
			out.needsTransport[d] = out.enabled[d]
		}
	}
	return out, nil
}

type packetContext struct {
	direction             Direction
	source                observed[string]
	member, profile, kind string
	generation            uint64
	exitNode              string
	selection             *exitSelection
}
type DirectionCounters struct {
	ReceivedPackets  uint64 `json:"receivedPackets"`
	ReceivedBytes    uint64 `json:"receivedBytes"`
	ForwardedPackets uint64 `json:"forwardedPackets"`
	ForwardedBytes   uint64 `json:"forwardedBytes"`
	DroppedPackets   uint64 `json:"droppedPackets"`
	DroppedBytes     uint64 `json:"droppedBytes"`
	EvaluatedPackets uint64 `json:"evaluatedPackets"`
	EditedPackets    uint64 `json:"editedPackets"`
	RuleHits         uint64 `json:"ruleHits"`
}
type PacketPolicyStats struct {
	Adapter   string                   `json:"adapter"`
	SessionID string                   `json:"sessionID"`
	Outbound  DirectionCounters        `json:"outbound"`
	Inbound   DirectionCounters        `json:"inbound"`
	Rules     []EventInspectionCounter `json:"rules"`
}
type packetMetrics struct {
	dirs    [2]trafficRow
	session string
}

func (m *packetMetrics) snapshot(adapter string, p *EventProgram) PacketPolicyStats {
	rules := p.InspectionCounters()
	if rules == nil {
		rules = []EventInspectionCounter{}
	}
	return PacketPolicyStats{adapter, m.session, m.dirs[0].snapshot(), m.dirs[1].snapshot(), rules}
}
func (ep *EventProgram) hit(c *EventInspectionCounter, size int) {
	ep.hits++
	if ep.direction == Inbound {
		c.PacketsIn++
		c.BytesIn += uint64(size)
	} else {
		c.PacketsOut++
		c.BytesOut += uint64(size)
	}
}
func (ep *EventProgram) dispatch(p *packet, newFlow bool, ctx packetContext, meters *trafficRow) bool {
	selected := ep
	if ep.rich == nil && ctx.direction == Inbound {
		selected = ep.incoming
		if selected == nil {
			return true
		}
	}
	selected.hits = 0
	selected.edited = false
	selected.direction = ctx.direction
	var allow bool
	if selected.rich != nil {
		allow = selected.applyRich(p, newFlow, ctx)
	} else if p.headerOnly {
		allow = true
	} else {
		allow = selected.applyCompact(p, newFlow, ctx.source)
	}
	if meters != nil {
		meters.evaluated(selected.hits, allow && selected.edited)
	}
	return allow
}

type RawPacketPolicy struct {
	epoch                  time.Time
	mu                     sync.Mutex
	adapter, profile, kind string
	events                 *EventProgram
	metrics                packetMetrics
	udp                    [2]udpHistory
	now                    func() time.Time
	closed                 bool
}

func NewRawPacketPolicy(adapter, profile, kind, source string) (*RawPacketPolicy, error) {
	if adapter == "wireguard-shared" {
		return nil, errors.New("shared WireGuard owns its routing policy instance")
	}
	for _, s := range []string{profile, kind} {
		if len(s) > 256 || !utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0 {
			return nil, errors.New("invalid packet policy context")
		}
	}
	events, err := CompileAdapterEvents(adapter, source)
	if err != nil {
		return nil, err
	}
	return &RawPacketPolicy{adapter: adapter, profile: profile, kind: kind, events: events, metrics: packetMetrics{session: rand.Text()}, now: time.Now, epoch: time.Now()}, nil
}
func (s *RawPacketPolicy) NeedsPackets(d Direction) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d > Inbound || s.closed {
		return -1
	}
	if s.events != nil && s.events.enabled[d] {
		return 1
	}
	return 0
}
func (s *RawPacketPolicy) Observe(d Direction, n, bytes uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed && d <= Inbound && (s.events == nil || !s.events.enabled[d]) {
		s.metrics.dirs[d].passthrough(n, bytes)
	}
}

// RejectInput accounts for a buffer the owning bridge could not safely borrow.
func (s *RawPacketPolicy) RejectInput(d Direction, size int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed && d <= Inbound {
		m := &s.metrics.dirs[d]
		m.received(max(0, size))
		m.finish(max(0, size), false)
	}
}

func (s *RawPacketPolicy) Apply(d Direction, raw []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || d > Inbound {
		return false
	}
	m := &s.metrics.dirs[d]
	e := s.events
	if e == nil || !e.enabled[d] {
		m.passthrough(1, uint64(len(raw)))
		return true
	}
	m.received(len(raw))
	p, err := parseIP(raw, false, true, !e.needsTransport[d])
	if err != nil {
		m.finish(len(raw), false)
		return false
	}
	var seen int32
	var elapsed uint64
	tracking := !p.headerOnly && p.protocol == 17 && e.trackUDP[d]
	if tracking && e.rich == nil {
		selected := e
		if d == Inbound {
			selected = e.incoming
		}
		tracking = selected.table[udpOpen].candidates(p.dstPort).mask != (candidateBits{})
	}
	if tracking {
		elapsed = uint64(max(0, s.now().Sub(s.epoch).Milliseconds()))
		seen = s.udp[d].seen(key(p), elapsed)
		if seen < 0 {
			m.finish(len(raw), false)
			return false
		}
	}
	allowed := e.dispatch(&p, tracking && seen == 0, packetContext{direction: d, profile: s.profile, kind: s.kind}, m)
	if allowed && tracking {
		s.udp[d].accept(key(p), elapsed)
	}
	m.finish(len(raw), allowed)
	return allowed
}
func (s *RawPacketPolicy) Status() PacketPolicyStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.metrics.snapshot(s.adapter, s.events)
}
func (s *RawPacketPolicy) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.events.Close()
		s.events = nil
		for i := range s.udp {
			s.udp[i].close()
		}
	}
}
