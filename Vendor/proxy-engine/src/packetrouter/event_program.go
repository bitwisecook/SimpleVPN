// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package packetrouter

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"net/netip"
	"strconv"
	"strings"
)

type eventKind uint8

const (
	tcpSyn eventKind = iota
	udpOpen
	tlsHello
	dnsQuery
	quicInitial
	eventKinds
)

var eventNames = [...]string{"tcp.syn", "udp.open", "tls.hello", "dns.query", "quic.initial"}

type eventAction uint8

const (
	countEvent eventAction = iota
	dropEvent
	markDSCP
	clampMSS
	setDNSRecursion
)

type EventInspectionCounter struct {
	ID         string `json:"id"`
	PacketsOut uint64 `json:"packetsOut"`
	BytesOut   uint64 `json:"bytesOut"`
	PacketsIn  uint64 `json:"packetsIn"`
	BytesIn    uint64 `json:"bytesIn"`
	Drops      uint64 `json:"drops"`
}
type eventInstruction struct {
	index        int
	kind         eventKind
	port         uint16
	destination  netip.Prefix
	source, name string
	action       eventAction
	value        uint16
}

// Compile port-specific dispatch and keep wildcard rows in source order.
// The packet path has no source parsing, pattern compilation or scripting runtime.
type candidateBits [2]uint64

func (c *candidateBits) add(index int) { c[index/64] |= uint64(1) << (index % 64) }

type compactSelection struct {
	mask  candidateBits
	fixed *compactOutcome
}

type compactIndex struct {
	allPorts compactSelection
	ports    map[uint16]compactSelection
}

func (c *compactIndex) candidates(port uint16) compactSelection {
	if rows, ok := c.ports[port]; ok {
		return rows
	}
	return c.allPorts
}

func (ep *EventProgram) addCandidate(kind eventKind, port uint16, i int) {
	index := &ep.table[kind]
	if port == 0 {
		index.allPorts.mask.add(i)
		return
	}
	if index.ports == nil {
		index.ports = make(map[uint16]compactSelection)
	}
	selection := index.ports[port]
	selection.mask.add(i)
	index.ports[port] = selection
}

// Finish once, after all registrations. Each destination port receives its
// wildcard rules even when they were declared after the port-specific rule.
func (ep *EventProgram) finishCompact(prepare func(*compactSelection) error) error {
	for i := range ep.table {
		group := &ep.table[i]
		if prepare != nil {
			if err := prepare(&group.allPorts); err != nil {
				return err
			}
		}
		for port, sel := range group.ports {
			sel.mask[0] |= group.allPorts.mask[0]
			sel.mask[1] |= group.allPorts.mask[1]
			if prepare != nil {
				if err := prepare(&sel); err != nil {
					return err
				}
			}
			group.ports[port] = sel
		}
	}
	return nil
}

type EventProgram struct {
	adapter        string
	incoming       *EventProgram
	enabled        [2]bool
	trackUDP       [2]bool
	needsTransport [2]bool
	selectExit     bool
	hits           uint64
	edited         bool
	direction      Direction
	native         *nativeCompact
	rich           *richPacketProgram
	table          [eventKinds]compactIndex
	rows           []eventInstruction
	counts         []EventInspectionCounter
}

func eventIdentifier(s string) bool {
	if len(s) == 0 || len(s) > 80 {
		return false
	}
	for i, c := range []byte(s) {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || i > 0 && ((c >= '0' && c <= '9') || c == '_' || c == '-') {
			continue
		}
		return false
	}
	return true
}
func eventHost(s string) bool {
	if len(s) > 253 || s == "" {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// CompileEvents accepts one named handler per line. Every predicate must match.
// Actions on one event run in declaration order. Drop ends processing immediately.
func CompileEvents(text string) (*EventProgram, error) {
	return CompileAdapterEvents("wireguard-shared", text)
}

func compileCompactReference(text string) (*EventProgram, error) {
	p := new(EventProgram)
	ids := make(map[string]bool)
	for line, raw := range strings.Split(text, "\n") {
		words := strings.Fields(strings.SplitN(raw, "#", 2)[0])
		if len(words) == 0 {
			continue
		}
		bad := func(s string) (*EventProgram, error) { return nil, fmt.Errorf("line %d: %s", line+1, s) }
		if len(words) < 5 || words[0] != "on" || !eventIdentifier(words[1]) || ids[words[1]] {
			return bad("expected on UNIQUE_ID EVENT [FIELD VALUE ...] => ACTION")
		}
		if len(ids) >= 128 {
			return bad("choose up to 128 event handlers")
		}
		row := &eventInstruction{index: len(ids), kind: eventKinds}
		for i, n := range eventNames {
			if words[2] == n {
				row.kind = eventKind(i)
				break
			}
		}
		if row.kind == eventKinds {
			return bad("unknown event")
		}
		i := 3
		fields := map[string]bool{}
		for i < len(words) && words[i] != "=>" {
			if i+1 >= len(words) || fields[words[i]] {
				return bad("missing or duplicate predicate")
			}
			k, v := words[i], words[i+1]
			fields[k] = true
			i += 2
			switch k {
			case "port":
				n, e := strconv.ParseUint(v, 10, 16)
				if e != nil || n == 0 {
					return bad("expected destination port 1–65535")
				}
				row.port = uint16(n)
			case "dst":
				prefix, e := netip.ParsePrefix(v)
				if e != nil {
					a, er := netip.ParseAddr(v)
					if er != nil || a.Zone() != "" {
						return bad("invalid destination network")
					}
					prefix = netip.PrefixFrom(a, a.BitLen())
				}
				if prefix.Addr().Is4In6() || prefix.Masked() != prefix {
					return bad("use a canonical destination network")
				}
				row.destination = prefix
			case "source":
				if !validRouteAlias(v) {
					return bad("invalid source rule ID")
				}
				row.source = v
			case "name":
				v = strings.ToLower(strings.TrimSuffix(v, "."))
				if (row.kind != tlsHello && row.kind != dnsQuery) || !eventHost(v) {
					return bad("name requires a DNS question or visible TLS server name")
				}
				row.name = v
			default:
				return bad("unknown predicate " + k)
			}
		}
		if i+1 >= len(words) {
			return bad("expected => and an action")
		}
		args := words[i+1:]
		val := uint64(0)
		var err error
		if len(args) == 2 {
			val, err = strconv.ParseUint(args[1], 10, 16)
		}
		switch args[0] {
		case "count", "drop":
			if len(args) != 1 {
				return bad("unexpected action argument")
			}
			if args[0] == "drop" {
				row.action = dropEvent
			}
		case "mark-dscp":
			if len(args) != 2 || err != nil || val > 63 {
				return bad("DSCP must be 0–63")
			}
			row.action = markDSCP
		case "clamp-mss":
			if row.kind != tcpSyn || len(args) != 2 || err != nil || val < 536 {
				return bad("clamp-mss requires tcp.syn and an MSS of 536–65535")
			}
			row.action = clampMSS
		case "set-dns-rd":
			if row.kind != dnsQuery || len(args) != 2 || err != nil || val > 1 {
				return bad("set-dns-rd requires dns.query and 0 or 1")
			}
			row.action = setDNSRecursion
		default:
			return bad("unknown action " + args[0])
		}
		row.value = uint16(val)
		ids[words[1]] = true
		p.counts = append(p.counts, EventInspectionCounter{ID: words[1]})
		p.addCandidate(row.kind, row.port, row.index)
		p.rows = append(p.rows, *row)
	}
	if len(ids) == 0 {
		return nil, nil
	}
	return p, p.finishCompact(nil)
}
func validRouteAlias(s string) bool {
	if len(s) == 0 || len(s) > 80 {
		return false
	}
	for _, c := range []byte(s) {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}

// Close releases plans owned by this program after all users stop dispatching.
// Callers may close a nil or already closed program.
func (p *EventProgram) Close() {
	if p != nil && p.rich != nil {
		p.rich.code.Close()
	}
}

// NativeEventCounts reports compiled rich event groups. Compact programs and
// portable inspection builds have no rich native groups.
func (p *EventProgram) NativeEventCounts() (scalar, general int) {
	if p == nil || p.rich == nil {
		return 0, 0
	}
	return p.rich.code.NativeEventCounts()
}

func (p *EventProgram) InspectionCounters() []EventInspectionCounter {
	if p == nil {
		return nil
	}
	out := append([]EventInspectionCounter(nil), p.counts...)
	if p.incoming != nil {
		out = append(out, p.incoming.counts...)
	}
	return out
}
func (ep *EventProgram) matchCompactReference(mask candidateBits, p *packet, source observed[string], name string) bool {
	if mask == (candidateBits{}) {
		return true
	}
	for word, hits := range mask {
		for ; hits != 0; hits &= hits - 1 {
			r := &ep.rows[word*64+bits.TrailingZeros64(hits)]
			if r.destination.IsValid() && !r.destination.Contains(p.dst) || r.source != "" && (!source.present || r.source != source.value) || r.name != "" && !strings.EqualFold(r.name, name) {
				continue
			}
			c := &ep.counts[r.index]
			ep.hit(c, len(p.raw))
			switch r.action {
			case dropEvent:
				c.Drops++
				return false
			case markDSCP:
				ep.edited = markPacketDSCP(p, byte(r.value)) || ep.edited
			case clampMSS:
				ep.edited = clampTCPMSS(p, r.value) || ep.edited
			case setDNSRecursion:
				ep.edited = setPacketRecursion(p, byte(r.value)) || ep.edited
			}
		}
	}
	return true
}
func markPacketDSCP(p *packet, value byte) bool {
	tc := p.raw[1]
	if p.src.Is6() {
		tc = p.raw[0]<<4 | p.raw[1]>>4
	}
	if tc>>2 == value {
		return false
	}
	if p.src.Is4() {
		p.raw[1] = byte(value<<2) | p.raw[1]&3
		p.fixIPChecksum()
	} else {
		p.raw[0] = p.raw[0]&0xf0 | byte(value>>2)
		p.raw[1] = p.raw[1]&0x3f | byte(value<<6)
	}
	return true
}

func setPacketRecursion(p *packet, value byte) bool {
	pos := p.transport + 10
	if p.raw[pos]&1 == value {
		return false
	}
	p.raw[pos] = p.raw[pos]&0xfe | value
	p.fixTransportChecksum()
	return true
}

func clampTCPMSS(p *packet, maxMSS uint16) bool {
	changed := false
	h := p.raw[p.transport:]
	end := int(h[12]>>4) * 4
	for i := 20; i < end; {
		kind := h[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+2 > end {
			break
		}
		n := int(h[i+1])
		if n < 2 || n > end-i {
			break
		}
		if kind == 2 && n == 4 && binary.BigEndian.Uint16(h[i+2:]) > maxMSS {
			binary.BigEndian.PutUint16(h[i+2:], maxMSS)
			changed = true
		}
		i += n
	}
	if changed {
		p.fixTransportChecksum()
	}
	return changed
}

// Validate the invariant v1/v2 Initial header, including token and packet length.
// Protected payload and header-protected packet-number bits remain opaque.
func isQUICInitial(b []byte) bool {
	if len(b) < 1200 || b[0]&0xc0 != 0xc0 {
		return false
	}
	v := binary.BigEndian.Uint32(b[1:])
	typ := b[0] >> 4 & 3
	if !(v == 1 && typ == 0 || v == 0x6b3343cf && typ == 1) {
		return false
	}
	off := 5
	for n := 0; n < 2; n++ {
		if off >= len(b) {
			return false
		}
		l := int(b[off])
		if l > 20 || l > len(b)-off-1 {
			return false
		}
		off += l + 1
	}
	read := func() (uint64, bool) {
		if off >= len(b) {
			return 0, false
		}
		n := 1 << uint(b[off]>>6)
		if n > len(b)-off {
			return 0, false
		}
		v := uint64(b[off] & 63)
		off++
		for i := 1; i < n; i++ {
			v = v<<8 | uint64(b[off])
			off++
		}
		return v, true
	}
	token, ok := read()
	if !ok || token > uint64(len(b)-off) {
		return false
	}
	off += int(token)
	length, ok := read()
	return ok && length >= 17 && length <= uint64(len(b)-off)
}

// Apply runs under the router lock on validated outgoing packets. A router with
// no handlers skips this call entirely. Cheap dispatch precedes protocol parsing.
func (ep *EventProgram) Apply(p *packet, newFlow bool, source observed[string]) bool {
	return ep.dispatch(p, newFlow, packetContext{source: source}, nil)
}

func (ep *EventProgram) applyCompact(p *packet, newFlow bool, source observed[string]) bool {
	candidates := func(k eventKind) compactSelection { return ep.table[k].candidates(p.dstPort) }
	switch p.protocol {
	case 6:
		tcp := p.raw[p.transport:]
		if tcp[13]&0x12 == 2 {
			return ep.matchCompact(candidates(tcpSyn), p, source, "")
		}
		if mask := candidates(tlsHello); mask.mask != (candidateBits{}) {
			if name, ok := eventTLSHello(tcp[int(tcp[12]>>4)*4:]); ok {
				return ep.matchCompact(mask, p, source, name)
			}
		}
	case 17:
		if newFlow && !ep.matchCompact(candidates(udpOpen), p, source, "") {
			return false
		}
		payload := p.raw[p.transport+8:]
		if p.dstPort == 53 {
			if mask := candidates(dnsQuery); mask.mask != (candidateBits{}) {
				if name, ok := eventDNSQuestion(payload); ok && !ep.matchCompact(mask, p, source, name) {
					return false
				}
			}
		}
		if mask := candidates(quicInitial); mask.mask != (candidateBits{}) && isQUICInitial(payload) {
			return ep.matchCompact(mask, p, source, "")
		}
	}
	return true
}
