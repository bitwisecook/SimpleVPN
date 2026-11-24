// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package packetrouter

import (
	"encoding/binary"
	"errors"
	"strings"

	"pxengine/routelang"
	"pxengine/routelang/catalog"
)

type richPacketProgram struct {
	code     *routelang.PacketExecutor
	matches  []string
	counters map[string]int
	// Apply runs under the router lock. Reuse the staging area and clear all
	// evidence/packet references on every return, including denied packets.
	host packetEventHost
}

func isRichProgram(text string) bool {
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		words := strings.Fields(line)
		if words[0] != "on" {
			return true
		}
		// The legacy header has "=>" after predicates; its IPv6 CIDRs
		// also contain colons, so examine the handler ID token only.
		return len(words) > 1 && (strings.Contains(words[1], ":") || len(words) > 2 && strings.HasPrefix(words[2], ":"))
	}
	return false
}

func compileRichPackets(text string, schema routelang.Schema) (*EventProgram, error) {
	code, err := routelang.Compile(text, schema, nil)
	if err != nil {
		return nil, err
	}
	ids := code.HandlerIDs()
	if len(ids) == 0 {
		return nil, nil
	}
	if len(ids) > 128 {
		return nil, errors.New("choose up to 128 event handlers")
	}
	ep := &EventProgram{rich: &richPacketProgram{matches: make([]string, 0, len(ids)), counters: make(map[string]int, len(ids))}}
	for i, id := range ids {
		if !eventIdentifier(id) {
			return nil, errors.New("invalid packet handler ID")
		}
		ep.rich.counters[id] = i
		ep.counts = append(ep.counts, EventInspectionCounter{ID: id})
	}
	ep.rich.code, err = code.NewPacketExecutor()
	if err != nil {
		return nil, err
	}
	return ep, nil
}

// Packet writes are staged until every applicable event returns successfully.
// The VM reads only the fields the program actually requests.
type observed[T any] struct {
	value   T
	present bool
}

func present[T any](v T) observed[T] { return observed[T]{v, true} }

type packetEventHost struct {
	adapter    string
	ctx        packetContext
	packet     *packet
	source     observed[string]
	question   observed[evidenceQuestion]
	serverName observed[string]
	dscp       observed[byte]
	mss        observed[uint16]
	recursion  observed[bool]
}

func (h *packetEventHost) readMSS() (uint16, bool) {
	if h.packet == nil || h.packet.protocol != 6 {
		return 0, false
	}
	if h.mss.present {
		return h.mss.value, true
	}
	tcp := h.packet.raw[h.packet.transport:]
	for i, end := 20, int(tcp[12]>>4)*4; i < end; {
		kind := tcp[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+2 > end || tcp[i+1] < 2 || i+int(tcp[i+1]) > end {
			break
		}
		if kind == 2 && tcp[i+1] == 4 {
			return binary.BigEndian.Uint16(tcp[i+2:]), true
		}
		i += int(tcp[i+1])
	}
	return 0, false
}

func (h *packetEventHost) Read(field string) (routelang.Value, bool) {
	p := h.packet
	n := int64(0)
	switch field {
	case "ip.src", "ip.client_address":
		return routelang.Addr(p.src), true
	case "ip.dst", "ip.server_address":
		return routelang.Addr(p.dst), true
	case "port.src", "port.client":
		n = int64(p.srcPort)
	case "port.dst", "port.server":
		n = int64(p.dstPort)
	case "flow.source":
		if !h.source.present {
			return routelang.Value{}, false
		}
		return routelang.String(h.source.value), true
	case "flow.direction":
		if h.ctx.direction == Inbound {
			return routelang.String("inbound"), true
		}
		return routelang.String("outbound"), true
	case "flow.adapter":
		return routelang.String(h.adapter), true
	case "flow.profile":
		if h.ctx.profile == "" {
			return routelang.Value{}, false
		}
		return routelang.String(h.ctx.profile), true
	case "vpn.kind":
		if h.ctx.kind == "" {
			return routelang.Value{}, false
		}
		return routelang.String(h.ctx.kind), true
	case "flow.member":
		if h.ctx.member == "" {
			return routelang.Value{}, false
		}
		return routelang.String(h.ctx.member), true
	case "flow.has_exit_node":
		return routelang.Bool(h.ctx.exitNode != ""), true
	case "flow.exit_node":
		if h.ctx.exitNode == "" {
			return routelang.Value{}, false
		}
		return routelang.String(h.ctx.exitNode), true
	case "flow.generation":
		if h.ctx.member == "" || h.ctx.generation > 1<<63-1 {
			return routelang.Value{}, false
		}
		return routelang.Int(int64(h.ctx.generation)), true
	case "ip.version":
		n = int64(p.raw[0] >> 4)
	case "ip.protocol":
		n = int64(p.protocol)
	case "ip.length":
		n = int64(len(p.raw))
	case "ip.ecn", "ip.dscp":
		tc := p.raw[1]
		if p.src.Is6() {
			tc = p.raw[0]<<4 | p.raw[1]>>4
		}
		if field == "ip.ecn" {
			n = int64(tc & 3)
		} else if h.dscp.present {
			n = int64(h.dscp.value)
		} else {
			n = int64(tc >> 2)
		}
	case "ipv4.ttl":
		n = int64(p.raw[8])
	case "ipv4.id":
		n = int64(binary.BigEndian.Uint16(p.raw[4:]))
	case "ipv4.fragment_offset":
		n = int64(binary.BigEndian.Uint16(p.raw[6:])&0x1fff) * 8
	case "ipv4.more_fragments":
		return routelang.Bool(p.raw[6]&0x20 != 0), true
	case "ipv6.hop_limit":
		n = int64(p.raw[7])
	case "ipv6.flow_label":
		n = int64(binary.BigEndian.Uint32(p.raw[:4]) & 0xfffff)
	case "tcp.flags":
		n = int64(p.raw[p.transport+13])
	case "tcp.sequence":
		n = int64(binary.BigEndian.Uint32(p.raw[p.transport+4:]))
	case "tcp.payload_length":
		n = int64(len(p.raw) - p.transport - int(p.raw[p.transport+12]>>4)*4)
	case "tcp.mss":
		v, ok := h.readMSS()
		if !ok {
			return routelang.Value{}, false
		}
		return routelang.Int(int64(v)), true
	case "udp.length":
		n = int64(binary.BigEndian.Uint16(p.raw[p.transport+4:]))
	case "icmp.type":
		n = int64(p.raw[p.transport])
	case "icmp.code":
		n = int64(p.raw[p.transport+1])
	case "dns.name":
		if !h.question.present {
			return routelang.Value{}, false
		}
		v, e := routelang.DNS(h.question.value.name)
		return v, e == nil
	case "dns.id":
		if !h.question.present {
			return routelang.Value{}, false
		}
		n = int64(h.question.value.id)
	case "dns.type":
		if !h.question.present {
			return routelang.Value{}, false
		}
		n = int64(h.question.value.kind)
	case "dns.rd":
		if !h.question.present {
			return routelang.Value{}, false
		}
		if h.recursion.present {
			return routelang.Bool(h.recursion.value), true
		}
		return routelang.Bool(p.raw[p.transport+10]&1 != 0), true
	case "tls.sni":
		if !h.serverName.present {
			return routelang.Value{}, false
		}
		v, e := routelang.DNS(h.serverName.value)
		return v, e == nil
	case "quic.version":
		n = int64(binary.BigEndian.Uint32(p.raw[p.transport+9:]))
	case "quic.dcid":
		q := p.raw[p.transport+8:]
		v, err := routelang.Bytes(q[6 : 6+int(q[5])])
		return v, err == nil
	default:
		return routelang.Value{}, false
	}
	return routelang.Int(n), true
}

func (h *packetEventHost) Write(field string, value routelang.Value) error {
	switch field {
	case "ip.dscp":
		if value.Type() == routelang.TInt && value.AsInt() >= 0 && value.AsInt() <= 63 {
			h.dscp = present(byte(value.AsInt()))
			return nil
		}
	case "tcp.mss":
		if current, ok := h.readMSS(); ok && value.Type() == routelang.TInt && value.AsInt() >= 536 && value.AsInt() <= int64(current) {
			h.mss = present(uint16(value.AsInt()))
			return nil
		}
	case "dns.rd":
		if value.Type() == routelang.TBool {
			h.recursion = present(value.AsBool())
			return nil
		}
	}
	if id, ok := routelang.ExitNodeEffect(field); ok && value.Type() == routelang.TBool && value.AsBool() && h.ctx.selection != nil {
		selection := h.ctx.selection
		if err := selection.choose(id); err != nil {
			selection.failure = err.Error()
			return err
		}
		h.ctx = selection.chosen.eventContext(h.ctx.direction, h.ctx.source)
		h.ctx.selection, h.ctx.exitNode = selection, id
		return nil
	}
	return errors.New("invalid packet field write")
}
func (h *packetEventHost) Action(name string, args []routelang.Value) error {
	if name == "count" && len(args) == 0 {
		return nil
	}
	return errors.New("action unavailable on a raw IP packet")
}

func (h *packetEventHost) commit() bool {
	edited := false
	if h.dscp.present {
		edited = markPacketDSCP(h.packet, h.dscp.value)
	}
	if h.mss.present {
		edited = clampTCPMSS(h.packet, h.mss.value) || edited
	}
	if h.recursion.present {
		var v byte
		if h.recursion.value {
			v = 1
		}
		edited = setPacketRecursion(h.packet, v) || edited
	}
	return edited
}

func (ep *EventProgram) applyRich(p *packet, newFlow bool, ctx packetContext) bool {
	code := ep.rich.code
	h := &ep.rich.host
	defer func() { *h = packetEventHost{} }()
	var question observed[evidenceQuestion]
	var sni observed[string]
	eventName := func(event string) string {
		if ctx.direction == Inbound {
			return inboundNames[event]
		}
		return event
	}
	run := func(event string) bool {
		event = eventName(event)
		if !code.Handles(event) {
			return true
		}
		if h.packet == nil {
			h.packet, h.source, h.adapter, h.ctx = p, ctx.source, ep.adapter, ctx
		}
		h.question, h.serverName = question, sni
		result, err := code.RunInto(event, h, ep.rich.matches)
		for i, id := range result.Matches {
			c := &ep.counts[ep.rich.counters[id]]
			ep.hit(c, len(p.raw))
			if i == len(result.Matches)-1 && (err != nil || result.Dropped) {
				c.Drops++
			}
		}
		return err == nil && !result.Dropped
	}
	if ctx.selection != nil && !run(catalog.ExitSelectionEvent) {
		return false
	}
	if !run("ip.packet") {
		return false
	}
	if p.src.Is4() {
		if !run("ipv4.packet") {
			return false
		}
	} else if !run("ipv6.packet") {
		return false
	}
	if !p.headerOnly {
		switch p.protocol {
		case 6:
			tcp := p.raw[p.transport:]
			if tcp[13]&0x12 == 2 && !run("tcp.syn") {
				return false
			}
			payload := tcp[int(tcp[12]>>4)*4:]
			if len(payload) > 0 {
				if !run("tcp.data") {
					return false
				}
				if code.Handles(eventName("tls.client_hello")) {
					if name, ok := eventTLSHello(payload); ok {
						sni = present(name)
						if !run("tls.client_hello") {
							return false
						}
					}
				}
			}
		case 17:
			if newFlow && !run("udp.open") || !run("udp.datagram") {
				return false
			}
			payload := p.raw[p.transport+8:]
			if p.dstPort == 53 && code.Handles(eventName("dns.query")) {
				if _, q, ok := parseEvidenceQuestion(payload, false); ok {
					question = present(q)
					if !run("dns.query") {
						return false
					}
				}
			}
			if code.Handles(eventName("quic.initial")) && isQUICInitial(payload) && !run("quic.initial") {
				return false
			}
		case 1:
			if !run("icmp.message") {
				return false
			}
		case 58:
			if !run("icmpv6.message") {
				return false
			}
		}
	}
	if h.packet != nil {
		ep.edited = h.commit()
	}
	return true
}
