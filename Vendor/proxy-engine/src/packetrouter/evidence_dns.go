// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package packetrouter

import (
	"encoding/binary"
	"net/netip"
	"pxengine/internal/clienthello"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type evidenceQuestion struct {
	id   uint16
	name string
	kind dnsmessage.Type
}

func parseEvidenceQuestion(msg []byte, response bool) (dnsmessage.Parser, evidenceQuestion, bool) {
	var parser dnsmessage.Parser
	var q evidenceQuestion
	if len(msg) < 12 || len(msg) > 4096 || binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return parser, q, false
	}
	h, err := parser.Start(msg)
	if err != nil || h.Response != response || h.OpCode != 0 || h.Truncated || h.RCode != dnsmessage.RCodeSuccess {
		return parser, q, false
	}
	question, err := parser.Question()
	if err != nil || question.Class != dnsmessage.ClassINET {
		return parser, q, false
	}
	name, ok := clienthello.Hostname(question.Name.String())
	if !ok {
		return parser, q, false
	}
	// Advance from the question section into answers.
	if _, err = parser.Question(); err != dnsmessage.ErrSectionDone {
		return parser, q, false
	}
	return parser, evidenceQuestion{h.ID, name, question.Type}, true
}

func eventDNSQuestion(payload []byte) (string, bool) {
	_, q, ok := parseEvidenceQuestion(payload, false)
	return q.name, ok
}

type dnsAddressHint struct {
	address netip.Addr
	ttl     time.Duration
}

func evidenceAnswers(msg []byte, parser dnsmessage.Parser, q evidenceQuestion) []dnsAddressHint {
	const limit = 32
	count := int(binary.BigEndian.Uint16(msg[6:8]))
	if count == 0 || count > limit {
		return nil
	}
	type link struct {
		target string
		ttl    uint32
	}
	type record struct {
		name    string
		address netip.Addr
		ttl     uint32
	}
	links := map[string]link{}
	var addresses []record
	for i := 0; i < count; i++ {
		h, err := parser.AnswerHeader()
		if err != nil {
			return nil
		}
		if h.Class != dnsmessage.ClassINET {
			if parser.SkipAnswer() != nil {
				return nil
			}
			continue
		}
		name, ok := clienthello.Hostname(h.Name.String())
		if !ok {
			return nil
		}
		switch h.Type {
		case dnsmessage.TypeCNAME:
			body, err := parser.CNAMEResource()
			if err != nil {
				return nil
			}
			target, ok := clienthello.Hostname(body.CNAME.String())
			if !ok {
				return nil
			}
			n := link{target, h.TTL}
			if old, found := links[name]; found {
				if old.target != target {
					return nil
				}
				n.ttl = min(n.ttl, old.ttl)
			}
			links[name] = n
		case dnsmessage.TypeA:
			if h.Length != 4 {
				return nil
			}
			body, err := parser.AResource()
			if err != nil {
				return nil
			}
			if q.kind == h.Type {
				addresses = append(addresses, record{name, netip.AddrFrom4(body.A), h.TTL})
			}
		case dnsmessage.TypeAAAA:
			if h.Length != 16 {
				return nil
			}
			body, err := parser.AAAAResource()
			if err != nil {
				return nil
			}
			if q.kind == h.Type {
				addresses = append(addresses, record{name, netip.AddrFrom16(body.AAAA), h.TTL})
			}
		default:
			if parser.SkipAnswer() != nil {
				return nil
			}
		}
	}
	name := q.name
	ttl := uint32(300)
	for steps := 0; ; steps++ {
		n, ok := links[name]
		if !ok {
			break
		}
		if steps >= 8 {
			return nil
		}
		name = n.target
		ttl = min(ttl, n.ttl)
	}
	var hints []dnsAddressHint
	for _, a := range addresses {
		if a.name != name || !a.address.IsGlobalUnicast() || a.address.Is4In6() {
			continue
		}
		lifetime := time.Duration(min(ttl, a.ttl)) * time.Second
		duplicate := false
		for i := range hints {
			if hints[i].address == a.address {
				hints[i].ttl = min(hints[i].ttl, lifetime)
				duplicate = true
				break
			}
		}
		if !duplicate {
			hints = append(hints, dnsAddressHint{a.address, lifetime})
		}
	}
	return hints
}
