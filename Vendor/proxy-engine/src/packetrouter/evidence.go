// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package packetrouter

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"pxengine/internal/clienthello"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const evidenceLease = 8 * time.Second

type evidenceScope struct {
	port, source      string
	generation, owner uint64
}

func scopeOf(f *flow) evidenceScope { return evidenceScope{f.port, f.source, f.generation, f.owner} }

type evidenceAddress struct {
	scope evidenceScope
	ip    netip.Addr
}
type dnsCandidates struct {
	names         map[string]time.Time
	overflowUntil time.Time
}
type pendingQuestionKey struct {
	flow *flow
	id   uint16
}
type pendingQuestion struct {
	question evidenceQuestion
	until    time.Time
}
type flowNotes struct {
	dns, sni             string
	dnsUntil, helloUntil time.Time
	partial              []byte
}
type inspectorEvidence struct {
	until, lastSweep time.Time
	timer            *time.Timer
	pending          map[pendingQuestionKey]pendingQuestion
	addresses        map[evidenceAddress]*dnsCandidates
	notes            map[*flow]*flowNotes
	buffers          int
}

// All access, including the single lease expiry timer, is under Router.mu.
func (r *Router) renewEvidenceLocked(now time.Time) {
	if r.evidence != nil && !now.Before(r.evidence.until) {
		r.stopEvidenceLocked()
	}
	if r.evidence == nil {
		e := &inspectorEvidence{pending: make(map[pendingQuestionKey]pendingQuestion), addresses: make(map[evidenceAddress]*dnsCandidates), notes: make(map[*flow]*flowNotes)}
		r.evidence = e
		e.timer = time.AfterFunc(evidenceLease, func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.evidence != e {
				return
			}
			if left := e.until.Sub(r.now()); left > 0 {
				e.timer.Reset(left)
				return
			}
			r.stopEvidenceLocked()
		})
	}
	e := r.evidence
	e.until = now.Add(evidenceLease)
	// The timer already wakes at the previous deadline and checks for renewal.
	e.sweep(now)
}

func (r *Router) stopEvidenceLocked() {
	if e := r.evidence; e != nil {
		e.timer.Stop()
		for _, n := range e.notes {
			clear(n.partial)
		}
		r.evidence = nil
	}
}
func (e *inspectorEvidence) endHello(n *flowNotes) {
	if n.partial != nil {
		clear(n.partial)
		e.buffers--
		n.partial = nil
	}
	n.helloUntil = time.Time{}
}
func (e *inspectorEvidence) sweep(now time.Time) {
	if now.Sub(e.lastSweep) < time.Second {
		return
	}
	e.lastSweep = now
	for k, q := range e.pending {
		if !now.Before(q.until) {
			delete(e.pending, k)
		}
	}
	for k, c := range e.addresses {
		for name, end := range c.names {
			if !now.Before(end) {
				delete(c.names, name)
			}
		}
		if len(c.names) == 0 && !now.Before(c.overflowUntil) {
			delete(e.addresses, k)
		}
	}
	for f, n := range e.notes {
		if !n.helloUntil.IsZero() && !now.Before(n.helloUntil) {
			e.endHello(n)
		}
		if !now.Before(n.dnsUntil) {
			n.dns = ""
		}
		if now.Sub(f.lastSeen) > 2*time.Minute || n.helloUntil.IsZero() && n.sni == "" && n.dns == "" {
			e.endHello(n)
			delete(e.notes, f)
		}
	}
}

func (e *inspectorEvidence) unique(k evidenceAddress, now time.Time) (string, time.Time) {
	c := e.addresses[k]
	if c == nil || now.Before(c.overflowUntil) {
		return "", time.Time{}
	}
	var found string
	var until time.Time
	for name, end := range c.names {
		if !now.Before(end) {
			continue
		}
		if found != "" {
			return "", time.Time{}
		}
		found, until = name, end
	}
	return found, until
}

func (e *inspectorEvidence) open(f *flow, dst netip.Addr, now time.Time) {
	if !now.Before(e.until) {
		return
	}
	e.sweep(now)
	if len(e.notes) >= 2048 {
		return
	}
	dns, end := e.unique(evidenceAddress{scopeOf(f), dst}, now)
	tcp := f.reverse.tuple.protocol == 6
	if dns == "" && !tcp {
		return
	}
	n := &flowNotes{dns: dns, dnsUntil: end}
	if tcp {
		n.helloUntil = now.Add(3 * time.Second)
	}
	e.notes[f] = n
}

func (e *inspectorEvidence) names(f *flow, dst netip.Addr, now time.Time) (dns, sni string) {
	if e == nil || !now.Before(e.until) {
		return "", ""
	}
	n := e.notes[f]
	if n == nil {
		return "", ""
	}
	if n.dns != "" && now.Before(n.dnsUntil) {
		if name, _ := e.unique(evidenceAddress{scopeOf(f), dst}, now); name == n.dns {
			dns = name
		}
	}
	return dns, n.sni
}

func (e *inspectorEvidence) outbound(f *flow, p packet, now time.Time) {
	if !now.Before(e.until) {
		return
	}
	switch p.protocol {
	case 17:
		if p.dstPort != 53 {
			return
		}
		_, q, ok := parseEvidenceQuestion(p.raw[p.transport+8:], false)
		if !ok || (q.kind != dnsmessage.TypeA && q.kind != dnsmessage.TypeAAAA) {
			return
		}
		e.sweep(now)
		k := pendingQuestionKey{f, q.id}
		if _, known := e.pending[k]; !known && len(e.pending) >= 512 {
			return
		}
		e.pending[k] = pendingQuestion{q, now.Add(5 * time.Second)}
	case 6:
		n := e.notes[f]
		if n == nil || n.helloUntil.IsZero() {
			return
		}
		if !now.Before(n.helloUntil) {
			e.endHello(n)
			return
		}
		tcp := p.raw[p.transport:]
		payload := tcp[int(tcp[12]>>4)*4:]
		if len(payload) == 0 {
			return
		}
		seq := binary.BigEndian.Uint32(tcp[4:8])
		if tcp[13]&2 != 0 {
			seq++
		}
		offset := seq - (f.syn + 1)
		if offset > uint32(len(n.partial)) {
			e.endHello(n)
			return
		}
		overlap := min(len(n.partial)-int(offset), len(payload))
		if !bytes.Equal(n.partial[int(offset):int(offset)+overlap], payload[:overlap]) {
			e.endHello(n)
			return
		}
		payload = payload[overlap:]
		if len(payload) == 0 {
			return
		}
		if len(n.partial)+len(payload) > maxHelloBytes+40 {
			e.endHello(n)
			return
		}
		if n.partial == nil {
			name, status := clienthello.ServerName(payload)
			if status != clienthello.Incomplete || e.buffers >= 32 {
				if status == clienthello.Visible {
					n.sni = name
				}
				e.endHello(n)
				return
			}
			n.partial = make([]byte, 0, maxHelloBytes+40)
			e.buffers++
			n.partial = append(n.partial, payload...)
			return
		}
		n.partial = append(n.partial, payload...)
		name, status := clienthello.ServerName(n.partial)
		if status != clienthello.Incomplete {
			if status == clienthello.Visible {
				n.sni = name
			}
			e.endHello(n)
		}
	}
}

func (e *inspectorEvidence) inbound(f *flow, p packet, now time.Time) {
	if !now.Before(e.until) || p.protocol != 17 || p.srcPort != 53 {
		return
	}
	payload := p.raw[p.transport+8:]
	if len(payload) < 12 {
		return
	}
	k := pendingQuestionKey{f, binary.BigEndian.Uint16(payload)}
	want, ok := e.pending[k]
	if !ok || !now.Before(want.until) {
		return
	}
	parser, q, ok := parseEvidenceQuestion(payload, true)
	if !ok || q != want.question {
		return
	}
	delete(e.pending, k)
	for _, h := range evidenceAnswers(payload, parser, q) {
		k := evidenceAddress{scopeOf(f), h.address}
		c := e.addresses[k]
		if c == nil {
			if h.ttl == 0 || len(e.addresses) >= 1024 {
				continue
			}
			c = &dnsCandidates{names: make(map[string]time.Time)}
			e.addresses[k] = c
		}
		if h.ttl == 0 {
			delete(c.names, q.name)
			continue
		}
		expiry := now.Add(h.ttl)
		if _, found := c.names[q.name]; !found && len(c.names) >= 4 {
			if expiry.After(c.overflowUntil) {
				c.overflowUntil = expiry
			}
		} else {
			c.names[q.name] = expiry
		}
	}
}
