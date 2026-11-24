// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package packetrouter

import (
	"errors"
	"net/netip"
	"sort"
	"time"
)

// Count IP packets and wire bytes accepted by the VPN port or delivered to the
// capture interface. A partially accepted fragment batch counts each outcome.
type TrafficCounters struct {
	PacketsOut     uint64 `json:"packetsOut"`
	BytesOut       uint64 `json:"bytesOut"`
	PacketsIn      uint64 `json:"packetsIn"`
	BytesIn        uint64 `json:"bytesIn"`
	Drops          uint64 `json:"drops"`
	LastDropReason string `json:"lastDropReason,omitempty"`
}

type ruleKey struct {
	kind, source, port, event string
	prefix                    netip.Prefix
}
type ruleCounter struct {
	key    ruleKey
	id     uint64
	active bool
	TrafficCounters
}

type InspectRequest struct {
	Table  string `json:"table"`
	Cursor uint64 `json:"cursor"`
	Limit  int    `json:"limit"`
	Port   string `json:"port"`
	RuleID uint64 `json:"ruleID"`
}

type RuleRow struct {
	ID        uint64 `json:"id"`
	Kind      string `json:"kind"`
	Source    string `json:"source,omitempty"`
	Prefix    string `json:"prefix,omitempty"`
	Port      string `json:"port,omitempty"`
	EventID   string `json:"eventID,omitempty"`
	Active    bool   `json:"active"`
	Available bool   `json:"available"`
	TrafficCounters
}

type FlowRow struct {
	ID               uint64  `json:"id"`
	RuleID           uint64  `json:"ruleID"`
	Revision         uint64  `json:"revision"`
	SourceIP         string  `json:"sourceIP"`
	DestinationIP    string  `json:"destinationIP"`
	SourcePort       uint16  `json:"sourcePort"`
	DestinationPort  uint16  `json:"destinationPort"`
	Protocol         uint8   `json:"protocol"`
	Port             string  `json:"port"`
	PortGeneration   uint64  `json:"portGeneration"`
	Source           string  `json:"source,omitempty"`
	Owner            uint64  `json:"owner"`
	TranslatedSource string  `json:"translatedSource"`
	FirstSeen        float64 `json:"firstSeen"`
	LastSeen         float64 `json:"lastSeen"`
	Blocked          bool    `json:"blocked"`
	DNSName          string  `json:"dnsName,omitempty"`
	TLSServerName    string  `json:"tlsServerName,omitempty"`
	TrafficCounters
}
type Inspection struct {
	Table      string    `json:"table"`
	Revision   uint64    `json:"revision"`
	Total      int       `json:"total"`
	NextCursor uint64    `json:"nextCursor,omitempty"`
	Rules      []RuleRow `json:"rules,omitempty"`
	Flows      []FlowRow `json:"flows,omitempty"`
}

func (r *Router) publishRuleCounters(p Policy, events *EventProgram) {
	for _, record := range r.ruleCounters {
		record.active = false
	}
	if r.ruleCounters == nil {
		r.ruleCounters = make(map[ruleKey]*ruleCounter)
	}
	add := func(k ruleKey) *ruleCounter {
		record := r.ruleCounters[k]
		if record == nil {
			r.nextRule++
			record = &ruleCounter{key: k, id: r.nextRule}
			r.ruleCounters[k] = record
		}
		record.active = true
		return record
	}
	r.unmatched = add(ruleKey{kind: "unmatched"})
	if p.SourceRules == nil {
		r.defaultCounter = add(ruleKey{kind: "default", port: p.Default})
	}
	for _, rule := range p.Rules {
		add(ruleKey{kind: "destination", prefix: rule.Prefix, port: rule.Port})
	}
	for _, source := range p.SourceRules {
		add(ruleKey{kind: "source", source: source.Source, port: source.Port})
		for _, override := range source.Destinations {
			add(ruleKey{kind: "override", source: source.Source, prefix: override.Prefix, port: override.Port})
		}
	}
	if events != nil {
		for _, ev := range events.InspectionCounters() {
			add(ruleKey{kind: "event", event: ev.ID})
		}
	}
	r.pruneRuleCounters()
}

// Called on revision changes or inspection, never in the packet loop.
func (r *Router) pruneRuleCounters() {
	pinned := make(map[*ruleCounter]bool)
	for _, f := range r.flows {
		if !f.rule.active {
			pinned[f.rule] = true
		}
	}
	for k, item := range r.ruleCounters {
		if !item.active && !pinned[item] {
			delete(r.ruleCounters, k)
		}
	}
}

func (r *Router) reject(reason string, rule *ruleCounter, f *flow) bool {
	r.stats.Drops[reason]++
	if f != nil {
		rule = f.rule
		f.counts.Drops++
		f.counts.LastDropReason = reason
	}
	if rule == nil {
		rule = r.unmatched
	}
	if rule != nil {
		rule.Drops++
		rule.LastDropReason = reason
	}
	return false
}

func (f *flow) inbound(length int) {
	f.rule.PacketsIn++
	f.rule.BytesIn += uint64(length)
	f.counts.PacketsIn++
	f.counts.BytesIn += uint64(length)
}

func (f *flow) outbound(packets, bytes uint64) {
	f.rule.PacketsOut += packets
	f.rule.BytesOut += bytes
	f.counts.PacketsOut += packets
	f.counts.BytesOut += bytes
}

func (r *Router) Inspect(req InspectRequest) (Inspection, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	page := Inspection{Table: req.Table, Revision: r.policy.Revision}
	if r.closed {
		return page, errors.New("routing session stopped")
	}
	if req.Table == "stopEvidence" {
		r.stopEvidenceLocked()
		return page, nil
	}
	if req.Limit < 0 || req.Limit > 128 || len(req.Port) > 256 {
		return page, errors.New("invalid inspection page")
	}
	if req.Limit == 0 {
		req.Limit = 50
	}
	now := r.now()
	r.expire(now)
	switch req.Table {
	case "rules":
		r.pruneRuleCounters()
		events := map[string]EventInspectionCounter{}
		if r.events != nil {
			for _, ev := range r.events.InspectionCounters() {
				events[ev.ID] = ev
			}
		}
		var after []*ruleCounter
		for _, item := range r.ruleCounters {
			if (req.Port != "" && item.key.port != req.Port) || (req.RuleID != 0 && item.id != req.RuleID) {
				continue
			}
			page.Total++
			if item.id > req.Cursor {
				after = append(after, item)
			}
		}
		sort.Slice(after, func(i, j int) bool { return after[i].id < after[j].id })
		if len(after) > req.Limit {
			after = after[:req.Limit]
			page.NextCursor = after[len(after)-1].id
		}
		for _, item := range after {
			k := item.key
			_, available := r.activePort(k.port)
			row := RuleRow{ID: item.id, Kind: k.kind, Source: k.source, Port: k.port, EventID: k.event, Active: item.active, Available: available, TrafficCounters: item.TrafficCounters}
			if k.prefix.IsValid() {
				row.Prefix = k.prefix.String()
			}
			if ev, ok := events[k.event]; k.kind == "event" && ok {
				row.PacketsOut += ev.PacketsOut
				row.BytesOut += ev.BytesOut
				row.PacketsIn += ev.PacketsIn
				row.BytesIn += ev.BytesIn
				row.Drops += ev.Drops
			}
			page.Rules = append(page.Rules, row)
		}
	case "flows":
		r.renewEvidenceLocked(now)
		var after []*flow
		for _, f := range r.flows {
			if (req.Port != "" && f.port != req.Port) || (req.RuleID != 0 && f.rule.id != req.RuleID) {
				continue
			}
			page.Total++
			if f.id > req.Cursor {
				after = append(after, f)
			}
		}
		sort.Slice(after, func(i, j int) bool { return after[i].id < after[j].id })
		if len(after) > req.Limit {
			after = after[:req.Limit]
			page.NextCursor = after[len(after)-1].id
		}
		for _, f := range after {
			t := f.reverse.tuple
			port, up := r.activePort(f.port)
			row := FlowRow{ID: f.id, RuleID: f.rule.id, Revision: f.revision, SourceIP: f.captureSource.String(), DestinationIP: t.src.String(),
				SourcePort: t.dstPort, DestinationPort: t.srcPort, Protocol: t.protocol, Port: f.port, PortGeneration: f.generation,
				Source: f.source, Owner: f.owner, TranslatedSource: f.translated.String(), FirstSeen: unixSeconds(f.firstSeen), LastSeen: unixSeconds(f.lastSeen),
				Blocked: f.blocked || !up || port.Generation != f.generation, TrafficCounters: f.counts}
			row.DNSName, row.TLSServerName = r.evidence.names(f, t.src, now)
			page.Flows = append(page.Flows, row)
		}
	default:
		return page, errors.New("unknown inspection table")
	}
	return page, nil
}

func unixSeconds(t time.Time) float64 { return float64(t.UnixMilli()) / 1000 }
