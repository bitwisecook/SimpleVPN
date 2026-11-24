// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package packetrouter

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"testing"
	"time"
)

func TestInspectRuleAndFlowAccounting(t *testing.T) {
	const capture, assigned, remote = "198.19.255.1", "10.0.0.2", "192.0.2.77"
	accept := true
	port := Port{ID: "default", Generation: 9, MTU: 1280, Addresses: []netip.Addr{netip.MustParseAddr(assigned)},
		Allowed: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, Send: func([]byte) bool { return accept }}
	other := port
	other.ID = "private"
	other.Generation = 10
	claim := netip.MustParsePrefix("192.0.2.0/24")
	policy := Policy{Revision: 1, Default: "default", Rules: []Rule{{claim, "private"}}}
	r, err := New([]netip.Addr{netip.MustParseAddr(capture)}, []Port{port, other}, policy, func([]byte) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	now := time.Unix(1720000000, 0)
	r.now = func() time.Time { return now }
	out := testDatagram(capture, remote, 40007, 17)
	if !r.Forward(out) {
		t.Fatal("failed to open flow")
	}
	accept = false
	if r.Forward(out) {
		t.Fatal("full queue accepted")
	}
	accept = true
	reply := testDatagram(remote, assigned, 443, 17)
	p, err := parse(reply, false)
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(reply[p.transport+2:], 40007)
	p.fixTransportChecksum()
	now = now.Add(3 * time.Second)
	if !r.Return("private", 10, reply) {
		t.Fatal("return rejected")
	}
	page, err := r.Inspect(InspectRequest{Table: "flows", Port: "private"})
	if err != nil || len(page.Flows) != 1 {
		t.Fatal(err, page)
	}
	f := page.Flows[0]
	if f.SourceIP != capture || f.DestinationIP != remote || f.TranslatedSource != assigned || f.SourcePort != 40007 || f.DestinationPort != 443 || f.Protocol != 17 ||
		f.PortGeneration != 10 || f.Revision != 1 || f.FirstSeen != 1720000000 || f.LastSeen != 1720000003 || f.PacketsOut != 1 || f.PacketsIn != 1 || f.Drops != 1 ||
		f.BytesOut != uint64(len(out)) || f.BytesIn != uint64(len(reply)) || f.LastDropReason != "VPN packet queue full" || f.Blocked {
		t.Fatalf("wrong flow: %+v", f)
	}
	byID := InspectRequest{Table: "rules", RuleID: f.RuleID}
	rules, err := r.Inspect(byID)
	if err != nil || len(rules.Rules) != 1 {
		t.Fatal(err, rules)
	}
	rule := rules.Rules[0]
	if !rule.Active || !rule.Available || rule.Kind != "destination" || rule.Prefix != claim.String() || rule.TrafficCounters != f.TrafficCounters {
		t.Fatalf("wrong rule: %+v", rule)
	}
	policy.Revision++
	policy.Rules = nil
	if err := r.Check(policy); err != nil {
		t.Fatal(err)
	}
	unchanged, _ := r.Inspect(byID)
	if unchanged.Revision != 1 || !unchanged.Rules[0].Active {
		t.Fatal("check published a revision", unchanged)
	}
	if err := r.Apply(policy); err != nil {
		t.Fatal(err)
	}
	if !r.Forward(out) || !r.Forward(testDatagram(capture, remote, 40008, 17)) {
		t.Fatal("revised policy rejected valid flows")
	}
	retired, _ := r.Inspect(byID)
	if retired.Rules[0].Active || retired.Rules[0].PacketsOut != 2 {
		t.Fatal("lost pinned rule accounting", retired)
	}
	first, _ := r.Inspect(InspectRequest{Table: "flows", Limit: 1})
	next, _ := r.Inspect(InspectRequest{Table: "flows", Limit: 1, Cursor: first.NextCursor})
	if first.Total != 2 || first.NextCursor == 0 || next.NextCursor != 0 || len(next.Flows) != 1 || next.Flows[0].ID <= first.Flows[0].ID ||
		next.Flows[0].Port != "default" || next.Flows[0].Revision != 2 {
		t.Fatal("unstable paging", first, next)
	}
	r.RemovePort("private")
	if r.Forward(out) {
		t.Fatal("retired member still forwarded")
	}
	stopped, _ := r.Inspect(byID)
	if stopped.Rules[0].Available || stopped.Rules[0].Drops != 2 {
		t.Fatal("lost stopped-member drop", stopped)
	}
	now = now.Add(3 * time.Minute)
	reaped, _ := r.Inspect(byID)
	if reaped.Total != 0 {
		t.Fatal("expired rule retained", reaped)
	}
	status, _ := json.Marshal(r.Status())
	var fields map[string]any
	if err := json.Unmarshal(status, &fields); err != nil || fields["rules"] != nil || fields["flowTable"] != nil {
		t.Fatal("normal status grew an inspection table", string(status))
	}
}

func TestInspectSourceRuleDeniedAndUnknown(t *testing.T) {
	const capture = "198.19.255.1"
	full := Port{ID: "home", Generation: 1, MTU: 1280, Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.2")}, Allowed: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, Send: func([]byte) bool { return true }}
	split := full
	split.ID = "office"
	split.Generation = 2
	split.Allowed = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	cfg := Policy{Revision: 7, SourceRules: []SourceRule{{Source: "mail", Port: "home", Destinations: []Rule{{netip.MustParsePrefix("192.0.2.0/24"), "office"}}}}}
	r, err := New([]netip.Addr{netip.MustParseAddr(capture)}, []Port{full, split}, cfg, func([]byte) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	dst := "192.0.2.3"
	sourceOwner := uint64(14)<<32 | 2
	if r.ForwardWithSource(testDatagram(capture, dst, 40001, 17), "mail", sourceOwner) || r.Forward(testDatagram(capture, dst, 40002, 17)) {
		t.Fatal("unauthorized traffic accepted")
	}
	if !r.ForwardWithSource(testDatagram(capture, "203.0.113.1", 40003, 17), "mail", sourceOwner) {
		t.Fatal("authorized default drop")
	}
	page, err := r.Inspect(InspectRequest{Table: "rules"})
	if err != nil || page.Total != 3 {
		t.Fatal(err, page)
	}
	for _, item := range page.Rules {
		switch item.Kind {
		case "unmatched":
			if item.Drops != 1 {
				t.Fatal(item)
			}
		case "override":
			if item.Drops != 1 || item.LastDropReason != "selected VPN cannot carry this destination" || item.Source != "mail" {
				t.Fatal(item)
			}
		case "source":
			if item.PacketsOut != 1 || item.Port != "home" {
				t.Fatal(item)
			}
		default:
			t.Fatal(item)
		}
	}
	page, _ = r.Inspect(InspectRequest{Table: "flows"})
	if len(page.Flows) != 1 || page.Flows[0].Source != "mail" || page.Flows[0].Owner != sourceOwner {
		t.Fatal(page)
	}
	if _, err := r.Inspect(InspectRequest{Table: "flows", Limit: 129}); err == nil {
		t.Fatal("accepted unbounded page")
	}
}
