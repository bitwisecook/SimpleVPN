// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package packetrouter

import (
	"net/netip"
	"testing"
)

func exitTestPort(id, address, exit string, destinations ...string) Port {
	port := Port{ID: id, Addresses: []netip.Addr{netip.MustParseAddr(address)},
		ExitNodeID: exit, MTU: 1280, Generation: 1, Send: func([]byte) bool { return true }}
	if exit != "" {
		port.Kind = "tailscale"
	}
	for _, destination := range destinations {
		port.Allowed = append(port.Allowed, netip.MustParsePrefix(destination))
	}
	return port
}

func TestOnExitSelectionUsesTheAuthenticatedMemberAndPinsTheFlow(t *testing.T) {
	const source = "198.19.255.1"
	const target = "192.0.2.30"
	defaultPort := exitTestPort("base", "10.0.0.2", "", "0.0.0.0/0")
	exitA := exitTestPort("exit-a", "100.64.0.3", "nFirst", "0.0.0.0/0")
	exitB := exitTestPort("exit-b", "100.64.0.4", "nSecond", "0.0.0.0/0")
	var outboundA, outboundB [][]byte
	exitA.Send = func(p []byte) bool { outboundA = append(outboundA, p); return true }
	exitB.Send = func(p []byte) bool { outboundB = append(outboundB, p); return true }
	policy := Policy{Revision: 1, Default: "base", EventSource: `
		on https: route.select { if port.dst == 443 { route.exit_node("nFirst"); } }
		on inspect: ip.packet {
			if !flow.has_exit_node { drop(); }
			if flow.exit_node != "nFirst" || flow.member != "exit-a" { drop(); }
		}`}
	r, err := New([]netip.Addr{netip.MustParseAddr(source)}, []Port{defaultPort, exitA, exitB}, policy, func([]byte) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	if !r.Forward(testDatagram(source, target, 44000, 6)) || len(outboundA) != 1 {
		t.Fatal("opening SYN did not use the selected exit")
	}
	packet, err := parse(outboundA[0], false)
	if err != nil || packet.src != exitA.Addresses[0] {
		t.Fatal("translated source did not belong to the selected exit", err)
	}
	policy.Revision = 2
	policy.EventSource = `on https: route.select { route.exit_node("nSecond"); }`
	if err := r.Apply(policy); err != nil {
		t.Fatal(err)
	}
	if !r.Forward(testDatagram(source, target, 44000, 6)) || len(outboundA) != 2 || len(outboundB) != 0 {
		t.Fatal("an existing connection moved to a different exit")
	}
	if !r.Forward(testDatagram(source, target, 44001, 6)) || len(outboundB) != 1 {
		t.Fatal("a new connection did not use the current policy")
	}
}

func TestOnExitSelectionCannotBroadenCaptureOrApplicationAuthorization(t *testing.T) {
	const source = "198.19.255.1"
	policyText := `on choose: route.select { route.exit_node("nFirst"); }`
	for _, testcase := range []struct {
		name   string
		policy Policy
		target string
		want   bool
	}{
		{"uncaptured", Policy{EventSource: policyText}, "192.0.2.30", false},
		{"wrong app egress", Policy{SourceRules: []SourceRule{{Source: "editor", Port: "base"}}, EventSource: policyText}, "192.0.2.30", false},
		{"authorized app", Policy{SourceRules: []SourceRule{{Source: "editor", Port: "exit-a"}}, EventSource: policyText}, "192.0.2.30", true},
		{"more specific tailnet route", Policy{Default: "base", EventSource: policyText}, "203.0.113.30", false},
		{"unknown exit", Policy{Default: "base", EventSource: `on choose: route.select { route.exit_node("nUnavailable"); }`}, "192.0.2.30", false},
		{"conflicting exits", Policy{Default: "base", EventSource: `on choose: route.select { route.exit_node("nFirst"); route.exit_node("nSecond"); }`}, "192.0.2.30", false},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			baseline := exitTestPort("base", "10.0.0.2", "", "0.0.0.0/0")
			exitA := exitTestPort("exit-a", "100.64.0.3", "nFirst", "0.0.0.0/0", "203.0.113.0/24")
			exitB := exitTestPort("exit-b", "100.64.0.4", "nSecond", "0.0.0.0/0")
			sent := 0
			exitA.Send = func([]byte) bool { sent++; return true }
			testcase.policy.Revision = 1
			r, err := New([]netip.Addr{netip.MustParseAddr(source)}, []Port{baseline, exitA, exitB}, testcase.policy, func([]byte) {})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(r.Close)
			packet := testDatagram(source, testcase.target, 44001, 17)
			var allowed bool
			if testcase.policy.SourceRules == nil {
				allowed = r.Forward(packet)
			} else {
				allowed = r.ForwardWithSource(packet, "editor", 100)
			}
			if allowed != testcase.want || (sent == 1) != testcase.want {
				t.Fatal("unexpected egress decision", allowed, sent, r.Status())
			}
		})
	}
}

func TestExitSelectionCompilesOnlyForLiteralIDsOnSharedRouteEvents(t *testing.T) {
	for _, source := range []string{
		`on missing: route.select { route.exit_node("London"); }`,
		`on dynamic: route.select { let node = "nFirst"; route.exit_node(node); }`,
		`on other: tcp.syn { route.exit_node("nFirst"); }`,
		`on inbound: inbound.route.select { route.exit_node("nFirst"); }`,
	} {
		if compiled, err := CompileEvents(source); err == nil {
			compiled.Close()
			t.Fatal("accepted unsupported selection", source)
		}
	}
	for _, source := range []string{
		`on other: route.select { route.exit_node("nFirst"); }`,
		`on other: ip.packet { if flow.has_exit_node { count(); } }`,
	} {
		if compiled, err := CompileAdapterEvents("tailscale-node", source); err == nil {
			compiled.Close()
			t.Fatal("accepted shared-router capabilities for a standalone policy", source)
		}
	}
}
