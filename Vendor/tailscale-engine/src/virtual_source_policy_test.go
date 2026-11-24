// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"encoding/json"
	"net/netip"
	"testing"

	"pxengine/packetrouter"
)

// Swift encodes optional sourceRules. Omission means ordinary capture; an
// explicit empty list is deny-all for an existing per-app session.
func TestVirtualSourcePolicyWireModes(t *testing.T) {
	capture := netip.MustParseAddr("198.19.255.1")
	port := packetrouter.Port{ID: "work", Generation: 1, MTU: 1280, Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.2")},
		Allowed: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, Send: func([]byte) bool { return true }}
	for _, tc := range []struct {
		wire          string
		scoped, valid bool
	}{
		{`{"version":1,"revision":1,"rules":[],"defaultOwner":"work"}`, false, true},
		{`{"version":1,"revision":1,"rules":[],"sourceRules":[],"defaultOwner":""}`, true, true},
		{`{"version":1,"revision":1,"rules":[],"sourceRules":[{"source":"123-ABC","port":"work"}],"defaultOwner":""}`, true, true},
		{`{"version":1,"revision":1,"sourceRules":[{"source":"app","port":"work","destinations":[{"prefix":"10.0.0.0/8","port":"work"}]}]}`, true, true},
		{`{"version":1,"revision":1,"sourceRules":[{"source":"app","port":"work","destinations":[{"prefix":"10.0.0.0/8","port":"missing"}]}]}`, true, false},
		{`{"version":1,"revision":1,"sourceRules":[{"source":"alias","port":"missing"}]}`, true, false},
		{`{"version":1,"revision":1,"sourceRules":[],"defaultOwner":"work"}`, true, false},
		{`{"version":1,"revision":1,"sourceRules":[{"source":"duplicate","port":"work"},{"source":"duplicate","port":"work"}]}`, true, false},
	} {
		var input vrPolicy
		if err := json.Unmarshal([]byte(tc.wire), &input); err != nil {
			t.Fatal(err)
		}
		policy, err := input.compile()
		if err != nil || (policy.SourceRules != nil) != tc.scoped {
			t.Fatalf("%s: lost source mode, %v", tc.wire, err)
		}
		_, err = packetrouter.New([]netip.Addr{capture}, []packetrouter.Port{port}, policy, func([]byte) {})
		if (err == nil) != tc.valid {
			t.Fatalf("%s: %v", tc.wire, err)
		}
	}
}
