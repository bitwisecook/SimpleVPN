// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//go:build routing_rust && cgo

package packetrouter

import (
	"bytes"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestNativeCompactCompilerParity(t *testing.T) {
	parts := []string{"", "port 0443", "port +443", "port 1 port 2", "source alias", "source 2-OK",
		"name A.Example.", "name a..example", "dst 0.0.0.0/0", "dst 2001:db8::/33",
		"dst 192.0.2.1/28", "dst ::ffff:192.0.2.1", "dst ::/+0", "dst fe80::1%en0"}
	for _, event := range eventNames {
		for _, pred := range parts {
			for _, action := range []string{"count", "mark-dscp 63", "set-dns-rd 1", "drop", "clamp-mss 536", "mark-dscp -1"} {
				text := fmt.Sprintf("on r %s %s => %s", event, pred, action)
				native, nerr := compileCompact(text)
				ref, rerr := compileCompactReference(text)
				if (nerr == nil) != (rerr == nil) || !slices.Equal(native.InspectionCounters(), ref.InspectionCounters()) {
					t.Fatalf("%q: native %v reference %v", text, nerr, rerr)
				}
			}
		}
	}
}

// Exercise the second 64-bit candidate word, mixed prefix lengths, missing
// attribution, name normalization, declaration order and terminal counters.
func TestNativeCompactMatchParity(t *testing.T) {
	var rules strings.Builder
	for i := 0; i < 128; i++ {
		pred, action := "", "count"
		switch i % 6 {
		case 1:
			pred = "port 80"
			action = "mark-dscp 2"
		case 2:
			pred = "name ExAmPlE.CoM."
			action = "mark-dscp 0"
		case 3:
			pred = "source selected dst 2001:db8:8000::/33"
			action = "mark-dscp 31"
		case 4:
			pred = "dst 192.0.2.128/25"
			action = "mark-dscp 63"
		}
		if i == 96 {
			pred = "source selected"
			action = "drop"
		}
		fmt.Fprintf(&rules, "on r%d dns.query %s => %s\n", i, pred, action)
	}
	native, err := compileCompact(rules.String())
	if err != nil {
		t.Fatal(err)
	}
	ref, err := compileCompactReference(rules.String())
	if err != nil {
		t.Fatal(err)
	}
	if native.native == nil {
		t.Fatal("missing native compact plan")
	}
	for _, dst := range []string{"192.0.2.1", "192.0.2.128", "2001:db8:8000::f", "2001:db8::1"} {
		src := "198.18.0.1"
		if netip.MustParseAddr(dst).Is6() {
			src = "2001:db8:1::1"
		}
		for _, port := range []uint16{53, 80, 443} {
			for _, identity := range []observed[string]{{}, present("other"), present("selected")} {
				for _, name := range []string{"", "eXaMpLe.cOm", "unmatched.test"} {
					raw := testDatagram(src, dst, 40000, 17)
					a, erra := parse(bytes.Clone(raw), false)
					b, errb := parse(bytes.Clone(raw), false)
					if erra != nil || errb != nil {
						t.Fatal(erra, errb)
					}
					nok := native.matchCompact(native.table[dnsQuery].candidates(port), &a, identity, name)
					rok := ref.matchCompactReference(ref.table[dnsQuery].candidates(port).mask, &b, identity, name)
					if nok != rok || !bytes.Equal(a.raw, b.raw) || !slices.Equal(native.counts, ref.counts) {
						t.Fatalf("native mismatch on %s:%d, source %v, DNS %q", dst, port, identity, name)
					}
				}
			}
		}
	}
}

func TestCompactSpecializesOnlyPacketIndependentSelections(t *testing.T) {
	source := "on base tcp.syn => count\non byport tcp.syn port 443 => mark-dscp 46\non private tcp.syn port 22 dst 10.0.0.0/8 => drop\non late tcp.syn => count"
	p, err := CompileEvents(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, port := range []uint16{22, 443, 999} {
		sel := p.table[tcpSyn].candidates(port)
		if (sel.fixed != nil) != (port != 22) {
			t.Fatalf("incorrect specialization for %d", port)
		}
	}
}
