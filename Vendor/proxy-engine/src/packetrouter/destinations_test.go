// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package packetrouter

import (
	"fmt"
	"math/rand"
	"net/netip"
	"sort"
	"testing"
)

func linearLookup(rules []Rule, addr netip.Addr) (Rule, bool) {
	for _, rule := range rules {
		if rule.Prefix.Contains(addr) {
			return rule, true
		}
	}
	return Rule{}, false
}

func TestCompiledDestinationPrecedence(t *testing.T) {
	rng := rand.New(rand.NewSource(522))
	for _, size := range []int{0, 1, 8, 9, 64, 4096} {
		var rules []Rule
		queries := []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1")}
		for i := 0; i < size; i++ {
			var raw [16]byte
			rng.Read(raw[:])
			addr := netip.AddrFrom16(raw)
			if i%2 == 0 {
				addr = netip.AddrFrom4([4]byte(raw[:4]))
			}
			p := netip.PrefixFrom(addr, rng.Intn(addr.BitLen()+1)).Masked()
			if i > 0 && i%7 == 0 {
				p = rules[i-1].Prefix
			}
			rules = append(rules, Rule{p, fmt.Sprint(i)})
			queries = append(queries, addr, p.Addr())
		}
		table := CompileDestinations(rules)
		sort.SliceStable(rules, func(i, j int) bool { return rules[i].Prefix.Bits() > rules[j].Prefix.Bits() })
		for _, addr := range queries {
			got, ok := table.Lookup(addr)
			want, exists := linearLookup(rules, addr)
			if ok != exists || got != want {
				t.Fatalf("%d rules, %v: got %v %v, want %v %v", size, addr, got, ok, want, exists)
			}
		}
		if len(rules) > 0 {
			addr := rules[0].Prefix.Addr()
			before, _ := table.Lookup(addr)
			rules[0].Port = "changed"
			if after, _ := table.Lookup(addr); after != before {
				t.Fatal("index aliases caller's slice")
			}
		}
	}
}

var benchmarkDecision Rule

func BenchmarkDestinationLookup(b *testing.B) {
	for _, size := range []int{4, 100, 4096} {
		rules := make([]Rule, size)
		for i := range rules {
			a := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0})
			rules[i] = Rule{netip.PrefixFrom(a, 24), "work"}
		}
		table := CompileDestinations(rules)
		queries := []netip.Addr{rules[0].Prefix.Addr(), rules[size/2].Prefix.Addr(), rules[size-1].Prefix.Addr(), netip.MustParseAddr("192.0.2.1")}
		for _, indexed := range []bool{false, true} {
			name := "linear"
			if indexed {
				name = "indexed"
			}
			b.Run(fmt.Sprintf("%d/%s", size, name), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					addr := queries[i%len(queries)]
					if indexed {
						benchmarkDecision, _ = table.Lookup(addr)
					} else {
						benchmarkDecision, _ = linearLookup(rules, addr)
					}
				}
			})
		}
	}
}
