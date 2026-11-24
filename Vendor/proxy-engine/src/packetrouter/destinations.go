// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package packetrouter

import (
	"net/netip"
	"sort"
)

const linearPrefixLimit = 8

// DestinationTable is an immutable longest-prefix index. Equal prefixes retain
// their first declared owner. The caller validates prefixes and authorizes ports.
type DestinationTable struct {
	small  []Rule
	v4, v6 []prefixGroup
}

type prefixGroup struct {
	bits  int
	ports map[netip.Prefix]string
}

// CompileDestinations takes its own copy of the routing decision data.
func CompileDestinations(rules []Rule) DestinationTable {
	var table DestinationTable
	if len(rules) <= linearPrefixLimit {
		table.small = append([]Rule(nil), rules...)
		sort.SliceStable(table.small, func(i, j int) bool {
			return table.small[i].Prefix.Bits() > table.small[j].Prefix.Bits()
		})
		return table
	}
	var v4, v6 [129]map[netip.Prefix]string
	for _, rule := range rules {
		groups := &v6
		if rule.Prefix.Addr().Is4() {
			groups = &v4
		}
		bits := rule.Prefix.Bits()
		if bits < 0 {
			continue
		}
		if groups[bits] == nil {
			groups[bits] = make(map[netip.Prefix]string)
		}
		if _, exists := groups[bits][rule.Prefix]; !exists {
			groups[bits][rule.Prefix] = rule.Port
		}
	}
	for bits := 128; bits >= 0; bits-- {
		if v4[bits] != nil {
			table.v4 = append(table.v4, prefixGroup{bits, v4[bits]})
		}
		if v6[bits] != nil {
			table.v6 = append(table.v6, prefixGroup{bits, v6[bits]})
		}
	}
	return table
}

func (table *DestinationTable) Lookup(addr netip.Addr) (Rule, bool) {
	if !addr.IsValid() || addr.Zone() != "" {
		return Rule{}, false
	}
	for _, rule := range table.small {
		if rule.Prefix.Contains(addr) {
			return rule, true
		}
	}
	groups := table.v6
	if addr.Is4() {
		groups = table.v4
	}
	for _, group := range groups {
		prefix := netip.PrefixFrom(addr, group.bits).Masked()
		if port, ok := group.ports[prefix]; ok {
			return Rule{Prefix: prefix, Port: port}, true
		}
	}
	return Rule{}, false
}
