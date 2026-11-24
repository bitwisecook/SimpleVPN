// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package routelang

import (
	"slices"
	"testing"
)

func TestComposedTraceSharesResourceBudgets(t *testing.T) {
	block := " {for outer in range(0,64) {for inner in range(0,24) {count();}}}"
	p := compile(t, "on first:tcp.syn"+block+" on second:tls.hidden"+block)
	for _, name := range []string{"tcp.syn", "tls.hidden"} {
		r, e := p.Run(name, fixtureHost())
		if e != nil || r.Dropped || r.Instructions <= MaxInstructions/2 {
			t.Fatal(name, r, e)
		}
	}
	r, e := p.RunTraceSequence([]string{"tcp.syn", "tls.hidden"}, fixtureHost())
	if e == nil || !r.Dropped || r.Instructions != MaxInstructions+1 || !slices.Equal(r.Matches, []string{"first", "second"}) {
		t.Fatal(r, e)
	}
	r, e = p.RunTraceSequence([]string{"tcp.syn", "tcp.syn"}, fixtureHost())
	if e == nil || !r.Dropped || r.Instructions != 0 {
		t.Fatal("duplicate hook executed", r, e)
	}
}
