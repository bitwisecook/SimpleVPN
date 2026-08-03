// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// Pure-logic tests for the shim: the pieces that decide what the app sees
// without needing a 1Password app to talk to. Run by
// Tools/build-onepassword-sdk.sh before the archive is produced.
package main

import "testing"

// titleScore is the shim's half of a contract shared with the app's FuzzyMatch:
// both must rank the same candidate the same way, or the list the lookup
// returns and the list the picker filters locally disagree about which row is
// first — and Return picks the first row.
func TestTitleScore(t *testing.T) {
	cases := []struct {
		query, title, id string
		want             int
		match            bool
	}{
		{"", "anything", "i1", 0, true},             // browse: everything, unranked
		{"i1", "anything", "i1", 0, true},           // a full UUID is not a guess
		{"gr lab vpn", "GR Lab VPN", "i1", 0, true}, // exact, case-folded
		{"gr", "GR Lab VPN", "i1", 1, true},         // prefix
		{"lab", "GR Lab VPN", "i1", 2, true},        // substring
		{"grv", "GR Lab VPN", "i1", 3, true},        // letters in order
		{"wrk", "Work Router", "i1", 3, true},       // the documented example
		{"zzz", "GR Lab VPN", "i1", 0, false},       // no match at all
		{"vpnn", "GR Lab VPN", "i1", 0, false},      // subsequence must run out
	}
	for _, c := range cases {
		score, ok := titleScore(c.query, c.title, c.id)
		if ok != c.match {
			t.Errorf("titleScore(%q, %q): match = %v, want %v", c.query, c.title, ok, c.match)
			continue
		}
		if ok && score != c.want {
			t.Errorf("titleScore(%q, %q) = %d, want %d", c.query, c.title, score, c.want)
		}
	}
}

// parseItemLink peels the two link shapes 1Password hands out; a bare title or
// UUID must pass through untouched (ok == false), because the caller then
// searches by name instead of trusting coordinates it doesn't have.
func TestParseItemLink(t *testing.T) {
	item, vault, ok := parseItemLink("op://Private/GR Lab VPN/password")
	if !ok || item != "GR Lab VPN" || vault != "Private" {
		t.Errorf("op:// = (%q, %q, %v)", item, vault, ok)
	}
	item, vault, ok = parseItemLink("onepassword://open/i?a=A&v=V&i=I")
	if !ok || item != "I" || vault != "V" {
		t.Errorf("deep link = (%q, %q, %v)", item, vault, ok)
	}
	if _, _, ok := parseItemLink("GR Lab VPN"); ok {
		t.Error("a bare title must not be read as a link")
	}
}

// A wire error code the app can act on beats a prose message it can't: an
// unmatched ACCOUNT is answered by naming the account, so it must never
// classify as a missing item ("pick the item again" sends the user in circles).
func TestClassifyAccountNotFoundBeatsNotFound(t *testing.T) {
	e := classify(errString("error processing SDK request: Account not found"))
	if e.Kind != kindAccountNotFound {
		t.Errorf("kind = %q, want %q", e.Kind, kindAccountNotFound)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
