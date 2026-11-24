// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestTwoVPNPolicy(t *testing.T) {
	f, err := os.Open("testdata/two-vpns.route")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p, err := compile(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ ip, id, vpn string }{
		{"10.42.8.19", "payroll", "finance"},
		{"10.42.8.20", "office", "work"},
		{"2001:db8:42::5", "office6", "work"},
		{"2001:db8:43::5", "default", ""},
		{"203.0.113.7", "default", ""},
	} {
		hit := p.lookup(netip.MustParseAddr(tc.ip))
		if hit.ID != tc.id || hit.Action.VPN != tc.vpn || (hit.Action.Kind == "drop") != (tc.vpn == "") {
			t.Errorf("%s: %+v", tc.ip, hit)
		}
	}
}

func TestRejectsAmbiguousAndUnsupportedDrafts(t *testing.T) {
	for _, tc := range []struct{ src, problem string }{
		{"policy 2\ndefault drop", "policy 1"},
		{"policy 1\nrule a ip 10.0.0.1/8 via work\ndefault drop", "canonical"},
		{"policy 1\nrule a ip ::ffff:192.0.2.1 via work\ndefault drop", "canonical"},
		{"policy 1\nrule a ip 10.0.0.0/8 via work\nrule b ip 10.0.0.1 drop\ndefault drop", "earlier rule a"},
		{"policy 1\nrule a ip 10.0.0.1 via work\nrule a ip 10.0.0.2 via home\ndefault drop", "duplicate"},
		{"policy 1\nrule a ip 10.0.0.1 via work", "final default"},
		{"policy 1\ndefault via home\nrule a ip 10.0.0.1 drop", "last statement"},
		{"policy 1\nrule a sni api.example.test via work\ndefault drop", "expected"},
		{"policy 1\nrule a ip 10.0.0.1 via [exec]\ndefault drop", "expected"},
		{strings.Repeat("x", maxSourceBytes+1), "256 KiB"},
	} {
		if _, err := compile(strings.NewReader(tc.src)); err == nil || !strings.Contains(err.Error(), tc.problem) {
			t.Errorf("expected %q, got %v", tc.problem, err)
		}
	}
}

func TestSourcePolicyPreviewAndTokens(t *testing.T) {
	source := "policy 1\nrule browser app signed office via work\nrule oneprocess process build via private\ndefault drop"
	for _, tc := range []struct {
		args []string
		id   string
	}{
		{[]string{"--app", "office", "-", "192.0.2.1"}, "browser"},
		{[]string{"--process", "build", "-", "2001:db8::7"}, "oneprocess"},
		{[]string{"--process", "office", "-", "192.0.2.1"}, "default"},
		{[]string{"--app", "unknown", "-", "192.0.2.1"}, "default"},
		{[]string{"-", "192.0.2.1"}, "default"},
	} {
		var output strings.Builder
		if err := runCommand(tc.args, strings.NewReader(source), &output); err != nil {
			t.Fatal(err)
		}
		var result struct{ Rule rule }
		if err := json.Unmarshal([]byte(output.String()), &result); err != nil || result.Rule.ID != tc.id {
			t.Fatalf("%v: %v, %s", tc.args, err, output.String())
		}
	}
	for _, tok := range highlight(source) {
		if tok.Kind == "error" {
			t.Fatal("valid source policy contains an error token")
		}
		name := source[tok.Offset : tok.Offset+tok.Length]
		if (name == "build" || name == "office") && tok.Kind != "source" {
			t.Fatal("missing source style", name)
		}
	}
	for _, invalid := range []string{
		"rule a process proc via work\ndefault via work",
		"rule a app signed shared via work\nrule b process shared drop\ndefault drop",
		"rule a app proc via work\ndefault drop",
		"rule a process proc via work\nrule b ip 192.0.2.1 via work\ndefault drop",
	} {
		if _, err := compile(strings.NewReader("policy 1\n" + invalid)); err == nil {
			t.Fatal("accepted invalid source policy", invalid)
		}
	}
}

func TestSourceDestinationPreview(t *testing.T) {
	const source = "policy 1\nrule host app signed client ip 10.42.0.7 via finance\nrule office app signed client ip 10.42.0.0/16 via work\nrule allow app signed client via home\nrule v6 process build ip 2001:db8::/32 via lab\nrule base process build drop\ndefault drop"
	for _, tc := range []struct{ kind, alias, ip, want string }{
		{"--app", "client", "10.42.0.7", "host"}, {"--app", "client", "10.42.0.9", "office"},
		{"--app", "client", "192.0.2.1", "allow"}, {"--process", "build", "2001:db8::8", "v6"},
		{"--process", "build", "10.42.0.7", "base"}, {"--process", "unknown", "10.42.0.7", "default"},
	} {
		var out strings.Builder
		err := runCommand([]string{tc.kind, tc.alias, "-", tc.ip}, strings.NewReader(source), &out)
		var got struct{ Rule rule }
		if err != nil || json.Unmarshal([]byte(out.String()), &got) != nil || got.Rule.ID != tc.want {
			t.Fatalf("%+v: %v, %s", tc, err, out.String())
		}
	}
	for _, tok := range highlight(source) {
		if tok.Kind == "error" {
			t.Fatal("error token in valid compound source rule")
		}
	}
	for _, bad := range []string{
		"rule a process builder ip 10.0.0.0/8 drop",
		"rule a process builder via home\nrule b process builder ip 10.0.0.0/8 via office",
		"rule a app signed cli ip 10.0.0.0/8 drop\nrule b app signed cli ip 10.0.0.1 via office\nrule c app signed cli via home",
	} {
		if _, err := compile(strings.NewReader("policy 1\n" + bad + "\ndefault drop")); err == nil {
			t.Fatal("accepted shadowed/incomplete", bad)
		}
	}
}
