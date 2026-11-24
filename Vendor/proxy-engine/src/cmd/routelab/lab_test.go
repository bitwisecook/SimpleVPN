// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"encoding/json"
	"pxengine/routelang"
	"testing"
)

func TestPlaygroundStagesUpdatesAndReportsBothBranches(t *testing.T) {
	const raw = `{"source":"on adjust: tcp.syn { if tcp.mss > 1280 { tcp.mss = 1280; } }","events":[{"event":"tcp.syn","fields":{"tcp.mss":1460},"bytes":[1,2]},{"event":"tcp.syn","fields":{"tcp.mss":1100},"bytes":[3]}]}`
	result, err := evaluate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Steps) != 2 || len(result.Counters) != 1 || result.Counters[0].Bytes == nil || *result.Counters[0].Bytes != 3 {
		t.Fatalf("incomplete counters %+v", result)
	}
	a, b := result.Steps[0], result.Steps[1]
	if a.Before["tcp.mss"] != int64(1460) || a.After["tcp.mss"] != int64(1280) || b.After["tcp.mss"] != int64(1100) || len(a.Trace) == 0 || !a.Trace[0].Taken || b.Trace[0].Taken {
		t.Fatalf("unexpected trace %+v", result)
	}
}
func TestMissingEvidenceRollsBackEarlierWrite(t *testing.T) {
	const raw = `{"source":"on example: tcp.syn { ip.dscp = 10; if tcp.mss > 1200 { count(); } }","events":[{"event":"tcp.syn","fields":{"ip.dscp":0}}]}`
	result, e := evaluate(raw)
	if e != nil || len(result.Steps) != 1 {
		t.Fatal(e)
	}
	step := result.Steps[0]
	if !step.Dropped || step.Error == "" || step.After["ip.dscp"] != int64(0) {
		t.Fatal(step)
	}
}

func TestRouteSelectReportsTheRequestedStableExitNode(t *testing.T) {
	const raw = `{"source":"on chosen: route.select { if port.dst == 443 { route.exit_node(\"nFirst\"); } }","events":[{"event":"route.select","fields":{"port.dst":443}}]}`
	result, err := evaluate(raw)
	if err != nil || len(result.Steps) != 1 {
		t.Fatal(err)
	}
	step := result.Steps[0]
	if step.Dropped || len(step.Actions) != 1 || step.Actions[0].Name != "route.exit_node" || step.Actions[0].Args[0] != "nFirst" {
		t.Fatal(step)
	}
}
func TestPlaygroundRejectsUnknownFieldsAndInputTypes(t *testing.T) {
	for _, raw := range []string{`{"source":"on test: tcp.syn { count(); }","events":[{"event":"tcp.syn","fields":{"tls.private_key":"invalid"}}]}`, `{"source":"on test: tcp.syn { count(); }","events":[{"event":"tcp.syn","fields":{"tcp.mss":true}}]}`} {
		var result evaluation
		if err := json.Unmarshal([]byte(encodedEvaluate(raw)), &result); err != nil || result.OK || result.Error == "" {
			t.Fatal(err, result)
		}
	}
}

func TestEmptyInputIsPresentAndUnknownByteCountsStayUnknown(t *testing.T) {
	measure := func(events []map[string]any) counter {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"source": "on audit: tcp.syn { if flow.source == \"\" { count(); } }", "events": events})
		if err != nil {
			t.Fatal(err)
		}
		r, err := evaluate(string(raw))
		if err != nil {
			t.Fatal(err)
		}
		if r.Steps[0].Dropped || len(r.Steps[0].Actions) != 1 || r.Steps[0].Actions[0].Name != "count" {
			t.Fatal("lost explicitly empty source", r.Steps)
		}
		if len(r.Steps) > 1 && (!r.Steps[1].Dropped || r.Steps[1].Error == "") {
			t.Fatal("missing source was converted to empty", r.Steps)
		}
		return r.Counters[0]
	}
	row := map[string]any{"event": "tcp.syn", "fields": map[string]any{"flow.source": ""}, "bytes": []int{}}
	count := measure([]map[string]any{row})
	if count.Bytes == nil || *count.Bytes != 0 || count.UnmeasuredEvents != 0 {
		t.Fatal("empty packet became unknown", count)
	}
	count = measure([]map[string]any{row, {"event": "tcp.syn", "fields": map[string]any{}}})
	if count.Bytes != nil || count.UnmeasuredEvents != 1 {
		t.Fatal("missing bytes became zero", count)
	}
	for _, tc := range []struct {
		kind  routelang.Type
		value any
	}{{routelang.TBytes, []any{}}, {routelang.ArrayType(routelang.TInt), []any{}}} {
		v, err := toValue(tc.kind, tc.value)
		if err != nil {
			t.Fatal(err)
		}
		got, err := fromValue(v)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(got)
		if string(b) != "[]" {
			t.Fatal("empty data changed type", string(b))
		}
	}
	if _, err := fromValue(routelang.Value{}); err == nil {
		t.Fatal("invalid value became an empty array")
	}
}

func TestLaterDropRollsBackEffectsAndFoundEmptyBackendIsAnError(t *testing.T) {
	for _, program := range []string{
		"on first: ip.packet { ip.dscp=16; count(); } on last: ip.packet { drop(); }",
		"table backends: dns -> string = external \"backends\"; on choose: proxy.pre_connect { match lookup(backends,tls.sni) { found(backend) {proxy.select_backend(backend);} missing {drop();} } }",
	} {
		e := map[string]any{"event": "ip.packet", "fields": map[string]any{"ip.dscp": 0}, "bytes": []int{}}
		isLookup := program[0] == 't'
		if isLookup {
			e = map[string]any{"event": "proxy.pre_connect", "fields": map[string]any{"tls.sni": "portal.example"}}
		}
		req := map[string]any{"source": program, "events": []any{e}}
		if isLookup {
			req["tableJSON"] = map[string]any{"backends": map[string]any{"key": "dns", "element": "string", "entries": []any{map[string]any{"key": "portal.example", "value": ""}}}}
		}
		raw, _ := json.Marshal(req)
		result, err := evaluate(string(raw))
		if err != nil {
			t.Fatal(err)
		}
		step := result.Steps[0]
		if !step.Dropped || len(step.Actions) != 0 {
			t.Fatal("committed dropped operation", step)
		}
		if isLookup && step.Error == "" {
			t.Fatal("invalid backend treated as a missing entry")
		}
		if !isLookup && (step.Error != "" || step.After["ip.dscp"] != int64(0)) {
			t.Fatal("lost explicit zero on rollback", step)
		}
	}
}
