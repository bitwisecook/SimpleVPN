// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"pxengine/routelang"
	"pxengine/routelang/catalog"
)

func socketQuery(t *testing.T, source string, fields ...map[string]any) string {
	t.Helper()
	events := make([]map[string]any, len(fields))
	for i, input := range fields {
		events[i] = map[string]any{"event": "socket.open", "fields": input}
	}
	raw, err := json.Marshal(map[string]any{"source": source, "events": events})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestProcessSelectionRequiresSeparateEvidence(t *testing.T) {
	const rule = `on process_route: socket.open {
		if socket.transport == "tcp" && socket.remote_port == 443 && process.signature_verified && process.signing_identifier == "example.client" && len(process.ancestor_paths) == 1 && process.proxy_endpoint_matched {
			source.select_member("work");
		}
	}`
	if _, err := routelang.Compile(rule, catalog.Packet(), nil); err == nil {
		t.Fatal("packet adapter admitted offline process evidence")
	}
	fields := func() map[string]any {
		return map[string]any{
			"socket.transport": "tcp", "socket.family": "ipv4", "socket.local_address": "192.0.2.73",
			"socket.local_port": 49012, "socket.remote_address": "198.51.100.18", "socket.remote_port": 443,
			"process.executable_path": "/opt/example/client", "process.executable_name": "client",
			"process.signing_identifier": "example.client", "process.signature_verified": true,
			"process.ancestor_paths": []string{"/usr/bin/make"}, "process.proxy_variable": "HTTP_PROXY",
			"process.expected_proxy_endpoint": "http://Proxy.Example:8080/", "process.proxy_endpoint_matched": true,
		}
	}
	falseVerdict, unavailable, unverified := fields(), fields(), fields()
	falseVerdict["process.proxy_endpoint_matched"] = false
	delete(unavailable, "process.proxy_endpoint_matched")
	unverified["process.signature_verified"] = false
	r, err := evaluate(socketQuery(t, rule, fields(), falseVerdict, unavailable, unverified))
	if err != nil {
		t.Fatal(err)
	}
	pick := r.Steps[0]
	if pick.Dropped || len(pick.Actions) != 1 || pick.Actions[0].Name != "source.select_member" ||
		pick.Actions[0].Args[0] != "work" || pick.Before["process.expected_proxy_endpoint"] != "proxy.example:8080" {
		t.Fatal(pick)
	}
	for _, i := range []int{1, 3} {
		if r.Steps[i].Dropped || len(r.Steps[i].Actions) != 0 {
			t.Fatal(r.Steps[i])
		}
	}
	if step := r.Steps[2]; !step.Dropped || !strings.Contains(step.Error, "process.proxy_endpoint_matched") || len(step.Actions) != 0 {
		t.Fatal(step)
	}
}

func TestProcessAncestryAndEffectsAreExplicit(t *testing.T) {
	const rule = `on ancestors: socket.open { if len(process.ancestor_paths) == 0 { source.select_member("local"); } }`
	r, err := evaluate(socketQuery(t, rule, map[string]any{"process.ancestor_paths": []string{}}, map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if r.Steps[0].Dropped || len(r.Steps[0].Actions) != 1 || !r.Steps[1].Dropped || !strings.Contains(r.Steps[1].Error, "process.ancestor_paths") {
		t.Fatal(r.Steps)
	}
	for _, source := range []string{
		`on choose: socket.open { source.select_member("work"); source.select_member("invalid/member"); }`,
		`on choose: socket.open { source.select_member("work"); } on veto: socket.open { drop(); }`,
	} {
		r, err := evaluate(socketQuery(t, source, map[string]any{}))
		if err != nil || !r.Steps[0].Dropped || len(r.Steps[0].Actions) != 0 {
			t.Fatal(err, r)
		}
	}
}

func TestProcessFixtureRejectsUnscopedProxyEvidence(t *testing.T) {
	for _, fields := range []map[string]any{
		{"process.proxy_endpoint_matched": true},
		{"process.proxy_endpoint_matched": false, "process.proxy_variable": "HTTP_PROXY"},
		{"process.proxy_variable": "UNRELATED", "process.expected_proxy_endpoint": "localhost:3128"},
		{"process.expected_proxy_endpoint": "http://user:synthetic-secret@localhost:3128/"},
		{"process.environment": map[string]any{"http_proxy": "synthetic-secret"}},
		{"process.ancestor_paths": []string{"relative/parent"}},
	} {
		raw := encodedEvaluate(socketQuery(t, "on decide: socket.open { count(); }", fields))
		var r evaluation
		if err := json.Unmarshal([]byte(raw), &r); err != nil || r.OK || r.Error == "" || strings.Contains(raw, "synthetic-secret") {
			t.Fatal("unsafe fixture accepted or echoed", r.Error)
		}
	}
	for _, endpoint := range []string{"proxy.example", "localhost:0", "localhost:65536", "localhost:80/path", "localhost:80?token", "localhost%2e:80", "K:3128", "[::1%25lo]:8080", "proxy.example: 80"} {
		if _, ok := fixtureProxyEndpoint(endpoint); ok {
			t.Fatal("accepted invalid endpoint", endpoint)
		}
	}
	for endpoint, want := range map[string]string{"[::1]:3128": "[::1]:3128", "HTTP://PROXY.EXAMPLE:080/": "proxy.example:80", "127.0.0.1:8080": "127.0.0.1:8080"} {
		if got, ok := fixtureProxyEndpoint(endpoint); !ok || got != want {
			t.Fatal(endpoint, got)
		}
	}
}

func TestSocketOpenKeepsMissingFieldsDistinct(t *testing.T) {
	const localPort = `on opening: socket.open { if socket.transport == "udp" && socket.local_port == 0 { source.select_member("dns"); } }`
	r, err := evaluate(socketQuery(t, localPort,
		map[string]any{"socket.transport": "udp", "socket.local_port": 0, "socket.local_address": "::", "socket.remote_address": "2001:db8::1", "socket.remote_port": 53},
		map[string]any{"socket.transport": "udp", "socket.remote_address": "2001:db8::2", "socket.remote_port": 53},
	))
	if err != nil {
		t.Fatal(err)
	}
	if step := r.Steps[0]; step.Dropped || len(step.Actions) != 1 || step.Before["socket.local_port"] != int64(0) {
		t.Fatal(step)
	}
	if step := r.Steps[1]; !step.Dropped || !strings.Contains(step.Error, "socket.local_port") || len(step.Actions) != 0 {
		t.Fatal(step)
	}
	const family = `on identify: socket.open { if socket.family == "ipv6" { count(); } }`
	r, err = evaluate(socketQuery(t, family, map[string]any{"socket.local_address": "::1"}))
	if err != nil || !r.Steps[0].Dropped || !strings.Contains(r.Steps[0].Error, "socket.family") {
		t.Fatal(err, r)
	}
}

func TestSocketOpenRejectsInconsistentFacts(t *testing.T) {
	const rule = "on validate: socket.open { count(); }"
	for _, fields := range []map[string]any{
		{"socket.transport": "quic"}, {"socket.family": "unix"},
		{"socket.family": "ipv6", "socket.local_address": "192.0.2.3"},
		{"socket.family": "ipv4", "socket.remote_address": "2001:db8::1"},
		{"socket.local_address": "::", "socket.remote_address": "192.0.2.1"},
		{"socket.remote_address": "server.example"}, {"socket.local_address": "::ffff:192.0.2.1"},
		{"socket.local_port": -1}, {"socket.local_port": 65536},
		{"socket.remote_port": 0}, {"socket.remote_port": 65536},
	} {
		if _, err := evaluate(socketQuery(t, rule, fields)); err == nil {
			t.Fatal("accepted inconsistent socket", fields)
		}
	}
	for _, fields := range []map[string]any{
		{"socket.family": "ipv6", "socket.transport": "udp", "socket.local_address": "::", "socket.remote_address": "2001:db8::5", "socket.remote_port": 65535},
		{"socket.family": "ipv4", "socket.transport": "tcp", "socket.local_address": "192.0.2.1", "socket.remote_address": "198.51.100.2", "socket.local_port": 65535, "socket.remote_port": 1},
	} {
		if _, err := evaluate(socketQuery(t, rule, fields)); err != nil {
			t.Fatal(err)
		}
	}
}
