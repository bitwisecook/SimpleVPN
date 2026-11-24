// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestHighlightByteSpans(t *testing.T) {
	source := "# café 🔒\r\npolicy\u20031\r\nrule ip ip 2001:db8::/32 via drop#尾\n"
	want := []struct{ text, kind string }{
		{"# café 🔒", "comment"}, {"policy", "keyword"}, {"1", "number"},
		{"rule", "keyword"}, {"ip", "rule"}, {"ip", "keyword"},
		{"2001:db8::/32", "network"}, {"via", "keyword"}, {"drop", "vpn"}, {"#尾", "comment"},
	}
	var output bytes.Buffer
	if err := runCommand([]string{"--tokens", "-"}, strings.NewReader(source), &output); err != nil {
		t.Fatal(err)
	}
	var got []highlightToken
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d tokens, want %d", len(got), len(want))
	}
	cursor := 0
	for i, w := range want {
		at := cursor + strings.Index(source[cursor:], w.text)
		expected := highlightToken{at, len(w.text), w.kind}
		if got[i] != expected {
			t.Fatalf("token %d (%q): got %+v, want %+v", i, w.text, got[i], expected)
		}
		cursor = at + len(w.text)
	}
}

func TestHighlightIncompleteAndInvalidDrafts(t *testing.T) {
	for _, test := range []struct {
		source string
		kinds  []string
	}{
		{"", []string{}},
		{"#\r\n\t  \n", []string{"comment"}},
		{"rule", []string{"keyword"}},
		{"policy 2", []string{"keyword", "error"}},
		{"rule a ip 10.0.0.0/24 via", []string{"keyword", "rule", "keyword", "network", "keyword"}},
		{"rule default ip 10.0.0.2/24 drop", []string{"keyword", "error", "keyword", "error", "keyword"}},
		{"default via bad! extra", []string{"keyword", "keyword", "error", "error"}},
		{"default drop extra", []string{"keyword", "keyword", "error"}},
		{"future something # 📝\ndefault drop", []string{"error", "error", "comment", "keyword", "keyword"}},
	} {
		t.Run(test.source, func(t *testing.T) {
			got := highlight(test.source)
			var kinds []string
			for _, token := range got {
				kinds = append(kinds, token.Kind)
			}
			if !slices.Equal(kinds, test.kinds) {
				t.Fatalf("got %v, want %v", kinds, test.kinds)
			}
			if len(got) == 0 {
				raw, err := json.Marshal(got)
				if err != nil || string(raw) != "[]" {
					t.Fatalf("empty token output: %s, %v", raw, err)
				}
			}
		})
	}
}

func TestStdinMatchesFileAcrossModes(t *testing.T) {
	source := "# 測試\r\npolicy\u20031\r\nrule desk ip 192.0.2.0/24 via work\r\ndefault drop"
	filename := filepath.Join(t.TempDir(), "policy.route")
	if err := os.WriteFile(filename, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"-"}, {"-", "192.0.2.7", "2001:db8::1"}, {"--tokens", "-"}} {
		fileArgs := slices.Clone(args)
		fileArgs[slices.Index(args, "-")] = filename
		var fromFile, fromStdin bytes.Buffer
		if err := runCommand(args, strings.NewReader(source), &fromStdin); err != nil {
			t.Fatal(err)
		}
		if err := runCommand(fileArgs, strings.NewReader(""), &fromFile); err != nil {
			t.Fatal(err)
		}
		if fromStdin.Len() == 0 || !bytes.Equal(fromFile.Bytes(), fromStdin.Bytes()) {
			t.Fatalf("mismatched output for %v", args)
		}
	}
}

func TestTokensRejectInputErrors(t *testing.T) {
	var output bytes.Buffer
	for _, args := range [][]string{{"--tokens"}, {"--tokens", "-", "extra"}, {"--tokens", "-"}} {
		err := runCommand(args, strings.NewReader(strings.Repeat("X", maxSourceBytes+1)), &output)
		if err == nil || output.Len() != 0 {
			t.Fatalf("expected failure without JSON for %v", args)
		}
	}
}
