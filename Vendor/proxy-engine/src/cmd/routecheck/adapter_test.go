// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pxengine/routelang/catalog"
)

func TestLiveCompilerForEveryAdvertisedAdapter(t *testing.T) {
	var inventory bytes.Buffer
	if err := runCommand([]string{"--adapters"}, strings.NewReader(""), &inventory); err != nil {
		t.Fatal(err)
	}
	var adapters []catalog.Adapter
	if err := json.Unmarshal(inventory.Bytes(), &adapters); err != nil || len(adapters) == 0 {
		t.Fatalf("adapter list: %v", err)
	}
	for _, adapter := range adapters {
		t.Run(adapter.ID, func(t *testing.T) {
			var out bytes.Buffer
			rule := "on observe: tcp.syn { count(); }"
			if events := catalog.SSHEvents(adapter.ID); len(events) > 0 {
				rule = "on observe: " + events[0] + " {count();}"
			}
			err := runCommand([]string{"--events-for", adapter.ID, "-"}, strings.NewReader(rule), &out)
			if adapter.RichPolicy {
				if err != nil || !strings.Contains(out.String(), "observe") {
					t.Fatalf("live compiler: %s, %v", out.String(), err)
				}
			} else if err == nil || !strings.Contains(err.Error(), adapter.Name) || out.Len() != 0 {
				t.Fatalf("unsupported mode passed preflight or lacked diagnostic: %s, %v", out.String(), err)
			}
		})
	}
	var out bytes.Buffer
	if err := runCommand([]string{"--events-for", "unrecognized", "-"}, strings.NewReader(""), &out); err == nil {
		t.Fatal("unknown adapter was accepted")
	}
}

func TestShippedNativeImagesMatchPolicySources(t *testing.T) {
	policies := filepath.Join("..", "..", "..", "..", "routing-core", "policies")
	for _, tc := range []struct{ file, adapter, handler string }{
		{"mail", "ssh-libssh", "block_smtp"},
		{"office", "openvpn3", "office"},
		{"dscp", "openvpn3", "priority"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			path := filepath.Join(policies, tc.file)
			expected, err := os.ReadFile(path + ".rcr")
			if err != nil {
				t.Fatal(err)
			}
			var image bytes.Buffer
			err = runCommand([]string{"--emit-handler", tc.adapter, tc.handler, path + ".route"}, strings.NewReader(""), &image)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(expected, image.Bytes()) {
				t.Fatalf("recompile %s.route before shipping its native handler", tc.file)
			}
		})
	}
}
