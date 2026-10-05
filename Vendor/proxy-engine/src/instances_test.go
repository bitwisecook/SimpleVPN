// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package pxengine

import (
	"bytes"
	"testing"
	"time"
)

func TestIndependentProxyStacksCarryIdenticalFlowTuples(t *testing.T) {
	create := func() (uint64, *engineState, <-chan []byte) {
		t.Helper()
		up, err := parseUpstream("http://"+fakeDNSoverTCPProxy(t), "", "")
		if err != nil {
			t.Fatal(err)
		}
		rx := make(chan []byte, 32)
		st, err := buildEngineWithOptions(engineOptions{up: up, mtu: 1280,
			packetOutput: func(p []byte) {
				select {
				case rx <- bytes.Clone(p):
				default:
				}
			},
			diagnostic: func(string, ...any) {}, stateOutput: func(string, string) {},
		})
		if err != nil {
			t.Fatal(err)
		}
		handle := pxInstances.Add(st)
		t.Cleanup(func() {
			if owned, ok := pxInstances.Remove(handle); ok {
				stopEngine(owned)
			}
		})
		return handle, st, rx
	}
	h1, first, rx1 := create()
	h2, second, rx2 := create()
	exchange := func(st *engineState, rx <-chan []byte, id byte) {
		t.Helper()
		query := []byte{id, 7, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		injectIPv4(t, st, udpPacketV4("198.18.0.1", "10.0.0.53", 40000, 53, query))
		select {
		case raw := <-rx:
			if len(raw) < 40 || raw[28] != id || raw[29] != 7 {
				t.Fatalf("wrong scoped DNS reply: %x", raw)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("scoped proxy did not return DNS over its own HTTP CONNECT session")
		}
	}
	exchange(first, rx1, 1)
	exchange(second, rx2, 2)
	owned, ok := pxInstances.Remove(h1)
	if !ok {
		t.Fatal("first proxy handle missing")
	}
	stopEngine(owned)
	if _, ok := pxInstances.Get(h1); ok {
		t.Fatal("stale proxy handle resolves")
	}
	exchange(second, rx2, 3)
	h3, restarted, rx3 := create()
	if h3 == h1 || h3 == h2 {
		t.Fatal("proxy handle was reused")
	}
	exchange(restarted, rx3, 4)
	exchange(second, rx2, 5)
}
