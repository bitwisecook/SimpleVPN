// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// Exercise the production constructor and handle registry with two independent
// encrypted loopback sessions, including identical inner addresses. No external
// VPN, credentials, global callback slot or mock WireGuard device participates.
func newScopedWGPair(t *testing.T) (uint64, *wgTestDevice, *wgTestDevice) {
	t.Helper()
	priv, pub := wgTestKeyPair()
	peerPriv, peerPub := wgTestKeyPair()
	peer := newWGTestDevice(t, "scoped-responder")
	peer.up(strings.Join([]string{
		"private_key=" + wgTestHex(t, peerPriv), "replace_peers=true",
		"public_key=" + wgTestHex(t, pub), "allowed_ip=" + wgTestOurTunnelIP + "/32", "",
	}, "\n"))
	rx := make(chan []byte, 32)
	st, problem := createWGState(wgStartConfig{
		PrivateKey: priv, PeerPublicKey: peerPub,
		Endpoint:   fmt.Sprintf("127.0.0.1:%d", peer.listenPort()),
		AllowedIPs: []string{wgTestPeerTunnelIP + "/32"}, MTU: wgDefaultMTU,
	}, &loopbackBind{}, func(p []byte) { rx <- bytes.Clone(p) }, func(string, ...any) {})
	if problem != nil {
		t.Fatalf("production constructor: %v", problem)
	}
	handle := wgInstances.Add(st)
	t.Cleanup(func() {
		if owned, ok := wgInstances.Remove(handle); ok {
			owned.dev.Close()
			owned.tundev.Close()
		}
	})
	ours := &wgTestDevice{t: t, name: "scoped-client", dev: st.dev, tun: st.tundev, rx: rx}
	peer.apply(strings.Join([]string{
		"public_key=" + wgTestHex(t, pub), "update_only=true",
		fmt.Sprintf("endpoint=127.0.0.1:%d", ours.listenPort()), "",
	}, "\n"))
	return handle, ours, peer
}

func TestWGScopedSessionsSurviveIndependentStopAndRestart(t *testing.T) {
	h1, first, peer1 := newScopedWGPair(t)
	h2, second, peer2 := newScopedWGPair(t)
	exchange := func(ours, peer *wgTestDevice, message string) {
		t.Helper()
		out := wgTestIPv4UDP(t, wgTestOurTunnelIP, wgTestPeerTunnelIP, message)
		ours.send(out)
		if got := peer.awaitPacket(5 * time.Second); !bytes.Equal(out, got) {
			t.Fatalf("%s outbound: %x", message, got)
		}
		in := wgTestIPv4UDP(t, wgTestPeerTunnelIP, wgTestOurTunnelIP, message+" return")
		peer.send(in)
		if got := ours.awaitPacket(5 * time.Second); !bytes.Equal(in, got) {
			t.Fatalf("%s return: %x", message, got)
		}
	}
	exchange(first, peer1, "first")
	exchange(second, peer2, "second")

	// Retained references are safe during concurrent status/packet operations;
	// removing the handle fences new requests before device teardown.
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				if st, ok := wgInstances.Get(h1); ok {
					_ = statusWGState(st)
				}
			}
		}()
	}
	owned, ok := wgInstances.Remove(h1)
	if !ok {
		t.Fatal("first handle missing")
	}
	owned.dev.Close()
	owned.tundev.Close()
	wg.Wait()
	if _, ok := wgInstances.Get(h1); ok {
		t.Fatal("stopped handle still resolves")
	}
	if _, ok := wgInstances.Remove(h1); ok {
		t.Fatal("stop is not idempotent")
	}
	exchange(second, peer2, "second after first stopped")
	h3, third, peer3 := newScopedWGPair(t)
	if h3 == h1 || h3 == h2 {
		t.Fatal("a stale handle was reused")
	}
	exchange(third, peer3, "restarted first")
	exchange(second, peer2, "second after restart")
}
