//go:build darwin && tailscale_scoped

// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"golang.org/x/sys/unix"
	"net"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"testing"
)

// Exercise the same netns entry points used by DERP/control and magicsock.
// An invalid selection may never fall back to the OS default interface.
func TestTailscaleNodeScopedCarrierSockets(t *testing.T) {
	iface, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	active, invalid := new(netmon.Monitor), new(netmon.Monitor)
	active.SetRequiredInterface(uint32(iface.Index))
	invalid.SetRequiredInterface(^uint32(0))
	ctx := context.Background()
	listener, err := netns.Listener(t.Logf, active).ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	c, err := listener.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var index int
	err = c.Control(func(fd uintptr) { index, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF) })
	if err != nil || index != iface.Index {
		t.Fatalf("carrier interface %d, want %d: %v", index, iface.Index, err)
	}
	if pc, err := netns.Listener(t.Logf, invalid).ListenPacket(ctx, "udp4", "127.0.0.1:0"); err == nil {
		pc.Close()
		t.Fatal("unavailable UDP carrier used another interface")
	}
	if c, err := netns.NewDialer(t.Logf, invalid).DialContext(ctx, "udp4", listener.LocalAddr().String()); err == nil {
		c.Close()
		t.Fatal("unavailable control carrier used another interface")
	}
	if active.RequiredInterface() != uint32(iface.Index) {
		t.Fatal("another node changed this node's carrier")
	}
}
