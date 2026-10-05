// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"golang.org/x/sys/unix"
	"net"
	"strconv"
	"testing"
)

func TestPhysicalBindScopeAndMissingPath(t *testing.T) {
	iface, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	b := newPhysicalBind(uint32(iface.Index))
	_, _, err = b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, item := range []struct {
		c          *net.UDPConn
		level, opt int
	}{{b.ipv4, unix.IPPROTO_IP, unix.IP_BOUND_IF}, {b.ipv6, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF}} {
		raw, err := item.c.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var index int
		err = raw.Control(func(fd uintptr) { index, err = unix.GetsockoptInt(int(fd), item.level, item.opt) })
		if err != nil || index != iface.Index {
			t.Fatalf("socket scope = %d, want %d (%v)", index, iface.Index, err)
		}
	}
	endpoint, err := b.ParseEndpoint(net.JoinHostPort("127.0.0.1", strconv.Itoa(b.ipv4.LocalAddr().(*net.UDPAddr).Port)))
	if err != nil {
		t.Fatal(err)
	}
	if err = b.SetInterface(0); err != nil {
		t.Fatal(err)
	}
	if err = b.Send([][]byte{{1}}, endpoint, 0); err == nil {
		t.Fatal("missing path sent packet")
	}
	if err = b.SetInterface(uint32(iface.Index)); err != nil {
		t.Fatal(err)
	}
	if err = b.Send([][]byte{{1}}, endpoint, 0); err != nil {
		t.Fatal(err)
	}
}
