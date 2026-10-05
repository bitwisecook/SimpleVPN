// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"

	"github.com/tailscale/wireguard-go/conn"
	"golang.org/x/sys/unix"
)

// Every transport socket is scoped to a physical interface before bind. A
// missing path blackholes sends; it never removes scope and falls into capture.
type physicalBind struct {
	mu         sync.Mutex
	index      uint32
	ipv4, ipv6 *net.UDPConn
}

func newPhysicalBind(index uint32) *physicalBind { return &physicalBind{index: index} }
func (b *physicalBind) BatchSize() int           { return 1 }
func (b *physicalBind) SetMark(uint32) error     { return nil }
func (b *physicalBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &conn.StdNetEndpoint{AddrPort: addr}, nil
}
func scopeSocket(fd int, family int, index uint32) error {
	if index == 0 {
		return errors.New("physical network unavailable")
	}
	if family == unix.AF_INET6 {
		return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, int(index))
	}
	return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF, int(index))
}
func (b *physicalBind) listen(network string, port uint16) (*net.UDPConn, error) {
	family := unix.AF_INET
	if network == "udp6" {
		family = unix.AF_INET6
	}
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var problem error
		err := raw.Control(func(fd uintptr) { problem = scopeSocket(int(fd), family, b.index) })
		if err != nil {
			return err
		}
		return problem
	}}
	pc, err := lc.ListenPacket(context.Background(), network, ":"+strconv.Itoa(int(port)))
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}
func receiveUDP(c *net.UDPConn) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, addr, err := c.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = &conn.StdNetEndpoint{AddrPort: addr}
		return 1, nil
	}
}
func (b *physicalBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ipv4 != nil || b.ipv6 != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if b.index == 0 {
		return nil, 0, errors.New("physical network unavailable")
	}
	v4, err := b.listen("udp4", port)
	if err != nil {
		return nil, 0, err
	}
	actual := uint16(v4.LocalAddr().(*net.UDPAddr).Port)
	v6, err := b.listen("udp6", actual)
	if err != nil {
		v4.Close()
		return nil, 0, err
	}
	b.ipv4, b.ipv6 = v4, v6
	return []conn.ReceiveFunc{receiveUDP(v4), receiveUDP(v6)}, actual, nil
}
func (b *physicalBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ipv4 != nil {
		b.ipv4.Close()
		b.ipv4 = nil
	}
	if b.ipv6 != nil {
		b.ipv6.Close()
		b.ipv6 = nil
	}
	return nil
}
func (b *physicalBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	endpoint, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.index == 0 {
		return unix.ENETDOWN
	}
	c := b.ipv4
	if endpoint.DstIP().Is6() {
		c = b.ipv6
	}
	if c == nil {
		return net.ErrClosed
	}
	for _, packet := range bufs {
		if _, err := c.WriteToUDPAddrPort(packet[offset:], endpoint.AddrPort); err != nil {
			return err
		}
	}
	return nil
}
func (b *physicalBind) SetInterface(index uint32) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Block all sends until BOTH sockets have successfully changed scope.
	b.index = 0
	if index == 0 {
		return nil
	}
	for _, item := range []struct {
		c      *net.UDPConn
		family int
	}{{b.ipv4, unix.AF_INET}, {b.ipv6, unix.AF_INET6}} {
		if item.c == nil {
			continue
		}
		raw, err := item.c.SyscallConn()
		if err != nil {
			return err
		}
		var problem error
		if err = raw.Control(func(fd uintptr) { problem = scopeSocket(int(fd), item.family, index) }); err != nil {
			return err
		}
		if problem != nil {
			return problem
		}
	}
	b.index = index
	return nil
}
