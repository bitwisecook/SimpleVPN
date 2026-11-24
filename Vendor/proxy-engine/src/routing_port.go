// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package pxengine

import (
	"errors"
	"net"
	"net/netip"
	"sync"
)

// RoutingPortConfig configures one isolated raw-IP proxy port in a shared packet router.
// It travels only in the provider's start options.
type RoutingPortConfig struct {
	RequiresAuth *bool  `json:"requiresAuth,omitempty"`
	Upstream     string `json:"upstream"`
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	MTU          int    `json:"mtu"`
	TLSRoutes    string `json:"tlsRoutes,omitempty"`
}

type RoutingPort struct {
	mu       sync.RWMutex
	st       *engineState
	Endpoint netip.AddrPort
	Adapter  string
}

// NewRoutingPort requires a physical-interface-scoped dialer for both proxy and relay
// sockets. Numeric endpoints keep opening an underlay socket independent of tunnel DNS.
func NewRoutingPort(cfg RoutingPortConfig, dialer *net.Dialer, output func([]byte)) (*RoutingPort, error) {
	if dialer == nil || dialer.Control == nil || output == nil || cfg.MTU < 1280 || cfg.MTU > 9000 {
		return nil, errors.New("invalid shared proxy port configuration")
	}
	s := startConfig{RequiresAuth: cfg.RequiresAuth, Upstream: cfg.Upstream, Username: cfg.Username, Password: cfg.Password, MTU: cfg.MTU, TLSRoutes: cfg.TLSRoutes}
	up, err := s.proxy()
	if err != nil || !up.kind.dialledInProcess() {
		return nil, errors.New("unsupported shared proxy transport")
	}
	ep, err := netip.ParseAddrPort(up.address)
	if err != nil || ep.Addr().IsUnspecified() || ep.Addr().Zone() != "" {
		return nil, errors.New("the shared proxy port requires a numeric upstream address")
	}
	st, err := buildEngineWithOptions(engineOptions{up: up, mtu: s.MTU, tlsRoutes: s.TLSRoutes, dialer: dialer, packetOutput: output,
		diagnostic: func(string, ...any) {}, stateOutput: func(string, string) {}})
	if err != nil {
		return nil, err
	}
	return &RoutingPort{st: st, Endpoint: ep, Adapter: "proxy-" + schemeName(up.kind)}, nil
}

func (p *RoutingPort) Send(raw []byte) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.st == nil || len(raw) > maxPacketSize {
		return false
	}
	proto, ok := ipProtocolOf(raw)
	if !ok {
		return false
	}
	pkt := newInboundPacket(raw)
	p.st.ep.InjectInbound(proto, pkt)
	pkt.DecRef()
	return true
}

// Traffic reports bytes transferred by the proxy after TCP/UDP framing is removed.
func (p *RoutingPort) Traffic() (in, out, dropped int64) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.st == nil {
		return 0, 0, 0
	}
	return p.st.bytesDown.Load(), p.st.bytesUp.Load(), p.st.packetsInDrop.Load()
}

func (p *RoutingPort) Close() {
	p.mu.Lock()
	st := p.st
	p.st = nil
	p.mu.Unlock()
	if st != nil {
		stopEngine(st)
	}
}
