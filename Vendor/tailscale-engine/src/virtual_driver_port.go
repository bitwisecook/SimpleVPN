// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"

	"pxengine/packetrouter"
	"pxengine/routelang/catalog"
)

// Swift supplies only the authenticated child's negotiated addresses, routes
// and MTU. Credentials and the transport's private state stay with its driver.
type vrDriverConfig struct {
	Adapter    string `json:"adapter"`
	Generation uint64 `json:"generation"`
}

type vrDriverSend func(slot uint32, generation uint64, raw []byte) bool

type vrDriverPort struct {
	id, adapter     string
	slot            uint32
	write           vrDriverSend
	gate            sync.RWMutex
	generation      uint64
	active          bool
	stopped         bool
	rx, tx, dropped atomic.Int64
}

func newVRDriverPort(slot int, m vrMember, write vrDriverSend) (*vrDriverPort, uint64, error) {
	a, ok := catalog.AdapterByID(m.External.Adapter)
	if !ok || !a.PacketPolicy() || a.ID == "wireguard-shared" || m.External.Generation == 0 ||
		m.Proxy != nil || !reflect.ValueOf(m.WireGuard).IsZero() || len(m.Addresses) == 0 || len(m.Addresses) > 32 ||
		len(m.Allowed) == 0 || len(m.Allowed) > 4096 || m.MTU < 576 || m.MTU > 65535 {
		return nil, 0, errors.New("invalid provider port negotiation")
	}
	generation := m.External.Generation
	return &vrDriverPort{id: m.ID, adapter: a.ID, slot: uint32(slot), write: write, generation: generation, active: true}, generation, nil
}

func (p *vrDriverPort) send(generation uint64, raw []byte) bool {
	p.gate.RLock()
	defer p.gate.RUnlock()
	if !p.active || p.generation != generation || !p.write(p.slot, generation, raw) {
		p.dropped.Add(1)
		return false
	}
	p.tx.Add(int64(len(raw)))
	return true
}
func (p *vrDriverPort) revoke(generation uint64) bool {
	p.gate.Lock()
	defer p.gate.Unlock()
	if generation != 0 && p.generation != generation {
		return false
	}
	p.active = false
	if generation == 0 {
		p.stopped = true
	}
	return true
}

func (p *vrDriverPort) status() wgStatusPayload {
	p.gate.RLock()
	defer p.gate.RUnlock()
	state := "stopped"
	if p.active {
		state = "running"
	}
	return wgStatusPayload{State: state, RxBytes: p.rx.Load(), TxBytes: p.tx.Load(), PacketsDropped: p.dropped.Load()}
}

func (st *vrState) hasExternal() bool {
	for _, p := range st.external {
		if p != nil {
			return true
		}
	}
	return false
}
func (st *vrState) driver(slot uint32) *vrDriverPort {
	if uint64(slot) >= uint64(len(st.external)) {
		return nil
	}
	return st.external[slot]
}
func (st *vrState) returnDriver(slot uint32, generation uint64, raw []byte) bool {
	p := st.driver(slot)
	if p == nil || generation == 0 || len(raw) == 0 || len(raw) > maxPacketSize {
		return false
	}
	// Router.Return validates the live incarnation again under its own flow lock.
	// No driver lock is held across the callback to the capture interface.
	if st.router.Return(p.id, generation, raw) {
		p.rx.Add(int64(len(raw)))
		return true
	}
	p.dropped.Add(1)
	return false
}
func (st *vrState) revokeDriver(slot uint32, generation uint64) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	p := st.driver(slot)
	if st.closed || generation == 0 || p == nil || !p.revoke(generation) {
		return false
	}
	st.router.RemovePort(p.id)
	return true
}

func (st *vrState) replaceDriver(slot uint32, old uint64, m vrMember) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	p := st.driver(slot)
	if st.closed || p == nil || m.External == nil || m.ID != p.id || m.External.Adapter != p.adapter {
		return false
	}
	_, next, err := newVRDriverPort(int(slot), m, p.write)
	if err != nil || old == 0 || next <= old {
		return false
	}
	port := packetrouter.Port{ID: p.id, Generation: next, MTU: m.MTU, ExitNodeID: m.ExitNodeID,
		Send: func(raw []byte) bool { return p.send(next, raw) }}
	if port.Addresses, port.Allowed, err = negotiatedRoutes(m.Addresses, m.Allowed); err != nil {
		return false
	}
	p.gate.Lock()
	defer p.gate.Unlock()
	if p.stopped || p.active || p.generation != old || st.router.ReplacePort(old, port) != nil {
		return false
	}
	p.generation, p.active = next, true
	return true
}
func negotiatedRoutes(addresses, routes []string) ([]netip.Addr, []netip.Prefix, error) {
	assigned := make([]netip.Addr, 0, len(addresses))
	for _, value := range addresses {
		if prefix, err := netip.ParsePrefix(value); err == nil {
			assigned = append(assigned, prefix.Addr())
			continue
		}
		address, err := netip.ParseAddr(value)
		if err != nil {
			return nil, nil, errors.New("invalid assigned VPN address")
		}
		assigned = append(assigned, address)
	}
	allowed := make([]netip.Prefix, 0, len(routes))
	for _, value := range routes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, nil, errors.New("invalid authorized VPN prefix")
		}
		allowed = append(allowed, prefix)
	}
	return assigned, allowed, nil
}
