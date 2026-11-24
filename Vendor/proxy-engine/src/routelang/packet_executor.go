// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package routelang

import "errors"

// PacketExecutor installs a verified program on the shared router's staged
// packet host. Selection is fixed for the lifetime of each event. The offline
// evaluator continues to use Program directly, including its branch traces.
type PacketExecutor struct {
	portable     *Program
	native       map[string]packetNativeEvent
	closed       bool
	scalarEvents int
}

type packetNativeEvent interface {
	run(Host, []string) (Result, error)
	close()
}

func (p *Program) NewPacketExecutor() (*PacketExecutor, error) {
	plans, scalar, err := compilePacketPlans(p)
	if err != nil {
		return nil, err
	}
	e := &PacketExecutor{native: plans, scalarEvents: scalar}
	if !nativePacketsRequired {
		e.portable = p
	}
	return e, nil
}

// NativeEventCounts counts event groups installed on each native backend.
func (p *PacketExecutor) NativeEventCounts() (scalar, general int) {
	return p.scalarEvents, len(p.native) - p.scalarEvents
}

func (p *PacketExecutor) Handles(event string) bool {
	if p.closed {
		return true
	} // A retired executor denies any attempted dispatch.
	if nativePacketsRequired {
		return p.native[event] != nil
	}
	return p.portable != nil && p.portable.Handles(event)
}

func (p *PacketExecutor) RunInto(event string, host Host, matches []string) (Result, error) {
	if p.closed {
		return Result{Dropped: true}, errors.New("packet executor closed")
	}
	if nativePacketsRequired {
		if n := p.native[event]; n != nil {
			if host == nil {
				return Result{Dropped: true}, errors.New("packet host unavailable")
			}
			return n.run(host, matches[:0])
		}
		if p.native == nil {
			return Result{Dropped: true}, errors.New("native packet plan unavailable")
		}
		return Result{}, nil
	}
	if p.portable == nil {
		return Result{Dropped: true}, errors.New("packet program unavailable")
	}
	return p.portable.RunInto(event, host, matches)
}

// Close releases native plans after the router has excluded packet dispatch.
func (p *PacketExecutor) Close() {
	for _, n := range p.native {
		n.close()
	}
	p.native = nil
	p.portable = nil
	p.scalarEvents = 0
	p.closed = true
}
