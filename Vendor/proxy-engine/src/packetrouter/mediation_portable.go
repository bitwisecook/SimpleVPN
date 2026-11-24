// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//go:build !routing_rust

package packetrouter

// Portable reference for Go-only engine fixtures. The shipped core owns
// accounting and UDP history in routing-core/src/mediation.rs.
type trafficRow DirectionCounters

func (m *trafficRow) snapshot() DirectionCounters { return DirectionCounters(*m) }
func (m *trafficRow) forward(n, b uint64)         { m.ForwardedPackets += n; m.ForwardedBytes += b }
func (m *trafficRow) evaluated(hits uint64, edited bool) {
	m.EvaluatedPackets++
	m.RuleHits += hits
	if edited {
		m.EditedPackets++
	}
}
func (m *trafficRow) passthrough(n, bytes uint64) {
	m.ReceivedPackets += n
	m.ReceivedBytes += bytes
	m.ForwardedPackets += n
	m.ForwardedBytes += bytes
}
func (m *trafficRow) received(size int) { m.ReceivedPackets++; m.ReceivedBytes += uint64(size) }
func (m *trafficRow) finish(size int, allowed bool) {
	if allowed {
		m.ForwardedPackets++
		m.ForwardedBytes += uint64(size)
	} else {
		m.DroppedPackets++
		m.DroppedBytes += uint64(size)
	}
}

type udpHistory struct{ flows map[tuple]uint64 }

func (u *udpHistory) seen(k tuple, ms uint64) int32 {
	if stamp, ok := u.flows[k]; ok && ms-stamp < 120000 {
		return 1
	}
	delete(u.flows, k)
	if len(u.flows) >= 8192 {
		for k, t := range u.flows {
			if ms-t >= 120000 {
				delete(u.flows, k)
			}
		}
	}
	if len(u.flows) >= 8192 {
		return -1
	}
	return 0
}
func (u *udpHistory) accept(k tuple, ms uint64) {
	if u.flows == nil {
		u.flows = make(map[tuple]uint64)
	}
	u.flows[k] = ms
}
func (u *udpHistory) close() { u.flows = nil }
