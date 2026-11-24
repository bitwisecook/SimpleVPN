// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//go:build !routing_rust

package packetrouter

const NativeRouting = false

func compileCompact(text string) (*EventProgram, error) { return compileCompactReference(text) }

type nativeCompact struct{}
type compactOutcome struct{}

func (ep *EventProgram) matchCompact(selection compactSelection, p *packet, source observed[string], name string) bool {
	return ep.matchCompactReference(selection.mask, p, source, name)
}
