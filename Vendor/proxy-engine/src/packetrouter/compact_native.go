// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//go:build routing_rust && cgo

package packetrouter

/*
#cgo CFLAGS: -I${SRCDIR}/../../../routing-core/include
#cgo noescape svp_compact_compile
#cgo nocallback svp_compact_compile
#cgo noescape svp_compact_match
#cgo nocallback svp_compact_match
#include "routing_compact.h"
*/
import "C"

import (
	"errors"
	"math/bits"
	"unsafe"
)

const NativeRouting = true

type compactOutcome = C.svp_compact_result

type nativeCompact struct {
	rows []C.svp_compact_row
}

func compileCompact(text string) (*EventProgram, error) {
	if text == "" {
		return nil, nil
	}
	var rows [128]C.svp_compact_row
	var diagnostic [256]C.char
	count := int(C.svp_compact_compile((*C.uint8_t)(unsafe.Pointer(unsafe.StringData(text))), C.size_t(len(text)),
		&rows[0], C.size_t(len(rows)), &diagnostic[0], C.size_t(len(diagnostic))))
	if count < 0 || count > len(rows) {
		if msg := C.GoString(&diagnostic[0]); msg != "" {
			return nil, errors.New(msg)
		}
		return nil, errors.New("invalid compact routing plan")
	}
	if count == 0 {
		return nil, nil
	}
	native := &nativeCompact{rows: append([]C.svp_compact_row(nil), rows[:count]...)}
	p := &EventProgram{native: native, counts: make([]EventInspectionCounter, count)}
	for i := range native.rows {
		row := &native.rows[i]
		if int(row.kind) >= len(p.table) || row.id_len == 0 || int(row.id_len) > len(row.id) {
			return nil, errors.New("invalid native routing handler")
		}
		p.counts[i].ID = C.GoStringN((*C.char)(unsafe.Pointer(&row.id[0])), C.int(row.id_len))
		p.addCandidate(eventKind(row.kind), uint16(row.port), i)
	}
	if err := p.finishCompact(native.prepare); err != nil {
		return nil, err
	}
	return p, nil
}

// Event and port are already known at dispatch. Where they determine every
// predicate, run the Rust matcher once at activation and retain its effects.
func (n *nativeCompact) prepare(sel *compactSelection) error {
	if sel.mask == (candidateBits{}) {
		return nil
	}
	for i, word := range sel.mask {
		for ; word != 0; word &= word - 1 {
			r := &n.rows[i*64+bits.TrailingZeros64(word)]
			if r.family != 0 || r.name_len != 0 || r.source_len != 0 {
				return nil
			}
		}
	}
	var address [16]C.uint8_t
	fixed := new(compactOutcome)
	if C.svp_compact_match(&n.rows[0], C.size_t(len(n.rows)), C.uint64_t(sel.mask[0]), C.uint64_t(sel.mask[1]),
		&address[0], 4, nil, 0, nil, 0, fixed) != 0 {
		return errors.New("invalid constant compact routing plan")
	}
	sel.fixed = fixed
	return nil
}

func (ep *EventProgram) matchCompact(selection compactSelection, p *packet, source observed[string], name string) bool {
	if selection.fixed != nil {
		return ep.applyCompactOutcome(selection.fixed, p)
	}
	candidates := selection.mask
	if candidates == (candidateBits{}) {
		return true
	}
	n := ep.native
	if n == nil {
		return false
	}
	var address [16]byte
	family := C.uint8_t(6)
	if p.dst.Is4() {
		a := p.dst.As4()
		copy(address[:], a[:])
		family = 4
	} else {
		address = p.dst.As16()
	}
	var result C.svp_compact_result
	sourceID := ""
	if source.present {
		sourceID = source.value
	}
	if C.svp_compact_match(&n.rows[0], C.size_t(len(n.rows)), C.uint64_t(candidates[0]), C.uint64_t(candidates[1]),
		(*C.uint8_t)(unsafe.Pointer(&address[0])), family, (*C.char)(unsafe.Pointer(unsafe.StringData(sourceID))),
		C.size_t(len(sourceID)), (*C.char)(unsafe.Pointer(unsafe.StringData(name))), C.size_t(len(name)), &result) != 0 {
		return false
	}
	return ep.applyCompactOutcome(&result, p)
}

func (ep *EventProgram) applyCompactOutcome(result *compactOutcome, p *packet) bool {
	last := -1
	for i, hit := range result.hits {
		for mask := uint64(hit); mask != 0; mask &= mask - 1 {
			last = i*64 + bits.TrailingZeros64(mask)
			ep.hit(&ep.counts[last], len(p.raw))
		}
	}
	// Earlier mutations are observable even if a later compact rule drops.
	// A run of MSS clamps has the same effect as its smallest ceiling.
	if result.has_dscp != 0 {
		ep.edited = markPacketDSCP(p, byte(result.dscp)) || ep.edited
	}
	if result.has_mss != 0 {
		ep.edited = clampTCPMSS(p, uint16(result.mss)) || ep.edited
	}
	if result.has_recursion != 0 {
		ep.edited = setPacketRecursion(p, byte(result.recursion)) || ep.edited
	}
	if result.dropped != 0 {
		ep.counts[last].Drops++
		return false
	}
	return true
}
