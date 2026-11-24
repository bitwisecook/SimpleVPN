// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

//go:build routing_rust && cgo

package routelang

/*
#cgo CFLAGS: -I${SRCDIR}/../../../routing-core/include
#cgo noescape rc_rich_new
#cgo nocallback rc_rich_new
#cgo noescape rc_rich_eval
#cgo nocallback rc_rich_eval
#cgo nocallback rc_rich_free
#cgo nocallback rc_rich_message_free
#include "routing_rich.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

type richPacketHandler struct {
	plan   *C.RCRichPlan
	source nativeHandlerSource
	fields []nativePacketField
}
type richPacketEvent struct{ handlers []richPacketHandler }

func (e *richPacketEvent) close() {
	for _, h := range e.handlers {
		C.rc_rich_free(h.plan)
	}
	e.handlers = nil
}

func compileRichPacketEvent(handlers []handler, remaining *int) (*richPacketEvent, error) {
	e := &richPacketEvent{}
	for _, h := range handlers {
		b, fields, err := marshalRichHandler(h, min(richPlanLimit, *remaining))
		if err != nil {
			e.close()
			return nil, fmt.Errorf("handler %q: %w", h.id, err)
		}
		plan := C.rc_rich_new((*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(b))), C.uint32_t(len(b)))
		if plan == nil {
			e.close()
			return nil, fmt.Errorf("handler %q: native packet plan rejected", h.id)
		}
		*remaining -= len(b)
		e.handlers = append(e.handlers, richPacketHandler{plan, nativeSource(h), fields})
	}
	return e, nil
}

func (e *richPacketEvent) run(host Host, matches []string) (Result, error) {
	r := Result{Matches: matches}
	budget := C.uint32_t(maxByteWork)
	for _, h := range e.handlers {
		r.Matches = append(r.Matches, h.source.id)
		var small [512]byte
		snapshot := richWire(small[:0])
		for _, f := range h.fields {
			v, ok := host.Read(f.name)
			if ok && v.t == f.kind && v.valid() {
				snapshot = snapshot.value(v)
			} else {
				snapshot = append(snapshot, 0)
			}
		}
		var edits C.RCFrame
		out := C.rc_rich_eval(h.plan, (*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(snapshot))), C.uint32_t(len(snapshot)), &edits, C.uint32_t(MaxInstructions-r.Instructions), budget)
		r.Instructions += int(out.instructions)
		budget = out.remaining_bytes
		if out.status != C.RC_OK {
			r.Dropped = true
			if out.status == C.RC_DROPPED {
				return r, nil
			}
			message := "invalid native packet execution"
			if out.message != nil {
				message = C.GoStringN((*C.char)(unsafe.Pointer(out.message)), C.int(out.message_len))
				C.rc_rich_message_free(out.message, out.message_len)
			}
			if int(out.pc) >= len(h.source.sites) {
				return r, errors.New(message)
			}
			i := h.source.sites[out.pc]
			switch out.status {
			case C.RC_MISSING_FIELD:
				return r, problem(i.line, "missing or invalid field %q", i.name)
			case C.RC_INVALID_WRITE:
				return r, problem(i.line, "%s: invalid packet field write", i.name)
			case C.RC_BUDGET:
				return r, problem(i.line, "instruction budget exceeded")
			default:
				return r, problem(i.line, "%s", message)
			}
		}
		// The shared-router host itself stages these writes across handlers/events.
		// Only the owner of the whole packet can commit after every hook permits it.
		for j, f := range h.fields {
			if edits.written&(1<<j) != 0 {
				if err := host.Write(f.name, Value{t: f.kind, n: int64(edits.values[j])}); err != nil {
					r.Dropped = true
					return r, err
				}
			}
		}
	}
	return r, nil
}

// Prefer the signed LLVM implementation when an event includes an exact release image.
func hasPrecompiledHandler(handlers []handler) bool {
	for _, h := range handlers {
		image, _, err := marshalRichHandler(h, richPlanLimit)
		if err == nil && bool(C.rc_rich_is_precompiled((*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(image))), C.uint32_t(len(image)))) {
			return true
		}
	}
	return false
}

// ExportReadOnlyEvent reuses the production RCR1 lowering for a native host
// without embedding a second Go runtime in the macOS app.
func (p *Program) ExportReadOnlyEvents(events []string) ([]NativeHandlerImage, error) {
	if len(p.ids) > 128 {
		return nil, errors.New("invalid event group for this adapter")
	}
	out := make([]NativeHandlerImage, 0, len(p.ids))
	remaining := richPlanLimit
	for _, event := range events {
		for _, h := range p.handlers[event] {
			b, fields, err := marshalRichHandler(h, remaining)
			if err != nil {
				return nil, err
			}
			names := make([]string, 0, len(fields))
			for _, f := range fields {
				names = append(names, f.name)
			}
			plan := C.rc_rich_new((*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(b))), C.uint32_t(len(b)))
			if plan == nil {
				return nil, fmt.Errorf("handler %q: native plan rejected", h.id)
			}
			C.rc_rich_free(plan)
			out = append(out, NativeHandlerImage{Event: event, ID: h.id, Fields: names, Code: b})
			remaining -= len(b)
		}
	}
	if len(out) != len(p.ids) {
		return nil, errors.New("unexpected event group for adapter")
	}
	return out, nil
}

// LLVM lowers a verified handler to native-compiler IR for release tooling.
func LLVM(image []byte) ([]byte, error) {
	result := C.rc_compile_llvm((*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(image))), C.uint32_t(len(image)))
	if result.status != 0 {
		return nil, errors.New("invalid typed handler image")
	}
	defer C.rc_compiler_output_free(result)
	return C.GoBytes(unsafe.Pointer(result.bytes), C.int(result.length)), nil
}
