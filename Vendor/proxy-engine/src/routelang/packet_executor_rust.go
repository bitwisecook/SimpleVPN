// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

//go:build routing_rust && cgo

package routelang

/*
#cgo CFLAGS: -I${SRCDIR}/../../../routing-core/include
#cgo noescape rc_plan_new
#cgo nocallback rc_plan_new
#cgo noescape rc_eval
#cgo nocallback rc_eval
#cgo nocallback rc_plan_free
#include "routing_core.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

const nativePacketsRequired = true

// Retain only fault locations once Rust has copied each handler and table.
// Keeping Go bytecode here would pin a second copy of every installed table.
type nativeSite struct {
	line int
	name string
}
type nativeHandlerSource struct {
	id    string
	sites []nativeSite
}

func nativeSource(h handler) nativeHandlerSource {
	sites := make([]nativeSite, len(h.code))
	for pc, i := range h.code {
		sites[pc].line = i.line
		if i.op == read || i.op == write {
			sites[pc].name = i.name
		}
	}
	return nativeHandlerSource{id: h.id, sites: sites}
}

type nativePacketHandler struct {
	plan   *C.RCPlan
	source nativeHandlerSource
}

type nativePacketEvent struct {
	fields   []nativePacketField
	handlers []nativePacketHandler
}

func compilePacketPlans(p *Program) (map[string]packetNativeEvent, int, error) {
	plans := make(map[string]packetNativeEvent, len(p.handlers))
	scalar := 0
	remaining := richProgramLimit
	for event, handlers := range p.handlers {
		if !hasPrecompiledHandler(handlers) {
			if plan := compilePacketEvent(handlers); plan != nil {
				plans[event] = plan
				scalar++
				continue
			}
		}
		plan, err := compileRichPacketEvent(handlers, &remaining)
		if err != nil {
			for _, n := range plans {
				n.close()
			}
			return nil, 0, err
		}
		plans[event] = plan
	}
	return plans, scalar, nil
}

type packetLowering struct {
	fields []nativePacketField
	abi    []C.RCField
	index  map[string]uint32
}

func (l *packetLowering) field(i instruction) (uint32, bool) {
	if idx, ok := l.index[i.name]; ok {
		return idx, true
	}
	t := i.t
	var writable C.uint32_t
	switch i.name {
	case "ip.dscp":
		writable, t = C.RC_DSCP, TInt
	case "tcp.mss":
		writable, t = C.RC_MSS, TInt
	case "dns.rd":
		writable, t = C.RC_DNS_RD, TBool
	}
	if i.op == write && writable == C.RC_READ_ONLY {
		return 0, false
	}
	var typ C.uint32_t
	switch t {
	case TInt:
		typ = C.RC_INT
	case TBool:
		typ = C.RC_BOOL
	default:
		return 0, false
	}
	if len(l.fields) == C.RC_MAX_FIELDS {
		return 0, false
	}
	idx := uint32(len(l.fields))
	l.index[i.name] = idx
	l.fields = append(l.fields, nativePacketField{i.name, t})
	l.abi = append(l.abi, C.RCField{_type: typ, write: writable})
	return idx, true
}

var scalarBinaryOps = map[string]C.uint32_t{
	"==": C.RC_EQ, "!=": C.RC_NE, "<": C.RC_LT, "<=": C.RC_LE, ">": C.RC_GT, ">=": C.RC_GE,
	"+": C.RC_ADD, "-": C.RC_SUB, "*": C.RC_MUL, "/": C.RC_DIV, "%": C.RC_MOD,
}

func (l *packetLowering) lower(i instruction) (dst C.RCInstruction, ok bool) {
	switch i.op {
	case literal:
		switch i.v.t {
		case TInt:
			dst.op = C.RC_CONST_INT
		case TBool:
			dst.op = C.RC_CONST_BOOL
		default:
			return dst, false
		}
		dst.imm = C.int64_t(i.v.n)
	case read, write:
		idx, supported := l.field(i)
		if !supported {
			return dst, false
		}
		dst.op, dst.arg = C.RC_READ, C.uint32_t(idx)
		if i.op == write {
			dst.op = C.RC_WRITE
		}
	case load:
		dst.op, dst.arg = C.RC_LOAD, C.uint32_t(i.arg)
	case store:
		dst.op, dst.arg = C.RC_STORE, C.uint32_t(i.arg)
	case binaryOp:
		var found bool
		if dst.op, found = scalarBinaryOps[i.name]; !found {
			return dst, false
		}
	case unaryOp:
		switch i.name {
		case "!":
			dst.op = C.RC_NOT
		case "-":
			dst.op = C.RC_NEG
		default:
			return dst, false
		}
	case jump:
		dst.op, dst.arg = C.RC_JUMP, C.uint32_t(i.target)
	case branch:
		dst.op, dst.arg = C.RC_BRANCH_FALSE, C.uint32_t(i.target)
	case andThen:
		dst.op, dst.arg = C.RC_AND_THEN, C.uint32_t(i.target)
	case orElse:
		dst.op, dst.arg = C.RC_OR_ELSE, C.uint32_t(i.target)
	case deny:
		dst.op = C.RC_DROP
	case discard:
		dst.op = C.RC_DISCARD
	case hostAction:
		if i.name != "count" || i.arg != 0 {
			return dst, false
		}
		dst.op = C.RC_COUNT
	default:
		return dst, false
	}
	return dst, true
}

func compilePacketEvent(handlers []handler) *nativePacketEvent {
	lower := packetLowering{index: make(map[string]uint32)}
	codes := make([][]C.RCInstruction, len(handlers))
	for i, h := range handlers {
		code := make([]C.RCInstruction, len(h.code))
		for pc, instruction := range h.code {
			op, ok := lower.lower(instruction)
			if !ok {
				return nil
			}
			code[pc] = op
		}
		codes[i] = code
	}
	event := &nativePacketEvent{fields: lower.fields}
	for i, code := range codes {
		// The constructor copies these pointer-free arrays before returning.
		plan := C.rc_plan_new(unsafe.SliceData(code), C.uint32_t(len(code)), unsafe.SliceData(lower.abi), C.uint32_t(len(lower.abi)))
		if plan == nil {
			event.close()
			return nil
		}
		event.handlers = append(event.handlers, nativePacketHandler{plan: plan, source: nativeSource(handlers[i])})
	}
	return event
}

func (e *nativePacketEvent) close() {
	for _, h := range e.handlers {
		C.rc_plan_free(h.plan)
	}
	e.handlers = nil
}

func (e *nativePacketEvent) run(host Host, matches []string) (Result, error) {
	var frame C.RCFrame
	// Reads on the packet host are pure. A missing optional field faults only
	// if the Rust branch actually accesses it. Earlier event stages stay visible.
	for j, field := range e.fields {
		v, present := host.Read(field.name)
		if present && v.t == field.kind && v.valid() {
			frame.values[j] = C.int64_t(v.n)
			frame.present |= 1 << j
		}
	}
	r := Result{Matches: matches}
	var written C.uint32_t
	for _, h := range e.handlers {
		r.Matches = append(r.Matches, h.source.id)
		frame.written = 0
		out := C.rc_eval(h.plan, &frame, C.uint32_t(MaxInstructions-r.Instructions))
		r.Instructions += int(out.instructions)
		if out.status == C.RC_OK {
			written |= frame.written
			continue
		}
		r.Dropped = true
		if out.status == C.RC_DROPPED {
			return r, nil
		}
		if int(out.pc) >= len(h.source.sites) {
			return r, errors.New("invalid native packet instruction")
		}
		i := h.source.sites[out.pc]
		switch out.status {
		case C.RC_MISSING_FIELD:
			return r, problem(i.line, "missing or invalid field %q", i.name)
		case C.RC_INVALID_WRITE:
			return r, problem(i.line, "%s: invalid packet field write", i.name)
		case C.RC_ARITHMETIC_BOUNDS:
			return r, problem(i.line, "%v", errBounds)
		case C.RC_BUDGET:
			return r, problem(i.line, "instruction budget exceeded")
		default:
			return r, problem(i.line, "invalid native packet execution")
		}
	}
	for j, field := range e.fields {
		if written&(1<<j) == 0 {
			continue
		}
		v := Value{t: field.kind, n: int64(frame.values[j])}
		if err := host.Write(field.name, v); err != nil {
			r.Dropped = true
			return r, err
		}
	}
	return r, nil
}
