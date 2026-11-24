// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package routelang

import (
	"cmp"
	"encoding/binary"
	"errors"
	"maps"
	"slices"
	"strings"
)

// exitNodeEffect contains a colon, so policy authors cannot use it as a field.
const exitNodeEffect = "route.exit_node:"

func ValidExitNodeID(id string) bool {
	if len(id) < 2 || len(id) > 40 || id[0] != 'n' {
		return false
	}
	for i := 1; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func ExitNodeEffect(field string) (id string, ok bool) {
	id, ok = strings.CutPrefix(field, exitNodeEffect)
	return id, ok && ValidExitNodeID(id)
}

type nativePacketField struct {
	name string
	kind Type
}

// RCR1 encodes the frontend's verified instructions and immutable lookup tables
// once. No packet contents, source text or Go pointers are retained by Rust.
const (
	richPlanLimit    = 16 << 20
	richProgramLimit = 64 << 20
)

type richWire []byte

func (b richWire) u32(n int) richWire    { return binary.LittleEndian.AppendUint32(b, uint32(n)) }
func (b richWire) str(s string) richWire { return append(b.u32(len(s)), s...) }
func richKind(t Type) byte {
	switch t {
	case TBool:
		return 1
	case TInt:
		return 2
	case TString:
		return 3
	case TDNS:
		return 4
	case TAddr:
		return 5
	case TPrefix:
		return 6
	case TBytes:
		return 7
	}
	if t.isArray() {
		return 0x80 | richKind(t.element())
	}
	return 0
}
func (b richWire) value(v Value) richWire {
	b = append(b, richKind(v.t))
	switch v.t {
	case TBool:
		return append(b, byte(v.n))
	case TInt:
		return binary.LittleEndian.AppendUint64(b, uint64(v.n))
	case TString, TDNS:
		return b.str(v.s)
	case TBytes:
		return append(b.u32(len(v.b)), v.b...)
	case TAddr, TPrefix:
		if v.ip.Is4() {
			a := v.ip.As4()
			b = append(append(b, 4), a[:]...)
		} else {
			a := v.ip.As16()
			b = append(append(b, 6), a[:]...)
		}
		if v.t == TPrefix {
			b = append(b, byte(v.n))
		}
	default:
		b = b.u32(len(v.a))
		for _, item := range v.a {
			b = b.value(item)
		}
	}
	return b
}

func packetFieldDescriptor(i instruction) (nativePacketField, byte, error) {
	var edit byte
	kind := i.t
	switch i.name {
	case "ip.dscp":
		edit, kind = 1, TInt
	case "tcp.mss":
		edit, kind = 2, TInt
	case "dns.rd":
		edit, kind = 3, TBool
	default:
		if _, ok := ExitNodeEffect(i.name); ok {
			edit, kind = 4, TBool
		}
	}
	if !kind.valid() || i.op == write && edit == 0 {
		return nativePacketField{}, 0, problem(i.line, "unsupported native packet field %q", i.name)
	}
	return nativePacketField{i.name, kind}, edit, nil
}

func marshalRichHandler(h handler, limit int) (richWire, []nativePacketField, error) {
	var fields []nativePacketField
	var descriptors richWire
	fieldIndices := make(map[string]int)
	tableIndices := make(map[*indexedTable]int)
	var tables []*indexedTable
	for _, i := range h.code {
		switch i.op {
		case read, write:
			f, edit, err := packetFieldDescriptor(i)
			if err != nil {
				return nil, nil, err
			}
			if _, ok := fieldIndices[i.name]; !ok {
				fieldIndices[i.name] = len(fields)
				fields = append(fields, f)
				descriptors = append(descriptors, richKind(f.kind), edit)
			}
		case matchLookup:
			if _, ok := tableIndices[i.table]; !ok {
				tableIndices[i.table] = len(tables)
				tables = append(tables, i.table)
			}
		}
	}
	if len(fields) > 32 || len(tables) > 256 {
		return nil, nil, errors.New("native packet plan exceeds field or table limit")
	}
	b := richWire("RCR1").u32(len(fields))
	b = append(b, descriptors...)
	b = b.u32(len(tables))
	for _, t := range tables {
		b = append(b, richKind(t.key), richKind(t.value))
		b = b.u32(len(t.exact))
		// Deterministic images let a release recognize its signed native specializations.
		keys := slices.Collect(maps.Keys(t.exact))
		slices.SortFunc(keys, func(a, b atom) int {
			if c := cmp.Compare(a.n, b.n); c != 0 {
				return c
			}
			if c := cmp.Compare(a.s, b.s); c != 0 {
				return c
			}
			return a.ip.Compare(b.ip)
		})
		for _, k := range keys {
			b = b.value(Value{t: t.key, n: k.n, s: k.s, ip: k.ip})
			b = b.value(t.exact[k])
			if len(b) > limit {
				return nil, nil, errors.New("native packet plan size limit exceeded")
			}
		}
	}
	b = b.u32(len(h.code))
	for _, i := range h.code {
		arg, aux := i.arg, i.aux
		switch i.op {
		case read, write:
			arg = fieldIndices[i.name]
		case matchLookup:
			aux = tableIndices[i.table]
		}
		b = append(b, byte(i.op))
		b = b.u32(arg).u32(i.target).u32(aux)
		b = append(b, richKind(i.t))
		b = b.str(i.name)
		if i.op == literal {
			b = b.value(i.v)
		}
		if len(b) > limit {
			return nil, nil, errors.New("native packet plan size limit exceeded")
		}
	}
	return b, fields, nil
}

// HandlerImage serializes one type-checked handler for the Rust native compiler.
func (p *Program) HandlerImage(id string) ([]byte, error) {
	for _, group := range p.handlers {
		for _, handler := range group {
			if handler.id == id {
				image, _, err := marshalRichHandler(handler, richPlanLimit)
				return image, err
			}
		}
	}
	return nil, errors.New("unknown handler")
}
