// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

// Package routelang compiles bounded, typed event policies without I/O.
// A host stages writes and actions until Run succeeds; an error denies the event.
package routelang

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	MaxSourceBytes  = 64 << 10
	MaxBytes        = 65535
	MaxString       = 4096
	MaxArray        = 64
	MaxInstructions = 8192
	maxStack        = 64
	maxLocals       = 128
	maxDepth        = 32
	maxByteWork     = 128 << 10
)

type Type string

const (
	TBool   Type = "bool"
	TInt    Type = "int"
	TString Type = "string"
	TDNS    Type = "dns"
	TAddr   Type = "addr"
	TPrefix Type = "prefix"
	TBytes  Type = "bytes"
)

func ArrayType(t Type) Type  { return Type("[]" + string(t)) }
func (t Type) element() Type { return Type(strings.TrimPrefix(string(t), "[]")) }
func (t Type) isArray() bool { return strings.HasPrefix(string(t), "[]") }
func (t Type) scalar() bool {
	switch t {
	case TBool, TInt, TString, TDNS, TAddr, TPrefix, TBytes:
		return true
	}
	return false
}
func (t Type) valid() bool { return t.scalar() || t.isArray() && t.element().scalar() }

// All mutable slices are private. Values can be shared by immutable compiled tables.
type Value struct {
	t  Type
	n  int64
	s  string
	ip netip.Addr
	b  []byte
	a  []Value
}

func (v Value) Type() Type { return v.t }
func Bool(b bool) Value {
	if b {
		return Value{t: TBool, n: 1}
	}
	return Value{t: TBool}
}
func Int(i int64) Value           { return Value{t: TInt, n: i} }
func String(s string) Value       { return Value{t: TString, s: s} }
func Addr(a netip.Addr) Value     { return Value{t: TAddr, ip: a} }
func Prefix(p netip.Prefix) Value { return Value{t: TPrefix, ip: p.Addr(), n: int64(p.Bits())} }
func Bytes(b []byte) (Value, error) {
	if len(b) > MaxBytes {
		return Value{}, errors.New("byte string exceeds limit")
	}
	return Value{t: TBytes, b: append([]byte(nil), b...)}, nil
}
func DNS(s string) (Value, error) {
	if len(s) > 254 {
		return Value{}, errors.New("DNS name exceeds 253 octets")
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= 128 {
			return Value{}, errors.New("DNS name requires ASCII labels")
		}
	}
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if s == "" || len(s) > 253 {
		return Value{}, errors.New("invalid DNS name")
	}
	for label := range strings.SplitSeq(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return Value{}, errors.New("invalid DNS label")
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return Value{}, errors.New("invalid DNS character")
			}
		}
	}
	return Value{t: TDNS, s: s}, nil
}
func Array(elem Type, items []Value) (Value, error) {
	if !elem.scalar() || len(items) > MaxArray {
		return Value{}, errors.New("invalid or oversized array")
	}
	for _, v := range items {
		if v.t != elem || !v.valid() {
			return Value{}, errors.New("invalid array element")
		}
	}
	return Value{t: ArrayType(elem), a: append([]Value(nil), items...)}, nil
}
func (v Value) AsBool() bool           { return v.n != 0 }
func (v Value) AsInt() int64           { return v.n }
func (v Value) AsString() string       { return v.s }
func (v Value) AsAddr() netip.Addr     { return v.ip }
func (v Value) AsPrefix() netip.Prefix { return netip.PrefixFrom(v.ip, int(v.n)) }
func (v Value) AsBytes() []byte        { return append([]byte(nil), v.b...) }
func (v Value) AsArray() []Value       { return append([]Value(nil), v.a...) }
func (v Value) valid() bool {
	switch v.t {
	case TBool, TInt, TDNS:
		return true
	case TString:
		return len(v.s) <= MaxString && utf8.ValidString(v.s)
	case TAddr:
		return v.ip.IsValid() && v.ip.Zone() == "" && !v.ip.Is4In6()
	case TPrefix:
		p := v.AsPrefix()
		return p.IsValid() && p == p.Masked() && !p.Addr().Is4In6()
	case TBytes:
		return len(v.b) <= MaxBytes
	default:
		return v.t.isArray() && v.t.element().scalar() && len(v.a) <= MaxArray
	}
}
func (v Value) render() (string, error) {
	switch v.t {
	case TBool:
		return strconv.FormatBool(v.AsBool()), nil
	case TInt:
		return strconv.FormatInt(v.n, 10), nil
	case TString, TDNS:
		return v.s, nil
	case TAddr:
		return v.ip.String(), nil
	case TPrefix:
		return v.AsPrefix().String(), nil
	case TBytes:
		if len(v.b) <= MaxString/2 {
			return hex.EncodeToString(v.b), nil
		}
	}
	return "", errors.New("value cannot be converted to a bounded string")
}

type Field struct {
	Type     Type `json:"type"`
	Writable bool `json:"writable"`
}
type Event struct {
	Fields  map[string]Field  `json:"fields"`
	Actions map[string][]Type `json:"actions"`
	// Compatibility declarations are accepted by the compiler but excluded
	// from the canonical inventory. An adapter must dispatch them explicitly.
	Compatibility map[string]Event `json:"-"`
}
type Schema map[string]Event

// Resolve returns the canonical declaration or one unambiguous compatibility
// declaration belonging to this adapter. It never imports another adapter's capabilities.
func (s Schema) Resolve(name string) (Event, bool) {
	if event, ok := s[name]; ok {
		return event, true
	}
	var outcome Event
	found := false
	for _, canonical := range s {
		if old, ok := canonical.Compatibility[name]; ok {
			if found {
				return Event{}, false
			}
			outcome, found = old, true
		}
	}
	return outcome, found
}

type Host interface {
	Read(field string) (Value, bool)
	Write(field string, value Value) error
	Action(name string, args []Value) error
}
type Entry struct{ Key, Value Value }
type Table struct {
	Key, Element Type
	Entries      []Entry
}
type TraceStep struct {
	Lookup  bool // Taken distinguishes Found from Missing for a lookup match.
	Line    int
	Taken   bool
	Handler string
}
type Result struct {
	// Dispatched lists the hooks actually entered for a traced composed observation.
	Dispatched   []string
	Dropped      bool
	Matches      []string
	Instructions int
	Trace        []TraceStep
}
type atom struct {
	n  int64
	s  string
	ip netip.Addr
}

func (v Value) key() atom { return atom{v.n, v.s, v.ip} }

type indexedTable struct {
	key, value Type
	exact      map[atom]Value
	prefixes   map[netip.Prefix]Value
	v4, v6     []int
}

func indexTable(t Table) (*indexedTable, error) {
	if !t.Key.scalar() || t.Key == TBytes || !t.Element.valid() || len(t.Entries) > 4096 {
		return nil, errors.New("invalid table type or more than 4096 entries")
	}
	m := &indexedTable{key: t.Key, value: t.Element, exact: make(map[atom]Value)}
	var widths [2][129]bool
	for _, e := range t.Entries {
		if e.Key.t != t.Key || !e.Key.valid() || e.Value.t != t.Element || !e.Value.valid() {
			return nil, errors.New("table entry has invalid type or value")
		}
		k := e.Key.key()
		if _, ok := m.exact[k]; ok {
			return nil, errors.New("duplicate table key")
		}
		m.exact[k] = e.Value
		if t.Key == TPrefix {
			if m.prefixes == nil {
				m.prefixes = make(map[netip.Prefix]Value)
			}
			p := e.Key.AsPrefix()
			m.prefixes[p] = e.Value
			family := 1
			if p.Addr().Is4() {
				family = 0
			}
			widths[family][p.Bits()] = true
		}
	}
	for i := 128; i >= 0; i-- {
		if widths[0][i] {
			m.v4 = append(m.v4, i)
		}
		if widths[1][i] {
			m.v6 = append(m.v6, i)
		}
	}
	return m, nil
}

// lookupOption is a disjoint result. Its tag is independent of the stored
// value, so every valid value, including empty strings and false, can match.
type lookupOption struct {
	value Value
	found bool
}

func (t *indexedTable) lookup(key Value) lookupOption {
	if key.t == TAddr && t.key == TPrefix {
		widths := t.v6
		if key.ip.Is4() {
			widths = t.v4
		}
		for _, bits := range widths {
			if v, ok := t.prefixes[netip.PrefixFrom(key.ip, bits).Masked()]; ok {
				return lookupOption{value: v, found: true}
			}
		}
	} else if v, ok := t.exact[key.key()]; ok {
		return lookupOption{value: v, found: true}
	}
	return lookupOption{}
}
func problem(line int, fmtStr string, a ...any) error {
	return fmt.Errorf("line %d: %s", line, fmt.Sprintf(fmtStr, a...))
}
