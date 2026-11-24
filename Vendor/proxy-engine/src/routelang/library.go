// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package routelang

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"maps"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

type signature struct {
	args   []Type
	result Type
}

var library = map[string]signature{
	"addr": {[]Type{TString}, TAddr}, "prefix": {[]Type{TString}, TPrefix}, "dns": {[]Type{TString}, TDNS}, "bytes": {[]Type{TString}, TBytes},
	"mask": {[]Type{TAddr, TInt}, TPrefix}, "range": {[]Type{TInt, TInt}, ArrayType(TInt)},
	"byte": {[]Type{TBytes, TInt}, TInt}, "u16be": {[]Type{TBytes, TInt}, TInt}, "slice": {[]Type{TBytes, TInt, TInt}, TBytes},
	"replace": {[]Type{TBytes, TInt, TInt, TBytes}, TBytes}, "write_u16be": {[]Type{TBytes, TInt, TInt}, TBytes},
	"string": {}, "int": {}, "len": {}, "at": {}, "lower": {}, "contains": {}, "starts_with": {}, "ends_with": {},
}

// BuiltinNames lists the functions callable in expressions for the offline language reference.
func BuiltinNames() []string { return slices.Sorted(maps.Keys(library)) }

func textType(t Type) bool { return t == TDNS || t == TString }
func builtinType(name string, args []Type) (Type, bool) {
	sig, ok := library[name]
	if !ok {
		return "", false
	}
	switch name {
	case "string":
		if len(args) == 1 && args[0].scalar() {
			return TString, true
		}
	case "int":
		if len(args) == 1 && (args[0] == TInt || args[0] == TString || args[0] == TBool) {
			return TInt, true
		}
	case "len":
		if len(args) == 1 && (textType(args[0]) || args[0] == TBytes || args[0].isArray()) {
			return TInt, true
		}
	case "at":
		if len(args) == 2 && args[1] == TInt {
			if args[0].isArray() {
				return args[0].element(), true
			}
			if args[0] == TBytes {
				return TInt, true
			}
		}
	case "lower":
		if len(args) == 1 && textType(args[0]) {
			return TString, true
		}
	case "contains", "starts_with", "ends_with":
		if len(args) == 2 && textType(args[0]) && textType(args[1]) {
			return TBool, true
		}
	default:
		if slices.Equal(sig.args, args) {
			return sig.result, true
		}
	}
	return "", false
}
func constant(x *expr, depth int) Value {
	if depth > maxDepth {
		fail(x.line, "constant exceeds nesting limit")
	}
	if x.op == "const" {
		return x.v
	}
	if x.op != "call" && x.op != "array" && x.op != "unary" {
		fail(x.line, "expected constant value")
	}
	a := make([]Value, len(x.args))
	ts := make([]Type, len(a))
	for i, arg := range x.args {
		a[i] = constant(arg, depth+1)
		ts[i] = a[i].t
	}
	if x.op == "array" {
		if len(a) == 0 {
			fail(x.line, "empty array needs an element type")
		}
		v, e := Array(a[0].t, a)
		if e != nil {
			fail(x.line, "%v", e)
		}
		return v
	}
	if x.op == "unary" && x.name == "-" && len(a) == 1 && a[0].t == TInt && a[0].n != math.MinInt64 {
		return Int(-a[0].n)
	}
	if _, ok := builtinType(x.name, ts); !ok {
		fail(x.line, "invalid constant %q", x.name)
	}
	budget := maxByteWork
	v, e := builtin(x.name, a, &budget)
	if e != nil {
		fail(x.line, "%v", e)
	}
	return v
}

var errBounds = errors.New("value outside supported bounds")
var errByteWork = errors.New("byte processing budget exceeded")

func charge(budget *int, n int) error {
	if n < 0 || n > *budget {
		return errByteWork
	}
	*budget -= n
	return nil
}
func builtin(name string, a []Value, budget *int) (Value, error) {
	v := a[0]
	switch name {
	case "contains", "starts_with", "ends_with", "addr", "prefix", "int", "dns":
		if e := charge(budget, len(v.s)); e != nil {
			return Value{}, e
		}
	}
	switch name {
	case "string":
		s, e := v.render()
		if e != nil {
			return Value{}, e
		}
		if e = charge(budget, len(s)); e != nil {
			return Value{}, e
		}
		return String(s), nil
	case "int":
		if v.t != TString {
			return Int(v.n), nil
		}
		n, e := strconv.ParseInt(v.s, 10, 64)
		if e != nil {
			return Value{}, errors.New("expected a signed 64-bit decimal integer")
		}
		return Int(n), nil
	case "addr":
		ip, e := netip.ParseAddr(v.s)
		w := Addr(ip)
		if e != nil || !w.valid() {
			return Value{}, errors.New("invalid IP address")
		}
		return w, nil
	case "prefix":
		ip, e := netip.ParsePrefix(v.s)
		w := Prefix(ip)
		if e != nil || !w.valid() {
			return Value{}, errors.New("invalid or noncanonical prefix")
		}
		return w, nil
	case "dns":
		return DNS(v.s)
	case "mask":
		n := a[1].n
		if n < 0 || n > int64(v.ip.BitLen()) {
			return Value{}, errBounds
		}
		return Prefix(netip.PrefixFrom(v.ip, int(n)).Masked()), nil
	case "bytes":
		n := hex.DecodedLen(len(v.s))
		if e := charge(budget, n); e != nil {
			return Value{}, e
		}
		b, e := hex.DecodeString(v.s)
		if e != nil {
			return Value{}, errors.New("expected pairs of hexadecimal digits")
		}
		return Value{t: TBytes, b: b}, nil
	case "lower":
		if e := charge(budget, len(v.s)); e != nil {
			return Value{}, e
		}
		w := String(strings.ToLower(v.s))
		if !w.valid() {
			return Value{}, errBounds
		}
		return w, nil
	case "contains":
		return Bool(strings.Contains(v.s, a[1].s)), nil
	case "starts_with":
		return Bool(strings.HasPrefix(v.s, a[1].s)), nil
	case "ends_with":
		return Bool(strings.HasSuffix(v.s, a[1].s)), nil
	case "len":
		if v.t.isArray() {
			return Int(int64(len(v.a))), nil
		}
		if v.t == TBytes {
			return Int(int64(len(v.b))), nil
		}
		return Int(int64(len(v.s))), nil
	case "range":
		end := a[1].n
		if end < v.n || uint64(end)-uint64(v.n) > MaxArray {
			return Value{}, errBounds
		}
		size := int(end - v.n)
		if e := charge(budget, size*valueSize); e != nil {
			return Value{}, e
		}
		out := make([]Value, size)
		for i := range out {
			out[i] = Int(v.n + int64(i))
		}
		return Value{t: ArrayType(TInt), a: out}, nil
	case "at", "byte", "u16be", "write_u16be":
		i := a[1].n
		if i < 0 {
			return Value{}, errBounds
		}
		if v.t.isArray() {
			if i >= int64(len(v.a)) {
				return Value{}, errBounds
			}
			return v.a[i], nil
		}
		if i >= int64(len(v.b)) {
			return Value{}, errBounds
		}
		if name == "at" || name == "byte" {
			return Int(int64(v.b[i])), nil
		}
		if int64(len(v.b))-i < 2 {
			return Value{}, errBounds
		}
		if name == "u16be" {
			return Int(int64(binary.BigEndian.Uint16(v.b[i:]))), nil
		}
		n := a[2].n
		if n < 0 || n > 65535 {
			return Value{}, errBounds
		}
		if e := charge(budget, len(v.b)); e != nil {
			return Value{}, e
		}
		out := bytes.Clone(v.b)
		binary.BigEndian.PutUint16(out[i:], uint16(n))
		return Value{t: TBytes, b: out}, nil
	case "replace", "slice":
		i, j := a[1].n, a[2].n
		if i < 0 || j < i || j > int64(len(v.b)) {
			return Value{}, errBounds
		}
		if name == "slice" {
			return Value{t: TBytes, b: v.b[i:j]}, nil
		}
		n := len(v.b) - int(j-i) + len(a[3].b)
		if n > MaxBytes {
			return Value{}, errBounds
		}
		if e := charge(budget, n); e != nil {
			return Value{}, e
		}
		out := make([]byte, 0, n)
		out = append(out, v.b[:i]...)
		out = append(out, a[3].b...)
		out = append(out, v.b[j:]...)
		return Value{t: TBytes, b: out}, nil
	}
	return Value{}, errors.New("unknown operation")
}

// Conservative accounting for temporary Value arrays on both wasm and 64-bit hosts.
const valueSize = 128

func binaryType(op string, a, b Type) (Type, bool) {
	switch op {
	case "in":
		return TBool, a == TAddr && b == TPrefix || b.isArray() && b.element() == a
	case "&&", "||":
		return TBool, a == TBool && b == TBool
	case "==", "!=":
		return TBool, a == b && a.scalar()
	case "<", ">", "<=", ">=":
		return TBool, a == b && (a == TInt || textType(a))
	case "+":
		if a == TString && b == TString {
			return TString, true
		}
	}
	return TInt, a == TInt && b == TInt
}

// Charge variable-length comparisons inside each membership iteration. A
// fixed opcode count alone would permit repeated scans of maximum-size buffers.
func equal(a, b Value, budget *int) (bool, error) {
	switch a.t {
	case TBytes:
		if len(a.b) != len(b.b) {
			return false, nil
		}
		if e := charge(budget, len(a.b)); e != nil {
			return false, e
		}
		return bytes.Equal(a.b, b.b), nil
	case TString, TDNS:
		if len(a.s) != len(b.s) {
			return false, nil
		}
		if e := charge(budget, len(a.s)); e != nil {
			return false, e
		}
		return a.s == b.s, nil
	}
	return a.key() == b.key(), nil
}
func binaryEval(op string, a, b Value, budget *int) (Value, error) {
	switch op {
	case "in":
		if b.t == TPrefix {
			return Bool(b.AsPrefix().Contains(a.ip)), nil
		}
		for _, x := range b.a {
			matched, e := equal(a, x, budget)
			if e != nil {
				return Value{}, e
			}
			if matched {
				return Bool(true), nil
			}
		}
		return Bool(false), nil
	case "==", "!=":
		eq, e := equal(a, b, budget)
		return Bool(eq == (op == "==")), e
	case "<", ">", "<=", ">=":
		cmp := 0
		if textType(a.t) {
			if e := charge(budget, min(len(a.s), len(b.s))); e != nil {
				return Value{}, e
			}
			cmp = strings.Compare(a.s, b.s)
		} else if a.n < b.n {
			cmp = -1
		} else if a.n > b.n {
			cmp = 1
		}
		switch op {
		case "<":
			return Bool(cmp < 0), nil
		case "<=":
			return Bool(cmp <= 0), nil
		case ">":
			return Bool(cmp > 0), nil
		default:
			return Bool(cmp >= 0), nil
		}
	case "+":
		if a.t == TString {
			size := len(a.s) + len(b.s)
			if size > MaxString {
				return Value{}, errBounds
			}
			if e := charge(budget, size); e != nil {
				return Value{}, e
			}
			return String(a.s + b.s), nil
		}
	}
	x, y := a.n, b.n
	switch op {
	case "+":
		v := x + y
		if y > 0 && v < x || y < 0 && v > x {
			return Value{}, errBounds
		}
		return Int(v), nil
	case "-":
		v := x - y
		if y < 0 && v < x || y > 0 && v > x {
			return Value{}, errBounds
		}
		return Int(v), nil
	case "*":
		v := x * y
		if x != 0 && (y == math.MinInt64 && x == -1 || x == math.MinInt64 && y == -1 || v/x != y) {
			return Value{}, errBounds
		}
		return Int(v), nil
	case "/", "%":
		if y == 0 || x == math.MinInt64 && y == -1 {
			return Value{}, errBounds
		}
		if op == "/" {
			return Int(x / y), nil
		}
		return Int(x % y), nil
	}
	return Value{}, errors.New("invalid arithmetic")
}
