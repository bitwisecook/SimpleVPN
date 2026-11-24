// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package routelang

import (
	"fmt"
	"maps"
	"slices"
)

type opcode uint8

const (
	literal opcode = iota
	read
	write
	load
	store
	array
	builtinCall
	binaryOp
	unaryOp
	matchLookup
	hostAction
	discard
	jump
	branch
	andThen
	orElse
	iterate
	advance
	deny
)

type instruction struct {
	op                     opcode
	line, arg, aux, target int
	name                   string
	t                      Type
	v                      Value
	table                  *indexedTable
}
type handler struct {
	id   string
	code []instruction
}
type Program struct {
	handlers map[string][]handler
	ids      []string
}

func (p *Program) HandlerIDs() []string      { return slices.Clone(p.ids) }
func (p *Program) Handles(event string) bool { return len(p.handlers[event]) != 0 }

type variable struct {
	slot int
	t    Type
}
type scope map[string]variable
type compiler struct {
	syntax         syntax
	event          Event
	code           []instruction
	nlocals, depth int
	calls          map[string]bool
	ret            Type
	exits          []int
	total          *int
}

func (c *compiler) emit(op opcode, line int) int {
	if len(c.code) >= MaxInstructions || *c.total >= 65536 {
		fail(line, "compiled program exceeds instruction limit")
	}
	*c.total++
	i := len(c.code)
	c.code = append(c.code, instruction{op: op, line: line})
	return i
}
func (c *compiler) slot(t Type, line int) variable {
	if c.nlocals >= maxLocals {
		fail(line, "too many live local variables")
	}
	v := variable{c.nlocals, t}
	c.nlocals++
	return v
}
func same(got, want Type, line int) {
	if got != want {
		fail(line, "expected %s, found %s", want, got)
	}
}
func (c *compiler) expr(x *expr, env scope) Type {
	c.depth++
	defer func() { c.depth-- }()
	if c.depth > maxDepth {
		fail(x.line, "expression exceeds nesting limit")
	}
	switch x.op {
	case "const":
		i := c.emit(literal, x.line)
		c.code[i].v = x.v
		return x.v.t
	case "name":
		if v, ok := env[x.name]; ok {
			i := c.emit(load, x.line)
			c.code[i].arg = v.slot
			return v.t
		}
		f, ok := c.event.Fields[x.name]
		if !ok {
			fail(x.line, "field %q unavailable on this event", x.name)
		}
		i := c.emit(read, x.line)
		c.code[i].name = x.name
		c.code[i].t = f.Type
		return f.Type
	case "array":
		if len(x.args) == 0 {
			fail(x.line, "array literal requires at least one element")
		}
		constantElements := true
		for _, element := range x.args {
			if element.op != "const" {
				constantElements = false
				break
			}
		}
		if constantElements {
			v := constant(x, 0)
			i := c.emit(literal, x.line)
			c.code[i].v = v
			return v.t
		}
		t := c.expr(x.args[0], env)
		if !t.scalar() {
			fail(x.line, "nested arrays are unavailable")
		}
		for _, a := range x.args[1:] {
			same(c.expr(a, env), t, x.line)
		}
		i := c.emit(array, x.line)
		c.code[i].t = ArrayType(t)
		c.code[i].arg = len(x.args)
		return ArrayType(t)
	case "unary":
		want := TInt
		if x.name == "!" {
			want = TBool
		}
		same(c.expr(x.args[0], env), want, x.line)
		i := c.emit(unaryOp, x.line)
		c.code[i].name = x.name
		return want
	case "binary":
		l := c.expr(x.args[0], env)
		if x.name == "&&" || x.name == "||" {
			same(l, TBool, x.line)
			op := andThen
			if x.name == "||" {
				op = orElse
			}
			i := c.emit(op, x.line)
			same(c.expr(x.args[1], env), TBool, x.line)
			c.code[i].target = len(c.code)
			return TBool
		}
		r := c.expr(x.args[1], env)
		typ, ok := binaryType(x.name, l, r)
		if !ok {
			fail(x.line, "operator %q cannot take %s and %s", x.name, l, r)
		}
		i := c.emit(binaryOp, x.line)
		c.code[i].name = x.name
		return typ
	case "call":
		if x.name == "lookup" {
			fail(x.line, "lookup returns Found(value) or Missing; use match lookup(table, key) with both arms")
		}
		if f, ok := c.syntax.functions[x.name]; ok {
			return c.userCall(x, f, env)
		}
		args := make([]Type, len(x.args))
		allConstant := len(args) > 0
		for i, a := range x.args {
			if a.op != "const" {
				allConstant = false
			}
			args[i] = c.expr(a, env)
		}
		t, ok := builtinType(x.name, args)
		if !ok {
			fail(x.line, "unknown function or invalid argument types for %q", x.name)
		}
		// Fold immutable conversions (including IP and prefix literals) at configuration time.
		if allConstant {
			c.code = c.code[:len(c.code)-len(args)]
			i := c.emit(literal, x.line)
			c.code[i].v = constant(x, 0)
			return t
		}
		i := c.emit(builtinCall, x.line)
		c.code[i].name = x.name
		c.code[i].arg = len(args)
		return t
	}
	panic("unknown expression")
}
func (c *compiler) userCall(x *expr, f function, env scope) Type {
	if len(f.args) != len(x.args) {
		fail(x.line, "%s expects %d arguments", f.name, len(f.args))
	}
	for i, a := range x.args {
		same(c.expr(a, env), f.args[i].t, x.line)
	}
	if c.calls[f.name] || len(c.calls) >= 16 {
		fail(x.line, "recursive or excessively nested call to %q", f.name)
	}
	c.calls[f.name] = true
	defer delete(c.calls, f.name)
	base := c.nlocals
	inner := scope{}
	for i := len(f.args) - 1; i >= 0; i-- {
		p := f.args[i]
		v := c.slot(p.t, x.line)
		inner[p.name] = v
		k := c.emit(store, x.line)
		c.code[k].arg = v.slot
	}
	outerRet, outerExits := c.ret, c.exits
	c.ret = f.ret
	c.exits = nil
	if !c.block(f.body, inner) {
		fail(f.line, "function %q does not return on every path", f.name)
	}
	for _, pc := range c.exits {
		c.code[pc].target = len(c.code)
	}
	c.ret, c.exits = outerRet, outerExits
	c.nlocals = base
	return f.ret
}

// Lower Found(T) | Missing directly into two control-flow edges. The value
// never occupies a scalar operand slot where an untested miss could escape.
func (c *compiler) match(s stmt, env scope) bool {
	x := s.x
	if x.op != "call" || x.name != "lookup" || len(x.args) != 2 || x.args[0].op != "name" {
		fail(s.line, "expected match lookup(table, key)")
	}
	table, ok := c.syntax.tables[x.args[0].name]
	if !ok {
		fail(x.line, "unknown table %q", x.args[0].name)
	}
	key := c.expr(x.args[1], env)
	if !(table.key == TPrefix && key == TAddr) {
		same(key, table.key, x.line)
	}
	if _, ok := env[s.name]; ok {
		fail(s.line, "duplicate local %q", s.name)
	}
	base := c.nlocals
	binding := c.slot(table.value, s.line)
	test := c.emit(matchLookup, s.line)
	c.code[test].arg = binding.slot
	c.code[test].table = table
	inner := maps.Clone(env)
	inner[s.name] = binding
	onFound := c.block(s.body, inner)
	c.nlocals = base
	end := c.emit(jump, s.line)
	c.code[test].target = len(c.code)
	onMissing := c.block(s.other, env)
	c.code[end].target = len(c.code)
	return onFound && onMissing
}
func (c *compiler) block(body []stmt, outer scope) bool {
	env := maps.Clone(outer)
	base := c.nlocals
	defer func() { c.nlocals = base }()
	returns := false
	for _, s := range body {
		if returns {
			fail(s.line, "unreachable statement")
		}
		switch s.op {
		case "let":
			if _, ok := env[s.name]; ok {
				fail(s.line, "duplicate local %q", s.name)
			}
			t := c.expr(s.x, env)
			if s.typ != "" {
				same(t, s.typ, s.line)
			}
			v := c.slot(t, s.line)
			env[s.name] = v
			i := c.emit(store, s.line)
			c.code[i].arg = v.slot
		case "assign":
			t := c.expr(s.x, env)
			if v, ok := env[s.name]; ok {
				same(t, v.t, s.line)
				i := c.emit(store, s.line)
				c.code[i].arg = v.slot
				continue
			}
			f, ok := c.event.Fields[s.name]
			if !ok || !f.Writable {
				fail(s.line, "field %q is unavailable or read-only", s.name)
			}
			same(t, f.Type, s.line)
			i := c.emit(write, s.line)
			c.code[i].name = s.name
		case "if":
			same(c.expr(s.x, env), TBool, s.line)
			test := c.emit(branch, s.line)
			yes := c.block(s.body, env)
			if len(s.other) == 0 {
				c.code[test].target = len(c.code)
			} else {
				end := c.emit(jump, s.line)
				c.code[test].target = len(c.code)
				no := c.block(s.other, env)
				c.code[end].target = len(c.code)
				returns = yes && no
			}
		case "match":
			returns = c.match(s, env)
		case "for":
			if _, ok := env[s.name]; ok {
				fail(s.line, "duplicate local %q", s.name)
			}
			typ := c.expr(s.x, env)
			if !typ.isArray() {
				fail(s.line, "for requires an array or range")
			}
			before := c.nlocals
			seq := c.slot(typ, s.line)
			index := c.slot(TInt, s.line)
			item := c.slot(typ.element(), s.line)
			k := c.emit(store, s.line)
			c.code[k].arg = seq.slot
			k = c.emit(literal, s.line)
			c.code[k].v = Int(0)
			k = c.emit(store, s.line)
			c.code[k].arg = index.slot
			start := c.emit(iterate, s.line)
			c.code[start].arg = seq.slot
			inner := maps.Clone(env)
			inner[s.name] = item
			c.block(s.body, inner)
			k = c.emit(advance, s.line)
			c.code[k].arg = index.slot
			c.code[k].target = start
			c.code[start].target = len(c.code)
			c.nlocals = before
		case "return":
			if c.ret == "" {
				fail(s.line, "return requires a function")
			}
			same(c.expr(s.x, env), c.ret, s.line)
			c.exits = append(c.exits, c.emit(jump, s.line))
			returns = true
		case "call":
			name := s.x.name
			if name == "lookup" {
				fail(s.line, "lookup must be consumed by an exhaustive match")
			}
			if c.ret != "" && (name == "drop" || name == "count") {
				fail(s.line, "intrinsic %s belongs in an event handler", name)
			}
			if name == "drop" {
				if len(s.x.args) != 0 {
					fail(s.line, "drop takes no arguments")
				}
				c.emit(deny, s.line)
				continue
			}
			types, ok := c.event.Actions[name]
			if name == "count" {
				ok = true
				types = nil
			}
			if ok {
				if len(types) != len(s.x.args) {
					fail(s.line, "action %s expects %d arguments", name, len(types))
				}
				if name == "route.exit_node" && len(types) == 1 && types[0] == TString {
					target := s.x.args[0]
					if target.op != "const" || target.v.t != TString || !ValidExitNodeID(target.v.s) {
						fail(s.line, "route.exit_node expects a quoted stable exit-node ID")
					}
					// Lower a static choice to a verified boolean host effect.
					// The target is immutable metadata, never a packet-supplied string.
					choice := c.emit(literal, s.line)
					c.code[choice].v = Bool(true)
					effect := c.emit(write, s.line)
					c.code[effect].name = exitNodeEffect + target.v.s
					c.code[effect].t = TBool
					continue
				}
				for i, a := range s.x.args {
					same(c.expr(a, env), types[i], s.line)
				}
				k := c.emit(hostAction, s.line)
				c.code[k].name = name
				c.code[k].arg = len(types)
			} else {
				c.expr(s.x, env)
				c.emit(discard, s.line)
			}
		}
	}
	return returns
}
func Compile(source string, schema Schema, external map[string]Table) (program *Program, err error) {
	defer func() {
		if e := recover(); e != nil {
			if d, ok := e.(diagnostic); ok {
				program = nil
				err = d.error
			} else {
				panic(e)
			}
		}
	}()
	if len(source) > MaxSourceBytes {
		return nil, fmt.Errorf("source exceeds %d bytes", MaxSourceBytes)
	}
	s := parse(source, external)
	p := &Program{handlers: map[string][]handler{}}
	total := 0
	// Check helpers independently of any adapter, including unused helpers.
	// They operate only on explicit parameters and immutable program tables.
	for _, name := range slices.Sorted(maps.Keys(s.functions)) {
		f := s.functions[name]
		if _, present := library[name]; present || name == "lookup" || name == "count" || name == "drop" {
			fail(f.line, "function name %q is reserved", name)
		}
		c := compiler{syntax: s, ret: f.ret, calls: map[string]bool{name: true}, total: &total}
		params := scope{}
		for _, arg := range f.args {
			params[arg.name] = c.slot(arg.t, f.line)
		}
		if !c.block(f.body, params) {
			fail(f.line, "function %q does not return on every path", f.name)
		}
	}
	for _, h := range s.handlers {
		event, ok := schema.Resolve(h.event)
		if !ok {
			fail(h.line, "event %q unavailable in this adapter", h.event)
		}
		c := compiler{syntax: s, event: event, calls: map[string]bool{}, total: &total}
		c.block(h.body, scope{})
		verifyStack(c.code)
		p.handlers[h.event] = append(p.handlers[h.event], handler{h.id, c.code})
		p.ids = append(p.ids, h.id)
	}
	return p, nil
}

// Verify every control-flow edge during compilation. The interpreter can then
// operate directly on fixed stack slots even across inlined returns and loops.
func verifyStack(code []instruction) {
	heights := make([]int, len(code)+1)
	for i := range heights {
		heights[i] = -1
	}
	heights[0] = 0
	queue := []int{0}
	for len(queue) > 0 {
		pc := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		h := heights[pc]
		if pc == len(code) {
			if h != 0 {
				panic("unbalanced emitted event")
			}
			continue
		}
		i := code[pc]
		push := func(to, n int) {
			if n < 0 {
				panic("invalid emitted stack operand")
			}
			if n > maxStack {
				fail(i.line, "operand stack exceeds %d values", maxStack)
			}
			if heights[to] == -1 {
				heights[to] = n
				queue = append(queue, to)
			} else if heights[to] != n {
				panic("inconsistent emitted stack")
			}
		}
		switch i.op {
		case deny:
			continue
		case jump, advance:
			push(i.target, h)
		case andThen, orElse:
			push(i.target, h)
			push(pc+1, h-1)
		case branch, matchLookup:
			push(i.target, h-1)
			push(pc+1, h-1)
		case iterate:
			push(i.target, h)
			push(pc+1, h)
		case literal, read, load:
			push(pc+1, h+1)
		case write, discard, store, binaryOp:
			push(pc+1, h-1)
		case array, builtinCall:
			push(pc+1, h-i.arg+1)
		case hostAction:
			push(pc+1, h-i.arg)
		case unaryOp:
			push(pc+1, h)
		}
	}
}

// NativeHandlerImage is a verified data program for the Swift event host.
// The signed Rust runtime revalidates code before use; fields are in ABI order.
type NativeHandlerImage struct {
	Event  string   `json:"event"`
	ID     string   `json:"id"`
	Fields []string `json:"fields"`
	Code   []byte   `json:"code"`
}
