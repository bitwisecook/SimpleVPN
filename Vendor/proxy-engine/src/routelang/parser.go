// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package routelang

import (
	"net/netip"
	"strconv"
	"strings"
)

type token struct {
	text, kind string
	line       int
}
type diagnostic struct{ error }

func fail(line int, format string, a ...any) { panic(diagnostic{problem(line, format, a...)}) }
func alpha(c byte) bool                      { return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func digit(c byte) bool                      { return c >= '0' && c <= '9' }
func lex(s string) []token {
	var out []token
	line := 1
	for i := 0; i < len(s); {
		c := s[i]
		switch c {
		case ' ', '\t', '\r':
			i++
			continue
		case '\n':
			line++
			i++
			continue
		}
		if c == '#' || strings.HasPrefix(s[i:], "//") {
			n := strings.IndexByte(s[i:], '\n')
			if n < 0 {
				break
			}
			i += n
			continue
		}
		start := i
		i++
		kind := "op"
		switch {
		case c == '"':
			kind = "string"
			closed := false
			for i < len(s) {
				b := s[i]
				i++
				if b == '\n' {
					fail(line, "newline in string")
				}
				if b == '"' {
					closed = true
					break
				}
				if b == '\\' && i < len(s) {
					i++
				}
			}
			if !closed {
				fail(line, "unterminated string")
			}
		case alpha(c):
			kind = "id"
			for i < len(s) && (alpha(s[i]) || digit(s[i]) || s[i] == '.') {
				i++
			}
		case digit(c):
			kind = "int"
			for i < len(s) && digit(s[i]) {
				i++
			}
			if i < len(s) && s[i] == '.' {
				kind = "ip"
				for i < len(s) && (digit(s[i]) || s[i] == '.' || s[i] == '/') {
					i++
				}
			}
		default:
			if i < len(s) {
				switch s[start : i+1] {
				case "->", "==", "!=", "&&", "||", "<=", ">=":
					i++
				}
			}
		}
		out = append(out, token{s[start:i], kind, line})
		if len(out) > 16000 {
			fail(line, "program exceeds token limit")
		}
	}
	return append(out, token{"", "eof", line})
}

type expr struct {
	op, name string
	v        Value
	args     []*expr
	line     int
}
type stmt struct {
	op, name    string
	typ         Type
	x           *expr
	body, other []stmt
	line        int
}
type parameter struct {
	name string
	t    Type
}
type function struct {
	name string
	args []parameter
	ret  Type
	body []stmt
	line int
}
type handlerAST struct {
	id, event string
	body      []stmt
	line      int
}
type syntax struct {
	functions map[string]function
	tables    map[string]*indexedTable
	handlers  []handlerAST
}
type parser struct {
	ts       []token
	i, depth int
}

func (p *parser) enter() {
	p.depth++
	if p.depth > maxDepth {
		fail(p.cur().line, "nesting exceeds %d", maxDepth)
	}
}
func (p *parser) cur() token { return p.ts[p.i] }
func (p *parser) take() token {
	t := p.cur()
	if t.kind == "eof" {
		fail(t.line, "unexpected end of source")
	}
	p.i++
	return t
}
func (p *parser) accept(s string) bool {
	if p.cur().text == s {
		p.i++
		return true
	}
	return false
}
func (p *parser) need(s string) {
	if !p.accept(s) {
		fail(p.cur().line, "expected %q, found %q", s, p.cur().text)
	}
}
func (p *parser) id() token {
	t := p.take()
	if t.kind != "id" || strings.HasSuffix(t.text, ".") || strings.Contains(t.text, "..") {
		fail(t.line, "expected identifier, found %q", t.text)
	}
	return t
}
func (p *parser) local() token {
	t := p.id()
	if strings.Contains(t.text, ".") {
		fail(t.line, "local name may not contain a dot")
	}
	return t
}
func (p *parser) typ() Type {
	array := p.accept("[")
	if array {
		p.need("]")
	}
	t := Type(p.id().text)
	if !t.scalar() {
		fail(p.cur().line, "unknown type %q", t)
	}
	if array {
		return ArrayType(t)
	}
	return t
}
func (p *parser) end() {
	if !p.accept(";") && p.cur().text != "}" {
		fail(p.cur().line, "expected semicolon")
	}
}
func (p *parser) block() []stmt {
	p.enter()
	defer func() { p.depth-- }()
	p.need("{")
	var b []stmt
	for !p.accept("}") {
		b = append(b, p.statement())
	}
	return b
}
func (p *parser) statement() stmt {
	t := p.id()
	s := stmt{op: t.text, line: t.line}
	switch t.text {
	case "let", "var":
		s.op = "let"
		s.name = p.local().text
		if p.accept(":") {
			s.typ = p.typ()
		}
		p.need("=")
		s.x = p.expression(1)
	case "if":
		s.x = p.expression(1)
		s.body = p.block()
		if p.accept("else") {
			if p.cur().text == "if" {
				p.enter()
				s.other = []stmt{p.statement()}
				p.depth--
			} else {
				s.other = p.block()
			}
		}
		return s
	case "match":
		s.x = p.expression(1)
		p.need("{")
		found, missing := false, false
		for !p.accept("}") {
			arm := p.id()
			switch arm.text {
			case "found":
				if found {
					fail(arm.line, "duplicate found arm")
				}
				found = true
				p.need("(")
				binding := p.local()
				switch binding.text {
				case "true", "false", "match", "found", "missing", "let", "var", "return", "if", "else", "for", "in":
					fail(binding.line, "expected a binding name, found %q", binding.text)
				}
				s.name = binding.text
				p.need(")")
				s.body = p.block()
			case "missing":
				if missing {
					fail(arm.line, "duplicate missing arm")
				}
				missing = true
				s.other = p.block()
			default:
				fail(arm.line, "lookup match requires found(value) and missing arms")
			}
		}
		if !found || !missing {
			fail(t.line, "lookup match requires both found(value) and missing arms")
		}
		return s
	case "for":
		s.name = p.local().text
		p.need("in")
		s.x = p.expression(1)
		s.body = p.block()
		return s
	case "return":
		s.x = p.expression(1)
	default:
		if p.accept("=") {
			s.op = "assign"
			s.name = t.text
			s.x = p.expression(1)
		} else {
			p.i--
			s.op = "call"
			s.x = p.expression(1)
			if s.x.op != "call" {
				fail(t.line, "expected assignment or call")
			}
		}
	}
	p.end()
	return s
}

var precedence = map[string]int{"||": 1, "&&": 2, "==": 3, "!=": 3, "in": 3, "<": 4, ">": 4, "<=": 4, ">=": 4, "+": 5, "-": 5, "*": 6, "/": 6, "%": 6}

func (p *parser) list(close string) []*expr {
	var a []*expr
	if p.accept(close) {
		return a
	}
	for {
		if len(a) >= MaxArray {
			fail(p.cur().line, "too many elements")
		}
		a = append(a, p.expression(1))
		if p.accept(close) {
			return a
		}
		p.need(",")
	}
}
func (p *parser) expression(min int) *expr {
	p.enter()
	defer func() { p.depth-- }()
	t := p.take()
	x := &expr{line: t.line}
	switch {
	case t.text == "!" || t.text == "-":
		x.op = "unary"
		x.name = t.text
		x.args = []*expr{p.expression(7)}
	case t.text == "(":
		x = p.expression(1)
		p.need(")")
	case t.text == "[":
		x.op = "array"
		x.args = p.list("]")
	case t.text == "true" || t.text == "false":
		x.op = "const"
		x.v = Bool(t.text == "true")
	case t.kind == "int":
		v, e := strconv.ParseInt(t.text, 10, 64)
		if e != nil {
			fail(t.line, "invalid integer")
		}
		x.op = "const"
		x.v = Int(v)
	case t.kind == "string":
		v, e := strconv.Unquote(t.text)
		if e != nil || !String(v).valid() {
			fail(t.line, "invalid or oversized string")
		}
		x.op = "const"
		x.v = String(v)
	case t.kind == "ip":
		x.op = "const"
		if strings.Contains(t.text, "/") {
			a, e := netip.ParsePrefix(t.text)
			if e != nil {
				fail(t.line, "invalid prefix")
			}
			x.v = Prefix(a)
		} else {
			a, e := netip.ParseAddr(t.text)
			if e != nil {
				fail(t.line, "invalid address")
			}
			x.v = Addr(a)
		}
		if !x.v.valid() {
			fail(t.line, "invalid address or noncanonical prefix")
		}
	case t.kind == "id":
		x.name = t.text
		x.op = "name"
		if p.accept("(") {
			x.op = "call"
			x.args = p.list(")")
		}
	default:
		fail(t.line, "expected expression, found %q", t.text)
	}
	for {
		if p.accept("[") {
			index := p.expression(1)
			p.need("]")
			x = &expr{line: t.line, op: "call", name: "at", args: []*expr{x, index}}
			continue
		}
		op := p.cur().text
		prec := precedence[op]
		if prec < min {
			break
		}
		p.take()
		rhs := p.expression(prec + 1)
		x = &expr{line: t.line, op: "binary", name: op, args: []*expr{x, rhs}}
	}
	return x
}
func parse(source string, external map[string]Table) syntax {
	p := parser{ts: lex(source)}
	s := syntax{functions: map[string]function{}, tables: map[string]*indexedTable{}}
	ids := map[string]bool{}
	tableEntries := 0
	for p.cur().kind != "eof" {
		decl := p.take()
		switch decl.text {
		case "on":
			id := p.local()
			p.need(":")
			event := p.id()
			if ids[id.text] || len(ids) >= 128 {
				fail(id.line, "duplicate handler or more than 128 handlers")
			}
			ids[id.text] = true
			s.handlers = append(s.handlers, handlerAST{id.text, event.text, p.block(), id.line})
		case "fn":
			name := p.local()
			f := function{name: name.text, line: name.line}
			if _, ok := s.functions[name.text]; ok || len(s.functions) >= 128 {
				fail(name.line, "duplicate or excess function")
			}
			p.need("(")
			if !p.accept(")") {
				seen := map[string]bool{}
				for {
					n := p.local()
					if seen[n.text] || len(seen) >= 16 {
						fail(n.line, "duplicate or excess parameter")
					}
					seen[n.text] = true
					p.need(":")
					f.args = append(f.args, parameter{n.text, p.typ()})
					if p.accept(")") {
						break
					}
					p.need(",")
				}
			}
			p.need("->")
			f.ret = p.typ()
			f.body = p.block()
			s.functions[name.text] = f
		case "table":
			n := p.local()
			if _, ok := s.tables[n.text]; ok || len(s.tables) >= 64 {
				fail(n.line, "duplicate or excess table")
			}
			p.need(":")
			key := p.typ()
			p.need("->")
			elem := p.typ()
			p.need("=")
			tab := Table{Key: key, Element: elem}
			if p.accept("external") {
				t := p.take()
				name, e := strconv.Unquote(t.text)
				if t.kind != "string" || e != nil {
					fail(t.line, "expected external dataset name")
				}
				var ok bool
				tab, ok = external[name]
				if !ok || tab.Key != key || tab.Element != elem {
					fail(t.line, "missing or incompatible dataset %q", name)
				}
			} else {
				p.need("{")
				if !p.accept("}") {
					for {
						k := constant(p.expression(1), 0)
						p.need(":")
						v := constant(p.expression(1), 0)
						tab.Entries = append(tab.Entries, Entry{k, v})
						if p.accept("}") {
							break
						}
						p.need(",")
					}
				}
			}
			tableEntries += len(tab.Entries)
			if tableEntries > 16384 {
				fail(n.line, "too many table entries")
			}
			m, e := indexTable(tab)
			if e != nil {
				fail(n.line, "%v", e)
			}
			s.tables[n.text] = m
			p.need(";")
		default:
			fail(decl.line, "expected table, fn or on")
		}
	}
	return s
}
