// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
// Package main adapts offline JSON fixtures to the same typed VM used by the
// packet router. It has no socket, filesystem, clock, or certificate operations.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"pxengine/routelang"
	"pxengine/routelang/catalog"
	"strings"
	"unicode/utf8"
)

type fixtureEvent struct {
	Event  string         `json:"event"`
	Fields map[string]any `json:"fields"`
	Bytes  []byte         `json:"bytes"`
}
type fixtureTable struct {
	Key, Element routelang.Type
	Entries      []struct{ Key, Value any }
}
type query struct {
	Source    *string
	TableJSON map[string]fixtureTable
	Events    []fixtureEvent
}
type action struct {
	Name string `json:"name"`
	Args []any  `json:"args"`
}
type condition struct {
	Line    int    `json:"line"`
	Taken   bool   `json:"taken"`
	Handler string `json:"handler"`
	Lookup  bool   `json:"lookup,omitempty"`
}
type frame struct {
	Dispatched []string       `json:"dispatched"`
	Event      string         `json:"event"`
	Matched    []string       `json:"matched"`
	Before     map[string]any `json:"before"`
	After      map[string]any `json:"after"`
	Actions    []action       `json:"actions"`
	Dropped    bool           `json:"dropped"`
	Error      string         `json:"error,omitempty"`
	Trace      []condition    `json:"trace"`
}
type counter struct {
	ID               string `json:"id"`
	Events           int    `json:"events"`
	Drops            int    `json:"drops"`
	UnmeasuredEvents int    `json:"unmeasuredEvents"`
	Bytes            *int   `json:"bytes"`
}
type evaluation struct {
	OK       bool      `json:"ok"`
	Error    string    `json:"error,omitempty"`
	Handlers []string  `json:"handlers"`
	Steps    []frame   `json:"steps"`
	Counters []counter `json:"counters"`
}

func toValue(t routelang.Type, v any) (routelang.Value, error) {
	switch t {
	case routelang.TString, routelang.TDNS, routelang.TAddr, routelang.TPrefix:
		if s, ok := v.(string); ok && len(s) <= routelang.MaxString && utf8.ValidString(s) {
			switch t {
			case routelang.TString:
				return routelang.String(s), nil
			case routelang.TDNS:
				return routelang.DNS(s)
			case routelang.TAddr:
				a, e := netip.ParseAddr(s)
				if e == nil && a.Zone() == "" && !a.Is4In6() {
					return routelang.Addr(a), nil
				}
			case routelang.TPrefix:
				p, e := netip.ParsePrefix(s)
				if e == nil && p.Masked() == p && !p.Addr().Is4In6() {
					return routelang.Prefix(p), nil
				}
			}
		}
	case routelang.TInt:
		if n, ok := v.(json.Number); ok {
			value, e := n.Int64()
			if e == nil && value >= -(1<<53-1) && value <= 1<<53-1 {
				return routelang.Int(value), nil
			}
		}
	case routelang.TBool:
		if b, ok := v.(bool); ok {
			return routelang.Bool(b), nil
		}
	case routelang.TBytes:
		if list, ok := v.([]any); ok && len(list) <= 8192 {
			b := make([]byte, len(list))
			for i, item := range list {
				val, e := toValue(routelang.TInt, item)
				if e != nil || val.AsInt() < 0 || val.AsInt() > 255 {
					return routelang.Value{}, errors.New("expected byte 0–255")
				}
				b[i] = byte(val.AsInt())
			}
			return routelang.Bytes(b)
		}
	}
	if element, array := strings.CutPrefix(string(t), "[]"); array {
		list, ok := v.([]any)
		if !ok || len(list) > routelang.MaxArray {
			return routelang.Value{}, fmt.Errorf("expected a bounded %s array", element)
		}
		items := make([]routelang.Value, len(list))
		for idx, item := range list {
			converted, err := toValue(routelang.Type(element), item)
			if err != nil {
				return routelang.Value{}, fmt.Errorf("array element %d: %w", idx, err)
			}
			items[idx] = converted
		}
		return routelang.Array(routelang.Type(element), items)
	}
	return routelang.Value{}, fmt.Errorf("expected %s value", t)
}
func fromValue(v routelang.Value) (any, error) {
	switch v.Type() {
	case routelang.TString, routelang.TDNS:
		return v.AsString(), nil
	case routelang.TBool:
		return v.AsBool(), nil
	case routelang.TInt:
		n := v.AsInt()
		if n < -(1<<53-1) || n > 1<<53-1 {
			return nil, errors.New("integer exceeds exact JSON range")
		}
		return n, nil
	case routelang.TAddr:
		return v.AsAddr().String(), nil
	case routelang.TPrefix:
		return v.AsPrefix().String(), nil
	case routelang.TBytes:
		b := v.AsBytes()
		res := make([]int, len(b))
		for i, c := range b {
			res[i] = int(c)
		}
		return res, nil
	}
	if !strings.HasPrefix(string(v.Type()), "[]") {
		return nil, errors.New("unsupported fixture value type")
	}
	list := v.AsArray()
	res := make([]any, len(list))
	for i, item := range list {
		value, err := fromValue(item)
		if err != nil {
			return nil, err
		}
		res[i] = value
	}
	return res, nil
}

type fixtureHost struct {
	extraFields map[string]routelang.Value
	values      map[string]routelang.Value
	actions     []action
}

func (h *fixtureHost) Read(name string) (routelang.Value, bool) {
	v, ok := h.values[name]
	if !ok {
		v, ok = h.extraFields[name]
	}
	return v, ok
}
func (h *fixtureHost) Write(name string, v routelang.Value) error {
	if id, ok := routelang.ExitNodeEffect(name); ok {
		if v.Type() != routelang.TBool || !v.AsBool() {
			return errors.New("invalid exit-node selection")
		}
		for _, prior := range h.actions {
			if prior.Name == "route.exit_node" {
				if prior.Args[0] != id {
					return errors.New("conflicting exit nodes selected")
				}
				return nil
			}
		}
		return h.Action("route.exit_node", []routelang.Value{routelang.String(id)})
	}
	switch name {
	case "ip.dscp":
		if n := v.AsInt(); n < 0 || n > 63 {
			return errors.New("ip.dscp must be 0–63")
		}
	case "tcp.mss":
		m, ok := h.values[name]
		if n := v.AsInt(); !ok || n < 536 || n > 65535 || n > m.AsInt() {
			return errors.New("tcp.mss requires an existing MSS and may only clamp it")
		}
	case "http.status":
		if n := v.AsInt(); n < 100 || n > 599 {
			return errors.New("HTTP status must be 100–599")
		}
	}
	h.values[name] = v
	return nil
}
func (h *fixtureHost) Action(name string, vs []routelang.Value) error {
	switch name {
	case "source.select_member":
		if len(vs) != 1 || vs[0].Type() != routelang.TString || !validMemberID(vs[0].AsString()) {
			return errors.New("source.select_member requires a member ID of 1–80 ASCII letters, digits, underscores or hyphens")
		}
	case "proxy.select_backend":
		if len(vs) != 1 || vs[0].Type() != routelang.TString || !validBackendID(vs[0].AsString()) {
			return errors.New("proxy.select_backend requires a backend identifier of 1–128 ASCII letters, digits, dots, underscores or hyphens, starting with a letter or digit")
		}
	case "session.expect":
		if len(vs) != 3 || vs[1].AsInt() < 1 || vs[1].AsInt() > 65535 || vs[2].AsInt() < 1 || vs[2].AsInt() > 300 {
			return errors.New("expectation requires a valid port and 1–300 seconds")
		}
	case "proxy.reply_client", "proxy.reply_server":
		if len(vs) != 1 || vs[0].AsInt() < 100 || vs[0].AsInt() > 599 {
			return errors.New("fixture response code must be 100–599")
		}
	}
	a := action{Name: name, Args: make([]any, len(vs))}
	for i, v := range vs {
		value, err := fromValue(v)
		if err != nil {
			return err
		}
		a.Args[i] = value
	}
	h.actions = append(h.actions, a)
	return nil
}
func validBackendID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for i, c := range []byte(id) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if i == 0 || c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}
func snapshot(m map[string]routelang.Value) (map[string]any, error) {
	res := make(map[string]any, len(m))
	for k, v := range m {
		value, err := fromValue(v)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", k, err)
		}
		res[k] = value
	}
	return res, nil
}
func evaluate(raw string) (evaluation, error) {
	if len(raw) > 768<<10 {
		return evaluation{}, errors.New("fixture exceeds 768 KiB")
	}
	if !utf8.ValidString(raw) {
		return evaluation{}, errors.New("fixture must be valid UTF-8")
	}
	var q query
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&q); err != nil {
		return evaluation{}, err
	}
	if q.Source == nil {
		return evaluation{}, errors.New("fixture is missing its source")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return evaluation{}, errors.New("expected a single fixture JSON object")
	}
	if len(q.Events) > 128 || len(q.TableJSON) > 32 {
		return evaluation{}, errors.New("use at most 128 events and 32 data tables")
	}
	tables := map[string]routelang.Table{}
	for name, t := range q.TableJSON {
		if len(t.Entries) > 2048 {
			return evaluation{}, errors.New("table exceeds 2048 rows")
		}
		tab := routelang.Table{Key: t.Key, Element: t.Element}
		for i, e := range t.Entries {
			key, er := toValue(t.Key, e.Key)
			if er != nil {
				return evaluation{}, fmt.Errorf("table %s row %d key: %w", name, i+1, er)
			}
			v, er := toValue(t.Element, e.Value)
			if er != nil {
				return evaluation{}, fmt.Errorf("table %s row %d value: %w", name, i+1, er)
			}
			tab.Entries = append(tab.Entries, routelang.Entry{Key: key, Value: v})
		}
		tables[name] = tab
	}
	schema := catalog.Schema()
	prog, err := routelang.Compile(*q.Source, schema, tables)
	if err != nil {
		return evaluation{}, err
	}
	result := evaluation{OK: true, Handlers: prog.HandlerIDs(), Steps: []frame{}, Counters: []counter{}}
	ids := map[string]int{}
	for _, name := range result.Handlers {
		ids[name] = len(result.Counters)
		result.Counters = append(result.Counters, counter{ID: name, Bytes: new(int)})
	}
	budget := 0
	for i, e := range q.Events {
		evt, ok := schema.Resolve(e.Event)
		if !ok {
			return evaluation{}, fmt.Errorf("event %d: unknown event %q", i+1, e.Event)
		}
		host := fixtureHost{values: map[string]routelang.Value{}}
		for k, input := range e.Fields {
			field, ok := evt.Fields[k]
			if !ok {
				return evaluation{}, fmt.Errorf("event %d: %s is unavailable on %s", i+1, k, e.Event)
			}
			v, err := toValue(field.Type, input)
			if err != nil {
				return evaluation{}, fmt.Errorf("event %d field %s: %w", i+1, k, err)
			}
			host.values[k] = v
		}
		if e.Event == "socket.open" {
			if err := validateSocketFixture(host.values); err != nil {
				return evaluation{}, fmt.Errorf("event %d: %w", i+1, err)
			}
		}
		before, err := snapshot(host.values)
		if err != nil {
			return evaluation{}, err
		}
		plan, err := catalog.PlanObservation(e.Event, host.values, prog.Handles("ftps.handshake"))
		if err != nil {
			return evaluation{}, fmt.Errorf("event %d: %w", i+1, err)
		}
		host.extraFields = plan.ExtraFields
		r, err := prog.RunTraceSequence(plan.Hooks, &host)
		f := frame{Event: e.Event, Dispatched: r.Dispatched, Matched: r.Matches, Before: before, After: before, Actions: host.actions, Dropped: r.Dropped, Trace: []condition{}}
		if f.Matched == nil {
			f.Matched = []string{}
		}
		if f.Actions == nil {
			f.Actions = []action{}
		}
		for _, c := range r.Trace {
			f.Trace = append(f.Trace, condition{Line: c.Line, Taken: c.Taken, Handler: c.Handler, Lookup: c.Lookup})
		}
		if err == nil && !f.Dropped {
			f.After, err = snapshot(host.values)
		}
		if err != nil {
			f.Error = err.Error()
			f.Dropped = true
		}
		if f.Dropped {
			f.After = before
			f.Actions = []action{}
		}

		for _, id := range r.Matches {
			c := &result.Counters[ids[id]]
			c.Events++
			if e.Bytes == nil {
				c.UnmeasuredEvents++
				c.Bytes = nil
			} else if c.Bytes != nil {
				*c.Bytes += len(e.Bytes)
			}
		}
		if f.Dropped && len(r.Matches) > 0 {
			result.Counters[ids[r.Matches[len(r.Matches)-1]]].Drops++
		}
		result.Steps = append(result.Steps, f)
		budget += r.Instructions
		if budget > 1000000 {
			return evaluation{}, errors.New("fixture run exceeded one million instructions")
		}
	}
	return result, nil
}
func encodedEvaluate(raw string) string {
	r, e := evaluate(raw)
	if e != nil {
		r = evaluation{Error: e.Error()}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if e = enc.Encode(r); e != nil {
		return `{"ok":false,"error":"invalid result"}`
	}
	return buf.String()
}
