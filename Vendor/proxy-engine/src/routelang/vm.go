// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package routelang

import (
	"errors"
	"math"
	"sync"
)

// Workspaces contain packet-derived values. Wipe every touched slot before reuse.
type workspace struct {
	stack                             [maxStack]Value
	locals                            [maxLocals]Value
	sp, stackUsed, localsUsed, budget int
}

var workspaces = sync.Pool{New: func() any { return new(workspace) }}

func (w *workspace) push(v Value) error {
	if w.sp == maxStack {
		return errors.New("operand stack limit exceeded")
	}
	w.stack[w.sp] = v
	w.sp++
	if w.sp > w.stackUsed {
		w.stackUsed = w.sp
	}
	return nil
}
func (w *workspace) pop() Value { w.sp--; return w.stack[w.sp] }
func (w *workspace) set(i int, v Value) {
	w.locals[i] = v
	if i >= w.localsUsed {
		w.localsUsed = i + 1
	}
}
func (w *workspace) release() {
	clear(w.stack[:w.stackUsed])
	clear(w.locals[:w.localsUsed])
	w.sp, w.stackUsed, w.localsUsed = 0, 0, 0
	workspaces.Put(w)
}

// Run dispatches only handlers registered for event. Hosts must stage changes
// and commit them only after a successful, permitted event.
func (p *Program) Run(event string, host Host) (Result, error) { return p.run(event, host, false, nil) }
func (p *Program) RunTrace(event string, host Host) (Result, error) {
	return p.run(event, host, true, nil)
}

// RunInto reuses caller-owned storage for dispatch IDs. The returned Matches
// slice is valid until the caller reuses that storage. Program remains immutable.
func (p *Program) RunInto(event string, host Host, matches []string) (Result, error) {
	return p.run(event, host, false, matches[:0])
}
func (p *Program) run(event string, host Host, trace bool, matches []string) (Result, error) {
	hs := p.handlers[event]
	if len(hs) == 0 {
		return Result{}, nil
	}
	w := workspaces.Get().(*workspace)
	defer w.release()
	w.budget = maxByteWork
	if cap(matches) < len(hs) {
		matches = make([]string, 0, len(hs))
	}
	r := Result{Matches: matches}
	err := w.dispatch(hs, host, trace, &r)
	return r, err
}

func (w *workspace) dispatch(handlers []handler, host Host, trace bool, r *Result) error {
	for _, h := range handlers {
		r.Matches = append(r.Matches, h.id)
		if err := w.execute(h, host, trace, r); err != nil {
			r.Dropped = true
			return err
		}
		if r.Dropped {
			break
		}
	}
	return nil
}

// RunTraceSequence evaluates a general event followed by its applicable
// refinements for a single input. A staged write or action can commit only
// after every entered hook succeeds. The whole sequence shares both budgets.
func (p *Program) RunTraceSequence(events []string, host Host) (Result, error) {
	if len(events) == 0 || len(events) > 8 {
		return Result{Dropped: true}, errors.New("expected 1–8 hooks for one observation")
	}
	n := 0
	for i, name := range events {
		if name == "" {
			return Result{Dropped: true}, errors.New("empty observation hook")
		}
		for _, prev := range events[:i] {
			if prev == name {
				return Result{Dropped: true}, errors.New("duplicate observation hook")
			}
		}
		n += len(p.handlers[name])
	}
	r := Result{Matches: make([]string, 0, n), Dispatched: make([]string, 0, len(events))}
	if n == 0 {
		r.Dispatched = append(r.Dispatched, events...)
		return r, nil
	}
	w := workspaces.Get().(*workspace)
	defer w.release()
	w.budget = maxByteWork
	for _, name := range events {
		r.Dispatched = append(r.Dispatched, name)
		if err := w.dispatch(p.handlers[name], host, true, &r); err != nil {
			return r, err
		}
		if r.Dropped {
			break
		}
	}
	return r, nil
}
func (w *workspace) execute(h handler, host Host, trace bool, r *Result) error {
	for pc := 0; pc < len(h.code); {
		i := &h.code[pc]
		pc++
		r.Instructions++
		if r.Instructions > MaxInstructions {
			return problem(i.line, "instruction budget exceeded")
		}
		var v Value
		var err error
		switch i.op {
		case literal:
			v = i.v
		case read:
			if host == nil {
				return problem(i.line, "host unavailable")
			}
			var ok bool
			v, ok = host.Read(i.name)
			if e := charge(&w.budget, len(v.s)); e != nil {
				return problem(i.line, "%v", e)
			}
			if !ok || v.t != i.t || !v.valid() {
				return problem(i.line, "missing or invalid field %q", i.name)
			}
		case write:
			if host == nil {
				return problem(i.line, "host unavailable")
			}
			if e := host.Write(i.name, w.pop()); e != nil {
				return problem(i.line, "%s: %v", i.name, e)
			}
			continue
		case load:
			v = w.locals[i.arg]
		case store:
			w.set(i.arg, w.pop())
			continue
		case discard:
			w.pop()
			continue
		case array:
			n := i.arg
			start := w.sp - n
			if err = charge(&w.budget, n*valueSize); err == nil {
				v = Value{t: i.t, a: append([]Value(nil), w.stack[start:w.sp]...)}
			}
			w.sp = start
		case builtinCall:
			start := w.sp - i.arg
			v, err = builtin(i.name, w.stack[start:w.sp], &w.budget)
			w.sp = start
		case binaryOp:
			b := w.pop()
			a := w.pop()
			v, err = binaryEval(i.name, a, b, &w.budget)
		case unaryOp:
			a := w.pop()
			if i.name == "!" {
				v = Bool(!a.AsBool())
			} else if a.n == math.MinInt64 {
				err = errBounds
			} else {
				v = Int(-a.n)
			}
		case matchLookup:
			key := w.pop()
			if e := charge(&w.budget, len(key.s)); e != nil {
				return problem(i.line, "%v", e)
			}
			option := i.table.lookup(key)
			if trace {
				r.Trace = append(r.Trace, TraceStep{Lookup: true, Handler: h.id, Line: i.line, Taken: option.found})
			}
			if option.found {
				w.set(i.arg, option.value)
			} else {
				pc = i.target
			}
			continue
		case hostAction:
			if host == nil {
				return problem(i.line, "host unavailable")
			}
			start := w.sp - i.arg
			// Hosts may retain arguments, so never expose reusable VM stack storage.
			var args []Value
			if i.arg > 0 {
				if e := charge(&w.budget, i.arg*valueSize); e != nil {
					return problem(i.line, "%v", e)
				}
				args = append(args, w.stack[start:w.sp]...)
			}
			if e := host.Action(i.name, args); e != nil {
				return problem(i.line, "%s: %v", i.name, e)
			}
			w.sp = start
			continue
		case jump:
			pc = i.target
			continue
		case branch:
			taken := w.pop().AsBool()
			if trace {
				r.Trace = append(r.Trace, TraceStep{Line: i.line, Taken: taken, Handler: h.id})
			}
			if !taken {
				pc = i.target
			}
			continue
		case andThen, orElse:
			truth := w.stack[w.sp-1].AsBool()
			if i.op == andThen && !truth || i.op == orElse && truth {
				pc = i.target
			} else {
				w.pop()
			}
			continue
		case iterate:
			idx := w.locals[i.arg+1].n
			seq := w.locals[i.arg].a
			if idx >= int64(len(seq)) {
				pc = i.target
			} else {
				w.set(i.arg+2, seq[idx])
			}
			continue
		case advance:
			w.locals[i.arg].n++
			pc = i.target
			continue
		case deny:
			r.Dropped = true
			return nil
		}
		if err == nil {
			err = w.push(v)
		}
		if err != nil {
			return problem(i.line, "%v", err)
		}
	}
	return nil
}
