// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

use super::{Field, Op, Table};

const BOOL: u8 = 1;
const INT: u8 = 2;
const TEXT: u8 = 3;
const DNS: u8 = 4;
const ADDR: u8 = 5;
const PREFIX: u8 = 6;
const BYTES: u8 = 7;

fn builtin_type(name: &str, args: &[u8]) -> Option<u8> {
    Some(match (name, args) {
        ("addr", [TEXT]) => ADDR,
        ("prefix", [TEXT]) => PREFIX,
        ("dns", [TEXT]) => DNS,
        ("bytes", [TEXT]) => BYTES,
        ("mask", [ADDR, INT]) => PREFIX,
        ("range", [INT, INT]) => 128 | INT,
        ("byte" | "u16be" | "at", [BYTES, INT]) => INT,
        ("slice", [BYTES, INT, INT])
        | ("replace", [BYTES, INT, INT, BYTES])
        | ("write_u16be", [BYTES, INT, INT]) => BYTES,
        ("string", [1..=7]) => TEXT,
        ("int", [INT | TEXT | BOOL]) => INT,
        ("len", [DNS | TEXT | BYTES | 129..=135]) => INT,
        ("at", [a @ 129..=135, INT]) => a & 127,
        ("lower", [DNS | TEXT]) => TEXT,
        ("contains" | "starts_with" | "ends_with", [DNS | TEXT, DNS | TEXT]) => BOOL,
        _ => return None,
    })
}
fn binary_type(name: &str, a: u8, b: u8) -> Option<u8> {
    Some(match name {
        "in" if (a == ADDR && b == PREFIX) || a < 128 && b == (a | 128) => BOOL,
        "==" | "!=" if a == b && a < 128 => BOOL,
        "<" | ">" | "<=" | ">=" if a == b && matches!(a, INT | DNS | TEXT) => BOOL,
        "+" if a == TEXT && b == TEXT => TEXT,
        "+" | "-" | "*" | "/" | "%" if a == INT && b == INT => INT,
        _ => return None,
    })
}

// Every reachable instruction receives one operand-stack shape. A local is
// available only when all incoming paths agree on its initialized type. Loop
// backedges can only erase knowledge at a join, so propagation reaches a fixpoint.
#[derive(Clone, Copy)]
pub(super) struct State {
    stack: [u8; 64],
    pub(super) depth: usize,
    locals: [u8; 128],
}
impl State {
    fn new() -> Self {
        Self {
            stack: [0; 64],
            depth: 0,
            locals: [0; 128],
        }
    }
    fn push(&mut self, kind: u8) -> Option<()> {
        if kind == 0 || self.depth >= 64 {
            return None;
        }
        self.stack[self.depth] = kind;
        self.depth += 1;
        Some(())
    }
    fn pop(&mut self) -> Option<u8> {
        self.depth = self.depth.checked_sub(1)?;
        Some(self.stack[self.depth])
    }
    fn expect(&mut self, kind: u8) -> Option<()> {
        (self.pop()? == kind).then_some(())
    }
    fn send(self, pc: usize, states: &mut [Option<State>], queue: &mut Vec<usize>) -> Option<()> {
        if let Some(old) = &mut states[pc] {
            if old.stack[..old.depth] != self.stack[..self.depth] {
                return None;
            }
            let mut changed = false;
            for (old, new) in old.locals.iter_mut().zip(self.locals) {
                if *old != 0 && *old != new {
                    *old = 0;
                    changed = true;
                }
            }
            if changed {
                queue.push(pc);
            }
        } else {
            states[pc] = Some(self);
            queue.push(pc);
        }
        Some(())
    }
}

pub(super) fn states(ops: &[Op], fields: &[Field], tables: &[Table]) -> Option<Vec<Option<State>>> {
    let mut queue = vec![0usize];
    let mut states = vec![None; ops.len() + 1];
    states[0] = Some(State::new());
    while let Some(pc) = queue.pop() {
        let mut s = states[pc]?;
        if pc == ops.len() {
            if s.depth != 0 {
                return None;
            }
            continue;
        }
        match &ops[pc] {
            Op::Literal(v) => s.push(v.kind())?,
            Op::Read(i) => s.push(fields[*i].kind)?,
            Op::Write(i) => s.expect(fields[*i].kind)?,
            Op::Store(i) => s.locals[*i] = s.pop()?,
            Op::Load(i) => s.push(s.locals[*i])?,
            Op::Array(kind, n) => {
                for _ in 0..*n {
                    s.expect(*kind)?;
                }
                s.push(128 | kind)?;
            }
            Op::Builtin(name, n) => {
                let begin = s.depth.checked_sub(*n)?;
                let kind = builtin_type(name, &s.stack[begin..s.depth])?;
                s.depth = begin;
                s.push(kind)?;
            }
            Op::Binary(name) => {
                let b = s.pop()?;
                let a = s.pop()?;
                s.push(binary_type(name, a, b)?)?;
            }
            Op::Unary(not) => {
                let ty = if *not { BOOL } else { INT };
                s.expect(ty)?;
                s.push(ty)?;
            }
            Op::Match {
                table,
                slot,
                missing,
            } => {
                let table = &tables[*table];
                let key = s.pop()?;
                if key != table.key && !(key == ADDR && table.key == PREFIX) {
                    return None;
                }
                s.send(*missing, &mut states, &mut queue)?;
                s.locals[*slot] = table.element;
            }
            Op::Count => (),
            Op::Discard => {
                s.pop()?;
            }
            Op::Jump(target) => {
                s.send(*target, &mut states, &mut queue)?;
                continue;
            }
            Op::Branch(target) => {
                s.expect(BOOL)?;
                s.send(*target, &mut states, &mut queue)?;
            }
            Op::And(target) | Op::Or(target) => {
                s.send(*target, &mut states, &mut queue)?;
                s.expect(BOOL)?;
            }
            Op::Iterate(slot, end) => {
                let kind = s.locals[*slot];
                if !(129..=135).contains(&kind) || s.locals[*slot + 1] != INT {
                    return None;
                }
                s.send(*end, &mut states, &mut queue)?;
                s.locals[*slot + 2] = kind & 127;
            }
            Op::Advance(slot, target) => {
                if s.locals[*slot] != INT {
                    return None;
                }
                s.send(*target, &mut states, &mut queue)?;
                continue;
            }
            Op::Deny => continue,
        }
        s.send(pc + 1, &mut states, &mut queue)?;
    }
    Some(states)
}
