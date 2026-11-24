// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

mod ssa;

use super::{MAX_FIELDS, RCField, RCFrame, RCInstruction, RCResult};

const STACK: usize = 64;
const LOCALS: usize = 128;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Type {
    Int,
    Bool,
}
#[derive(Clone, Copy)]
enum Edit {
    ReadOnly,
    Dscp,
    Mss,
    DnsRd,
}
#[derive(Clone, Copy)]
struct Field {
    slot: u8,
    ty: Type,
    edit: Edit,
}

impl Field {
    fn new(slot: usize, f: &RCField) -> Option<Self> {
        use {Edit::*, Type::*};
        let (ty, edit) = match (f.kind, f.write) {
            (1, 0) => (Int, ReadOnly),
            (2, 0) => (Bool, ReadOnly),
            (1, 1) => (Int, Dscp),
            (1, 2) => (Int, Mss),
            (2, 3) => (Bool, DnsRd),
            _ => return None,
        };
        Some(Self {
            slot: slot as u8,
            ty,
            edit,
        })
    }
    fn read(self, frame: &RCFrame) -> Option<i64> {
        let value = frame.values[self.slot as usize];
        if frame.present & (1 << self.slot) == 0
            || self.ty == Type::Bool && value != 0 && value != 1
        {
            None
        } else {
            Some(value)
        }
    }
    fn write(self, frame: &mut RCFrame, value: i64) -> Option<()> {
        match self.edit {
            Edit::Dscp if (0..=63).contains(&value) => (),
            Edit::Mss if value >= 536 && value <= self.read(frame)? => (),
            Edit::DnsRd if value == 0 || value == 1 => (),
            _ => return None,
        }
        frame.values[self.slot as usize] = value;
        frame.written |= 1 << self.slot;
        // The raw packet host exposes dns.rd only for a parsed question. A
        // staged DNS edit does not create an observation where none existed.
        if matches!(self.edit, Edit::Dscp) {
            frame.present |= 1 << self.slot;
        }
        Some(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Binary {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}
impl Binary {
    fn can_fault(self) -> bool {
        matches!(
            self,
            Self::Add | Self::Sub | Self::Mul | Self::Div | Self::Mod
        )
    }
    fn apply(self, a: i64, b: i64) -> Option<i64> {
        use Binary::*;
        Some(match self {
            Eq => (a == b) as i64,
            Ne => (a != b) as i64,
            Lt => (a < b) as i64,
            Le => (a <= b) as i64,
            Gt => (a > b) as i64,
            Ge => (a >= b) as i64,
            Add => a.checked_add(b)?,
            Sub => a.checked_sub(b)?,
            Mul => a.checked_mul(b)?,
            Div => a.checked_div(b)?,
            Mod => a.checked_rem(b)?,
        })
    }
}
#[derive(Clone, Copy)]
enum Op {
    Const(i64, Type),
    Read(Field),
    Write(Field),
    Load(u8),
    Store(u8),
    Binary(Binary),
    Neg,
    Not,
    Jump(usize),
    BranchFalse(usize),
    AndThen(usize),
    OrElse(usize),
    Drop,
    Count,
    Discard,
}
fn decode(i: RCInstruction, pc: usize, end: usize, fields: &[Field]) -> Option<Op> {
    use Op::*;
    let arg = i.arg as usize;
    let target = || (arg > pc && arg <= end).then_some(arg);
    let slot = || (arg < LOCALS).then_some(arg as u8);
    Some(match i.op {
        1 => Const(i.imm, Type::Int),
        2 if matches!(i.imm, 0 | 1) => Const(i.imm, Type::Bool),
        3 => Read(*fields.get(arg)?),
        4 => {
            let f = *fields.get(arg)?;
            if matches!(f.edit, Edit::ReadOnly) {
                return None;
            }
            Write(f)
        }
        5 => Load(slot()?),
        6 => Store(slot()?),
        7 => Binary(self::Binary::Eq),
        8 => Binary(self::Binary::Ne),
        9 => Binary(self::Binary::Lt),
        10 => Binary(self::Binary::Le),
        11 => Binary(self::Binary::Gt),
        12 => Binary(self::Binary::Ge),
        13 => Binary(self::Binary::Add),
        14 => Binary(self::Binary::Sub),
        15 => Binary(self::Binary::Mul),
        16 => Binary(self::Binary::Div),
        17 => Binary(self::Binary::Mod),
        18 => Neg,
        19 => Not,
        20 => Jump(target()?),
        21 => BranchFalse(target()?),
        22 => AndThen(target()?),
        23 => OrElse(target()?),
        24 => Drop,
        25 => Count,
        26 => Discard,
        _ => return None,
    })
}

// A bit per slot suffices for integer/boolean types. Propagate initialized
// locals by intersection, so a read after a join is valid on every path.
#[derive(Default, Clone, Copy)]
struct Shape {
    depth: u8,
    bools: u64,
    initialized: u128,
    bool_locals: u128,
}
impl Shape {
    fn push(&mut self, ty: Type) -> Option<()> {
        if self.depth as usize == STACK {
            return None;
        }
        if ty == Type::Bool {
            self.bools |= 1 << self.depth;
        }
        self.depth += 1;
        Some(())
    }
    fn pop(&mut self) -> Option<Type> {
        self.depth = self.depth.checked_sub(1)?;
        let bit = 1 << self.depth;
        let ty = if self.bools & bit != 0 {
            Type::Bool
        } else {
            Type::Int
        };
        self.bools &= !bit;
        Some(ty)
    }
    fn require(&mut self, ty: Type) -> Option<()> {
        (self.pop()? == ty).then_some(())
    }
    fn join(self, dest: &mut Option<Self>) -> Option<()> {
        if let Some(old) = dest {
            if old.depth != self.depth || old.bools != self.bools {
                return None;
            }
            old.initialized &= self.initialized & !(old.bool_locals ^ self.bool_locals);
            old.bool_locals &= old.initialized;
        } else {
            *dest = Some(self);
        }
        Some(())
    }
}
fn validate(code: &[Op]) -> Option<()> {
    let mut states = vec![None; code.len() + 1];
    states[0] = Some(Shape::default());
    for (pc, &op) in code.iter().enumerate() {
        let Some(mut shape) = states[pc].take() else {
            continue;
        };
        match op {
            Op::Const(_, ty) => shape.push(ty)?,
            Op::Read(f) => shape.push(f.ty)?,
            Op::Write(f) => shape.require(f.ty)?,
            Op::Load(slot) => {
                let bit = 1u128 << slot;
                if shape.initialized & bit == 0 {
                    return None;
                }
                shape.push(if shape.bool_locals & bit != 0 {
                    Type::Bool
                } else {
                    Type::Int
                })?;
            }
            Op::Store(slot) => {
                let bit = 1u128 << slot;
                if shape.pop()? == Type::Bool {
                    shape.bool_locals |= bit;
                } else {
                    shape.bool_locals &= !bit;
                }
                shape.initialized |= bit;
            }
            Op::Binary(binary) => {
                let rhs = shape.pop()?;
                shape.require(rhs)?;
                let ty = match binary {
                    Binary::Eq | Binary::Ne => Type::Bool,
                    _ if rhs != Type::Int => return None,
                    Binary::Lt | Binary::Le | Binary::Gt | Binary::Ge => Type::Bool,
                    _ => Type::Int,
                };
                shape.push(ty)?;
            }
            Op::Neg => {
                shape.require(Type::Int)?;
                shape.push(Type::Int)?;
            }
            Op::Not => {
                shape.require(Type::Bool)?;
                shape.push(Type::Bool)?;
            }
            Op::Jump(target) => {
                shape.join(&mut states[target])?;
                continue;
            }
            Op::BranchFalse(target) => {
                shape.require(Type::Bool)?;
                shape.join(&mut states[target])?;
            }
            Op::AndThen(target) | Op::OrElse(target) => {
                shape.join(&mut states[target])?;
                shape.require(Type::Bool)?;
            }
            Op::Drop => continue,
            Op::Count => (),
            Op::Discard => {
                shape.pop()?;
            }
        }
        shape.join(&mut states[pc + 1])?;
    }
    if states[code.len()].is_some_and(|s| s.depth != 0) {
        None
    } else {
        Some(())
    }
}

// Hard-coded machine-code kernels are selected once by a verified instruction
// pattern. A short budget uses the general evaluator to preserve the fault PC.
struct ConditionalEdit {
    input: Field,
    expected: i64,
    output: Field,
    value: i64,
}
pub(super) struct Plan {
    code: Box<[Op]>,
    conditional: Option<ConditionalEdit>,
    graph: Option<ssa::Graph>,
}
impl Plan {
    pub(super) fn new(raw: &[RCInstruction], descriptors: &[RCField]) -> Option<Self> {
        if descriptors.len() > MAX_FIELDS || raw.len() > super::MAX_INSTRUCTIONS {
            return None;
        }
        let fields: Vec<_> = descriptors
            .iter()
            .enumerate()
            .map(|(n, f)| Field::new(n, f))
            .collect::<Option<_>>()?;
        let code: Box<[_]> = raw
            .iter()
            .enumerate()
            .map(|(pc, &i)| decode(i, pc, raw.len(), &fields))
            .collect::<Option<_>>()?;
        validate(&code)?;
        let body = code.as_ref();
        let body = if matches!(body.last(), Some(Op::Count)) {
            &body[..body.len() - 1]
        } else {
            body
        };
        let conditional = match *body {
            [
                Op::Read(input),
                Op::Const(expected, _),
                Op::Binary(Binary::Eq),
                Op::BranchFalse(end),
                Op::Const(value, _),
                Op::Write(output),
            ] if end == code.len() => Some(ConditionalEdit {
                input,
                expected,
                output,
                value,
            }),
            _ => None,
        };
        let graph = if conditional.is_none() {
            ssa::Graph::compile(&code)
        } else {
            None
        };
        Some(Self {
            code,
            conditional,
            graph,
        })
    }
    pub(super) fn eval(&self, frame: &mut RCFrame, budget: u32) -> RCResult {
        if let Some(k) = &self.conditional {
            let end = self.code.len();
            if budget as usize >= end {
                return match k.input.read(frame) {
                    None => result(MISSING, 0, 1),
                    Some(v) if v != k.expected => result(OK, end, 4),
                    Some(_) if k.output.write(frame, k.value).is_none() => result(BAD_WRITE, 5, 6),
                    _ => result(OK, end, end as u32),
                };
            }
        }
        if budget as usize >= self.code.len() {
            if let Some(graph) = &self.graph {
                return graph.eval(frame);
            }
        }
        self.eval_ops(frame, budget)
    }
    fn eval_ops(&self, frame: &mut RCFrame, budget: u32) -> RCResult {
        let mut stack = [0i64; STACK];
        let mut locals = [0i64; LOCALS];
        let (mut sp, mut pc, mut count) = (0, 0, 0u32);
        while let Some(&op) = self.code.get(pc) {
            count += 1;
            if count > budget {
                return result(BUDGET, pc, count);
            }
            match op {
                Op::Const(v, _) => {
                    stack[sp] = v;
                    sp += 1;
                }
                Op::Read(f) => {
                    let Some(v) = f.read(frame) else {
                        return result(MISSING, pc, count);
                    };
                    stack[sp] = v;
                    sp += 1;
                }
                Op::Write(f) => {
                    sp -= 1;
                    if f.write(frame, stack[sp]).is_none() {
                        return result(BAD_WRITE, pc, count);
                    }
                }
                Op::Load(i) => {
                    stack[sp] = locals[i as usize];
                    sp += 1;
                }
                Op::Store(i) => {
                    sp -= 1;
                    locals[i as usize] = stack[sp];
                }
                Op::Binary(binary) => {
                    sp -= 1;
                    let Some(v) = binary.apply(stack[sp - 1], stack[sp]) else {
                        return result(BOUNDS, pc, count);
                    };
                    stack[sp - 1] = v;
                }
                Op::Neg => {
                    let Some(v) = stack[sp - 1].checked_neg() else {
                        return result(BOUNDS, pc, count);
                    };
                    stack[sp - 1] = v;
                }
                Op::Not => stack[sp - 1] = (stack[sp - 1] == 0) as i64,
                Op::Jump(target) => {
                    pc = target;
                    continue;
                }
                Op::BranchFalse(target) => {
                    sp -= 1;
                    if stack[sp] == 0 {
                        pc = target;
                        continue;
                    }
                }
                Op::AndThen(target) => {
                    if stack[sp - 1] == 0 {
                        pc = target;
                        continue;
                    }
                    sp -= 1;
                }
                Op::OrElse(target) => {
                    if stack[sp - 1] != 0 {
                        pc = target;
                        continue;
                    }
                    sp -= 1;
                }
                Op::Count => (),
                Op::Drop => return result(DROPPED, pc, count),
                Op::Discard => sp -= 1,
            }
            pc += 1;
        }
        result(OK, pc, count)
    }
}
const OK: u32 = 0;
const DROPPED: u32 = 1;
const MISSING: u32 = 2;
const BAD_WRITE: u32 = 3;
const BOUNDS: u32 = 4;
const BUDGET: u32 = 5;
fn result(status: u32, pc: usize, instructions: u32) -> RCResult {
    RCResult {
        status,
        pc: pc as u32,
        instructions,
    }
}

#[cfg(test)]
mod tests;
