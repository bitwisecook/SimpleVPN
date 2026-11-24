// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

mod native;
use crate::RCFrame;
use crate::values::{Value, binary, builtin, charge};
use routing_ir::{Field, Op, Program, wire};
use std::cell::RefCell;

use std::ptr;

use wire::Reader;

// Most-specific tables still use the general interpreter. A single constant
// CIDR guard followed by a DSCP edit needs only one address comparison.
struct PrefixEdit {
    input: usize,
    net: std::net::IpAddr,
    width: u8,
    output: usize,
    value: i64,
}
impl PrefixEdit {
    fn select(ops: &[Op], fields: &[Field]) -> Option<Self> {
        let body = if matches!(ops.last(), Some(Op::Count)) {
            &ops[..ops.len() - 1]
        } else {
            ops
        };
        match body {
            [
                Op::Read(input),
                Op::Literal(Value::Prefix(net, width)),
                Op::Binary(op),
                Op::Branch(end),
                Op::Literal(Value::Int(value)),
                Op::Write(output),
            ] if *end == ops.len()
                && op.as_ref() == "in"
                && fields[*input].kind == 5
                && fields[*output].edit == 1 =>
            {
                Some(Self {
                    input: *input,
                    net: *net,
                    width: *width,
                    output: *output,
                    value: *value,
                })
            }
            _ => None,
        }
    }
    fn run(
        &self,
        fields: &[Option<Value>],
        edits: &mut RCFrame,
        end: usize,
        bytes: usize,
    ) -> RCRichResult {
        let Some(Value::Addr(ip)) = fields[self.input].as_ref() else {
            return RCRichResult::new(2, 0, 1, bytes);
        };
        if !crate::values::prefix_contains(self.net, self.width, *ip) {
            return RCRichResult::new(0, end, 4, bytes);
        }
        if !(0..=63).contains(&self.value) {
            return RCRichResult::new(3, 5, 6, bytes);
        }
        edits.values[self.output] = self.value;
        edits.written |= 1 << self.output;
        RCRichResult::new(0, end, end as u32, bytes)
    }
}

pub struct RCRichPlan {
    prefix_edit: Option<PrefixEdit>,
    program: Program,
    native: Option<native::Kernel>,
    threaded: native::Threaded,
    #[cfg(test)]
    reference: bool,
}
impl std::ops::Deref for RCRichPlan {
    type Target = Program;
    fn deref(&self) -> &Program {
        &self.program
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct RCRichResult {
    status: u32,
    pc: u32,
    instructions: u32,
    remaining_bytes: u32,
    message: *mut u8,
    message_len: u32,
}
impl RCRichResult {
    fn new(status: u32, pc: usize, instructions: u32, remaining: usize) -> Self {
        Self {
            status,
            pc: pc as u32,
            instructions,
            remaining_bytes: remaining as u32,
            message: ptr::null_mut(),
            message_len: 0,
        }
    }
    fn error(e: Fault, pc: usize, executed: u32, remaining: usize) -> Self {
        match e {
            Fault::Status(s) => Self::new(s, pc, executed, remaining),
            Fault::Message(text) => {
                let mut r = Self::new(7, pc, executed, remaining);
                if !text.is_empty() {
                    let bytes = text.into_bytes().into_boxed_slice();
                    r.message_len = bytes.len() as u32;
                    r.message = Box::into_raw(bytes) as *mut u8;
                }
                r
            }
        }
    }
}
enum Fault {
    Status(u32),
    Message(String),
}
impl From<String> for Fault {
    fn from(text: String) -> Self {
        Self::Message(text)
    }
}
const INVALID: Fault = Fault::Status(6);

#[derive(Default)]
struct Workspace {
    fields: Vec<Option<Value>>,
    stack: Vec<Value>,
    locals: Vec<Option<Value>>,
}
thread_local! {static WORK:RefCell<Workspace>=RefCell::new(Workspace::default());}
impl Workspace {
    fn clear(&mut self) {
        self.fields.clear();
        self.stack.clear();
        self.locals.clear();
    }
    fn run(
        &mut self,
        plan: &RCRichPlan,
        snapshot: &[u8],
        edits: &mut RCFrame,
        limit: u32,
        bytes: usize,
    ) -> RCRichResult {
        let mut r = Reader::new(snapshot);
        for f in &plan.fields {
            let value = match r.byte() {
                Some(0) => None,
                Some(k) if f.kind == k => match r.value(k) {
                    Some(v) => Some(v),
                    None => return RCRichResult::new(6, 0, 0, bytes),
                },
                _ => return RCRichResult::new(6, 0, 0, bytes),
            };
            self.fields.push(value);
        }
        if !r.done() {
            return RCRichResult::new(6, 0, 0, bytes);
        }
        if let Some(kernel) = plan.native {
            self.locals.resize(plan.locals, None);
            return native::run(kernel, self, plan, edits, limit, bytes);
        }
        if let Some(kernel) = &plan.prefix_edit {
            if limit as usize >= plan.ops.len() {
                return kernel.run(&self.fields, edits, plan.ops.len(), bytes);
            }
        }
        self.locals.resize(plan.locals, None);
        #[cfg(test)]
        if plan.reference {
            return self.reference(plan, edits, limit, bytes);
        }
        plan.threaded.eval(self, plan, edits, limit, bytes)
    }
    #[cfg(test)]
    fn reference(
        &mut self,
        plan: &RCRichPlan,
        edits: &mut RCFrame,
        limit: u32,
        mut bytes: usize,
    ) -> RCRichResult {
        let mut executed = 0;
        let mut pc = 0;
        while let Some(op) = plan.ops.get(pc) {
            executed += 1;
            if executed > limit {
                return RCRichResult::new(5, pc, executed, bytes);
            }
            match self.step(op, pc, plan, edits, &mut bytes) {
                Ok(Some(next)) => pc = next,
                Ok(None) => return RCRichResult::new(1, pc, executed, bytes),
                Err(e) => return RCRichResult::error(e, pc, executed, bytes),
            }
        }
        RCRichResult::new(0, pc, executed, bytes)
    }
    fn write(
        &mut self,
        plan: &RCRichPlan,
        slot: usize,
        v: Value,
        edits: &mut RCFrame,
    ) -> Result<(), Fault> {
        let current = &mut self.fields[slot];
        let bits = match (&v, plan.fields[slot].edit) {
            (Value::Int(n), 1) if (0..=63).contains(n) => *n,
            (Value::Int(n), 2)
                if *n >= 536 && matches!(current,Some(Value::Int(before)) if n<=before) =>
            {
                *n
            }
            (Value::Bool(b), 3) => *b as i64,
            (Value::Bool(true), 4) => 1,
            _ => return Err(Fault::Status(3)),
        };
        // A DNS write alone cannot create a parsed DNS question.
        if plan.fields[slot].edit != 3 || current.is_some() {
            *current = Some(v);
        }
        edits.values[slot] = bits;
        edits.written |= 1 << slot;
        Ok(())
    }

    #[inline(always)]
    fn step(
        &mut self,
        op: &Op,
        pc: usize,
        plan: &RCRichPlan,
        edits: &mut RCFrame,
        budget: &mut usize,
    ) -> Result<Option<usize>, Fault> {
        let mut next = pc + 1;
        let stack = &mut self.stack;
        match op {
            Op::Literal(v) => stack.push(v.clone()),
            Op::Read(f) => {
                let v = self.fields[*f].as_ref().ok_or(Fault::Status(2))?;
                charge(budget, v.text_len())?;
                stack.push(v.clone());
            }
            Op::Write(slot) => {
                let v = stack.pop().ok_or(INVALID)?;
                self.write(plan, *slot, v, edits)?;
            }
            Op::Load(slot) => stack.push(self.locals[*slot].clone().ok_or(INVALID)?),
            Op::Store(slot) => self.locals[*slot] = Some(stack.pop().ok_or(INVALID)?),
            Op::Array(kind, n) => {
                let start = stack.len().checked_sub(*n).ok_or(INVALID)?;
                if stack[start..].iter().any(|v| v.kind() != *kind) {
                    return Err(INVALID);
                }
                charge(budget, n * 128)?;
                let items = stack[start..].into();
                stack.truncate(start);
                stack.push(Value::Array(*kind, items));
            }
            Op::Builtin(name, n) => {
                let start = stack.len().checked_sub(*n).ok_or(INVALID)?;
                let result = builtin(name, &stack[start..], budget)?;
                stack.truncate(start);
                stack.push(result);
            }
            Op::Binary(name) => {
                let rhs = stack.pop().ok_or(INVALID)?;
                let lhs = stack.last_mut().ok_or(INVALID)?;
                *lhs = binary(name, lhs, &rhs, budget)?;
            }
            Op::Unary(not) => {
                let v = stack.last_mut().ok_or(INVALID)?;
                *v =
                    match (not, &*v) {
                        (true, Value::Bool(b)) => Value::Bool(!b),
                        (false, Value::Int(n)) => Value::Int(n.checked_neg().ok_or_else(|| {
                            Fault::Message("value outside supported bounds".into())
                        })?),
                        _ => return Err(INVALID),
                    };
            }
            Op::Match {
                table,
                slot,
                missing,
            } => {
                let key = stack.pop().ok_or(INVALID)?;
                charge(budget, key.text_len())?;
                if let Some(v) = plan.tables[*table].lookup(&key) {
                    self.locals[*slot] = Some(v.clone());
                } else {
                    next = *missing;
                }
            }
            Op::Count => (),
            Op::Discard => {
                stack.pop().ok_or(INVALID)?;
            }
            Op::Jump(to) => next = *to,
            Op::Branch(to) => match stack.pop() {
                Some(Value::Bool(false)) => next = *to,
                Some(Value::Bool(true)) => (),
                _ => return Err(INVALID),
            },
            Op::And(to) | Op::Or(to) => {
                let Some(Value::Bool(b)) = stack.last() else {
                    return Err(INVALID);
                };
                if *b == matches!(op, Op::Or(_)) {
                    next = *to;
                } else {
                    stack.pop();
                }
            }
            Op::Iterate(slot, end) => {
                let Some(Value::Int(i)) = self.locals[*slot + 1].as_ref() else {
                    return Err(INVALID);
                };
                let Some(Value::Array(_, items)) = self.locals[*slot].as_ref() else {
                    return Err(INVALID);
                };
                let idx = usize::try_from(*i).map_err(|_| INVALID)?;
                if let Some(v) = items.get(idx) {
                    self.locals[*slot + 2] = Some(v.clone());
                } else {
                    next = *end;
                }
            }
            Op::Advance(slot, to) => {
                let Some(Value::Int(i)) = self.locals[*slot].as_mut() else {
                    return Err(INVALID);
                };
                *i = i.checked_add(1).ok_or(INVALID)?;
                next = *to;
            }
            Op::Deny => return Ok(None),
        }
        Ok(Some(next))
    }
}

/// # Safety
/// A nonempty image must designate n readable bytes for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_rich_is_precompiled(image: *const u8, n: u32) -> bool {
    unsafe { crate::input(image, n, 16 << 20) }.is_some_and(|image| native::select(image).is_some())
}

/// # Safety
/// A nonempty buffer must identify n readable bytes for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_rich_new(plan: *const u8, n: u32) -> *mut RCRichPlan {
    let Some(bytes) = (unsafe { crate::input(plan, n, 16 << 20) }) else {
        return ptr::null_mut();
    };
    wire::decode(bytes).map_or(ptr::null_mut(), |program| {
        Box::into_raw(Box::new(RCRichPlan {
            prefix_edit: PrefixEdit::select(&program.ops, &program.fields),
            native: native::select(bytes),
            threaded: native::Threaded::compile(&program.ops),
            #[cfg(test)]
            reference: false,
            program,
        }))
    })
}
/// # Safety
/// The caller owns this handle and has finished all concurrent evaluations.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_rich_free(plan: *mut RCRichPlan) {
    if !plan.is_null() {
        drop(unsafe { Box::from_raw(plan) });
    }
}
/// # Safety
/// Plan must remain live, edits must be exclusively writable, and snapshot must
/// have n readable bytes. Any returned message belongs to the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_rich_eval(
    plan: *const RCRichPlan,
    snapshot: *const u8,
    n: u32,
    edits: *mut RCFrame,
    ins: u32,
    bytes: u32,
) -> RCRichResult {
    let bad = || RCRichResult::new(6, 0, 0, bytes as usize);
    if plan.is_null() || edits.is_null() || ins > 8192 || bytes > 131072 {
        return bad();
    }
    let Some(snapshot) = (unsafe { crate::input(snapshot, n, 4 << 20) }) else {
        return bad();
    };
    let plan = unsafe { &*plan };
    let edits = unsafe { &mut *edits };
    edits.written = 0;
    WORK.with(|cell| {
        let mut work = cell.borrow_mut();
        let result = work.run(plan, snapshot, edits, ins, bytes as usize);
        if result.status != 0 {
            edits.written = 0;
        }
        work.clear();
        result
    })
}
/// # Safety
/// Free exactly one returned message with its matching reported length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_rich_message_free(message: *mut u8, len: u32) {
    if !message.is_null() {
        let slice = ptr::slice_from_raw_parts_mut(message, len as usize);
        drop(unsafe { Box::from_raw(slice) });
    }
}

#[cfg(test)]
mod tests;
