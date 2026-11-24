// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

use super::*;
use std::ffi::c_void;

pub(super) type Kernel = unsafe extern "C" fn(*mut c_void, u32);
include!(concat!(env!("OUT_DIR"), "/policy_registry.rs"));

struct Context<'a> {
    work: &'a mut Workspace,
    plan: &'a RCRichPlan,
    edits: &'a mut RCFrame,
    bytes: usize,
    result: Option<RCRichResult>,
}

pub(super) fn run(
    kernel: Kernel,
    work: &mut Workspace,
    plan: &RCRichPlan,
    edits: &mut RCFrame,
    limit: u32,
    bytes: usize,
) -> RCRichResult {
    let mut ctx = Context {
        work,
        plan,
        edits,
        bytes,
        result: None,
    };
    // The registry selected this signed function by the entire verified image.
    unsafe { kernel((&raw mut ctx).cast(), limit) };
    ctx.result
        .unwrap_or_else(|| RCRichResult::new(6, 0, 0, ctx.bytes))
}

#[unsafe(no_mangle)]
unsafe extern "C" fn rc_aot_finish(ptr: *mut c_void, status: u32, pc: u32, count: u32) {
    let c = unsafe { &mut *ptr.cast::<Context<'_>>() };
    c.result = Some(if status == 7 {
        RCRichResult::error(
            Fault::Message("value outside supported bounds".into()),
            pc as usize,
            count,
            c.bytes,
        )
    } else {
        RCRichResult::new(status, pc as usize, count, c.bytes)
    });
}

#[unsafe(no_mangle)]
unsafe extern "C" fn rc_aot_read_scalar(ptr: *mut c_void, slot: u32, out: *mut i64) -> bool {
    let c = unsafe { &mut *ptr.cast::<Context<'_>>() };
    let v = match c.work.fields.get(slot as usize).and_then(Option::as_ref) {
        Some(Value::Int(n)) => *n,
        Some(Value::Bool(b)) => i64::from(*b),
        _ => return false,
    };
    unsafe { out.write(v) };
    true
}
#[unsafe(no_mangle)]
unsafe extern "C" fn rc_aot_write_scalar(ptr: *mut c_void, slot: u32, bits: i64) -> bool {
    let c = unsafe { &mut *ptr.cast::<Context<'_>>() };
    let slot = slot as usize;
    let value = match c.plan.fields[slot].kind {
        2 => Value::Int(bits),
        1 if matches!(bits, 0 | 1) => Value::Bool(bits != 0),
        _ => return false,
    };
    c.work.write(c.plan, slot, value, c.edits).is_ok()
}

// Unboxed numeric policies lower directly to LLVM registers. Operations on
// managed values use their checked Rust primitive. Each symbol has a fixed
// operation, so a compiled block never dispatches on a packet-supplied opcode.
macro_rules! primitive {
    ($name:ident, $pattern:pat) => {
        #[unsafe(no_mangle)]
        unsafe extern "C" fn $name(ptr: *mut c_void, pc: u32, count: u32) -> i32 {
            let c = unsafe { &mut *ptr.cast::<Context<'_>>() };
            let pc = pc as usize;
            let next = match c.plan.ops.get(pc) {
                Some(op @ $pattern) => c.work.step(op, pc, c.plan, c.edits, &mut c.bytes),
                _ => Err(INVALID),
            };
            match next {
                Ok(Some(to)) => to as i32,
                Ok(None) => {
                    c.result = Some(RCRichResult::new(1, pc, count, c.bytes));
                    -1
                }
                Err(e) => {
                    c.result = Some(RCRichResult::error(e, pc, count, c.bytes));
                    -1
                }
            }
        }
    };
}
primitive!(rc_aot_literal, Op::Literal(_));
primitive!(rc_aot_read, Op::Read(_));
primitive!(rc_aot_write, Op::Write(_));
primitive!(rc_aot_load, Op::Load(_));
primitive!(rc_aot_store, Op::Store(_));
primitive!(rc_aot_array, Op::Array(_, _));
primitive!(rc_aot_builtin, Op::Builtin(_, _));
primitive!(rc_aot_binary, Op::Binary(_));
primitive!(rc_aot_unary, Op::Unary(_));
primitive!(rc_aot_lookup, Op::Match { .. });
primitive!(rc_aot_discard, Op::Discard);
primitive!(rc_aot_branch, Op::Branch(_));
primitive!(rc_aot_and, Op::And(_));
primitive!(rc_aot_or, Op::Or(_));
primitive!(rc_aot_iterate, Op::Iterate(_, _));
primitive!(rc_aot_advance, Op::Advance(_, _));

type Primitive = unsafe extern "C" fn(*mut c_void, u32, u32) -> i32;
pub(super) struct Threaded(Box<[Primitive]>);
impl Threaded {
    /// Bind the verified operation to a signed implementation at activation.
    /// A user edit needs no writable executable memory in the system extension.
    pub(super) fn compile(ops: &[Op]) -> Self {
        let code = ops
            .iter()
            .map(|op| -> Primitive {
                match op {
                    Op::Literal(_) => rc_aot_literal,
                    Op::Read(_) => rc_aot_read,
                    Op::Write(_) => rc_aot_write,
                    Op::Load(_) => rc_aot_load,
                    Op::Store(_) => rc_aot_store,
                    Op::Array(..) => rc_aot_array,
                    Op::Builtin(..) => rc_aot_builtin,
                    Op::Binary(_) => rc_aot_binary,
                    Op::Unary(_) => rc_aot_unary,
                    Op::Match { .. } => rc_aot_lookup,
                    Op::Count => rc_aot_count,
                    Op::Discard => rc_aot_discard,
                    Op::Jump(_) => rc_aot_jump,
                    Op::Branch(_) => rc_aot_branch,
                    Op::And(_) => rc_aot_and,
                    Op::Or(_) => rc_aot_or,
                    Op::Iterate(..) => rc_aot_iterate,
                    Op::Advance(..) => rc_aot_advance,
                    Op::Deny => rc_aot_deny,
                }
            })
            .collect();
        Self(code)
    }
    pub(super) fn eval(
        &self,
        work: &mut Workspace,
        plan: &RCRichPlan,
        edits: &mut RCFrame,
        limit: u32,
        bytes: usize,
    ) -> RCRichResult {
        let mut ctx = Context {
            work,
            plan,
            edits,
            bytes,
            result: None,
        };
        let mut pc = 0;
        let mut count = 0;
        while let Some(primitive) = self.0.get(pc) {
            count += 1;
            if count > limit {
                return RCRichResult::new(5, pc, count, ctx.bytes);
            }
            // Targets are fixed Rust function addresses selected from the verified image.
            let next = unsafe { primitive((&raw mut ctx).cast(), pc as u32, count) };
            if next < 0 {
                return ctx
                    .result
                    .unwrap_or_else(|| RCRichResult::new(6, pc, count, ctx.bytes));
            }
            pc = next as usize;
        }
        RCRichResult::new(0, pc, count, ctx.bytes)
    }
}
primitive!(rc_aot_jump, Op::Jump(_));
primitive!(rc_aot_count, Op::Count);
primitive!(rc_aot_deny, Op::Deny);
