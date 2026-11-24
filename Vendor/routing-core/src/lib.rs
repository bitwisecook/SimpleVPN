// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

mod compact;
mod dns;
mod flow_log;
mod mediation;
mod rich;
mod scalar;
pub mod syntax;
use routing_ir::values;

use scalar::Plan;
use std::ptr;
use std::slice;

const MAX_FIELDS: usize = 32;
const MAX_INSTRUCTIONS: usize = 8192;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RCInstruction {
    op: u32,
    arg: u32,
    imm: i64,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RCField {
    kind: u32,
    write: u32,
}
#[repr(C)]
#[derive(Clone, Default)]
pub struct RCFrame {
    values: [i64; MAX_FIELDS],
    present: u32,
    written: u32,
}
#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub struct RCResult {
    status: u32,
    pc: u32,
    instructions: u32,
}

pub struct RCPlan(Plan);

// All array lengths are bounded before a slice is formed.
unsafe fn input<'a, T>(ptr: *const T, n: u32, limit: usize) -> Option<&'a [T]> {
    if n == 0 {
        return Some(&[]);
    }
    if n as usize > limit || ptr.is_null() || (ptr as usize) % std::mem::align_of::<T>() != 0 {
        return None;
    }
    // SAFETY: the C caller supplies n initialized elements for this call.
    Some(unsafe { slice::from_raw_parts(ptr, n as usize) })
}

/// # Safety
/// Each nonempty array must designate the indicated number of readable entries.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_plan_new(
    code: *const RCInstruction,
    n: u32,
    fields: *const RCField,
    field_count: u32,
) -> *mut RCPlan {
    let (Some(code), Some(fields)) = (unsafe { input(code, n, MAX_INSTRUCTIONS) }, unsafe {
        input(fields, field_count, MAX_FIELDS)
    }) else {
        return ptr::null_mut();
    };
    Plan::new(code, fields).map_or(ptr::null_mut(), |p| Box::into_raw(Box::new(RCPlan(p))))
}

/// # Safety
/// The handle must come from rc_plan_new, have no active users and be freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_plan_free(plan: *mut RCPlan) {
    if !plan.is_null() {
        drop(unsafe { Box::from_raw(plan) });
    }
}

/// # Safety
/// The caller holds the plan alive and grants exclusive access to a valid frame.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_eval(
    plan: *const RCPlan,
    frame: *mut RCFrame,
    remaining: u32,
) -> RCResult {
    if plan.is_null() || frame.is_null() || remaining as usize > MAX_INSTRUCTIONS {
        return RCResult {
            status: 6,
            pc: 0,
            instructions: 0,
        };
    }
    unsafe { (&*plan).0.eval(&mut *frame, remaining) }
}

#[repr(C)]
pub struct RCCompilerOutput {
    status: u32,
    length: u32,
    bytes: *mut u8,
}

/// Emit LLVM IR for one verified image. The caller owns the result on success.
/// # Safety
/// The image must be readable for n bytes for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_compile_llvm(image: *const u8, n: u32) -> RCCompilerOutput {
    let invalid = RCCompilerOutput {
        status: 1,
        length: 0,
        bytes: ptr::null_mut(),
    };
    let Some(image) = (unsafe { input(image, n, 16 << 20) }) else {
        return invalid;
    };
    let Ok(ir) = routing_ir::llvm::compile(image, 0) else {
        return invalid;
    };
    let bytes = ir.into_bytes().into_boxed_slice();
    RCCompilerOutput {
        status: 0,
        length: bytes.len() as u32,
        bytes: Box::into_raw(bytes).cast::<u8>(),
    }
}

/// # Safety
/// Pass the unmodified successful result from rc_compile_llvm exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_compiler_output_free(output: RCCompilerOutput) {
    if !output.bytes.is_null() {
        let region = ptr::slice_from_raw_parts_mut(output.bytes, output.length as usize);
        drop(unsafe { Box::from_raw(region) });
    }
}
