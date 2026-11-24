// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

//! Ahead-of-time lowering from verified RCR1 to target-independent LLVM IR.
//! Operand and local slots have constant addresses. LLVM promotes these to SSA
//! and inserts phi nodes at joins. Faults and budget checks are observable.

use super::{Op, Program, values::Value, wire};
use std::fmt::Write;

pub fn compile(image: &[u8], index: usize) -> Result<String, &'static str> {
    let program = wire::decode(image).ok_or("invalid typed handler image")?;
    let depths = program.stack_depths().ok_or("invalid control-flow graph")?;
    let scalar = numeric(&program);
    let mut ir = String::from(
        "declare void @rc_aot_finish(ptr, i32, i32, i32)\ndeclare i1 @rc_aot_read_scalar(ptr, i32, ptr)\ndeclare i1 @rc_aot_write_scalar(ptr, i32, i64)\n",
    );
    for name in ["sadd", "ssub", "smul"] {
        writeln!(
            ir,
            "declare {{ i64, i1 }} @llvm.{name}.with.overflow.i64(i64, i64)"
        )
        .unwrap();
    }
    for name in [
        "literal", "read", "write", "load", "store", "array", "builtin", "binary", "unary",
        "lookup", "discard", "branch", "and", "or", "iterate", "advance",
    ] {
        writeln!(ir, "declare i32 @rc_aot_{name}(ptr, i32, i32)").unwrap();
    }
    writeln!(ir,"define void @rc_policy_{index}(ptr %ctx, i32 %limit) {{\nentry:\n %counter = alloca i32\n store i32 0, ptr %counter").unwrap();
    if scalar {
        for i in 0..depths.iter().flatten().max().copied().unwrap_or(0) {
            writeln!(ir, " %s{i} = alloca i64").unwrap();
        }
        for i in 0..program.locals {
            writeln!(ir, " %l{i} = alloca i64").unwrap();
        }
        // The host writes field results here only after a checked read.
        writeln!(ir, " %readback = alloca i64").unwrap();
    }
    ir.push_str(" br label %p0\n");
    for (pc, op) in program.ops.iter().enumerate() {
        let Some(depth) = depths[pc] else { continue };
        writeln!(ir,"p{pc}:\n %old{pc} = load i32, ptr %counter\n %n{pc} = add nuw i32 %old{pc}, 1\n store i32 %n{pc}, ptr %counter\n %over{pc} = icmp ugt i32 %n{pc}, %limit\n br i1 %over{pc}, label %budget{pc}, label %body{pc}\nbudget{pc}:").unwrap();
        finish(&mut ir, 5, pc);
        writeln!(ir, "body{pc}:").unwrap();
        match op {
            Op::Jump(to) => jump(&mut ir, *to),
            Op::Count => jump(&mut ir, pc + 1),
            Op::Deny => finish(&mut ir, 1, pc),
            _ if scalar => lower_scalar(&mut ir, op, pc, depth),
            _ => lower_managed(&mut ir, op, pc),
        }
    }
    let end = program.ops.len();
    writeln!(ir, "p{end}:\n %n{end} = load i32, ptr %counter").unwrap();
    finish(&mut ir, 0, end);
    ir.push_str("}\n");
    Ok(ir)
}

fn numeric(p: &Program) -> bool {
    p.fields.iter().all(|f| matches!(f.kind, 1 | 2))
        && p.ops.iter().all(|op| match op {
            Op::Binary(name) => name.as_ref() != "in",
            Op::Literal(Value::Bool(_) | Value::Int(_))
            | Op::Read(_)
            | Op::Write(_)
            | Op::Load(_)
            | Op::Store(_)
            | Op::Unary(_)
            | Op::Count
            | Op::Discard
            | Op::Jump(_)
            | Op::Branch(_)
            | Op::And(_)
            | Op::Or(_)
            | Op::Deny => true,
            _ => false,
        })
}

fn jump(ir: &mut String, to: usize) {
    writeln!(ir, " br label %p{to}").unwrap();
}
fn finish(ir: &mut String, status: u8, pc: usize) {
    writeln!(
        ir,
        " call void @rc_aot_finish(ptr %ctx, i32 {status}, i32 {pc}, i32 %n{pc})\n ret void"
    )
    .unwrap();
}
fn guard(ir: &mut String, good: &str, pc: usize, status: u8) {
    writeln!(
        ir,
        " br i1 %{good}{pc}, label %ok{pc}, label %fault{pc}\nfault{pc}:"
    )
    .unwrap();
    finish(ir, status, pc);
    writeln!(ir, "ok{pc}:").unwrap();
}
fn lower_scalar(ir: &mut String, op: &Op, pc: usize, depth: usize) {
    let top = depth.saturating_sub(1);
    match op {
        Op::Literal(v) => {
            let n=match v {Value::Bool(b)=>i64::from(*b),Value::Int(n)=>*n,_=>unreachable!()};
            writeln!(ir," store i64 {n}, ptr %s{depth}").unwrap();
        }
        Op::Read(i) => {
            writeln!(ir," %ok_read{pc} = call i1 @rc_aot_read_scalar(ptr %ctx, i32 {i}, ptr %readback)").unwrap();
            guard(ir,"ok_read",pc,2);
            writeln!(ir," %v{pc} = load i64, ptr %readback\n store i64 %v{pc}, ptr %s{depth}").unwrap();
        }
        Op::Write(i) => {
            writeln!(ir," %v{pc} = load i64, ptr %s{top}\n %ok_write{pc} = call i1 @rc_aot_write_scalar(ptr %ctx, i32 {i}, i64 %v{pc})").unwrap();
            guard(ir,"ok_write",pc,3);
        }
        Op::Load(i)=>writeln!(ir," %v{pc} = load i64, ptr %l{i}\n store i64 %v{pc}, ptr %s{depth}").unwrap(),
        Op::Store(i)=>writeln!(ir," %v{pc} = load i64, ptr %s{top}\n store i64 %v{pc}, ptr %l{i}").unwrap(),
        Op::Branch(to) | Op::And(to) | Op::Or(to) => {
            let test=if matches!(op,Op::Or(_)) {"ne"} else {"eq"};
            writeln!(ir," %v{pc} = load i64, ptr %s{top}\n %take{pc} = icmp {test} i64 %v{pc}, 0\n br i1 %take{pc}, label %p{to}, label %p{}",pc+1).unwrap();
            return;
        }
        Op::Unary(true)=>writeln!(ir," %a{pc} = load i64, ptr %s{top}\n %v{pc} = xor i64 %a{pc}, 1\n store i64 %v{pc}, ptr %s{top}").unwrap(),
        Op::Unary(false)=>{
            writeln!(ir," %b{pc} = load i64, ptr %s{top}").unwrap();
            checked(ir,"ssub",pc,"0",&format!("%b{pc}"));
            writeln!(ir," store i64 %v{pc}, ptr %s{top}").unwrap();
        }
        Op::Binary(name)=>{
            let lhs=depth-2;
            writeln!(ir," %a{pc} = load i64, ptr %s{lhs}\n %b{pc} = load i64, ptr %s{top}").unwrap();
            match name.as_ref() {
                "+"|"-"|"*"=>{
                    let intrinsic=match name.as_ref() {"+"=>"sadd","-"=>"ssub",_=>"smul"};
                    checked(ir,intrinsic,pc,&format!("%a{pc}"),&format!("%b{pc}"));
                }
                "/"|"%"=> {
                    writeln!(ir," %nz{pc} = icmp ne i64 %b{pc}, 0\n %min{pc} = icmp eq i64 %a{pc}, -9223372036854775808\n %neg{pc} = icmp eq i64 %b{pc}, -1\n %overflow{pc} = and i1 %min{pc}, %neg{pc}\n %fits{pc} = xor i1 %overflow{pc}, true\n %valid{pc} = and i1 %nz{pc}, %fits{pc}").unwrap();
                    guard(ir,"valid",pc,7);
                    let op=if name.as_ref()=="/" {"sdiv"} else {"srem"};
                    writeln!(ir," %v{pc} = {op} i64 %a{pc}, %b{pc}").unwrap();
                }
                comparison=>{
                    let pred=match comparison {"=="=>"eq","!="=>"ne","<"=>"slt",">"=>"sgt","<="=>"sle",">="=>"sge",_=>unreachable!()};
                    writeln!(ir," %cmp{pc} = icmp {pred} i64 %a{pc}, %b{pc}\n %v{pc} = zext i1 %cmp{pc} to i64").unwrap();
                }
            }
            writeln!(ir," store i64 %v{pc}, ptr %s{lhs}").unwrap();
        }
        Op::Discard=>(),
        _=>unreachable!(),
    }
    jump(ir, pc + 1);
}
fn checked(ir: &mut String, intrinsic: &str, pc: usize, a: &str, b: &str) {
    writeln!(ir," %pair{pc} = call {{i64, i1}} @llvm.{intrinsic}.with.overflow.i64(i64 {a}, i64 {b})\n %overflow{pc} = extractvalue {{i64, i1}} %pair{pc}, 1\n %valid{pc} = xor i1 %overflow{pc}, true").unwrap();
    guard(ir, "valid", pc, 7);
    writeln!(ir, " %v{pc} = extractvalue {{i64, i1}} %pair{pc}, 0").unwrap();
}
fn lower_managed(ir: &mut String, op: &Op, pc: usize) {
    let (name, alternate) = match op {
        Op::Literal(_) => ("literal", None),
        Op::Read(_) => ("read", None),
        Op::Write(_) => ("write", None),
        Op::Load(_) => ("load", None),
        Op::Store(_) => ("store", None),
        Op::Array(..) => ("array", None),
        Op::Builtin(..) => ("builtin", None),
        Op::Binary(_) => ("binary", None),
        Op::Unary(_) => ("unary", None),
        Op::Match { missing, .. } => ("lookup", Some(*missing)),
        Op::Discard => ("discard", None),
        Op::Branch(to) => ("branch", Some(*to)),
        Op::And(to) => ("and", Some(*to)),
        Op::Or(to) => ("or", Some(*to)),
        Op::Iterate(_, to) => ("iterate", Some(*to)),
        Op::Advance(..) => ("advance", None),
        _ => unreachable!(),
    };
    writeln!(ir," %next{pc} = call i32 @rc_aot_{name}(ptr %ctx, i32 {pc}, i32 %n{pc})\n %failed{pc} = icmp slt i32 %next{pc}, 0\n br i1 %failed{pc}, label %exit{pc}, label %continue{pc}\nexit{pc}:\n ret void\ncontinue{pc}:").unwrap();
    if let Some(to) = alternate {
        writeln!(
            ir,
            " %take{pc} = icmp eq i32 %next{pc}, {to}\n br i1 %take{pc}, label %p{to}, label %p{}",
            pc + 1
        )
        .unwrap();
    } else if let Op::Advance(_, to) = op {
        jump(ir, *to);
    } else {
        jump(ir, pc + 1);
    }
}
