// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

use super::*;
use crate::{rc_eval, rc_plan_free, rc_plan_new};
use std::ptr;

fn op(op: u32, arg: u32) -> RCInstruction {
    RCInstruction { op, arg, imm: 0 }
}
fn int(imm: i64) -> RCInstruction {
    RCInstruction { op: 1, arg: 0, imm }
}
fn boolean(v: bool) -> RCInstruction {
    RCInstruction {
        op: 2,
        arg: 0,
        imm: v as i64,
    }
}
const NUMBER: RCField = RCField { kind: 1, write: 0 };
const FLAG: RCField = RCField { kind: 2, write: 0 };
const DSCP: RCField = RCField { kind: 1, write: 1 };
const MSS: RCField = RCField { kind: 1, write: 2 };
const RD: RCField = RCField { kind: 2, write: 3 };
fn frame(values: &[i64], present: u32) -> RCFrame {
    let mut frame = RCFrame {
        present,
        ..Default::default()
    };
    frame.values[..values.len()].copy_from_slice(values);
    frame
}

#[test]
fn conditional_kernel_preserves_fault_and_budget_locations() {
    for salt in [0, 1, 63, 64, -1, i64::MAX] {
        let plan = Plan::new(
            &[op(3, 0), int(443), op(7, 0), op(21, 6), int(salt), op(4, 1)],
            &[NUMBER, DSCP],
        )
        .unwrap();
        assert!(plan.conditional.is_some());
        for budget in 0..10 {
            for present in 0..4 {
                for port in [0, 443] {
                    let mut fast = frame(&[port, 0], present);
                    let mut reference = fast.clone();
                    let r = plan.eval(&mut fast, budget);
                    assert_eq!(r, plan.eval_ops(&mut reference, budget));
                    assert_eq!(fast.values, reference.values);
                    assert_eq!(fast.written, reference.written);
                    let attempted = if present & 1 == 0 {
                        1
                    } else if port == 443 {
                        6
                    } else {
                        4
                    };
                    assert_eq!(r.instructions, attempted.min(budget + 1));
                    if budget < attempted {
                        assert_eq!(r, result(BUDGET, budget as usize, budget + 1));
                    } else if present & 1 == 0 {
                        assert_eq!(r, result(MISSING, 0, 1));
                    } else if port == 443 && !(0..=63).contains(&salt) {
                        assert_eq!(r, result(BAD_WRITE, 5, 6));
                    } else {
                        assert_eq!(r.status, OK);
                        assert_eq!(fast.written, if port == 443 { 2 } else { 0 });
                    }
                }
            }
        }
    }
}

#[test]
fn short_circuit_never_reads_unreached_fields() {
    for (opcode, short) in [(22, false), (23, true)] {
        let plan = Plan::new(
            &[op(3, 0), op(opcode, 3), op(3, 1), op(21, 5), op(24, 0)],
            &[FLAG, FLAG],
        )
        .unwrap();
        let mut f = frame(&[short as i64, 0], 1);
        let r = plan.eval(&mut f, 8192);
        assert_eq!(
            r,
            if short {
                result(DROPPED, 4, 4)
            } else {
                result(OK, 5, 3)
            }
        );
        f.values[0] = (!short) as i64;
        assert_eq!(plan.eval(&mut f, 8192), result(MISSING, 2, 3));
        f.values[0] = 2;
        assert_eq!(plan.eval(&mut f, 8192), result(MISSING, 0, 1));
    }
}
#[test]
fn staged_edits_and_independent_presence() {
    let code = [
        int(1200),
        op(4, 0),
        op(3, 0),
        int(1200),
        op(7, 0),
        op(21, 11),
        boolean(false),
        op(4, 1),
        op(3, 1),
        op(19, 0),
        op(26, 0),
    ];
    let plan = Plan::new(&code, &[MSS, RD]).unwrap();
    let mut f = frame(&[1452, 1], 3);
    assert_eq!(plan.eval(&mut f, 8192), result(OK, 11, 11));
    assert_eq!(f.written, 3);
    assert_eq!(&f.values[..2], &[1200, 0]);
    let mut missing = frame(&[0, 1], 2);
    assert_eq!(plan.eval(&mut missing, 8192), result(BAD_WRITE, 1, 2));
    let mut missing_dns = frame(&[1452, 0], 1);
    assert_eq!(plan.eval(&mut missing_dns, 8192), result(MISSING, 8, 9));
    for second in [1201, 535, -1] {
        let plan = Plan::new(&[int(1200), op(4, 0), int(second), op(4, 0)], &[MSS]).unwrap();
        let mut f = frame(&[1460], 1);
        assert_eq!(plan.eval(&mut f, 8192), result(BAD_WRITE, 3, 4));
    }
}

#[test]
fn arithmetic_matches_signed_checked_semantics() {
    for (kind, a, b, expected) in [
        (13, 20, 2, Some(22)),
        (14, 20, 2, Some(18)),
        (15, 20, 2, Some(40)),
        (16, 21, 2, Some(10)),
        (17, -21, 2, Some(-1)),
        (13, i64::MAX, 1, None),
        (14, i64::MIN, 1, None),
        (15, i64::MAX, 2, None),
        (16, i64::MIN, -1, None),
        (17, i64::MIN, -1, None),
        (16, 21, 0, None),
        (17, 21, 0, None),
    ] {
        let code = [
            int(a),
            int(b),
            op(kind, 0),
            op(6, 127),
            op(5, 127),
            int(expected.unwrap_or(0)),
            op(7, 0),
            op(21, 9),
            op(24, 0),
        ];
        let p = Plan::new(&code, &[]).unwrap();
        let r = p.eval(&mut RCFrame::default(), 8192);
        assert_eq!(
            r,
            if expected.is_some() {
                result(DROPPED, 8, 9)
            } else {
                result(BOUNDS, 2, 3)
            }
        );
    }
    let p = Plan::new(&[int(i64::MIN), op(18, 0), op(26, 0)], &[]).unwrap();
    assert_eq!(p.eval(&mut RCFrame::default(), 2), result(BOUNDS, 1, 2));
}

#[test]
fn verifier_rejects_malformed_and_unsupported_bytecode() {
    let mut invalid = vec![
        vec![op(99, 0)],
        vec![int(2)],
        vec![op(26, 0)],
        vec![op(20, 0)],
        vec![op(20, 2)],
        vec![op(5, 1), op(26, 0)],
        vec![int(1), op(6, 128)],
        vec![op(3, 32), op(26, 0)],
        vec![boolean(true), op(4, 0)],
        vec![int(1), op(4, 1)],
        vec![int(1), op(4, 2)],
        vec![
            boolean(true),
            op(21, 4),
            int(1),
            op(20, 5),
            boolean(false),
            op(26, 0),
        ],
        vec![
            boolean(true),
            op(21, 4),
            int(1),
            op(6, 0),
            op(5, 0),
            op(26, 0),
        ],
        vec![
            boolean(true),
            op(21, 2),
            int(1),
            boolean(false),
            op(7, 0),
            op(26, 0),
        ],
        vec![
            RCInstruction {
                op: 2,
                arg: 0,
                imm: 7,
            },
            op(26, 0),
        ],
    ];
    let mut deep = vec![int(0); STACK + 1];
    deep.extend(vec![op(26, 0); STACK + 1]);
    invalid.push(deep);
    for code in invalid {
        assert!(Plan::new(&code, &[DSCP, RD, NUMBER]).is_none());
    }
    for field in [
        RCField { kind: 0, write: 0 },
        RCField { kind: 1, write: 3 },
        RCField { kind: 2, write: 2 },
    ] {
        assert!(Plan::new(&[], &[field]).is_none());
    }
    assert!(Plan::new(&vec![op(25, 0); 8193], &[]).is_none());
    assert!(Plan::new(&[], &[NUMBER; 33]).is_none());
}

#[test]
fn evaluator_abi_copies_plan_and_checks_null_lengths_and_budget() {
    unsafe {
        assert!(rc_plan_new(ptr::null(), 1, ptr::null(), 0).is_null());
        assert!(rc_plan_new(ptr::null(), 0, ptr::null(), 1).is_null());
        assert!(rc_plan_new(ptr::null(), 0, ptr::null(), 33).is_null());
        let mut source = [op(25, 0), op(24, 0)];
        let p = rc_plan_new(source.as_ptr(), 2, ptr::null(), 0);
        assert!(!p.is_null());
        source.fill(op(0, 0));
        let mut f = RCFrame::default();
        assert_eq!(rc_eval(p, &mut f, 1), result(BUDGET, 1, 2));
        assert_eq!(rc_eval(p, &mut f, 2), result(DROPPED, 1, 2));
        assert_eq!(rc_eval(p, &mut f, 8193), result(6, 0, 0));
        assert_eq!(rc_eval(p, ptr::null_mut(), 8192), result(6, 0, 0));
        rc_plan_free(p);
        let empty = rc_plan_new(ptr::null(), 0, ptr::null(), 0);
        assert_eq!(rc_eval(empty, &mut f, 0), result(OK, 0, 0));
        rc_plan_free(empty);
    }
}

#[test]
fn kernel_with_count_preserves_instruction_counts() {
    let plan = Plan::new(
        &[
            op(3, 0),
            int(443),
            op(7, 0),
            op(21, 7),
            int(42),
            op(4, 1),
            op(25, 0),
        ],
        &[NUMBER, DSCP],
    )
    .unwrap();
    assert!(plan.conditional.is_some());
    for p in [443, 80] {
        for budget in 0..=9 {
            let mut f = frame(&[p, 0], 3);
            let mut reference = f.clone();
            let r = plan.eval(&mut f, budget);
            assert_eq!(r, plan.eval_ops(&mut reference, budget));
            assert_eq!(f.written, reference.written);
        }
    }
}

#[test]
fn ssa_phi_edges_faults_and_folded_branches_match_source_execution() {
    // Local 0 has two definitions at a join. A checked operation feeding an
    // unused comparison still traps. A constant false guard skips a missing field.
    let programs = [
        vec![
            op(3, 0),
            op(21, 5),
            int(7),
            op(6, 0),
            op(20, 7),
            int(13),
            op(6, 0),
            op(5, 0),
            op(4, 2),
            boolean(false),
            op(22, 12),
            op(3, 3),
            op(26, 0),
        ],
        vec![
            op(3, 1),
            op(6, 0),
            op(5, 0),
            int(1),
            op(13, 0),
            op(6, 1),
            op(5, 0),
            int(1),
            op(13, 0),
            op(5, 1),
            op(7, 0),
            op(26, 0),
        ],
    ];
    for code in programs {
        let p = Plan::new(&code, &[FLAG, NUMBER, DSCP, FLAG]).unwrap();
        assert!(p.graph.is_some());
        for present in 0..8 {
            for x in [0, 1, i64::MAX] {
                for flag in [0, 1] {
                    for budget in [0, 3, 8, 13, 8192] {
                        let mut actual = frame(&[flag, x, 0], present);
                        let mut expected = actual.clone();
                        let a = p.eval(&mut actual, budget);
                        let b = p.eval_ops(&mut expected, budget);
                        assert_eq!(a, b);
                        assert_eq!(
                            (actual.written, actual.values),
                            (expected.written, expected.values)
                        );
                    }
                }
            }
        }
    }
}
