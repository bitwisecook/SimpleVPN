// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

use super::*;
use std::net::IpAddr;

fn word(out: &mut Vec<u8>, v: usize) {
    out.extend((v as u32).to_le_bytes());
}
fn text(out: &mut Vec<u8>, s: &str) {
    word(out, s.len());
    out.extend(s.bytes());
}
fn int(n: i64) -> Vec<u8> {
    let mut b = vec![2];
    b.extend(n.to_le_bytes());
    b
}
fn addr(ip: &str) -> Vec<u8> {
    let mut b = vec![5];
    match ip.parse::<IpAddr>().unwrap() {
        IpAddr::V4(a) => {
            b.push(4);
            b.extend(a.octets());
        }
        IpAddr::V6(a) => {
            b.push(6);
            b.extend(a.octets());
        }
    };
    b
}
fn constant(v: &[u8]) -> Vec<u8> {
    let mut op = ins(0, 0, 0, 0, 0, "");
    op.extend(v);
    op
}
fn ins(op: u8, arg: usize, to: usize, aux: usize, kind: u8, name: &str) -> Vec<u8> {
    let mut bytes = vec![op];
    word(&mut bytes, arg);
    word(&mut bytes, to);
    word(&mut bytes, aux);
    bytes.push(kind);
    text(&mut bytes, name);
    bytes
}
fn simple(op: u8, arg: usize) -> Vec<u8> {
    ins(op, arg, 0, 0, 0, "")
}
fn table(key: u8, val: u8, entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![key, val];
    word(&mut out, entries.len());
    for (k, v) in entries {
        out.extend(k);
        out.extend(v);
    }
    out
}
fn encode(fields: &[(u8, u8)], tables: &[Vec<u8>], ops: &[Vec<u8>]) -> Vec<u8> {
    let mut out = b"RCR1".to_vec();
    word(&mut out, fields.len());
    for &(a, b) in fields {
        out.extend([a, b]);
    }
    word(&mut out, tables.len());
    for t in tables {
        out.extend(t);
    }
    word(&mut out, ops.len());
    for op in ops {
        out.extend(op);
    }
    out
}
struct Owned(*mut RCRichPlan);
impl Owned {
    fn new(bytes: &[u8]) -> Self {
        let p = unsafe { rc_rich_new(bytes.as_ptr(), bytes.len() as u32) };
        assert!(!p.is_null());
        Self(p)
    }
    fn eval(
        &self,
        bytes: &[u8],
        ins: u32,
        byte_limit: u32,
    ) -> (u32, u32, u32, u32, String, RCFrame) {
        let mut edits = RCFrame::default();
        let r = unsafe {
            rc_rich_eval(
                self.0,
                bytes.as_ptr(),
                bytes.len() as u32,
                &mut edits,
                ins,
                byte_limit,
            )
        };
        let msg = if !r.message.is_null() {
            let b = unsafe { std::slice::from_raw_parts(r.message, r.message_len as usize) };
            let m = std::str::from_utf8(b).unwrap().to_owned();
            unsafe { rc_rich_message_free(r.message, r.message_len) };
            m
        } else {
            String::new()
        };
        (
            r.status,
            r.pc,
            r.instructions,
            r.remaining_bytes,
            msg,
            edits,
        )
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        unsafe { rc_rich_free(self.0) }
    }
}

#[test]
fn longest_prefix_lookup_distinguishes_present_zero_and_miss() {
    let prefix = |ip: &str, bits: u8| {
        let mut b = addr(ip);
        b[0] = 6;
        b.push(bits);
        b
    };
    let table = table(
        6,
        2,
        &[
            (prefix("10.0.0.0", 8), int(13)),
            (prefix("10.0.1.0", 24), int(0)),
            (prefix("2001:db8::", 32), int(42)),
            (prefix("2001:db8:3::", 48), int(0)),
        ],
    );
    let p = Owned::new(&encode(
        &[(5, 0), (2, 1)],
        &[table],
        &[
            simple(1, 0),
            ins(9, 127, 5, 0, 0, ""),
            simple(3, 127),
            simple(2, 1),
            ins(12, 0, 6, 0, 0, ""),
            simple(18, 0),
        ],
    ));
    for (ip, want) in [
        ("10.0.1.7", Some(0)),
        ("10.8.0.1", Some(13)),
        ("192.0.2.1", None),
        ("2001:db8:3::1", Some(0)),
        ("2001:db8:4::1", Some(42)),
        ("::1", None),
    ] {
        let mut fields = addr(ip);
        fields.push(0);
        let (state, _, count, _, _, edits) = p.eval(&fields, 8192, 131072);
        match want {
            Some(v) => {
                assert_eq!((state, count, edits.written, edits.values[1]), (0, 5, 2, v));
            }
            None => assert_eq!((state, count, edits.written), (1, 3, 0)),
        }
    }
}
#[test]
fn iterator_uses_shared_instruction_and_byte_budgets() {
    // Build [1,2], then add both items to a typed local.
    let mut p = vec![
        constant(&int(1)),
        constant(&int(2)),
        ins(5, 2, 0, 0, 130, ""),
        simple(4, 125),
        constant(&int(0)),
        simple(4, 126),
        constant(&int(0)),
        simple(4, 3),
        ins(16, 125, 14, 0, 0, ""),
        simple(3, 3),
        simple(3, 127),
        ins(7, 0, 0, 0, 0, "+"),
        simple(4, 3),
        ins(17, 126, 8, 0, 0, ""),
        simple(3, 3),
        simple(2, 0),
    ];
    let wire = encode(&[(2, 1)], &[], &p);
    let plan = Owned::new(&wire);
    let (s, pc, n, remain, _, effect) = plan.eval(&[0], 8192, 256);
    assert_eq!(
        (s, pc, n, remain, effect.values[0], effect.written),
        (0, 16, 23, 0, 3, 1)
    );
    let (s, pc, n, _, _, e) = plan.eval(&[0], 8, 256);
    assert_eq!((s, pc, n, e.written), (5, 8, 9, 0));
    let (s, pc, n, remain, msg, e) = plan.eval(&[0], 8192, 255);
    assert_eq!((s, pc, n, remain, e.written), (7, 2, 3, 255, 0));
    assert_eq!(msg, "byte processing budget exceeded");
    p.push(ins(17, 0, 3, 0, 0, ""));
    assert!(wire::decode(&encode(&[(2, 1)], &[], &p)).is_none());
}
#[test]
fn staged_edits_abort_on_missing_or_invalid_evidence() {
    let p = Owned::new(&encode(
        &[(2, 1), (4, 0)],
        &[],
        &[
            constant(&int(23)),
            simple(2, 0),
            simple(1, 1),
            ins(6, 1, 0, 0, 0, "len"),
            simple(2, 0),
        ],
    ));
    let (s, pc, n, _, _, edits) = p.eval(&[0, 0], 8192, 100);
    assert_eq!((s, pc, n, edits.written), (2, 2, 3, 0));
    let mut snapshot = vec![0, 4];
    text(&mut snapshot, "host.test");
    let (s, _, n, rem, _, edits) = p.eval(&snapshot, 8192, 100);
    assert_eq!(
        (s, n, rem, edits.values[0], edits.written),
        (0, 5, 91, 9, 1)
    );
}
#[test]
fn plan_and_snapshot_reject_malformed_records_without_partial_work() {
    let code = encode(&[(2, 1)], &[], &[constant(&int(1)), simple(2, 0)]);
    for end in 0..code.len() {
        assert!(wire::decode(&code[..end]).is_none());
    }
    let p = Owned::new(&code);
    for input in [
        vec![],
        vec![0, 0],
        vec![2, 1, 2],
        vec![4, 255, 255, 255, 255],
    ] {
        let (s, _, n, _, _, edits) = p.eval(&input, 8192, 131072);
        assert_eq!((s, n, edits.written), (6, 0, 0));
    }
    let bad_join = encode(
        &[],
        &[],
        &[
            constant(&[1, 1]),
            ins(13, 0, 3, 0, 0, ""),
            constant(&int(3)),
            simple(11, 0),
        ],
    );
    assert!(wire::decode(&bad_join).is_none());
    let duplicate = table(2, 2, &[(int(3), int(1)), (int(3), int(2))]);
    assert!(wire::decode(&encode(&[], &[duplicate], &[])).is_none());
}

#[test]
fn cidr_edit_kernel_matches_full_vm_with_and_without_count() {
    for with_count in [false, true] {
        for value in [0, 63, 64] {
            let mut prefix = addr("192.0.2.0");
            prefix[0] = 6;
            prefix.push(24);
            let n = if with_count { 7 } else { 6 };
            let mut ops = vec![
                simple(1, 0),
                constant(&prefix),
                ins(7, 0, 0, 0, 0, "in"),
                ins(13, 0, n, 0, 0, ""),
                constant(&int(value)),
                simple(2, 1),
            ];
            if with_count {
                ops.push(ins(10, 0, 0, 0, 0, "count"));
            }
            let code = encode(&[(5, 0), (2, 1)], &[], &ops);
            let fast = Owned::new(&code);
            let reference = Owned::new(&code);
            // Unique handles are not used concurrently in this fixture.
            unsafe {
                assert!((*reference.0).prefix_edit.take().is_some());
            }
            for ip in [vec![0], addr("::1"), addr("192.0.2.5"), addr("192.0.3.0")] {
                let mut input = ip;
                input.push(0);
                for budget in 0..=9 {
                    let (a, pc, i, bytes, msg, out) = fast.eval(&input, budget, 300);
                    let (b, pc2, j, remain, m, out2) = reference.eval(&input, budget, 300);
                    assert_eq!(
                        (a, pc, i, bytes, msg, out.written, out.values),
                        (b, pc2, j, remain, m, out2.written, out2.values)
                    );
                }
            }
        }
    }
}

#[test]
fn signed_llvm_policies_match_checked_evaluation_at_every_budget() {
    let cases: &[(&[u8], Vec<Vec<u8>>)] = &[
        (
            include_bytes!("../../policies/mail.rcr"),
            vec![vec![0], int(22), int(25)],
        ),
        (
            include_bytes!("../../policies/office.rcr"),
            vec![
                vec![0, 0],
                [addr("10.42.2.7"), int(3)].concat(),
                [addr("10.17.2.3"), vec![0]].concat(),
                [addr("2001:db8::1"), int(0)].concat(),
            ],
        ),
        (
            include_bytes!("../../policies/dscp.rcr"),
            vec![
                vec![0],
                int(1),
                int(32),
                int(48),
                int(i64::MAX),
                int(i64::MIN),
            ],
        ),
    ];
    for (image, frames) in cases {
        let compiled = Owned::new(image);
        let reference = Owned::new(image);
        assert!(unsafe { (*compiled.0).native.is_some() });
        unsafe {
            (*reference.0).reference = true;
            (*reference.0).native = None;
            (*reference.0).prefix_edit = None;
        }
        for frame in frames {
            for limit in 0..80 {
                for bytes in [0, 256, 131072] {
                    let (s, p, n, b, m, e) = compiled.eval(frame, limit, bytes);
                    let (rs, rp, rn, rb, rm, re) = reference.eval(frame, limit, bytes);
                    assert_eq!(
                        (s, p, n, b, m, e.written, e.values),
                        (rs, rp, rn, rb, rm, re.written, re.values),
                        "limit {limit}, bytes {bytes}, input {frame:?}"
                    );
                }
            }
        }
    }
}
