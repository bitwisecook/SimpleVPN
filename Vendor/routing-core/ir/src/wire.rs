// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

use super::*;
use crate::values::Blob;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

pub struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let value = self.0.get(..n)?;
        self.0 = &self.0[n..];
        Some(value)
    }
    pub fn byte(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn word(&mut self) -> Option<usize> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?) as usize)
    }
    fn bytes(&mut self, limit: usize) -> Option<&'a [u8]> {
        let n = self.word()?;
        if n > limit {
            return None;
        }
        self.take(n)
    }
    fn text(&mut self, limit: usize) -> Option<&'a str> {
        std::str::from_utf8(self.bytes(limit)?).ok()
    }
    pub fn done(&self) -> bool {
        self.0.is_empty()
    }
    fn addr(&mut self) -> Option<IpAddr> {
        match self.byte()? {
            4 => Some(Ipv4Addr::from(<[u8; 4]>::try_from(self.take(4)?).ok()?).into()),
            6 => Some(Ipv6Addr::from(<[u8; 16]>::try_from(self.take(16)?).ok()?).into()),
            _ => None,
        }
    }
    pub fn value(&mut self, kind: u8) -> Option<Value> {
        let v = match kind {
            1 => Value::Bool(match self.byte()? {
                0 => false,
                1 => true,
                _ => return None,
            }),
            2 => Value::Int(i64::from_le_bytes(self.take(8)?.try_into().ok()?)),
            3 => Value::Text(Arc::from(self.text(4096)?)),
            4 => Value::Dns(Arc::from(self.text(253)?)),
            5 => Value::Addr(self.addr()?),
            6 => Value::Prefix(self.addr()?, self.byte()?),
            7 => Value::Bytes(Blob::from(self.bytes(65535)?.to_vec())),
            129..=135 => {
                let elem = kind & 0x7f;
                let n = self.word()?;
                if n > 64 {
                    return None;
                }
                let mut vs = Vec::with_capacity(n);
                for _ in 0..n {
                    if self.byte()? != elem {
                        return None;
                    }
                    vs.push(self.value(elem)?);
                }
                Value::Array(elem, vs.into())
            }
            _ => return None,
        };
        v.valid().then_some(v)
    }
    fn typed(&mut self, expected: u8) -> Option<Value> {
        let kind = self.byte()?;
        if expected != 0 && kind != expected {
            return None;
        }
        self.value(kind)
    }
    fn table(&mut self) -> Option<Table> {
        let key = self.byte()?;
        let value = self.byte()?;
        let n = self.word()?;
        if !(1..=6).contains(&key) || !valid_kind(value) || n > 4096 {
            return None;
        }
        let mut entries = HashMap::new();
        let mut widths = [Vec::new(), Vec::new()];
        for _ in 0..n {
            let k = self.typed(key)?;
            if let Value::Prefix(ip, bits) = &k {
                let family = &mut widths[ip.is_ipv6() as usize];
                if !family.contains(bits) {
                    family.push(*bits);
                }
            }
            if entries.insert(k, self.typed(value)?).is_some() {
                return None;
            }
        }
        for v in &mut widths {
            v.sort_unstable_by(|a, b| b.cmp(a));
        }
        Some(Table {
            key,
            element: value,
            entries,
            widths,
        })
    }
}
fn valid_kind(k: u8) -> bool {
    matches!(k,1..=7|129..=135)
}

pub fn decode(bytes: &[u8]) -> Option<Program> {
    let mut r = Reader::new(bytes);
    if r.take(4)? != b"RCR1" {
        return None;
    }
    let nf = r.word()?;
    if nf > 32 {
        return None;
    }
    let mut fields = Vec::with_capacity(nf);
    for _ in 0..nf {
        let kind = r.byte()?;
        let edit = r.byte()?;
        if !valid_kind(kind) || !matches!((kind, edit), (_, 0) | (2, 1 | 2) | (1, 3 | 4)) {
            return None;
        }
        fields.push(Field { kind, edit });
    }
    let nt = r.word()?;
    if nt > 256 {
        return None;
    }
    let mut tables = Vec::with_capacity(nt);
    for _ in 0..nt {
        tables.push(r.table()?);
    }
    let n = r.word()?;
    if n > 8192 {
        return None;
    }
    let mut ops = Vec::with_capacity(n);
    let mut locals = 0;
    for pc in 0..n {
        let opcode = r.byte()?;
        let arg = r.word()?;
        let target = r.word()?;
        let aux = r.word()?;
        let kind = r.byte()?;
        let name = r.text(64)?;
        if matches!(opcode, 3 | 4 | 9 | 16 | 17) {
            let high = arg.checked_add(if opcode == 16 { 3 } else { 1 })?;
            if high > 128 {
                return None;
            }
            locals = locals.max(high);
        }
        if matches!(opcode, 9 | 12 | 13 | 14 | 15 | 16) && (target <= pc || target > n) {
            return None;
        }
        let op = match opcode {
            0 => Op::Literal(r.typed(0)?),
            1 if arg < nf => Op::Read(arg),
            2 if arg < nf && fields[arg].edit != 0 => Op::Write(arg),
            3 => Op::Load(arg),
            4 => Op::Store(arg),
            5 if (129..=135).contains(&kind) && (1..=64).contains(&arg) => {
                Op::Array(kind & 127, arg)
            }
            6 if builtin_arity(name) == Some(arg) => Op::Builtin(name.into(), arg),
            7 if matches!(
                name,
                "==" | "!=" | "<" | ">" | "<=" | ">=" | "+" | "-" | "*" | "/" | "%" | "in"
            ) =>
            {
                Op::Binary(name.into())
            }
            8 if matches!(name, "-" | "!") => Op::Unary(name == "!"),
            9 if aux < nt => Op::Match {
                table: aux,
                slot: arg,
                missing: target,
            },
            10 if name == "count" && arg == 0 => Op::Count,
            11 => Op::Discard,
            12 => Op::Jump(target),
            13 => Op::Branch(target),
            14 => Op::And(target),
            15 => Op::Or(target),
            16 => Op::Iterate(arg, target),
            17 if target < pc
                && matches!(ops.get(target),Some(Op::Iterate(slot,_)) if *slot+1==arg) =>
            {
                Op::Advance(arg, target)
            }
            18 => Op::Deny,
            _ => return None,
        };
        ops.push(op);
    }
    if !r.done() {
        return None;
    }
    super::verify::states(&ops, &fields, &tables)?;
    Some(Program {
        fields,
        ops,
        tables,
        locals,
    })
}
fn builtin_arity(name: &str) -> Option<usize> {
    Some(match name {
        "string" | "int" | "len" | "lower" | "addr" | "prefix" | "bytes" | "dns" => 1,
        "mask" | "range" | "byte" | "u16be" | "at" | "contains" | "starts_with" | "ends_with" => 2,
        "slice" | "write_u16be" => 3,
        "replace" => 4,
        _ => return None,
    })
}
