// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

pub mod values;
mod verify;
pub mod wire;
use std::collections::HashMap;
use values::Value;
pub struct Field {
    pub kind: u8,
    pub edit: u8,
}
pub enum Op {
    Literal(Value),
    Read(usize),
    Write(usize),
    Load(usize),
    Store(usize),
    Array(u8, usize),
    Builtin(Box<str>, usize),
    Binary(Box<str>),
    Unary(bool),
    Match {
        table: usize,
        slot: usize,
        missing: usize,
    },
    Count,
    Discard,
    Jump(usize),
    Branch(usize),
    And(usize),
    Or(usize),
    Iterate(usize, usize),
    Advance(usize, usize),
    Deny,
}
pub struct Table {
    key: u8,
    element: u8,
    entries: HashMap<Value, Value>,
    widths: [Vec<u8>; 2],
}
impl Table {
    pub fn lookup(&self, key: &Value) -> Option<&Value> {
        if let (6, Value::Addr(ip)) = (self.key, key) {
            for &bits in &self.widths[ip.is_ipv6() as usize] {
                let base = crate::values::network(*ip, bits)?;
                if let Some(v) = self.entries.get(&Value::Prefix(base, bits)) {
                    return Some(v);
                }
            }
            None
        } else {
            self.entries.get(key)
        }
    }
}

pub struct Program {
    pub fields: Vec<Field>,
    pub ops: Vec<Op>,
    pub tables: Vec<Table>,
    pub locals: usize,
}

impl Program {
    pub fn stack_depths(&self) -> Option<Vec<Option<usize>>> {
        verify::states(&self.ops, &self.fields, &self.tables)
            .map(|states| states.iter().map(|s| s.map(|state| state.depth)).collect())
    }
}
pub mod llvm;
