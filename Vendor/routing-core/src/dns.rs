// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::HashMap;

const LIMIT: usize = 253;
const WORDS: usize = 4;
type Bits = [u64; WORDS];

fn set(bits: &mut Bits, index: usize) {
    bits[index / 64] |= 1 << (index % 64);
}

// Advance a 256-position NFA state without allocating on the query path.
fn advance(states: Bits) -> Bits {
    let mut carry = 0;
    states.map(|word| {
        let shifted = word << 1 | carry;
        carry = word >> 63;
        shifted
    })
}

struct Glob {
    accepted: Box<[Bits; 94]>,
    stars: Bits,
    end: usize,
}

impl Glob {
    fn compile(mut tokens: &[u8]) -> Option<Self> {
        let mut glob = Self {
            accepted: Box::new([[0; WORDS]; 94]),
            stars: [0; WORDS],
            end: 0,
        };
        let mut last_star = false;
        while let Some((&op, rest)) = tokens.split_first() {
            tokens = rest;
            if op == 3 && last_star {
                continue;
            }
            if glob.end >= LIMIT {
                return None;
            }
            last_star = op == 3;
            match op {
                1 => {
                    let (&byte, tail) = tokens.split_first()?;
                    set(
                        glob.accepted.get_mut(usize::from(byte.checked_sub(33)?))?,
                        glob.end,
                    );
                    tokens = tail;
                }
                2 => {
                    for row in glob.accepted.iter_mut() {
                        set(row, glob.end);
                    }
                }
                3 => set(&mut glob.stars, glob.end),
                4 => {
                    let (mask, tail) = tokens.split_at_checked(16)?;
                    for (offset, row) in glob.accepted.iter_mut().enumerate() {
                        let byte = 33 + offset;
                        if mask[byte / 8] & (1 << (byte % 8)) != 0 {
                            set(row, glob.end);
                        }
                    }
                    tokens = tail;
                }
                _ => return None,
            }
            glob.end += 1;
        }
        (glob.end > 0).then_some(glob)
    }

    fn closure(&self, state: Bits) -> Bits {
        // Consecutive stars have been merged, so one epsilon step is sufficient.
        let skip = advance(std::array::from_fn(|i| state[i] & self.stars[i]));
        std::array::from_fn(|i| state[i] | skip[i])
    }

    fn matches(&self, name: &[u8]) -> bool {
        let mut state = self.closure([1, 0, 0, 0]);
        for &byte in name {
            let mask = &self.accepted[usize::from(byte - 33)];
            let next = advance(std::array::from_fn(|i| state[i] & mask[i]));
            state = self.closure(std::array::from_fn(|i| {
                next[i] | (state[i] & self.stars[i])
            }));
            if state == [0; WORDS] {
                return false;
            }
        }
        state[self.end / 64] & (1 << (self.end % 64)) != 0
    }
}

#[derive(Default)]
pub struct RCDnsPlan {
    exact: HashMap<Vec<u8>, u16>,
    suffix: HashMap<Vec<u8>, u16>,
    globs: Vec<(u16, Glob)>,
    last: Option<u16>,
}

impl RCDnsPlan {
    fn add(&mut self, index: u16, kind: u8, bytes: &[u8]) -> Option<()> {
        if index >= 256 || self.last.is_some_and(|n| index <= n) {
            return None;
        }
        match kind {
            1 | 2 if !bytes.is_empty() && bytes.len() <= LIMIT && printable(bytes) => {
                let table = if kind == 1 {
                    &mut self.exact
                } else {
                    &mut self.suffix
                };
                table.entry(bytes.to_vec()).or_insert(index);
            }
            3 => self.globs.push((index, Glob::compile(bytes)?)),
            _ => return None,
        }
        self.last = Some(index);
        Some(())
    }
    fn lookup(&self, name: &[u8]) -> Option<u16> {
        let mut hit = self.exact.get(name).copied();
        let mut suffix = name;
        while !suffix.is_empty() {
            if let Some(&index) = self.suffix.get(suffix) {
                hit = Some(hit.map_or(index, |n| n.min(index)));
            }
            let Some(dot) = suffix.iter().position(|&b| b == b'.') else {
                break;
            };
            suffix = &suffix[dot + 1..];
        }
        for (index, glob) in &self.globs {
            if hit.is_some_and(|prior| prior <= *index) {
                break;
            }
            if glob.matches(name) {
                return Some(*index);
            }
        }
        hit
    }
}
fn printable(name: &[u8]) -> bool {
    name.iter().all(|b| (33..=126).contains(b))
}

#[unsafe(no_mangle)]
pub extern "C" fn rc_dns_plan_new() -> *mut RCDnsPlan {
    Box::into_raw(Box::new(RCDnsPlan::default()))
}

/// # Safety
/// The caller exclusively owns the plan. The encoded match pattern is readable for len bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_dns_plan_add(
    plan: *mut RCDnsPlan,
    index: u16,
    kind: u8,
    bytes: *const u8,
    len: u32,
) -> bool {
    let (Some(plan), Some(pattern)) = (unsafe { plan.as_mut() }, unsafe {
        super::input(bytes, len, LIMIT * 17)
    }) else {
        return false;
    };
    plan.add(index, kind, pattern).is_some()
}

#[repr(C)]
pub struct DnsResult {
    pub status: u32,
    pub index: u16,
}

/// # Safety
/// The plan is live and immutable. The canonical question name is readable for len bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_dns_match(
    plan: *const RCDnsPlan,
    bytes: *const u8,
    len: u32,
) -> DnsResult {
    if let (Some(plan), Some(name)) = (unsafe { plan.as_ref() }, unsafe {
        super::input(bytes, len, LIMIT)
    }) {
        if printable(name) {
            if name != b"." && !name.is_empty() {
                if let Some(index) = plan.lookup(name) {
                    return DnsResult { status: 1, index };
                }
            }
            return DnsResult {
                status: 0,
                index: 0,
            };
        }
    }
    DnsResult {
        status: 2,
        index: 0,
    }
}

/// # Safety
/// The pointer came from rc_dns_plan_new and has no remaining users.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_dns_plan_free(plan: *mut RCDnsPlan) {
    if !plan.is_null() {
        drop(unsafe { Box::from_raw(plan) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn first_rule_wins_across_match_types() {
        let mut plan = RCDnsPlan::default();
        plan.add(1, 2, b"lab").unwrap();
        plan.add(2, 3, &[1, b'w', 3, 3]).unwrap();
        plan.add(3, 1, b"www.lab").unwrap();
        assert_eq!(plan.lookup(b"www.lab"), Some(1));
        assert_eq!(plan.lookup(b"ww"), Some(2));
        assert_eq!(plan.lookup(b"xlab"), None);
        assert!(plan.add(3, 3, &[255]).is_none());
    }
    #[test]
    fn long_globs_cross_word_boundaries() {
        for n in [1, 63, 64, 65, 127, 128, 191, 192, 252] {
            let mut ops = vec![2; n];
            ops.extend_from_slice(&[1, b'z']);
            let glob = Glob::compile(&ops).unwrap();
            let mut name = vec![b'a'; n];
            name.push(b'z');
            assert!(glob.matches(&name));
            name[n] = b'y';
            assert!(!glob.matches(&name));
        }
    }
}
