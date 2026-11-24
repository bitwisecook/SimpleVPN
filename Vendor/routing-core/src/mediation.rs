// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
use std::collections::HashMap;

#[repr(C)]
#[derive(Default)]
pub struct RCTrafficCounters {
    received_packets: u64,
    received_bytes: u64,
    forwarded_packets: u64,
    forwarded_bytes: u64,
    dropped_packets: u64,
    dropped_bytes: u64,
    evaluated_packets: u64,
    edited_packets: u64,
    rule_hits: u64,
}
/// # Safety
/// The row must be initialized and exclusively accessible for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_traffic_record(
    row: *mut RCTrafficCounters,
    stage: u32,
    packets: u64,
    bytes: u64,
    hits: u64,
    edited: u64,
) {
    let Some(r) = (unsafe { row.as_mut() }) else {
        return;
    };
    if stage == 0 || stage == 3 {
        r.received_packets = r.received_packets.saturating_add(packets);
        r.received_bytes = r.received_bytes.saturating_add(bytes);
    }
    if stage == 1 || stage == 3 {
        r.forwarded_packets = r.forwarded_packets.saturating_add(packets);
        r.forwarded_bytes = r.forwarded_bytes.saturating_add(bytes);
    }
    if stage == 2 {
        r.dropped_packets = r.dropped_packets.saturating_add(packets);
        r.dropped_bytes = r.dropped_bytes.saturating_add(bytes);
    }
    if stage == 4 {
        r.evaluated_packets = r.evaluated_packets.saturating_add(packets);
        r.edited_packets = r.edited_packets.saturating_add(edited);
        r.rule_hits = r.rule_hits.saturating_add(hits);
    }
}

const CAP: usize = 8192;
const IDLE: u64 = 120_000;
const NONE: usize = usize::MAX;
#[repr(C)]
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub struct RCUdpTuple {
    family: u8,
    src: [u8; 16],
    dst: [u8; 16],
    src_port: u16,
    dst_port: u16,
}
struct Slot {
    key: RCUdpTuple,
    stamp: u64,
    prev: usize,
    next: usize,
}
pub struct RCUdpHistory {
    keys: HashMap<RCUdpTuple, usize>,
    slots: Vec<Slot>,
    free: Vec<usize>,
    head: usize,
    tail: usize,
    last: u64,
}
impl RCUdpHistory {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
            slots: Vec::new(),
            free: Vec::new(),
            head: NONE,
            tail: NONE,
            last: 0,
        }
    }
    fn unlink(&mut self, i: usize) {
        let s = &self.slots[i];
        let (prev, next) = (s.prev, s.next);
        if prev == NONE {
            self.head = next
        } else {
            self.slots[prev].next = next
        }
        if next == NONE {
            self.tail = prev
        } else {
            self.slots[next].prev = prev
        }
    }
    fn expire(&mut self, now: u64) {
        self.last = self.last.max(now);
        while self.head != NONE && self.last - self.slots[self.head].stamp >= IDLE {
            let i = self.head;
            self.keys.remove(&self.slots[i].key);
            self.unlink(i);
            self.free.push(i);
        }
    }
    fn seen(&mut self, k: &RCUdpTuple, now: u64) -> i32 {
        self.expire(now);
        if self.keys.contains_key(k) {
            1
        } else if self.keys.len() >= CAP {
            -1
        } else {
            0
        }
    }
    fn accept(&mut self, k: RCUdpTuple, now: u64) {
        self.expire(now);
        let i = if let Some(&i) = self.keys.get(&k) {
            if self.tail == i {
                self.slots[i].stamp = self.last;
                return;
            }
            self.unlink(i);
            i
        } else {
            if self.keys.len() >= CAP {
                return;
            }
            let i = self.free.pop().unwrap_or(self.slots.len());
            self.keys.insert(k, i);
            i
        };
        let slot = Slot {
            key: k,
            stamp: self.last,
            prev: self.tail,
            next: NONE,
        };
        if i == self.slots.len() {
            self.slots.push(slot)
        } else {
            self.slots[i] = slot
        }
        if self.tail == NONE {
            self.head = i
        } else {
            self.slots[self.tail].next = i
        }
        self.tail = i;
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn rc_udp_history_new() -> *mut RCUdpHistory {
    Box::into_raw(Box::new(RCUdpHistory::new()))
}
/// # Safety
/// Only the owner may release this live handle, after outstanding calls finish.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_udp_history_free(h: *mut RCUdpHistory) {
    if !h.is_null() {
        drop(unsafe { Box::from_raw(h) });
    }
}
/// # Safety
/// The history must be exclusively accessible, and the tuple readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_udp_seen(
    h: *mut RCUdpHistory,
    key: *const RCUdpTuple,
    now: u64,
) -> i32 {
    match (unsafe { h.as_mut() }, unsafe { key.as_ref() }) {
        (Some(h), Some(k)) if matches!(k.family, 4 | 6) => h.seen(k, now),
        _ => -1,
    }
}
/// # Safety
/// The history must be exclusively accessible, and the tuple readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_udp_accept(h: *mut RCUdpHistory, key: *const RCUdpTuple, now: u64) {
    if let (Some(h), Some(k)) = (unsafe { h.as_mut() }, unsafe { key.as_ref() }) {
        if matches!(k.family, 4 | 6) {
            h.accept(*k, now)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn udp_admission_is_bounded_and_expires_only_idle_tuples() {
        let key = |port| RCUdpTuple {
            family: 4,
            src: [0; 16],
            dst: [1; 16],
            src_port: port,
            dst_port: 53,
        };
        let mut h = RCUdpHistory::new();
        for i in 0..CAP {
            let k = key(i as u16);
            assert_eq!(h.seen(&k, 0), 0);
            h.accept(k, 0);
        }
        assert_eq!(h.seen(&key(CAP as u16), 10), -1);
        h.accept(key(0), 60_000);
        assert_eq!(h.seen(&key(0), IDLE), 1);
        assert_eq!(h.seen(&key(1), IDLE), 0);
        h.accept(key(1), IDLE);
        assert_eq!(h.slots.len(), CAP);
        assert_eq!(h.keys.len(), 2);
    }
    #[test]
    fn disabled_and_active_direction_counts_are_independent() {
        let mut rows = [RCTrafficCounters::default(), RCTrafficCounters::default()];
        unsafe {
            rc_traffic_record(&mut rows[0], 3, 5, 400, 0, 0);
            rc_traffic_record(&mut rows[1], 0, 2, 100, 0, 0);
            rc_traffic_record(&mut rows[1], 4, 2, 0, 4, 1);
            rc_traffic_record(&mut rows[1], 1, 1, 60, 0, 0);
            rc_traffic_record(&mut rows[1], 2, 1, 40, 0, 0);
        }
        assert_eq!(
            (
                rows[0].received_packets,
                rows[0].forwarded_packets,
                rows[0].evaluated_packets
            ),
            (5, 5, 0)
        );
        assert_eq!(
            (
                rows[1].received_bytes,
                rows[1].forwarded_bytes,
                rows[1].dropped_bytes,
                rows[1].rule_hits,
                rows[1].edited_packets
            ),
            (100, 60, 40, 4, 1)
        );
    }
}
