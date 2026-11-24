// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

use std::{collections::HashMap, slice, time::Instant};

const CAPACITY: usize = 1024;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct Endpoint {
    address: [u8; 16],
    port: u16,
    protocol: u8,
    family: u8,
}

impl Endpoint {
    fn parse(packet: &[u8], inbound: bool) -> Option<Self> {
        let family = packet.first()? >> 4;
        let mut address = [0; 16];
        let (protocol, transport) = match family {
            4 => {
                let header = packet.get(..20)?;
                let offset = (header[0] as usize & 15) * 4;
                let length = u16::from_be_bytes([header[2], header[3]]) as usize;
                if offset < header.len() {
                    return None;
                }
                let transport = packet.get(offset..length)?;
                let remote = if inbound { 12 } else { 16 };
                address[..4].copy_from_slice(&header[remote..remote + 4]);
                let later_fragment = header[6] & 31 != 0 || header[7] != 0;
                (header[9], if later_fragment { &[][..] } else { transport })
            }
            6 => {
                let header = packet.get(..40)?;
                let length = u16::from_be_bytes([header[4], header[5]]) as usize;
                let remote = if inbound { 8 } else { 24 };
                address.copy_from_slice(&header[remote..remote + 16]);
                ipv6_transport(header[6], packet.get(40..40 + length)?)?
            }
            _ => return None,
        };
        let port = if matches!(protocol, 6 | 17) && transport.len() >= 4 {
            let offset = if inbound { 0 } else { 2 };
            u16::from_be_bytes([transport[offset], transport[offset + 1]])
        } else {
            0
        };
        Some(Self {
            address,
            port,
            protocol,
            family,
        })
    }
}

fn ipv6_transport(mut protocol: u8, mut payload: &[u8]) -> Option<(u8, &[u8])> {
    for _ in 0..8 {
        let length = match protocol {
            0 | 43 | 60 => (*payload.get(1)? as usize + 1) * 8,
            44 => {
                let fragment = payload.get(..8)?;
                if fragment[2] != 0 || fragment[3] & 0xf8 != 0 {
                    return Some((fragment[0], &[]));
                }
                8
            }
            51 => (*payload.get(1)? as usize + 2) * 4,
            _ => return Some((protocol, payload)),
        };
        protocol = payload[0];
        payload = payload.get(length..)?;
    }
    Some((protocol, &[]))
}

struct Entry {
    endpoint: Endpoint,
    bytes: [u64; 2],
    packets: [u64; 2],
    first: Instant,
    last: Instant,
    previous: Option<usize>,
    next: Option<usize>,
}

#[derive(Default)]
pub struct RCFlowLog {
    indices: HashMap<Endpoint, usize>,
    entries: Vec<Entry>,
    oldest: Option<usize>,
    newest: Option<usize>,
}

impl RCFlowLog {
    fn record(&mut self, endpoint: Endpoint, length: usize, inbound: bool, now: Instant) {
        let index = if let Some(&index) = self.indices.get(&endpoint) {
            index
        } else {
            let index = if self.entries.len() < CAPACITY {
                self.entries.len()
            } else {
                let index = self.oldest.expect("a full flow log has an oldest entry");
                self.indices.remove(&self.entries[index].endpoint);
                self.unlink(index);
                index
            };
            let entry = Entry {
                endpoint,
                bytes: [0; 2],
                packets: [0; 2],
                first: now,
                last: now,
                previous: None,
                next: None,
            };
            if index == self.entries.len() {
                self.entries.push(entry);
            } else {
                self.entries[index] = entry;
            }
            self.indices.insert(endpoint, index);
            self.append(index);
            index
        };
        let entry = &mut self.entries[index];
        let direction = usize::from(inbound);
        entry.bytes[direction] = entry.bytes[direction].saturating_add(length as u64);
        entry.packets[direction] = entry.packets[direction].saturating_add(1);
        entry.last = now;
        if self.newest != Some(index) {
            self.unlink(index);
            self.append(index);
        }
    }

    fn unlink(&mut self, index: usize) {
        let Entry { previous, next, .. } = self.entries[index];
        if let Some(previous) = previous {
            self.entries[previous].next = next;
        } else {
            self.oldest = next;
        }
        if let Some(next) = next {
            self.entries[next].previous = previous;
        } else {
            self.newest = previous;
        }
    }

    fn append(&mut self, index: usize) {
        self.entries[index].previous = self.newest;
        self.entries[index].next = None;
        if let Some(previous) = self.newest {
            self.entries[previous].next = Some(index);
        } else {
            self.oldest = Some(index);
        }
        self.newest = Some(index);
    }
}

#[repr(C)]
pub struct RCFlowLogRow {
    address: [u8; 16],
    port: u16,
    protocol: u8,
    family: u8,
    bytes: [u64; 2],
    packets: [u64; 2],
    age_first: f64,
    age_last: f64,
}

#[unsafe(no_mangle)]
pub extern "C" fn rc_flow_log_new() -> *mut RCFlowLog {
    Box::into_raw(Box::default())
}

/// # Safety
/// The owner releases the live handle once, after calls finish.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_flow_log_free(log: *mut RCFlowLog) {
    if !log.is_null() {
        drop(unsafe { Box::from_raw(log) });
    }
}

/// # Safety
/// The caller serializes access and supplies a live log and readable packet.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_flow_log_record(
    log: *mut RCFlowLog,
    packet: *const u8,
    length: usize,
    inbound: bool,
) {
    if packet.is_null() || !(20..=65_535).contains(&length) {
        return;
    }
    let packet = unsafe { slice::from_raw_parts(packet, length) };
    if let (Some(log), Some(endpoint)) = (unsafe { log.as_mut() }, Endpoint::parse(packet, inbound))
    {
        log.record(endpoint, length, inbound, Instant::now());
    }
}

/// # Safety
/// The caller serializes access and supplies a live log. When rows is non-null,
/// it points to space for capacity rows. A null output queries the current count.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_flow_log_snapshot(
    log: *const RCFlowLog,
    rows: *mut RCFlowLogRow,
    capacity: usize,
) -> usize {
    let Some(log) = (unsafe { log.as_ref() }) else {
        return 0;
    };
    if rows.is_null() {
        return log.entries.len();
    }
    let now = Instant::now();
    let mut next = log.newest;
    let mut count = 0;
    while let Some(index) = next.filter(|_| count < capacity) {
        let entry = &log.entries[index];
        let Endpoint {
            address,
            port,
            protocol,
            family,
        } = entry.endpoint;
        unsafe {
            rows.add(count).write(RCFlowLogRow {
                address,
                port,
                protocol,
                family,
                bytes: entry.bytes,
                packets: entry.packets,
                age_first: now.duration_since(entry.first).as_secs_f64(),
                age_last: now.duration_since(entry.last).as_secs_f64(),
            });
        }
        next = entry.previous;
        count += 1;
    }
    count
}

#[cfg(test)]
mod tests;
