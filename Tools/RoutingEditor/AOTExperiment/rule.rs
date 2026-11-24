// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

#[unsafe(no_mangle)]
pub extern "C" fn evaluate(event: u8, present: u8, port: u16, ip: u32) -> u32 {
    if event != 1 {
        return 0;
    }
    if present & 1 == 0 {
        return 2;
    }
    if port != 443 {
        return 0;
    }
    if present & 2 == 0 {
        return 2;
    }
    if ip >> 24 == 10 {
        return 0x1001;
    }
    if ip >> 8 == 0xc00002 {
        return 3;
    }
    0
}
