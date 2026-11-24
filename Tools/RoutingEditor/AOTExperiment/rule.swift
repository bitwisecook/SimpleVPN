// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

@c(evaluate)
public func evaluate(_ event: UInt8, _ present: UInt8, _ port: UInt16, _ ip: UInt32) -> UInt32 {
    guard event == 1 else { return 0 }
    guard present & 1 != 0 else { return 2 }
    guard port == 443 else { return 0 }
    guard present & 2 != 0 else { return 2 }
    if ip >> 24 == 10 { return 0x1001 }
    if ip >> 8 == 0xc00002 { return 3 }
    return 0
}
