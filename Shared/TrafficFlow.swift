// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  TrafficFlow.swift
//  One observed traffic flow in a VPN's per-connection log, keyed by the remote
//  endpoint. Built in the extension from shared header-only accounting and
//  sent to the app over the "flows" IPC message. No payload is ever captured.
//

import Foundation

struct TrafficFlow: Codable, Sendable, Identifiable, Equatable {
    var family: Int          // 4 | 6
    var address: String      // remote IP (presentation)
    var port: Int            // remote L4 port (0 = non-TCP/UDP)
    var proto: Int           // IPPROTO_TCP (6) / UDP (17) / other
    var bytesIn: Int64
    var bytesOut: Int64
    var packetsIn: Int64
    var packetsOut: Int64
    var ageFirst: Double     // seconds since first seen (relative — clocks don't cross the boundary)
    var ageLast: Double      // seconds since last seen

    var id: String { "\(address)|\(port)|\(proto)" }

    var protoName: String {
        switch proto { case 6: "TCP"; case 17: "UDP"; case 1: "ICMP"; case 58: "ICMPv6"; default: "IP\(proto)" }
    }
    var bytesTotal: Int64 { bytesIn + bytesOut }
    var endpoint: String {
        guard port > 0 else { return address }
        return family == 6 ? "[\(address)]:\(port)" : "\(address):\(port)"
    }
}
