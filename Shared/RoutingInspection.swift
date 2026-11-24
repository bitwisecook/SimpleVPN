// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

nonisolated struct RoutingInspectionRequest: Codable, Sendable, Equatable {
    var table: String
    var cursor: UInt64 = 0
    var limit: Int = 40
    var port: String?
    var ruleID: UInt64?

    var isValid: Bool {
        ["rules", "flows"].contains(table) && (1...128).contains(limit)
            && (port?.utf8.count ?? 0) <= 256
    }
}

nonisolated struct RoutingInspectionPage: Codable, Sendable, Equatable {
    let table: String
    let revision: UInt64
    let total: Int
    let nextCursor: UInt64?
    let rules: [RoutingInspectionRule]?
    let flows: [RoutingInspectionFlow]?
    var sessionID: String?
}

nonisolated struct RoutingInspectionRule: Codable, Sendable, Equatable, Identifiable {
    let id: UInt64
    let kind: String
    let source, prefix, port, eventID: String?
    let active: Bool
    var available: Bool? = nil
    var lastDropReason: String? = nil
    let packetsOut, bytesOut, packetsIn, bytesIn, drops: UInt64
}

nonisolated struct RoutingInspectionFlow: Codable, Sendable, Equatable, Identifiable {
    let id, ruleID, revision, portGeneration, owner: UInt64
    let sourceIP, destinationIP, translatedSource, port: String
    let sourcePort, destinationPort: UInt16
    let `protocol`: UInt8
    let source: String?
    let firstSeen, lastSeen: Double
    let blocked: Bool
    var lastDropReason: String? = nil
    let packetsOut, bytesOut, packetsIn, bytesIn, drops: UInt64
    let dnsName, tlsServerName: String?
}
