// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

/// Rates exist only between two observations of the same live rule. A gap
/// after occlusion or a router restart must not draw a continuous chart.
struct RuleActivityHistory {
    struct Sample: Identifiable {
        let id: Date
        let bytesOut, bytesIn, packetsOut, packetsIn, drops: Double
    }

    private struct Reading {
        let packetsOut, bytesOut, packetsIn, bytesIn, drops: UInt64
        let series: String
        let session: String?
        let date: Date
    }
    private var previous: Reading?
    private(set) var samples: [Sample] = []
    static let capacity = 90

    mutating func record(_ rule: RoutingInspectionRule, session: String?, at date: Date) {
        record(packetsOut: rule.packetsOut, bytesOut: rule.bytesOut, packetsIn: rule.packetsIn,
               bytesIn: rule.bytesIn, drops: rule.drops, series: String(rule.id), session: session, at: date)
    }

    mutating func record(packetsOut: UInt64, bytesOut: UInt64, packetsIn: UInt64, bytesIn: UInt64, drops: UInt64,
                         series: String, session: String?, at date: Date) {
        defer { previous = Reading(packetsOut: packetsOut, bytesOut: bytesOut, packetsIn: packetsIn, bytesIn: bytesIn,
                                   drops: drops, series: series, session: session, date: date) }
        guard let old = previous, old.session == session, old.series == series else {
            samples.removeAll()
            return
        }
        let dt = date.timeIntervalSince(old.date)
        guard dt > 0, dt < 10, bytesOut >= old.bytesOut, bytesIn >= old.bytesIn,
              packetsOut >= old.packetsOut, packetsIn >= old.packetsIn, drops >= old.drops else {
            samples.removeAll()
            return
        }
        samples.append(Sample(id: date, bytesOut: Double(bytesOut - old.bytesOut) / dt,
                              bytesIn: Double(bytesIn - old.bytesIn) / dt,
                              packetsOut: Double(packetsOut - old.packetsOut) / dt,
                              packetsIn: Double(packetsIn - old.packetsIn) / dt,
                              drops: Double(drops - old.drops) / dt))
        if samples.count > Self.capacity { samples.removeFirst(samples.count - Self.capacity) }
    }
}

struct RuleActivityPager {
    private(set) var cursors: [UInt64] = [0]
    var cursor: UInt64 { cursors.last ?? 0 }
    var number: Int { cursors.count }

    mutating func advance(to next: UInt64) {
        if next > cursor { cursors.append(next) }
    }
    mutating func back() {
        if cursors.count > 1 { cursors.removeLast() }
    }
}

struct RuleActivityTarget: Identifiable {
    let id: String          // A connected member addresses the shared provider.
    let compositionID: String
    let name: String
}
