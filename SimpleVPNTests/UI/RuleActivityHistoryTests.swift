// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Testing
@testable import SimpleVPN

@MainActor
struct RuleActivityHistoryTests {
    private let start = Date(timeIntervalSinceReferenceDate: 1_000)

    private func rule(_ n: UInt64, id: UInt64 = 1) -> RoutingInspectionRule {
        RoutingInspectionRule(id: id, kind: "source", source: "test-app", prefix: nil,
                              port: "vpn", eventID: nil, active: true,
                              packetsOut: n, bytesOut: n * 10, packetsIn: n * 2, bytesIn: n * 100, drops: n)
    }

    @Test func recordsDirectionalRatesOnlyOverContinuousIntervals() throws {
        var history = RuleActivityHistory()
        history.record(rule(4), session: "virtual-session", at: start)
        #expect(history.samples.isEmpty)
        history.record(rule(10), session: "virtual-session", at: start.addingTimeInterval(2))
        let sample = try #require(history.samples.first)
        #expect(sample.bytesOut == 30 && sample.bytesIn == 300)
        #expect(sample.packetsOut == 3 && sample.packetsIn == 6 && sample.drops == 3)
        // Pausing a window, resetting counters, changing rules and restarting
        // the provider each require a fresh baseline.
        history.record(rule(100), session: "virtual-session", at: start.addingTimeInterval(30))
        #expect(history.samples.isEmpty)
        history.record(rule(110), session: "virtual-session", at: start.addingTimeInterval(32))
        #expect(history.samples.count == 1)
        history.record(rule(1), session: "virtual-session", at: start.addingTimeInterval(34))
        #expect(history.samples.isEmpty)
        history.record(rule(3), session: "virtual-session", at: start.addingTimeInterval(36))
        history.record(rule(5, id: 2), session: "virtual-session", at: start.addingTimeInterval(38))
        #expect(history.samples.isEmpty)
        history.record(rule(8, id: 2), session: "virtual-session", at: start.addingTimeInterval(40))
        history.record(rule(14, id: 2), session: "new-session", at: start.addingTimeInterval(42))
        #expect(history.samples.isEmpty)
    }

    @Test func historyStaysBoundedAcrossLongInspection() {
        var history = RuleActivityHistory()
        for tick in 0...200 {
            history.record(rule(UInt64(tick)), session: "s", at: start.addingTimeInterval(Double(tick * 2)))
        }
        #expect(history.samples.count == RuleActivityHistory.capacity)
        #expect(history.samples.last?.id == start.addingTimeInterval(400))
    }

    @Test func pagingReturnsToExactPriorCursorAfterSearch() {
        var pager = RuleActivityPager()
        pager.back()
        #expect(pager.cursor == 0 && pager.number == 1)
        pager.advance(to: 45)
        pager.advance(to: 103)
        pager.advance(to: 103)
        pager.advance(to: 42)
        #expect(pager.cursor == 103 && pager.number == 3)
        pager.back()
        #expect(pager.cursor == 45 && pager.number == 2)
        pager.back()
        #expect(pager.cursor == 0 && pager.number == 1)
    }
}
