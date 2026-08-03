// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  TrafficHistoryTests.swift
//  Pins the promises the scrolling traffic graph is built on. Every one of them is
//  a promise about NOT lying:
//    • coarsening history must not erase a burst — a 1 s spike an hour ago has to
//      still read as a spike, so `max` is carried down the tiers alongside `avg`;
//    • a coarse average must be the mean of the SAMPLES underneath it, not a mean
//      of means (that's why buckets carry a weight);
//    • stitching tiers together must produce one continuous timeline — strictly
//      increasing, each bucket starting exactly where the previous one ended, so
//      the chart shows neither a gap nor a doubled line at a tier boundary;
//    • a range query must be served at the finest resolution still available for
//      that range, and no finer (scrolling back an hour must not try to load 24 h
//      of 1 s samples);
//    • the store is a fixed-cost ring: a day of inserts, or two, must leave it at
//      exactly the same bounded size.
//

import Foundation
import Testing
@testable import SimpleVPN

struct TrafficHistoryTests {

    /// A tidy epoch aligned to a minute, so tier boundaries land on round numbers
    /// and the assertions can be exact rather than approximate.
    private let epoch = TrafficHistory.align(Date(timeIntervalSinceReferenceDate: 800_000_000), to: 60)

    /// Feed `seconds` of 1 Hz samples starting at `epoch`.
    private func feed(_ history: inout TrafficHistory, seconds: Int,
                      rate: (Int) -> (in: Double, out: Double)) {
        for i in 0..<seconds {
            let r = rate(i)
            history.record(inRate: r.in, outRate: r.out, at: epoch.addingTimeInterval(Double(i)))
        }
    }

    private func steady(_ inRate: Double, _ outRate: Double,
                        spikeAt: Int? = nil, spike: Double = 0) -> (Int) -> (in: Double, out: Double) {
        { i in i == spikeAt ? (in: spike, out: spike / 2) : (in: inRate, out: outRate) }
    }

    // MARK: Full resolution

    @Test func tierZeroKeepsEverySampleAtOneSecond() throws {
        var h = TrafficHistory()
        feed(&h, seconds: 60) { i in (in: Double(i), out: Double(i) * 2) }

        let recent = h.recent(10)
        #expect(recent.count == 10)
        #expect(recent.allSatisfy { $0.interval == 1 })
        // Oldest first, one second apart, no holes.
        for (a, b) in zip(recent, recent.dropFirst()) {
            #expect(b.start.timeIntervalSince(a.start) == 1)
        }
        // At 1 s the bucket IS the sample: average and peak coincide.
        let last = try #require(recent.last)
        #expect(last.avgIn == 59)
        #expect(last.maxIn == 59)
        #expect(last.avgOut == 118)
        #expect(last.maxOut == 118)
        #expect(h.latest?.avgIn == 59)
        #expect(h.newestTime == epoch.addingTimeInterval(59))
    }

    @Test func samplesArrivingOutOfOrderAreIgnored() {
        var h = TrafficHistory()
        feed(&h, seconds: 30, rate: steady(100, 50))
        let before = h.storedBucketCount
        h.record(inRate: 9_999, outRate: 9_999, at: epoch)          // clock stepped back
        #expect(h.storedBucketCount == before)
        #expect(h.latest?.avgIn == 100)
        #expect(h.samples(in: epoch...epoch.addingTimeInterval(30)).allSatisfy { $0.maxIn == 100 })
    }

    // MARK: Decimation

    @Test func decimationIntoTenSecondBucketsKeepsPeakAndTrueAverage() throws {
        // 4000 s of 100 B/s with one 5000 B/s second at t+5. Long enough that tier 0
        // has evicted the opening minutes, so the query MUST be answered from tier 1.
        var h = TrafficHistory()
        feed(&h, seconds: 4_000, rate: steady(100, 50, spikeAt: 5, spike: 5_000))

        let buckets = h.samples(in: epoch...epoch.addingTimeInterval(20))
        #expect(buckets.count == 3)
        #expect(buckets.allSatisfy { $0.interval == 10 })
        let first = try #require(buckets.first)
        #expect(first.start == epoch)
        // The burst survives coarsening…
        #expect(first.maxIn == 5_000)
        #expect(first.maxOut == 2_500)
        // …and the average is the mean of the ten samples underneath, not of means.
        #expect(abs(first.avgIn - (9 * 100 + 5_000) / 10) < 0.000_1)
        #expect(abs(first.avgOut - (9 * 50 + 2_500) / 10) < 0.000_1)
        // A quiet neighbour is untouched by the spike.
        let second = try #require(buckets.dropFirst().first)
        #expect(second.avgIn == 100)
        #expect(second.maxIn == 100)
    }

    @Test func decimationIntoOneMinuteBucketsKeepsPeakAndTrueAverage() throws {
        // A full day: tier 1 has now wrapped past the opening, so the oldest end of
        // the range can only be answered from the 60 s tier.
        var h = TrafficHistory()
        feed(&h, seconds: 86_400, rate: steady(200, 100, spikeAt: 30, spike: 12_000))

        let buckets = h.samples(in: epoch...epoch.addingTimeInterval(120))
        #expect(buckets.count == 3)
        #expect(buckets.allSatisfy { $0.interval == 60 })
        let first = try #require(buckets.first)
        #expect(first.start == epoch)
        #expect(first.maxIn == 12_000)               // the spike is still visible a day later
        #expect(first.maxOut == 6_000)
        #expect(abs(first.avgIn - (59 * 200 + 12_000) / 60) < 0.000_1)
        // The following minute never saw the spike.
        let second = try #require(buckets.dropFirst().first)
        #expect(second.maxIn == 200)
        #expect(second.avgIn == 200)
    }

    // MARK: Stitching

    @Test func tierStitchingIsMonotonicGaplessAndOverlapFree() throws {
        // 30 000 s ≈ 8 h 20 m: long enough that all three tiers are in play at once
        // (tier 0 holds the last hour, tier 1 has wrapped, tier 2 covers the rest).
        var h = TrafficHistory()
        feed(&h, seconds: 30_000, rate: steady(100, 50))

        let oldest = try #require(h.oldestTime)
        let newest = try #require(h.newestTime)
        let buckets = h.samples(in: oldest...newest)
        #expect(buckets.count > 100)

        // All three resolutions present, coarse → fine, never getting finer and then
        // coarser again (that would mean the segments were assembled out of order).
        let intervals = buckets.map(\.interval)
        #expect(Set(intervals) == [60, 10, 1])
        for (a, b) in zip(intervals, intervals.dropFirst()) { #expect(b <= a) }

        for (a, b) in zip(buckets, buckets.dropFirst()) {
            #expect(b.start > a.start)                                   // monotonic
            #expect(abs(b.start.timeIntervalSince(a.end)) < 0.001)       // gapless AND no overlap
        }
        #expect(buckets.first?.start == oldest)
        let lastStart = try #require(buckets.last).start
        #expect(abs(lastStart.timeIntervalSince(newest)) < 0.001)

        // The handovers land on the coarser tier's grid, which is what makes the
        // seams exact rather than "close enough".
        for (a, b) in zip(buckets, buckets.dropFirst()) where a.interval != b.interval {
            let offset = b.start.timeIntervalSinceReferenceDate
                .truncatingRemainder(dividingBy: a.interval)
            #expect(offset == 0)
        }
    }

    // MARK: Tier selection

    @Test func rangeQueriesPickTheRightTier() throws {
        var h = TrafficHistory()
        feed(&h, seconds: 30_000, rate: steady(100, 50))
        let end = try #require(h.newestTime)

        // Last minute → full resolution.
        let live = h.samples(in: end.addingTimeInterval(-60)...end)
        #expect(!live.isEmpty)
        #expect(live.allSatisfy { $0.interval == 1 })

        // Mid-history (inside tier 1's coverage, outside tier 0's hour) → 10 s.
        let mid = h.samples(in: epoch.addingTimeInterval(10_000)...epoch.addingTimeInterval(10_100))
        #expect(!mid.isEmpty)
        #expect(mid.allSatisfy { $0.interval == 10 })

        // The far past → 60 s.
        let old = h.samples(in: epoch...epoch.addingTimeInterval(300))
        #expect(!old.isEmpty)
        #expect(old.allSatisfy { $0.interval == 60 })

        // A range beyond anything recorded is empty rather than fabricated.
        #expect(h.samples(in: end.addingTimeInterval(600)...end.addingTimeInterval(1_200)).isEmpty)
        #expect(TrafficHistory().samples(in: epoch...end).isEmpty)
        #expect(TrafficHistory().isEmpty)
    }

    @Test func peakOverAVisibleWindowIgnoresSpikesOutsideIt() throws {
        var h = TrafficHistory()
        feed(&h, seconds: 4_000, rate: steady(100, 50, spikeAt: 5, spike: 5_000))
        let newest = try #require(h.newestTime)
        #expect(h.peak(in: epoch...epoch.addingTimeInterval(20)) == 5_000)
        // The recent window is quiet; the floor keeps an idle graph from scaling to noise.
        #expect(h.peak(in: newest.addingTimeInterval(-60)...newest) == 1_024)
    }

    // MARK: Memory

    @Test func memoryStaysBoundedAcrossADayOfInserts() throws {
        var h = TrafficHistory()
        feed(&h, seconds: 86_400, rate: steady(100, 50))

        #expect(TrafficHistory.capacity == 3_600 + 2_160 + 1_440)
        #expect(h.storedBucketCount <= TrafficHistory.capacity)
        let counts = h.tierCounts
        #expect(counts[0] == 3_600)                       // 1 h at 1 s, full and capped
        #expect(counts[1] == 2_160)                       // 6 h at 10 s, full and capped
        #expect(counts[2] <= 1_440)
        // Still reaches back a full day, and no further.
        #expect(try #require(h.oldestTime) == epoch)
        #expect(h.newestTime == epoch.addingTimeInterval(86_399))
    }

    @Test func memoryStopsGrowingOnceEveryTierIsFull() throws {
        var full = TrafficHistory()
        feed(&full, seconds: 90_000, rate: steady(100, 50))       // 25 h: every tier has wrapped
        #expect(full.tierCounts == [3_600, 2_160, 1_440])
        #expect(full.storedBucketCount == TrafficHistory.capacity)

        var longer = TrafficHistory()
        feed(&longer, seconds: 150_000, rate: steady(100, 50))    // 41 h — identical footprint
        #expect(longer.tierCounts == full.tierCounts)
        #expect(longer.storedBucketCount == TrafficHistory.capacity)

        // …and it has forgotten the oldest data rather than kept it: the window slid.
        let fullOldest = try #require(full.oldestTime)
        let longerOldest = try #require(longer.oldestTime)
        #expect(longerOldest > fullOldest)
        #expect(longerOldest == epoch.addingTimeInterval(150_000 - 86_400))
    }
}
