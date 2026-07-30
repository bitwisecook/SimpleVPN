// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  TrafficHistory.swift
//  The throughput store behind EVERY graph in the app — one instance per key
//  (profile id for tunnel counters, BSD interface name for link counters).
//
//  Why tiers rather than one flat window: a 60-sample window meant the graphs only
//  ever knew about the last minute, and anything longer had to be squashed into the
//  pane width, so an hour of history rendered as a smear. Instead this keeps a
//  fixed-cost pyramid — recent time at full resolution, older time progressively
//  coarser — and the chart scrolls over it:
//
//      tier 0 :   1 s buckets × 3600  →  the last  1 hour, full resolution
//      tier 1 :  10 s buckets × 2160  →  the last  6 hours
//      tier 2 :  60 s buckets × 1440  →  the last 24 hours
//
//  A bucket that falls off the end of a tier has ALREADY been folded into the next
//  one at the moment it closed (`cascade`), carrying both the running sum/weight
//  (so the coarse average is the true average of the samples underneath, not an
//  average of averages) AND the max of both directions. Keeping the max is the whole
//  point of storing four numbers instead of two: a 200 Mb/s spike lasting three
//  seconds still shows as a 200 Mb/s peak in a 60 s bucket, so coarse history reads
//  as "there was a burst here", not as a 10 Mb/s plateau.
//
//  MEMORY BOUND (the reason the tiers are capped rather than "keep everything"):
//  3600 + 2160 + 1440 = 7200 buckets per key, forever — inserts never grow it.
//  Each stored bucket is a `Date` + 5 `Double`s = 48 bytes, so ~346 KB per key
//  (~2.4 MB even with eight interfaces plus a handful of tunnels being graphed).
//  Each tier is a fixed-capacity ring buffer, so a 1 Hz insert is O(1) with no
//  reallocation and no array shuffling once the ring is full.
//

import Foundation

nonisolated struct TrafficHistory: Sendable {

    // MARK: - Public shape

    /// One aggregated slice of time. `avg*` is the mean rate over the slice,
    /// `max*` the highest 1 s rate seen inside it — equal at tier 0, where the
    /// slice IS a single sample.
    struct Bucket: Sendable, Equatable, Identifiable {
        /// Start of the slice, aligned to a multiple of `interval` since the
        /// reference date — so buckets from one tier always tile exactly.
        let start: Date
        /// Width of the slice in seconds (1, 10 or 60 — which tier served it).
        let interval: TimeInterval
        let avgIn: Double
        let avgOut: Double
        let maxIn: Double
        let maxOut: Double

        var end: Date { start.addingTimeInterval(interval) }
        /// Plot position: the middle of the slice, which is where its average
        /// actually belongs on a time axis.
        var mid: Date { start.addingTimeInterval(interval / 2) }
        var id: Date { start }
        /// Peak across both directions — the y-ceiling contribution of this slice.
        var peak: Double { max(maxIn, maxOut) }
    }

    /// Tier geometry, finest first. Public so the tests (and anyone reasoning
    /// about the memory bound) read the same numbers the store uses.
    static let tierIntervals: [TimeInterval] = [1, 10, 60]
    static let tierCapacities: [Int] = [3600, 2160, 1440]
    /// Total buckets retained per key, across all tiers — the hard memory bound.
    static let capacity: Int = tierCapacities.reduce(0, +)

    /// How far back the store can possibly reach (24 h).
    static let span: TimeInterval = tierIntervals[tierIntervals.count - 1]
        * TimeInterval(tierCapacities[tierCapacities.count - 1])

    private var tiers: [Ring]

    init() {
        tiers = zip(Self.tierIntervals, Self.tierCapacities).map { Ring(interval: $0, capacity: $1) }
    }

    // MARK: - Ingest

    /// Fold one 1 Hz throughput sample in. `time` must be non-decreasing across
    /// calls; a sample that arrives out of order (clock stepped back) is dropped
    /// rather than corrupting a closed bucket.
    mutating func record(inRate: Double, outRate: Double, at time: Date = Date()) {
        let i = max(0, inRate), o = max(0, outRate)
        add(tier: 0, at: time, sumIn: i, sumOut: o, maxIn: i, maxOut: o, weight: 1)
    }

    private mutating func add(tier index: Int, at time: Date,
                              sumIn: Double, sumOut: Double,
                              maxIn: Double, maxOut: Double, weight: Double) {
        guard index < tiers.count else { return }
        let start = Self.align(time, to: tiers[index].interval)

        if let current = tiers[index].newest {
            if current.start == start {
                tiers[index].mergeIntoNewest(sumIn: sumIn, sumOut: sumOut,
                                             maxIn: maxIn, maxOut: maxOut, weight: weight)
                return
            }
            guard start > current.start else { return }   // out of order → ignore
            // The newest bucket just closed: decimate it down into the coarser tier
            // before it can ever be evicted, so nothing is lost when the ring wraps.
            cascade(from: index, current)
        }
        tiers[index].append(Accum(start: start, sumIn: sumIn, sumOut: sumOut,
                                  maxIn: maxIn, maxOut: maxOut, weight: weight))
    }

    private mutating func cascade(from index: Int, _ closed: Accum) {
        guard index + 1 < tiers.count else { return }
        add(tier: index + 1, at: closed.start,
            sumIn: closed.sumIn, sumOut: closed.sumOut,
            maxIn: closed.maxIn, maxOut: closed.maxOut, weight: closed.weight)
    }

    // MARK: - Queries

    /// Buckets covering `range`, at the finest resolution each part of it still
    /// has — tier 0 for the recent end, then tier 1, then tier 2 further back.
    ///
    /// The handover between tiers is placed on a boundary of the COARSER tier, so
    /// the segments abut exactly: the last coarse bucket ends precisely where the
    /// first fine bucket begins. No gap (nothing between them is unrepresented)
    /// and no overlap (no instant is counted twice), which is what lets a scrolling
    /// chart cross an hour boundary without a visible seam or a doubled line.
    /// Result is ordered oldest → newest with strictly increasing `start`.
    func samples(in range: ClosedRange<Date>) -> [Bucket] {
        // Where each finer tier takes over, rounded UP to the coarser tier's grid.
        var handover = [Date?](repeating: nil, count: tiers.count)
        for i in 0..<(tiers.count - 1) {
            guard let oldest = tiers[i].oldest?.start else { continue }
            handover[i] = Self.align(oldest, to: tiers[i + 1].interval, rounding: .up)
        }

        var out: [Bucket] = []
        // Coarsest first so the output comes out in time order.
        for i in stride(from: tiers.count - 1, through: 0, by: -1) {
            // This tier serves from its own handover point (or the start of the
            // request) up to the point the next finer tier takes over.
            let lower = handover[i].map { max($0, range.lowerBound) } ?? range.lowerBound
            let upper = i > 0 ? (handover[i - 1] ?? Date.distantFuture) : Date.distantFuture
            guard lower < upper else { continue }
            out.append(contentsOf: tiers[i].buckets(overlapping: lower, before: upper,
                                                    notAfter: range.upperBound))
        }
        return out
    }

    /// The newest `count` full-resolution (1 s) buckets — the shape the old flat
    /// rolling window had, for the readouts, sparklines and compact graphs that
    /// only ever wanted "the last minute".
    func recent(_ count: Int) -> [Bucket] { tiers[0].newest(count) }

    /// Newest bucket at full resolution — the "current rate".
    var latest: Bucket? { tiers[0].newest.map { $0.bucket(interval: tiers[0].interval) } }

    /// Timestamp of the newest sample, or nil if nothing has been recorded. The
    /// scrolling chart follows THIS rather than wall-clock `Date()`, so it advances
    /// on data arriving instead of needing a poller of its own.
    var newestTime: Date? { tiers[0].newest?.start }
    var oldestTime: Date? {
        for i in stride(from: tiers.count - 1, through: 0, by: -1) {
            if let t = tiers[i].oldest?.start { return t }
        }
        return nil
    }

    var isEmpty: Bool { tiers.allSatisfy { $0.count == 0 } }
    /// Buckets currently retained across all tiers — bounded by `capacity`.
    var storedBucketCount: Int { tiers.reduce(0) { $0 + $1.count } }
    /// Per-tier retained counts, finest first (diagnostics and tests).
    var tierCounts: [Int] { tiers.map(\.count) }

    /// Highest rate in either direction anywhere in `range`, floored at 1 KB/s so
    /// an idle graph doesn't scale itself to noise.
    func peak(in range: ClosedRange<Date>) -> Double {
        max(1_024, samples(in: range).map(\.peak).max() ?? 0)
    }

    // MARK: - Bucket alignment

    static func align(_ time: Date, to interval: TimeInterval,
                      rounding rule: FloatingPointRoundingRule = .down) -> Date {
        let t = time.timeIntervalSinceReferenceDate / interval
        return Date(timeIntervalSinceReferenceDate: t.rounded(rule) * interval)
    }

    // MARK: - Storage

    /// A bucket while it is still accumulating: running sums plus running maxima.
    /// `weight` is the number of 1 s samples folded in, which is what makes the
    /// coarse average a true average rather than an average of averages.
    private struct Accum: Sendable {
        var start: Date
        var sumIn: Double = 0
        var sumOut: Double = 0
        var maxIn: Double = 0
        var maxOut: Double = 0
        var weight: Double = 0

        func bucket(interval: TimeInterval) -> Bucket {
            let w = weight > 0 ? weight : 1
            return Bucket(start: start, interval: interval,
                          avgIn: sumIn / w, avgOut: sumOut / w,
                          maxIn: maxIn, maxOut: maxOut)
        }
    }

    /// Fixed-capacity ring of buckets, oldest at `head`. Once full, appending
    /// overwrites the oldest slot: O(1), no reallocation, no memmove.
    private struct Ring: Sendable {
        let interval: TimeInterval
        let capacity: Int
        private var storage: [Accum] = []
        private var head = 0

        init(interval: TimeInterval, capacity: Int) {
            self.interval = interval
            self.capacity = max(1, capacity)
        }

        var count: Int { storage.count }

        /// 0 = oldest.
        private func element(_ i: Int) -> Accum { storage[(head + i) % storage.count] }

        var oldest: Accum? { storage.isEmpty ? nil : element(0) }
        var newest: Accum? { storage.isEmpty ? nil : element(storage.count - 1) }

        mutating func append(_ a: Accum) {
            if storage.count < capacity {
                storage.append(a)                 // never wrapped yet ⇒ head is 0
            } else {
                storage[head] = a
                head = (head + 1) % capacity
            }
        }

        mutating func mergeIntoNewest(sumIn: Double, sumOut: Double,
                                      maxIn: Double, maxOut: Double, weight: Double) {
            guard !storage.isEmpty else { return }
            let i = (head + storage.count - 1) % storage.count
            storage[i].sumIn += sumIn
            storage[i].sumOut += sumOut
            storage[i].maxIn = max(storage[i].maxIn, maxIn)
            storage[i].maxOut = max(storage[i].maxOut, maxOut)
            storage[i].weight += weight
        }

        func newest(_ n: Int) -> [Bucket] {
            guard n > 0, !storage.isEmpty else { return [] }
            let take = min(n, storage.count)
            return (storage.count - take..<storage.count).map { element($0).bucket(interval: interval) }
        }

        /// Buckets whose coverage overlaps `[lower, …)`, that begin before `upper`,
        /// and that begin no later than `notAfter`. Half-open on `upper` is what
        /// makes the tier handover exact: the bucket ending exactly AT the handover
        /// belongs to the coarse tier, the one starting there to the fine tier.
        func buckets(overlapping lower: Date, before upper: Date, notAfter: Date) -> [Bucket] {
            guard !storage.isEmpty else { return [] }
            var out: [Bucket] = []
            for i in 0..<storage.count {
                let a = element(i)
                if a.start > notAfter { break }          // ordered ⇒ nothing later qualifies
                guard a.start < upper else { break }
                guard a.start.addingTimeInterval(interval) > lower else { continue }
                out.append(a.bucket(interval: interval))
            }
            return out
        }
    }
}
