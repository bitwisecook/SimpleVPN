// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Observation

@MainActor @Observable final class RoutingFilterActivity {
    enum Rule: Hashable { case route(UUID?), resolver(UUID?), proxy }
    struct Sample: Identifiable {
        var id: Int64
        var matches: Int
    }
    struct Counter {
        var total = 0
        var samples: [Sample] = []
        mutating func hit(minute: Int64) {
            total += 1
            if samples.last?.id == minute {
                samples[samples.count - 1].matches += 1
            } else {
                samples.removeAll { $0.id <= minute - 60 || $0.id > minute }
                samples.append(Sample(id: minute, matches: 1))
            }
        }
    }
    private var byProfile: [String: [Rule: Counter]] = [:]
    func hit(_ profile: String, _ rule: Rule) {
        let minute = Int64(Date().timeIntervalSince1970 / 60)
        byProfile[profile, default: [:]][rule, default: Counter()].hit(minute: minute)
    }
    func counter(_ profile: String, _ rule: Rule) -> Counter { byProfile[profile]?[rule] ?? Counter() }
    func clear(_ profile: String) { byProfile[profile] = nil }
    func retainRules(for id: String, profile: CustomRoutingProfile) {
        guard let old = byProfile[id] else { return }
        let keys = Set(profile.routes.rules.map { Rule.route($0.id) } + profile.dns.resolverRules.map { Rule.resolver($0.id) })
        byProfile[id] = old.filter { key, _ in
            switch key {
            case .route(nil): !profile.routes.isIdentity
            case .resolver(nil): !profile.dns.isIdentity
            case .proxy: !profile.proxy.isIdentity
            default: keys.contains(key)
            }
        }
    }
}
