// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Network

/// Immutable after the provider admits a configuration. Rust indexes exact and
/// suffix rules and evaluates globs with a fixed-size set of active states.
nonisolated final class DNSRoutingPlan: Sendable {
    enum Match { case matched(Int), original, invalid }
    enum PlanError: LocalizedError {
        case invalid
        var errorDescription: String? { "The DNS routing core could not compile the query rules." }
    }
    private nonisolated(unsafe) let plan: OpaquePointer
    init(_ policy: DNSQueryPolicy) throws {
        guard policy.problem == nil, let raw = rc_dns_plan_new() else { throw PlanError.invalid }
        for (index, route) in policy.routes.enumerated() where route.rule.enabled {
            guard let pattern = route.rule.match.compiledPattern,
                  pattern.bytes.withUnsafeBufferPointer({ rc_dns_plan_add(raw, UInt16(index), pattern.kind, $0.baseAddress, UInt32($0.count)) })
            else { rc_dns_plan_free(raw); throw PlanError.invalid }
        }
        plan = raw
    }
    deinit { rc_dns_plan_free(plan) }
    func lookup(_ canonicalName: String) -> Match {
        var name = canonicalName
        return name.withUTF8 { bytes in
            let result = rc_dns_match(plan, bytes.baseAddress, UInt32(bytes.count))
            switch result.status {
            case RC_DNS_MATCHED.rawValue: return .matched(Int(result.index))
            case RC_DNS_UNMATCHED.rawValue: return .original
            default: return .invalid
            }
        }
    }
}

/// Query policy execution, shared by the provider and transport-injected runtime tests.
/// No fallback to the original resolver after an explicit resolver rule matched.
actor DNSQueryForwarder {
    typealias Transport = @Sendable (Data, NWEndpoint, Bool) async -> Data?
    private let plan: DNSRoutingPlan
    private let policy: DNSQueryPolicy
    private let transport: Transport
    private let capacity: Int
    private var inFlight = 0
    private var counts: [DNSQueryCounts]
    func activityCounts() -> [DNSQueryCounts] { counts }

    init(policy: DNSQueryPolicy, capacity: Int = 256,
         transport: @escaping Transport = { await DNSQueryExchange.run(query: $0, endpoint: $1, tcp: $2) }) throws {
        plan = try DNSRoutingPlan(policy)
        self.counts = Array(repeating: DNSQueryCounts(), count: policy.routes.count + 1)
        self.policy = policy; self.transport = transport; self.capacity = max(1, min(256, capacity))
    }
    func answer(_ query: Data, original: NWEndpoint, tcp: Bool) async -> Data? {
        guard !Task.isCancelled, query.count <= DNSWireMessage.maximumSize else { return nil }
        guard let question = DNSWireMessage.question(query), question.type != 251, question.type != 252 else {
            return DNSWireMessage.failure(for: query)
        }
        guard inFlight < capacity else { return DNSWireMessage.failure(for: query) }
        inFlight += 1
        defer { inFlight -= 1 }
        let match: Int?
        switch plan.lookup(question.name) {
        case .matched(let index): match = index
        case .original: match = nil
        case .invalid: return DNSWireMessage.failure(for: query)
        }
        let row = match ?? policy.routes.count
        counts[row].matches &+= 1
        counts[row].queryBytes &+= UInt64(query.count)
        var answered = false
        defer {
            if !answered { counts[row].failed &+= 1 }
        }
        let route = match.map { policy.routes[$0] }
        let endpoints: [NWEndpoint]
        if let route, route.rule.target == .resolvers {
            endpoints = route.servers.map { .hostPort(host: NWEndpoint.Host($0), port: 53) }
        } else { endpoints = [original] }
        for endpoint in endpoints {
            if Task.isCancelled { return nil }
            if let reply = await transport(query, endpoint, tcp), !Task.isCancelled,
               DNSWireMessage.response(reply, matches: query) {
                counts[row].answered &+= 1
                counts[row].replyBytes &+= UInt64(reply.count)
                answered = true
                return reply
            }
        }
        return DNSWireMessage.failure(for: query)
    }
}
