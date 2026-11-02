// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Network

/// Query policy execution, shared by the provider and transport-injected runtime tests.
/// No fallback to the original resolver after an explicit resolver rule matched.
actor DNSQueryForwarder {
    typealias Transport = @Sendable (Data, NWEndpoint, Bool) async -> Data?
    private let policy: DNSQueryPolicy
    private let transport: Transport
    private let capacity: Int
    private var inFlight = 0
    init(policy: DNSQueryPolicy, capacity: Int = 256,
         transport: @escaping Transport = { await DNSQueryExchange.run(query: $0, endpoint: $1, tcp: $2) }) {
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
        let route = policy.route(for: question.name)
        let endpoints: [NWEndpoint]
        if let route, route.rule.target == .resolvers {
            endpoints = route.servers.map { .hostPort(host: NWEndpoint.Host($0), port: 53) }
        } else { endpoints = [original] }
        for endpoint in endpoints {
            if Task.isCancelled { return nil }
            if let reply = await transport(query, endpoint, tcp), DNSWireMessage.response(reply, matches: query) { return reply }
        }
        return DNSWireMessage.failure(for: query)
    }
}
