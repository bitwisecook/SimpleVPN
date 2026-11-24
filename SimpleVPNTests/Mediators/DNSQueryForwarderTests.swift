// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Network
import Testing
@testable import SimpleVPN

private actor QueryTransportRecorder {
    var endpoints: [NWEndpoint] = []
    var messages: [Data] = []
    let fail: Bool
    init(fail: Bool = false) { self.fail = fail }
    func exchange(_ query: Data, _ endpoint: NWEndpoint, _ tcp: Bool) -> Data? {
        endpoints.append(endpoint); messages.append(query)
        guard !fail else { return nil }
        var reply = query; reply[2] |= 0x80; reply[3] |= 0x80; return reply
    }
}

@MainActor
struct DNSQueryForwarderTests {
    private let original = NWEndpoint.hostPort(host: "127.0.0.1", port: 5300)
    private func policy(_ kind: DNSNameMatch.Kind, _ pattern: String,
                        target: DNSQueryRule.Target = .resolvers, servers: [String] = ["192.0.2.53"]) -> DNSQueryPolicy {
        let rule = DNSQueryRule(match: .init(kind: kind, pattern: pattern), target: target, servers: servers)
        return DNSQueryPolicy(routes: [.init(profileID: "a", profileName: "Lab", rule: rule, servers: servers)])
    }
    @Test func nativeMatcherAgreesWithPreviewAcrossRuleOrderingAndGlobClasses() throws {
        let patterns: [(DNSNameMatch.Kind, String)] = [(.glob, "db[0-9]?.lab"), (.suffix, "lab"),
            (.exact, "db77.lab"), (.glob, "a**[!0-9]x"), (.glob, "ab\\*cd"), (.exact, "host")]
        let routes = patterns.flatMap { policy($0.0, $0.1).routes }
        for ordered in [routes, Array(routes.reversed())] {
            let source = DNSQueryPolicy(routes: ordered)
            let plan = try DNSRoutingPlan(source)
            for name in ["db01.lab", "lab", "other.lab", "db77.lab", "ab*cd", "alphax", "a9x", "host", "unmatched", "."] {
                switch plan.lookup(name) {
                case .matched(let index): #expect(source.routeIndex(for: name) == index)
                case .original: #expect(source.routeIndex(for: name) == nil)
                case .invalid: Issue.record("DNS plan rejected a parsed question")
                }
            }
        }
    }

    @Test(arguments: [DNSNameMatch.Kind.exact, .glob]) func actualForwardingSelectsTheRuleResolver(_ kind: DNSNameMatch.Kind) async throws {
        let recorder = QueryTransportRecorder()
        let router = try DNSQueryForwarder(policy: policy(kind, kind == .glob ? "*.example" : "portal.example"),
                                      transport: { await recorder.exchange($0, $1, $2) })
        let query = DNSWireMessageTests.query("portal.example")
        #expect(await router.answer(query, original: original, tcp: false) != nil)
        #expect(await recorder.endpoints == [.hostPort(host: "192.0.2.53", port: 53)])
        #expect(await recorder.messages == [query])
    }
    @Test func actualActivityAttributesRetriesFallbacksAndBytesWithoutRecordingNames() async throws {
        let working = policy(.exact, "lab.example")
        var broken = policy(.suffix, "example", servers: ["192.0.2.54", "192.0.2.55"]).routes[0]
        broken.profileID = "other"
        var policy = working
        policy.routes.append(broken)
        let router = try DNSQueryForwarder(policy: policy) { query, endpoint, _ in
            if endpoint == .hostPort(host: "192.0.2.54", port: 53) || endpoint == .hostPort(host: "192.0.2.55", port: 53) { return nil }
            var reply = query
            reply[2] |= 0x80
            reply[3] |= 3 // Valid NXDOMAIN is still an upstream answer.
            return reply
        }
        let matched = DNSWireMessageTests.query("lab.example")
        let failed = DNSWireMessageTests.query("other.example")
        let fallback = DNSWireMessageTests.query("unmatched.test")
        // Draft preview and a malformed query do not execute any rule.
        _ = policy.route(for: "lab.example")
        _ = await router.answer(Data([0, 1]), original: original, tcp: false)
        #expect(await router.activityCounts() == [DNSQueryCounts](repeating: DNSQueryCounts(), count: 3))
        _ = await router.answer(matched, original: original, tcp: false)
        _ = await router.answer(failed, original: original, tcp: true)
        _ = await router.answer(fallback, original: original, tcp: false)
        let rows = await router.activityCounts()
        #expect(rows == [
            DNSQueryCounts(matches: 1, answered: 1, failed: 0, queryBytes: UInt64(matched.count), replyBytes: UInt64(matched.count)),
            DNSQueryCounts(matches: 1, answered: 0, failed: 1, queryBytes: UInt64(failed.count), replyBytes: 0),
            DNSQueryCounts(matches: 1, answered: 1, failed: 0, queryBytes: UInt64(fallback.count), replyBytes: UInt64(fallback.count))
        ])
        let digest = DNSQueryActivity.digest(try DNSQueryActivity.configurationData(policy))
        let result = DNSQueryActivity(session: UUID(), generation: digest, rows: rows)
        #expect(result.agrees(with: digest, ruleCount: 2))
        #expect(!result.agrees(with: digest, ruleCount: 1))
        #expect(!result.agrees(with: Data(repeating: 0, count: 32), ruleCount: 2))
        let encoded = try JSONEncoder().encode(result)
        #expect(!String(decoding: encoded, as: UTF8.self).contains("example"))
        #expect(!String(decoding: encoded, as: UTF8.self).contains("unmatched.test"))
    }
    @Test func unmatchedQueriesKeepTheOriginalEndpoint() async throws {
        let recorder = QueryTransportRecorder()
        let router = try DNSQueryForwarder(policy: policy(.exact, "portal.example"), transport: { await recorder.exchange($0, $1, $2) })
        _ = await router.answer(DNSWireMessageTests.query("child.portal.example"), original: original, tcp: true)
        #expect(await recorder.endpoints == [original])
    }
    @Test func matchedResolverFailureNeverTriesOriginal() async throws {
        let recorder = QueryTransportRecorder(fail: true)
        let router = try DNSQueryForwarder(policy: policy(.glob, "*.example", servers: ["192.0.2.53", "192.0.2.54"]),
                                      transport: { await recorder.exchange($0, $1, $2) })
        let reply = try #require(await router.answer(DNSWireMessageTests.query("portal.example"), original: original, tcp: false))
        #expect(reply[3] & 15 == 2)
        #expect(await recorder.endpoints == [.hostPort(host: "192.0.2.53", port: 53), .hostPort(host: "192.0.2.54", port: 53)])
    }
    @Test func explicitOriginalTargetDoesNotRewriteResolver() async throws {
        let recorder = QueryTransportRecorder()
        let router = try DNSQueryForwarder(policy: policy(.exact, "portal.example", target: .original, servers: []),
                                      transport: { await recorder.exchange($0, $1, $2) })
        _ = await router.answer(DNSWireMessageTests.query("portal.example"), original: original, tcp: false)
        #expect(await recorder.endpoints == [original])
    }
    @Test func missingResolverFailsWithoutOpeningAnyConnection() async throws {
        let recorder = QueryTransportRecorder()
        let router = try DNSQueryForwarder(policy: policy(.exact, "portal.example", servers: []), transport: { await recorder.exchange($0, $1, $2) })
        let reply = try #require(await router.answer(DNSWireMessageTests.query("portal.example"), original: original, tcp: false))
        #expect(reply[3] & 15 == 2)
        #expect(await recorder.endpoints.isEmpty)
    }
}
