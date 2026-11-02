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
    @Test(arguments: [DNSNameMatch.Kind.exact, .glob]) func actualForwardingSelectsTheRuleResolver(_ kind: DNSNameMatch.Kind) async throws {
        let recorder = QueryTransportRecorder()
        let router = DNSQueryForwarder(policy: policy(kind, kind == .glob ? "*.example" : "portal.example"),
                                      transport: { await recorder.exchange($0, $1, $2) })
        let query = DNSWireMessageTests.query("portal.example")
        #expect(await router.answer(query, original: original, tcp: false) != nil)
        #expect(await recorder.endpoints == [.hostPort(host: "192.0.2.53", port: 53)])
        #expect(await recorder.messages == [query])
    }
    @Test func unmatchedQueriesKeepTheOriginalEndpoint() async {
        let recorder = QueryTransportRecorder()
        let router = DNSQueryForwarder(policy: policy(.exact, "portal.example"), transport: { await recorder.exchange($0, $1, $2) })
        _ = await router.answer(DNSWireMessageTests.query("child.portal.example"), original: original, tcp: true)
        #expect(await recorder.endpoints == [original])
    }
    @Test func matchedResolverFailureNeverTriesOriginal() async throws {
        let recorder = QueryTransportRecorder(fail: true)
        let router = DNSQueryForwarder(policy: policy(.glob, "*.example", servers: ["192.0.2.53", "192.0.2.54"]),
                                      transport: { await recorder.exchange($0, $1, $2) })
        let reply = try #require(await router.answer(DNSWireMessageTests.query("portal.example"), original: original, tcp: false))
        #expect(reply[3] & 15 == 2)
        #expect(await recorder.endpoints == [.hostPort(host: "192.0.2.53", port: 53), .hostPort(host: "192.0.2.54", port: 53)])
    }
    @Test func explicitOriginalTargetDoesNotRewriteResolver() async {
        let recorder = QueryTransportRecorder()
        let router = DNSQueryForwarder(policy: policy(.exact, "portal.example", target: .original, servers: []),
                                      transport: { await recorder.exchange($0, $1, $2) })
        _ = await router.answer(DNSWireMessageTests.query("portal.example"), original: original, tcp: false)
        #expect(await recorder.endpoints == [original])
    }
    @Test func missingResolverFailsWithoutOpeningAnyConnection() async throws {
        let recorder = QueryTransportRecorder()
        let router = DNSQueryForwarder(policy: policy(.exact, "portal.example", servers: []), transport: { await recorder.exchange($0, $1, $2) })
        let reply = try #require(await router.answer(DNSWireMessageTests.query("portal.example"), original: original, tcp: false))
        #expect(reply[3] & 15 == 2)
        #expect(await recorder.endpoints.isEmpty)
    }
}
