// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Testing
@testable import SimpleVPN

struct StandalonePacketPolicyConfigurationTests {
    @Test func protectedProfilesRejectProvidersWithOnlyVirtualRouting() throws {
        typealias Policy = StandalonePacketPolicyConfiguration
        let source = "on observe tcp.syn => count"
        var conf: [String: Any] = ["other": "kept"]
        try Policy.store(source, in: &conf)
        #expect(try Policy.source(in: conf) == source)
        let marker = try #require(conf["routingSession"] as? Data)
        // Released build 522 decodes this before engine dispatch and rejects a decoding error.
        #expect(throws: (any Error).self) { try JSONDecoder().decode(VirtualRoutingConfig.self, from: marker) }
        #expect(throws: (any Error).self) { try Policy.source(in: [Policy.sourceKey: source]) }
        #expect(throws: (any Error).self) { try Policy.source(in: ["routingSession": marker]) }
        #expect(throws: (any Error).self) { try Policy.source(in: ["routingSession": marker, Policy.sourceKey: 7]) }
        try Policy.store(nil, in: &conf)
        #expect(try Policy.source(in: conf) == nil)
        #expect(conf["other"] as? String == "kept")
    }

    @Test func invalidEditsPreserveThePreviousConfiguration() throws {
        typealias Policy = StandalonePacketPolicyConfiguration
        var conf: [String: Any] = [:]
        try Policy.store("previous", in: &conf)
        for source in ["", "a\u{0000}b", String(repeating: "é", count: 16_385)] {
            #expect(throws: (any Error).self) { try Policy.store(source, in: &conf) }
            #expect(try Policy.source(in: conf) == "previous")
        }
        let composition = Data("another format".utf8)
        var shared: [String: Any] = ["routingSession": composition]
        #expect(throws: (any Error).self) { try Policy.store("policy", in: &shared) }
        try Policy.store(nil, in: &shared)
        #expect(shared["routingSession"] as? Data == composition)
    }
}
