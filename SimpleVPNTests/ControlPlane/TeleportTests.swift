// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Testing
@testable import SimpleVPN

struct TeleportTests {
    @Test func inviteValidation() {
        let uuid = "b9e5a976-3ca6-45fb-85ba-bd30ce1d5527"
        #expect(TeleportSession.inviteProblem(uuid) == nil)
        #expect(TeleportSession.inviteProblem(" https://teleport.ui.link/\(uuid)\n") == nil)
        for bad in ["", "bad", "http://teleport.ui.link/\(uuid)",
                    "https://example.com/\(uuid)", "https://teleport.ui.link:443/\(uuid)",
                    "https://user@teleport.ui.link/\(uuid)", "https://teleport.ui.link/\(uuid)/extra",
                    "https://teleport.ui.link/\(uuid)?token=secret", "https://teleport.ui.link/\(uuid)#fragment"] {
            #expect(TeleportSession.inviteProblem(bad) != nil)
        }
    }

    @Test func oldWireGuardConfigsKeepTheirStaticConnection() throws {
        let config = try JSONDecoder().decode(WireGuardConfig.self, from: Data("{\"name\":\"Existing\"}".utf8))
        #expect(!config.usesTeleport)
        #expect(config.connectFault?.settingID == "wg.public-key")
    }

    @Test func teleportNegotiatesIdentityAndAddressesButStillValidatesRoutes() {
        var config = WireGuardConfig()
        config.usesTeleport = true
        #expect(config.connectProblem == nil)
        config.allowedIPs = ["192.168.10.0/24"]
        #expect(config.connectProblem == nil)
        config.allowedIPs = ["192.168.10.5/24"]
        #expect(config.connectFault?.settingID == "wg.allowed-ips")
    }

    @Test func secretsExistOnlyInThePrivateStartPayload() throws {
        var config = WireGuardConfig()
        config.usesTeleport = true
        let identity = TeleportSession(token: "test-sensitive-token", secret: "test-sensitive-secret")
        var start = WireGuardStartConfig(config: config, privateKey: "", presharedKey: "")
        start.teleport = identity
        start.clientName = "SimpleVPN"
        let encoded = start.jsonString()
        #expect(encoded.contains("session_token"))
        #expect(encoded.contains(identity.secret))
        #expect(!start.redactedJSONString().contains(identity.token))
        #expect(!start.redactedJSONString().contains(identity.secret))
        #expect(!identity.description.contains(identity.secret))
        let stored = try #require(config.redactedForStorage().encodedBlob())
        let persisted = String(decoding: stored, as: UTF8.self)
        #expect(!persisted.contains("session_token"))
        #expect(!persisted.contains(identity.secret))
        #expect(try JSONDecoder().decode(WireGuardConfig.self, from: stored).usesTeleport)
    }

    @Test func virtualCompositionAcceptsNegotiatedAddressesWithoutPersistingIdentity() throws {
        var a = WireGuardConfig(); a.usesTeleport = true; a.id = "a"
        var b = a; b.id = "b"
        let config = VirtualRoutingConfig(id: "fixture", members: [
            .init(id: "a", wireGuard: a, prefixes: []), .init(id: "b", wireGuard: b, prefixes: [])
        ], policy: .init(defaultOwner: "a"))
        #expect(config.problem == nil)
        let data = try JSONEncoder().encode(config)
        #expect(!String(decoding: data, as: UTF8.self).contains("session_secret"))
        let status = try #require(WireGuardEngineStatus.decode(json:
            #"{"state":"running","addresses":["192.168.88.5/32","fd00::5/128"],"dns":["192.168.88.1"]}"#))
        #expect(status.addresses.count == 2)
        #expect(status.dns == ["192.168.88.1"])
    }
}
