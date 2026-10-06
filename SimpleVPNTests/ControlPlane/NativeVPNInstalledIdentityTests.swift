// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
@preconcurrency import NetworkExtension
import Testing
@testable import SimpleVPN

struct NativeVPNInstalledIdentityTests {
    @Test func installedIdentityRejectsAnotherProfileAndNeverEncodesSecrets() throws {
        let p = NEVPNProtocolIKEv2()
        p.serverAddress = "vpn.example.com"; p.remoteIdentifier = "vpn.example.com"; p.username = "alice"
        p.passwordReference = Data("PRIVATE_REFERENCE_CANARY".utf8)
        let installed = try #require(NativeVPNInstalledIdentity(id: "first", protocol: p))
        let restored = try JSONDecoder().decode(NativeVPNInstalledIdentity.self, from: JSONEncoder().encode(installed))
        #expect(restored.matches(p))
        #expect(!String(decoding: try JSONEncoder().encode(installed), as: UTF8.self).contains("PRIVATE_REFERENCE_CANARY"))
        let other = try #require(p.copy() as? NEVPNProtocolIKEv2)
        other.username = "bob"
        #expect(!restored.matches(other))
        other.username = "alice"; other.remoteIdentifier = "other.example.com"
        #expect(!restored.matches(other))
        #expect(!restored.matches(NEVPNProtocolIPSec()))
    }
}

struct NativeProxyCredentialsTests {
    @Test func authenticatedNativeProxiesAreGatedAndLegacyCopiesAreRedacted() {
        let settings=NEProxySettings(), server=NEProxyServer(address:"proxy.example.com",port:8080)
        server.authenticationRequired=true; server.username="test"; server.password="TEST_ONLY_PROXY_SECRET"
        settings.httpServer=server; settings.httpEnabled=true
        #expect(NativeProxyCredentials.requiresBroker(settings))
        #expect(NativeProxyCredentials.hasStoredSecret(settings))
        let redacted=NativeProxyCredentials.redacted(settings)
        #expect(!NativeProxyCredentials.hasStoredSecret(redacted))
        #expect(redacted.httpEnabled)
        #expect(redacted.httpServer?.address == server.address)
        #expect(settings.httpServer?.password == "TEST_ONLY_PROXY_SECRET")
        // A required signature cannot silently become anonymous after redaction.
        #expect(NativeProxyCredentials.requiresBroker(redacted))
        let anonymous=NEProxySettings(); anonymous.httpServer=NEProxyServer(address:"proxy.example.com",port:8080)
        #expect(!NativeProxyCredentials.requiresBroker(anonymous))
    }
}
