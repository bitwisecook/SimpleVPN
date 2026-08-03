// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  WireGuardTests.swift
//  The WireGuard engine cannot be exercised without a live peer, so everything
//  that CAN go silently wrong without one is pinned here: the JSON contract
//  with the Go shim (field names on both sides — the Go twin is
//  TestWGStartConfigKeys in Vendor/tailscale-engine/src/wireguard_test.go),
//  the endpoint/route validation the editor and the engine must agree on, and
//  the config → NEPacketTunnelNetworkSettings mapping — the translation that
//  can produce a tunnel which connects and carries nothing.
//

import Foundation
import NetworkExtension
import Testing
@testable import SimpleVPN

struct WireGuardStartConfigTests {

    // MARK: Start-payload contract (must match Vendor/tailscale-engine/src/wireguard.go)

    @Test func startConfigEncodesExactlyTheKeysTheEngineParses() throws {
        var c = WireGuardConfig()
        c.peerPublicKey = "PUBKEY"
        c.endpoint = "vpn.example.com:51820"
        c.allowedIPs = ["0.0.0.0/0", "::/0"]
        c.persistentKeepalive = 25
        c.mtu = 1400

        let start = WireGuardStartConfig(config: c, privateKey: "PRIV", presharedKey: "PSK")
        let json = start.jsonString()
        let obj = try #require(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])

        // wgStartConfig in wireguard.go: these names are the contract.
        let expected: Set<String> = ["privateKey", "peerPublicKey", "presharedKey", "endpoint",
                                     "allowedIPs", "persistentKeepalive", "listenPort", "mtu"]
        #expect(Set(obj.keys) == expected)
        #expect(obj["privateKey"] as? String == "PRIV")
        #expect(obj["peerPublicKey"] as? String == "PUBKEY")
        #expect(obj["presharedKey"] as? String == "PSK")
        #expect(obj["endpoint"] as? String == "vpn.example.com:51820")
        #expect(obj["allowedIPs"] as? [String] == ["0.0.0.0/0", "::/0"])
        #expect(obj["persistentKeepalive"] as? Int == 25)
        #expect(obj["listenPort"] as? Int == 0)
        #expect(obj["mtu"] as? Int == 1400)
    }

    @Test func startPayloadRedactsTheKeys() {
        var c = WireGuardConfig()
        c.peerPublicKey = "peer-public-ok-to-show"
        c.endpoint = "h:1"
        let start = WireGuardStartConfig(config: c, privateKey: "very-private", presharedKey: "also-secret")
        let redacted = start.redactedJSONString()
        #expect(!redacted.contains("very-private"))
        #expect(!redacted.contains("also-secret"))
        #expect(redacted.contains("<redacted>"))
        // The peer's PUBLIC key stays — public by construction, and the useful
        // diagnostic when a config points at the wrong server.
        #expect(redacted.contains("peer-public-ok-to-show"))
    }

    @Test func mtuFallsBackWhenUnset() {
        var c = WireGuardConfig()
        c.endpoint = "h:1"
        c.mtu = nil
        let start = WireGuardStartConfig(config: c, privateKey: "k", presharedKey: "")
        #expect(start.mtu == WireGuardStartConfig.defaultMTU)
        #expect(WireGuardStartConfig.defaultMTU == 1420)
    }

    // MARK: Validation (mirrors wgResolveEndpoint / parseRoutes in the Go shim)

    @Test func endpointValidationMatchesEngine() {
        #expect(WireGuardConfig.endpointProblem("vpn.example.com:51820") == nil)
        #expect(WireGuardConfig.endpointProblem("192.0.2.1:51820") == nil)
        #expect(WireGuardConfig.endpointProblem("[2001:db8::1]:51820") == nil)
        // Rejections.
        #expect(WireGuardConfig.endpointProblem("") != nil)
        #expect(WireGuardConfig.endpointProblem("no-port-here") != nil)
        #expect(WireGuardConfig.endpointProblem("host:notaport") != nil)
        #expect(WireGuardConfig.endpointProblem("host:99999") != nil)
        #expect(WireGuardConfig.endpointProblem("2001:db8::1") != nil)   // v6 needs brackets
        #expect(WireGuardConfig.endpointProblem(":51820") != nil)        // no host
    }

    @Test func routeValidationMatchesEngine() {
        #expect(WireGuardConfig.routeProblem("0.0.0.0/0") == nil)
        #expect(WireGuardConfig.routeProblem("10.44.0.0/16") == nil)
        #expect(WireGuardConfig.routeProblem("::/0") == nil)
        // The engine's parseRoutes rejects host bits — the editor must too.
        #expect(WireGuardConfig.routeProblem("10.0.0.1/8") != nil)
        #expect(WireGuardConfig.routeProblem("banana") != nil)
        #expect(WireGuardConfig.routeProblem("10.0.0.0/33") != nil)
        #expect(WireGuardConfig.routeProblem("10.0.0.0") != nil)
    }

    @Test func connectProblemGatesTheEssentials() {
        var c = WireGuardConfig()
        #expect(c.connectProblem != nil)                       // brand new: no peer key
        c.peerPublicKey = "PUB"
        #expect(c.connectProblem != nil)                       // no endpoint
        c.endpoint = "vpn.example.com:51820"
        c.addresses = []
        #expect(c.connectProblem != nil)                       // no interface address
        c.addresses = ["10.0.0.2/32"]
        c.allowedIPs = []
        #expect(c.connectProblem != nil)                       // nothing routed
        c.allowedIPs = ["0.0.0.0/0"]
        // The private key is deliberately NOT part of connectProblem — it lives
        // in the keychain, not in this (redacted) value.
        #expect(c.connectProblem == nil)
    }

    // MARK: Redaction invariant

    @Test func redactedForStorageStripsKeysAndNothingElse() {
        var c = WireGuardConfig()
        c.privateKey = "PRIV"
        c.presharedKey = "PSK"
        c.peerPublicKey = "PUB"
        c.endpoint = "h:1"
        let stored = c.redactedForStorage()
        #expect(stored.privateKey.isEmpty)
        #expect(stored.presharedKey.isEmpty)
        #expect(stored.peerPublicKey == "PUB")
        #expect(stored.endpoint == "h:1")
        #expect(stored.id == c.id)
    }
}

// MARK: - Config → NEPacketTunnelNetworkSettings

@MainActor
struct WireGuardNetworkSettingsTests {

    private func fullTunnelConfig() -> WireGuardConfig {
        var c = WireGuardConfig()
        c.addresses = ["10.0.0.2/32", "fd00:7::2/128"]
        c.dns = ["10.0.0.1"]
        c.endpoint = "vpn.example.com:51820"
        c.allowedIPs = ["0.0.0.0/0", "::/0"]
        c.mtu = 1420
        return c
    }

    @Test func fullTunnelBuildsDefaultRoutesBothFamilies() throws {
        let s = try #require(WireGuardNetworkSettings.settings(for: fullTunnelConfig(),
                                                               resolvedEndpoint: "192.0.2.7:51820"))
        // The RESOLVED endpoint is the remote address — NE routes the tunnel's
        // own encrypted UDP around the tunnel via this.
        #expect(s.tunnelRemoteAddress == "192.0.2.7")
        #expect(s.ipv4Settings?.addresses == ["10.0.0.2"])
        #expect(s.ipv4Settings?.subnetMasks == ["255.255.255.255"])
        #expect(s.ipv4Settings?.includedRoutes?.contains { $0.destinationAddress == "0.0.0.0" } == true)
        #expect(s.ipv6Settings?.addresses == ["fd00:7::2"])
        #expect(s.ipv6Settings?.includedRoutes?.contains { $0.destinationAddress == "::" } == true)
        // wg-quick DNS semantics: the servers become the catch-all resolver.
        #expect(s.dnsSettings?.servers == ["10.0.0.1"])
        #expect(s.dnsSettings?.matchDomains == [""])
        #expect(s.mtu == 1420)
    }

    @Test func splitTunnelRoutesOnlyAllowedIPsPlusDNS() throws {
        var c = fullTunnelConfig()
        c.allowedIPs = ["10.44.0.0/16"]
        let s = try #require(WireGuardNetworkSettings.settings(for: c,
                                                               resolvedEndpoint: "192.0.2.7:51820"))
        let v4 = s.ipv4Settings?.includedRoutes ?? []
        #expect(!v4.contains { $0.destinationAddress == "0.0.0.0" })
        #expect(v4.contains { $0.destinationAddress == "10.44.0.0" })
        // The advertised resolver must stay reachable on a split tunnel.
        #expect(v4.contains { $0.destinationAddress == "10.0.0.1" && $0.destinationSubnetMask == "255.255.255.255" })
    }

    @Test func demotionStripsDefaultRouteAndCatchAllDNS() throws {
        let s = try #require(WireGuardNetworkSettings.settings(for: fullTunnelConfig(),
                                                               resolvedEndpoint: "192.0.2.7:51820",
                                                               suppressDefaultRoute: true))
        let v4 = s.ipv4Settings?.includedRoutes ?? []
        #expect(!v4.contains { $0.destinationAddress == "0.0.0.0" })
        // A demoted tunnel must not keep hijacking every lookup on the Mac…
        #expect(s.dnsSettings == nil)
        // …but its resolver stays reachable for its own traffic.
        #expect(v4.contains { $0.destinationAddress == "10.0.0.1" })
    }

    @Test func bareAddressesGetTheirPrefix() {
        #expect(WireGuardNetworkSettings.withPrefixLength("10.0.0.2") == "10.0.0.2/32")
        #expect(WireGuardNetworkSettings.withPrefixLength("fd00::2") == "fd00::2/128")
        #expect(WireGuardNetworkSettings.withPrefixLength("10.0.0.0/24") == "10.0.0.0/24")
    }

    @Test func noParseableAddressMeansNoSettings() {
        var c = fullTunnelConfig()
        c.addresses = ["not-an-address"]
        #expect(WireGuardNetworkSettings.settings(for: c, resolvedEndpoint: "192.0.2.7:51820") == nil)
    }

    @Test func remoteAddressParsesResolvedEndpoints() {
        #expect(WireGuardNetworkSettings.remoteAddress(fromResolved: "192.0.2.7:51820",
                                                       fallbackHost: "x") == "192.0.2.7")
        #expect(WireGuardNetworkSettings.remoteAddress(fromResolved: "[2001:db8::1]:51820",
                                                       fallbackHost: "x") == "2001:db8::1")
        #expect(WireGuardNetworkSettings.remoteAddress(fromResolved: "",
                                                       fallbackHost: "vpn.example.com") == "vpn.example.com")
    }
}

// MARK: - Engine status decode (the WGStatus payload)

struct WireGuardEngineStatusTests {

    @Test func decodesTheEnginePayload() throws {
        let json = """
        {"state":"running","endpoint":"192.0.2.7:51820","listenPort":51821,
         "rxBytes":2020,"txBytes":1010,"lastHandshake":1700000000,"packetsDropped":3}
        """
        let s = try #require(WireGuardEngineStatus.decode(json: json))
        #expect(s.isRunning)
        #expect(s.endpoint == "192.0.2.7:51820")
        #expect(s.listenPort == 51821)
        #expect(s.rxBytes == 2020 && s.txBytes == 1010)
        #expect(s.lastHandshakeDate == Date(timeIntervalSince1970: 1_700_000_000))
        #expect(s.packetsDropped == 3)
    }

    @Test func missingFieldsDegradeToDefaults() throws {
        let s = try #require(WireGuardEngineStatus.decode(json: #"{"state":"stopped"}"#))
        #expect(!s.isRunning)
        #expect(s.lastHandshakeDate == nil)
        #expect(s.rxBytes == 0)
    }
}
