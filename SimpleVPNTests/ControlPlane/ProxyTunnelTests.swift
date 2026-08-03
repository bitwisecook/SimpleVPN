// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProxyTunnelTests.swift
//  The proxy-tunnel engine cannot be exercised without a real proxy, so
//  everything that CAN go silently wrong without one is pinned here: the JSON
//  contract with the Go shim (field names on both sides), the upstream/route
//  validation the editor and the engine must agree on, and the config →
//  NEPacketTunnelNetworkSettings mapping — the one translation that can produce
//  a tunnel which connects and carries nothing (or routes everything into a
//  black hole).
//

import Foundation
import NetworkExtension
import Testing
@testable import SimpleVPN

struct ProxyTunnelConfigTests {

    // MARK: Start-payload contract (must match Vendor/proxy-engine/src/engine.go)

    @Test func startConfigEncodesExactlyTheKeysTheEngineParses() throws {
        var c = ProxyTunnelConfig()
        c.upstream = "socks5://proxy.example.com:1080"
        c.mtu = 1400

        let start = ProxyTunnelStartConfig(config: c, username: "u", password: "p")
        let json = start.jsonString()
        let obj = try #require(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])

        // startConfig in engine.go: these names are the contract.
        let expected: Set<String> = ["upstream", "username", "password", "mtu"]
        #expect(Set(obj.keys) == expected)
        #expect(obj["upstream"] as? String == "socks5://proxy.example.com:1080")
        #expect(obj["username"] as? String == "u")
        #expect(obj["password"] as? String == "p")
        #expect(obj["mtu"] as? Int == 1400)
    }

    @Test func startPayloadRedactsCredentials() {
        var c = ProxyTunnelConfig()
        c.upstream = "socks5://host:1080"
        let start = ProxyTunnelStartConfig(config: c, username: "alice", password: "hunter2")
        let redacted = start.redactedJSONString()
        #expect(!redacted.contains("alice"))
        #expect(!redacted.contains("hunter2"))
        #expect(redacted.contains("<redacted>"))
        // The upstream (no secret) still appears.
        #expect(redacted.contains("host:1080"))
    }

    @Test func mtuFallsBackWhenUnset() {
        var c = ProxyTunnelConfig()
        c.upstream = "http://p:8080"
        c.mtu = 0
        let start = ProxyTunnelStartConfig(config: c, username: "", password: "")
        #expect(start.mtu == ProxyTunnelStartConfig.defaultMTU)
    }

    // MARK: Upstream validation (mirrors parseUpstream in engine.go)

    @Test func upstreamValidationMatchesEngine() {
        #expect(ProxyTunnelConfig.upstreamProblem("socks5://host:1080") == nil)
        #expect(ProxyTunnelConfig.upstreamProblem("http://host") == nil)
        #expect(ProxyTunnelConfig.upstreamProblem("https://secure.example") == nil)
        // Rejections.
        #expect(ProxyTunnelConfig.upstreamProblem("") != nil)
        #expect(ProxyTunnelConfig.upstreamProblem("ftp://host") != nil)
        #expect(ProxyTunnelConfig.upstreamProblem("host:1080") != nil)             // no scheme
        #expect(ProxyTunnelConfig.upstreamProblem("socks5://") != nil)             // no host
        // Credentials in the URL are refused — they'd land in providerConfiguration.
        #expect(ProxyTunnelConfig.upstreamProblem("socks5://user:pass@host:1080") != nil)
    }

    @Test func presetDerivesFromScheme() {
        var c = ProxyTunnelConfig()
        c.upstream = "socks5://h:1"; #expect(c.preset == .socks5)
        c.upstream = "http://h:1";   #expect(c.preset == .httpConnect)
        c.upstream = "https://h:1";  #expect(c.preset == .httpsConnect)
        c.upstream = "ftp://h";      #expect(c.preset == nil)
    }

    @Test func connectProblemGuardsSplitTunnelWithNoRoutes() {
        var c = ProxyTunnelConfig()
        c.upstream = "socks5://h:1080"
        c.includeDefaultRoute = false
        c.includedRoutes = []
        #expect(c.connectProblem != nil)   // nothing would be routed
        c.includedRoutes = ["10.0.0.0/8"]
        #expect(c.connectProblem == nil)
    }

    // MARK: Lenient decoding (app ↔ extension version skew)

    @Test func decodeToleratesMissingFields() {
        let partial = Data(#"{"upstream":"socks5://h:1080"}"#.utf8)
        let c = ProxyTunnelConfig.decode(from: partial)
        #expect(c.upstream == "socks5://h:1080")
        #expect(c.includeDefaultRoute)                        // documented default
        #expect(c.mtu == ProxyTunnelStartConfig.defaultMTU)
    }

    @Test func decodeEmptyBlobIsDefaults() {
        let c = ProxyTunnelConfig.decode(from: nil)
        #expect(c.upstream.isEmpty)
        #expect(c.includeDefaultRoute)
    }

    // MARK: Status decoding (the PXStatus payload)

    @Test func statusDecodesAndOmitsNoSecret() {
        let json = #"{"state":"running","scheme":"socks5","activeFlows":3,"totalFlows":10,"failedFlows":1,"dnsQueries":5,"bytesUp":100,"bytesDown":200}"#
        let s = try! #require(ProxyTunnelStatus.decode(json: json))
        #expect(s.isRunning)
        #expect(s.scheme == "socks5")
        #expect(s.activeFlows == 3)
        #expect(s.totalFlows == 10)
        #expect(s.failedFlows == 1)
        #expect(s.dnsQueries == 5)
        #expect(s.bytesUp == 100 && s.bytesDown == 200)
    }
}

// MARK: - Network settings mapping

struct ProxyTunnelNetworkSettingsTests {

    @Test func defaultRouteCoversBothFamilies() throws {
        var c = ProxyTunnelConfig()
        c.upstream = "socks5://proxy.example:1080"
        c.includeDefaultRoute = true

        let settings = ProxyTunnelNetworkSettings.settings(for: c)
        let v4 = try #require(settings.ipv4Settings)
        #expect(v4.includedRoutes?.contains { $0.destinationAddress == "0.0.0.0" } == true)
        let v6 = try #require(settings.ipv6Settings)
        #expect(v6.includedRoutes?.contains { $0.destinationAddress == "::" } == true)
    }

    @Test func splitTunnelRoutesOnlyTheIncludedNetworks() throws {
        var c = ProxyTunnelConfig()
        c.upstream = "socks5://proxy.example:1080"
        c.includeDefaultRoute = false
        c.includedRoutes = ["10.0.0.0/8"]

        let settings = ProxyTunnelNetworkSettings.settings(for: c)
        let v4 = try #require(settings.ipv4Settings)
        let dests = v4.includedRoutes?.map(\.destinationAddress) ?? []
        #expect(dests.contains("10.0.0.0"))
        #expect(!dests.contains("0.0.0.0"))   // NOT a full tunnel
        // No IPv6 default gets invented for a v4-only split tunnel.
        #expect(settings.ipv6Settings == nil)
    }

    @Test func splitTunnelAddsRoutesForAdvertisedDNS() throws {
        var c = ProxyTunnelConfig()
        c.upstream = "socks5://proxy.example:1080"
        c.includeDefaultRoute = false
        c.includedRoutes = ["10.0.0.0/8"]
        c.dnsServers = ["1.1.1.1"]

        let settings = ProxyTunnelNetworkSettings.settings(for: c)
        let v4 = try #require(settings.ipv4Settings)
        let dests = v4.includedRoutes?.map(\.destinationAddress) ?? []
        // The resolver must be reachable through the tunnel or DNS never resolves.
        #expect(dests.contains("1.1.1.1"))
        let dns = try #require(settings.dnsSettings)
        #expect(dns.servers.contains("1.1.1.1"))
        #expect(dns.matchDomains == [""])   // catch-all so lookups go via the proxy
    }

    @Test func excludedRoutesBecomeCarveOuts() throws {
        var c = ProxyTunnelConfig()
        c.upstream = "socks5://proxy.example:1080"
        c.includeDefaultRoute = true
        c.excludedRoutes = ["192.168.0.0/16"]

        let settings = ProxyTunnelNetworkSettings.settings(for: c)
        let v4 = try #require(settings.ipv4Settings)
        #expect(v4.excludedRoutes?.contains { $0.destinationAddress == "192.168.0.0" } == true)
    }

    @Test func noDNSLeavesResolversAlone() throws {
        var c = ProxyTunnelConfig()
        c.upstream = "socks5://proxy.example:1080"
        c.dnsServers = []
        let settings = ProxyTunnelNetworkSettings.settings(for: c)
        #expect(settings.dnsSettings == nil)
    }
}
