// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  TailscaleTests.swift
//  The Tailscale/Headscale engine cannot be exercised without a real tailnet, so
//  everything that CAN go silently wrong without one is pinned here: the JSON
//  contract with the Go shim (field names on both sides), the validation the
//  editor and the engine must agree on, and the netmap → NEPacketTunnelNetworkSettings
//  mapping — the one translation that can produce a tunnel which connects and
//  carries nothing.
//

import Foundation
import NetworkExtension
import Testing
@testable import SimpleVPN

struct TailscaleConfigTests {

    // MARK: Start-payload contract (must match Vendor/tailscale-engine/src/main.go)

    @Test func startConfigEncodesExactlyTheKeysTheEngineParses() throws {
        var c = TailscaleConfig()
        c.preset = .headscale
        c.controlURL = "https://headscale.example.com"
        c.hostname = "Jims-Mac"
        c.acceptRoutes = true
        c.acceptDNS = false
        c.useExitNode = true
        c.exitNode = "100.64.0.7"
        c.exitNodeAllowLANAccess = true
        c.advertiseRoutes = ["192.168.7.0/24"]

        let start = TailscaleStartConfig(config: c, authKey: "tskey-auth-secret",
                                         stateDir: "/Library/Application Support/SimpleVPN/tailscale/abc")
        let json = start.jsonString()
        let obj = try #require(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])

        // startConfig in main.go: these names are the contract.
        let expected: Set<String> = ["controlURL", "hostname", "authKey", "stateDir",
                                     "acceptRoutes", "acceptDNS", "useExitNode", "exitNode",
                                     "exitNodeAllowLANAccess", "advertiseRoutes", "mtu"]
        #expect(Set(obj.keys) == expected)
        #expect(obj["controlURL"] as? String == "https://headscale.example.com")
        #expect(obj["authKey"] as? String == "tskey-auth-secret")
        #expect(obj["acceptDNS"] as? Bool == false)
        #expect(obj["exitNode"] as? String == "100.64.0.7")
        #expect(obj["mtu"] as? Int == 1280)
    }

    @Test func tailscalePresetNeverSendsAStaleHeadscaleURL() {
        var c = TailscaleConfig()
        c.preset = .headscale
        c.controlURL = "https://headscale.example.com"
        c.preset = .tailscale                       // user switched back
        #expect(c.effectiveControlURL.isEmpty)      // empty ⇒ Tailscale's own control plane
        let start = TailscaleStartConfig(config: c, authKey: "", stateDir: "/tmp/x")
        #expect(start.controlURL.isEmpty)
    }

    @Test func exitNodeIsClearedWhenTheToggleIsOff() {
        var c = TailscaleConfig()
        c.exitNode = "100.64.0.7"
        c.useExitNode = false
        let start = TailscaleStartConfig(config: c, authKey: "", stateDir: "/tmp/x")
        // Leaving the id in place would keep defaulting traffic through a peer
        // the user just deselected.
        #expect(start.exitNode.isEmpty)
    }

    @Test func redactedPayloadNeverCarriesTheAuthKey() {
        let start = TailscaleStartConfig(config: TailscaleConfig(), authKey: "tskey-auth-verysecret",
                                         stateDir: "/tmp/x")
        #expect(!start.redactedJSONString().contains("verysecret"))
        #expect(start.redactedJSONString().contains("<redacted>"))
        // An absent key must not be reported as a redacted one.
        let none = TailscaleStartConfig(config: TailscaleConfig(), authKey: "", stateDir: "/tmp/x")
        #expect(!none.redactedJSONString().contains("redacted"))
    }

    @Test func prefsPatchOmitsUnsetFields() throws {
        let patch = TailscalePrefsPatch(acceptDNS: false)
        let obj = try #require(try JSONSerialization.jsonObject(with: Data(patch.jsonString().utf8)) as? [String: Any])
        #expect(Set(obj.keys) == ["acceptDNS"])
        #expect(obj["acceptDNS"] as? Bool == false)
    }

    // MARK: Persistence

    @Test func configRoundTripsThroughItsBlob() {
        var c = TailscaleConfig()
        c.preset = .headscale
        c.controlURL = "https://hs.example.com"
        c.hostname = "mac"
        c.acceptRoutes = false
        c.acceptDNS = false
        c.useExitNode = true
        c.exitNode = "nodeidABC"
        c.exitNodeAllowLANAccess = false
        c.advertiseRoutes = ["10.0.0.0/8"]
        #expect(TailscaleConfig.decode(from: c.encodedBlob()) == c)
    }

    @Test func missingBlobAndGarbageBothGiveTheDocumentedDefaults() {
        for blob in [nil, Data("not json".utf8), Data("{}".utf8)] {
            let c = TailscaleConfig.decode(from: blob)
            #expect(c.preset == .tailscale)
            #expect(c.acceptRoutes)                 // on by default
            #expect(c.acceptDNS)                    // on by default
            #expect(!c.useExitNode)
            #expect(c.exitNodeAllowLANAccess)
            #expect(c.advertiseRoutes.isEmpty)
        }
    }

    @Test func unknownFieldsFromANewerAppDoNotBreakDecoding() {
        let blob = Data(#"{"preset":"headscale","controlURL":"https://x.example.com","somethingNew":42}"#.utf8)
        let c = TailscaleConfig.decode(from: blob)
        #expect(c.preset == .headscale)
        #expect(c.controlURL == "https://x.example.com")
        #expect(c.acceptRoutes)                     // absent ⇒ default, not false
    }

    // MARK: Control-URL validation (must mirror validateControlURL in main.go)

    @Test func headscaleAcceptsAnHTTPSURL() {
        #expect(TailscaleConfig.controlURLProblem("https://headscale.example.com", preset: .headscale) == nil)
        #expect(TailscaleConfig.controlURLProblem("https://vpn.example.co.uk:8443/", preset: .headscale) == nil)
    }

    @Test func plainHTTPIsRejected() {
        // The registration request carries this Mac's identity.
        #expect(TailscaleConfig.controlURLProblem("http://headscale.example.com", preset: .headscale) != nil)
    }

    @Test func garbageIsRejected() {
        for bad in ["headscale.example.com", "https://", "not a url at all", "ftp://x.example.com", "://x"] {
            #expect(TailscaleConfig.controlURLProblem(bad, preset: .headscale) != nil, "\(bad) should be rejected")
        }
    }

    @Test func headscaleRequiresAnAddressButTailscaleDoesNot() {
        #expect(TailscaleConfig.controlURLProblem("", preset: .headscale) != nil)
        #expect(TailscaleConfig.controlURLProblem("", preset: .tailscale) == nil)
    }

    // MARK: Advertised-CIDR validation (must mirror parseRoutes in main.go)

    @Test func validNetworksAreAccepted() {
        for good in ["192.168.1.0/24", "10.0.0.0/8", "fd00::/8", "0.0.0.0/0"] {
            #expect(TailscaleConfig.routeProblem(good) == nil, "\(good) should be accepted")
        }
    }

    @Test func hostBitsAreRejectedWithTheCorrectedSuggestion() throws {
        let problem = try #require(TailscaleConfig.routeProblem("192.168.1.7/24"))
        #expect(problem.contains("192.168.1.0/24"))
    }

    @Test func malformedNetworksAreRejected() {
        for bad in ["192.168.1.0", "banana", "10.0.0.0/33", "10.0.0.0/-1", "/24", "999.1.1.0/24", ""] {
            #expect(TailscaleConfig.routeProblem(bad) != nil, "\(bad) should be rejected")
        }
    }

    @Test func routeListSplittingHandlesTheWaysPeopleType() {
        #expect(TailscaleConfig.splitRoutes("192.168.1.0/24, 10.0.0.0/8") == ["192.168.1.0/24", "10.0.0.0/8"])
        #expect(TailscaleConfig.splitRoutes("192.168.1.0/24\n10.0.0.0/8") == ["192.168.1.0/24", "10.0.0.0/8"])
        #expect(TailscaleConfig.splitRoutes("  ").isEmpty)
        #expect(TailscaleConfig.routesProblem(["10.0.0.0/8", "nonsense"]) != nil)
        #expect(TailscaleConfig.routesProblem([]) == nil)
    }

    // MARK: State machine

    @Test func engineStateNamesMapToTheAppsStatus() {
        #expect(TailscaleBackendState(engineName: "Running").isConnected)
        #expect(TailscaleBackendState(engineName: "NeedsLogin").needsUserAction)
        #expect(TailscaleBackendState(engineName: "NeedsMachineAuth").needsUserAction)
        #expect(TailscaleBackendState(engineName: "InUseOtherUser").needsUserAction)
        #expect(!TailscaleBackendState(engineName: "Starting").needsUserAction)
        #expect(!TailscaleBackendState(engineName: "Starting").isConnected)
        #expect(TailscaleBackendState(engineName: "Stopped") == .stopped)
    }

    @Test func anUnknownStateFromANewerEngineDegradesRatherThanCrashing() {
        let s = TailscaleBackendState(engineName: "SomeFutureState")
        #expect(s == .noState)
        #expect(!s.isConnected)
        #expect(!s.needsUserAction)
    }

    @Test func statesThatStrandTheUserAreFiledAsIncidents() {
        #expect(TailscaleBackendState.needsLogin.incidentCategory == .auth)
        #expect(TailscaleBackendState.needsMachineAuth.incidentCategory == .auth)
        #expect(TailscaleBackendState.running.incidentCategory == nil)
        #expect(TailscaleBackendState.starting.incidentCategory == nil)
    }

    @Test func everyStateHasNonTechnicalStatusText() {
        for s in TailscaleBackendState.allCases {
            #expect(!s.displayText.isEmpty)
            #expect(!s.displayText.contains("ipn"))
            #expect(s.displayText.first!.isUppercase)
        }
    }

    // MARK: Status decoding

    @Test func statusDecodesTheEnginesPayload() throws {
        let json = """
        {"state":"Running","haveNodeKey":true,
         "selfIPs":["100.64.0.1","fd7a:115c:a1e0::1"],
         "selfDNSName":"jims-mac.tail1234.ts.net","selfHostName":"Jims-Mac",
         "magicDNSSuffix":"tail1234.ts.net","tailnet":"example.com",
         "peerCount":7,"peersOnline":4,
         "exitNodes":[{"id":"nABC","name":"nyc","hostName":"exit-nyc","ips":["100.64.0.9"],
                       "online":true,"active":false,"country":"United States","city":"New York"}],
         "exitNodeID":"","rxBytes":100,"txBytes":200,"health":["clock is skewed"],
         "packetsDropped":3}
        """
        let s = try #require(TailscaleStatus.decode(json: json))
        #expect(s.backendState == .running)
        #expect(s.primaryIPv4 == "100.64.0.1")
        #expect(s.primaryIPv6 == "fd7a:115c:a1e0::1")
        #expect(s.peersOnline == 4 && s.peerCount == 7)
        #expect(s.exitNodes.count == 1)
        #expect(s.exitNodes[0].pickerLabel == "nyc — New York, United States")
        #expect(s.health == ["clock is skewed"])
        #expect(s.packetsDropped == 3)
    }

    @Test func statusToleratesAnEmptyOrPartialPayload() throws {
        let s = try #require(TailscaleStatus.decode(json: "{}"))
        #expect(s.backendState == .noState)
        #expect(s.selfIPs.isEmpty)
        #expect(s.exitNodes.isEmpty)
        #expect(s.primaryIPv4.isEmpty)
        #expect(TailscaleStatus.decode(json: "not json") == nil)
    }

    @Test func stateEventDecodes() throws {
        let e = try #require(TailscaleStateEvent.decode(json: #"{"state":"NeedsLogin","authURL":"https://x/y"}"#))
        #expect(TailscaleBackendState(engineName: e.state) == .needsLogin)
        #expect(e.authURL == "https://x/y")
        #expect(e.message.isEmpty)
    }

    // MARK: Manual coverage

    @Test func everySettingHasAManualAnchorThatExists() throws {
        for spec in ["ts.control-url", "ts.hostname", "ts.auth-key", "ts.accept-routes",
                     "ts.accept-dns", "ts.exit-node", "ts.advertise-routes"] {
            let s = TailscaleView.specs[spec]
            #expect(!s.manualAnchor.contains("."))
            #expect(s.manualAnchor.hasPrefix("ts-"))
            #expect(!s.summary.isEmpty)
        }
        // The anchors are only useful if the manual actually has them.
        let url = try #require(Bundle(for: BundleToken.self).url(forResource: "manual", withExtension: "html")
                               ?? Bundle.main.url(forResource: "manual", withExtension: "html"))
        let html = try String(contentsOf: url, encoding: .utf8)
        for anchor in ["ts-what-is-it", "ts-control-url", "ts-hostname", "ts-auth-key",
                       "ts-accept-routes", "ts-accept-dns", "ts-exit-node", "ts-advertise-routes"] {
            #expect(html.contains("id=\"\(anchor)\""), "manual.html is missing #\(anchor)")
        }
    }

    // MARK: Kind wiring

    @Test func tailscaleIsAPacketTunnelKindWithNoOpenConnectProtocol() {
        #expect(VPNKind.tailscale.transport == .packetTunnel)
        #expect(VPNKind.tailscale.openconnectProtocol == nil)
        #expect(!VPNKind.tailscale.isSSLVPN)
        #expect(VPNKind(rawValue: "tailscale") == .tailscale)
        #expect(!VPNKind.tailscale.displayName.isEmpty)
    }

    @Test func serverAddressNamesTheCoordinationServer() {
        var c = TailscaleConfig()
        #expect(VPNController.tailscaleServerAddress(c) == "controlplane.tailscale.com")
        c.preset = .headscale
        c.controlURL = "https://hs.example.com:8443/"
        #expect(VPNController.tailscaleServerAddress(c) == "hs.example.com")
        c.controlURL = ""
        #expect(VPNController.tailscaleServerAddress(c).isEmpty)
    }

    @Test func defaultHostnameIsUsableAsAMachineName() {
        let h = VPNController.defaultTailscaleHostname()
        #expect(!h.isEmpty)
        #expect(!h.contains(" "))
        #expect(!h.contains("'"))
        #expect(!h.hasPrefix("-") && !h.hasSuffix("-"))
    }
}

/// Locates the test bundle's copy of the app resources.
private final class BundleToken {}

// MARK: - netmap → NEPacketTunnelNetworkSettings

struct TailscaleNetworkSettingsTests {

    private func config(_ json: String) throws -> TailscaleTunnelConfig {
        try #require(TailscaleTunnelConfig.decode(json: json))
    }

    @Test func splitTunnelMapsAddressesRoutesAndDNS() throws {
        let c = try config("""
        {"localAddrs":["100.64.0.1/32","fd7a:115c:a1e0::1/128"],
         "routes":["100.64.0.0/10","192.168.9.0/24","fd7a:115c:a1e0::/48"],
         "localRoutes":[],"subnetRoutes":[],"mtu":1280,
         "dns":{"nameservers":["100.100.100.100"],
                "searchDomains":["tail1234.ts.net"],
                "matchDomains":["tail1234.ts.net"]}}
        """)
        let s = try #require(TailscaleNetworkSettings.settings(for: c))

        // There is no server, so the "remote" is honestly this node itself.
        #expect(s.tunnelRemoteAddress == "100.64.0.1")
        #expect(s.mtu == 1280)

        let v4 = try #require(s.ipv4Settings)
        #expect(v4.addresses == ["100.64.0.1"])
        #expect(v4.subnetMasks == ["255.255.255.255"])
        #expect(v4.includedRoutes?.count == 2)
        #expect(v4.includedRoutes?.contains { $0.destinationAddress == "100.64.0.0" && $0.destinationSubnetMask == "255.192.0.0" } == true)

        let v6 = try #require(s.ipv6Settings)
        #expect(v6.addresses == ["fd7a:115c:a1e0::1"])
        #expect(v6.networkPrefixLengths == [128])
        #expect(v6.includedRoutes?.count == 1)

        let dns = try #require(s.dnsSettings)
        #expect(dns.servers == ["100.100.100.100"])
        #expect(dns.searchDomains == ["tail1234.ts.net"])
        // matchDomains present ⇒ split DNS: the tailnet resolver does not become
        // the Mac's primary one.
        #expect(dns.matchDomains == ["tail1234.ts.net"])
    }

    @Test func exitNodeProducesDefaultRoutesInBothFamilies() throws {
        let c = try config("""
        {"localAddrs":["100.64.0.1/32","fd7a:115c:a1e0::1/128"],
         "routes":["0.0.0.0/0","::/0"],"localRoutes":["192.168.1.0/24"],
         "subnetRoutes":[],"mtu":1280,"dns":{"nameservers":[],"searchDomains":[],"matchDomains":[]}}
        """)
        #expect(c.carriesDefaultRoute)
        let s = try #require(TailscaleNetworkSettings.settings(for: c))
        let v4 = try #require(s.ipv4Settings)
        #expect(v4.includedRoutes?.count == 1)
        #expect(v4.includedRoutes?.first?.destinationAddress == NEIPv4Route.default().destinationAddress)
        // "Keep using my local network" arrives as an excluded route.
        #expect(v4.excludedRoutes?.first?.destinationAddress == "192.168.1.0")
        let v6 = try #require(s.ipv6Settings)
        #expect(v6.includedRoutes?.first?.destinationAddress == NEIPv6Route.default().destinationAddress)
        #expect(v6.excludedRoutes == nil)
    }

    @Test func dnsOffLeavesTheMacsResolversAlone() throws {
        let c = try config("""
        {"localAddrs":["100.64.0.1/32"],"routes":["100.64.0.0/10"],
         "dns":{"nameservers":[],"searchDomains":[],"matchDomains":[]},"mtu":1280}
        """)
        // Installing an empty resolver would break every lookup on the machine.
        #expect(TailscaleNetworkSettings.settings(for: c)?.dnsSettings == nil)
    }

    @Test func dnsWithoutMatchDomainsBecomesThePrimaryResolver() throws {
        let c = try config("""
        {"localAddrs":["100.64.0.1/32"],"routes":["100.64.0.0/10"],
         "dns":{"nameservers":["100.100.100.100"],"searchDomains":["tail1234.ts.net"],"matchDomains":[]},
         "mtu":1280}
        """)
        let dns = try #require(TailscaleNetworkSettings.settings(for: c)?.dnsSettings)
        #expect(dns.matchDomains == nil || dns.matchDomains?.isEmpty == true)
        #expect(dns.searchDomains == ["tail1234.ts.net"])
    }

    @Test func ipv4OnlyNodeGetsNoIPv6Settings() throws {
        let c = try config(#"{"localAddrs":["100.64.0.1/32"],"routes":["100.64.0.0/10"],"mtu":1280}"#)
        let s = try #require(TailscaleNetworkSettings.settings(for: c))
        #expect(s.ipv4Settings != nil)
        #expect(s.ipv6Settings == nil)
    }

    @Test func noAddressesYetMeansNothingToApply() throws {
        // Registered but not yet given an address: applying empty settings would
        // tear down whatever is already in place.
        let c = try config(#"{"localAddrs":[],"routes":["100.64.0.0/10"],"mtu":1280}"#)
        #expect(TailscaleNetworkSettings.settings(for: c) == nil)
    }

    @Test func aMalformedRouteIsDroppedNotFatal() throws {
        let c = try config("""
        {"localAddrs":["100.64.0.1/32"],
         "routes":["100.64.0.0/10","garbage","10.0.0.0/99","192.168.0.0/16"],"mtu":1280}
        """)
        let v4 = try #require(TailscaleNetworkSettings.settings(for: c)?.ipv4Settings)
        #expect(v4.includedRoutes?.count == 2)   // losing one route beats losing the tunnel
    }

    @Test func zeroMTUFallsBackToTheEnginesDefault() throws {
        let c = try config(#"{"localAddrs":["100.64.0.1/32"],"routes":[],"mtu":0}"#)
        #expect(TailscaleNetworkSettings.settings(for: c)?.mtu == NSNumber(value: TailscaleStartConfig.defaultMTU))
    }

    @Test func prefixParsingCoversTheMaskArithmetic() {
        #expect(TailscaleNetworkSettings.parse("10.0.0.0/8")?.ipv4Mask == "255.0.0.0")
        #expect(TailscaleNetworkSettings.parse("100.64.0.0/10")?.ipv4Mask == "255.192.0.0")
        #expect(TailscaleNetworkSettings.parse("1.2.3.4/32")?.ipv4Mask == "255.255.255.255")
        #expect(TailscaleNetworkSettings.parse("0.0.0.0/0")?.isDefaultRoute == true)
        #expect(TailscaleNetworkSettings.parse("::/0")?.isDefaultRoute == true)
        #expect(TailscaleNetworkSettings.parse("fd00::/8")?.isIPv6 == true)
        for bad in ["10.0.0.0", "10.0.0.0/x", "nonsense/8", "10.0.0.0/33", "::/129"] {
            #expect(TailscaleNetworkSettings.parse(bad) == nil, "\(bad) should not parse")
        }
    }

    @Test func tunnelConfigToleratesAPartialPayload() throws {
        let c = try config("{}")
        #expect(c.localAddrs.isEmpty)
        #expect(c.mtu == TailscaleStartConfig.defaultMTU)
        #expect(!c.carriesDefaultRoute)
        #expect(TailscaleTunnelConfig.decode(json: "]not json[") == nil)
    }
}
