// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Testing
@testable import SimpleVPN

struct OwnedIPsecNetworkSettingsTests {
    @Test func tunnelCarriesOnlyAuthenticatedSelectorsAndExcludesTheOuterPeer() throws {
        let shape = OwnedIPsecNetworkSettings(addresses: ["10.1.0.2", "fd00::2"],
                                             routes: ["0.0.0.0/0", "192.0.2.0/24", "fd00::/64"], dns: ["192.0.2.53"])
        let settings = try shape.settings(gateway: "203.0.113.1", excluded: [], ownsGateway: true)
        #expect(settings.tunnelRemoteAddress == "203.0.113.1")
        #expect(settings.ipv4Settings?.subnetMasks == ["255.255.255.255"])
        #expect(settings.ipv4Settings?.excludedRoutes?.first?.destinationAddress == "203.0.113.1")
        #expect(settings.ipv6Settings?.networkPrefixLengths == [128])
        #expect(settings.dnsSettings?.servers == ["192.0.2.53"])
        let split = try shape.settings(gateway: "203.0.113.1", excluded: [], ownsGateway: false)
        #expect(split.ipv4Settings?.includedRoutes?.map(\.destinationAddress) == ["192.0.2.0"])
        #expect(split.dnsSettings == nil)
    }

    @Test func refusesMalformedSelectorsAndResolversOutsideTheTunnel() {
        for shape in [
            OwnedIPsecNetworkSettings(addresses: ["10.1.0.2"], routes: ["not-a-prefix"], dns: []),
            OwnedIPsecNetworkSettings(addresses: ["10.1.0.2"], routes: ["192.0.2.0/24"], dns: ["203.0.113.1"]),
            OwnedIPsecNetworkSettings(addresses: [], routes: ["0.0.0.0/0"], dns: []),
            OwnedIPsecNetworkSettings(addresses: ["fd00::2"], routes: ["0.0.0.0/0"], dns: [])
        ] {
            #expect(throws: (any Error).self) { try shape.settings(gateway: "203.0.113.1", excluded: [], ownsGateway: true) }
        }
    }

    @Test func l2tpUsesTheAuthenticatedPPPFrameSizeAndIPv4Network() throws {
        var negotiated = OwnedIPsecNetworkSettings(addresses: ["198.51.100.2"], routes: ["0.0.0.0/0"],
                                                  dns: ["192.0.2.53"], pppMTU: 1360)
        let result = try negotiated.settings(gateway: "203.0.113.1", excluded: [], ownsGateway: true)
        #expect(result.mtu?.intValue == 1360)
        #expect(result.ipv4Settings?.addresses == ["198.51.100.2"])
        #expect(result.ipv6Settings == nil)
        #expect(result.dnsSettings?.servers == ["192.0.2.53"])
        for invalid in [0, 575, 1501] {
            negotiated.pppMTU = invalid
            #expect(throws: (any Error).self) { try negotiated.settings(gateway: "203.0.113.1", excluded: [], ownsGateway: true) }
        }
    }

    @Test func l2tpAcceptsOnlyItsOwnStartCredentials() throws {
        let config = OwnedIPsecConfiguration(profileID: "fixture", kind: .l2tp, server: "192.0.2.1",
            localID: "client", remoteID: "gateway", username: "PPP user", usesXAuth: false, usesL2TP: true)
        let key = Data("ipsec pre-shared secret".utf8), password = Data("PPP password".utf8)
        let options: [String: Any] = [OwnedIPsecConfiguration.pskOption: key, OwnedIPsecConfiguration.pppPasswordOption: password]
        let decoded = try OwnedIPsecCredentials(config: config, options: options)
        #expect(decoded.psk == key && decoded.password == password)
        for bad in [Data(), Data([0]), Data([0x7f]), Data(repeating: 0x41, count: 256)] {
            var invalid = options
            invalid[OwnedIPsecConfiguration.pppPasswordOption] = bad
            #expect(throws: (any Error).self) { try OwnedIPsecCredentials(config: config, options: invalid) }
        }
        for unexpected in [OwnedIPsecConfiguration.eapPasswordOption, OwnedIPsecConfiguration.xauthPasswordOption] {
            var invalid = options
            invalid[unexpected] = password
            #expect(throws: (any Error).self) { try OwnedIPsecCredentials(config: config, options: invalid) }
        }
    }
}
