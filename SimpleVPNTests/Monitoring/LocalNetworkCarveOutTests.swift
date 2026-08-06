// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  LocalNetworkCarveOutTests.swift
//  "Allow local network access" decides what leaves the tunnel, so WIDTH is the
//  property under test. None of it can be proven against a live tunnel from here —
//  what CAN be proven, and is, is that the computation never produces a prefix
//  wider than the interface it came from, never produces a default route, and never
//  invents private space nobody is on.
//

import Foundation
import Testing
@testable import SimpleVPN

struct LocalNetworkCarveOutTests {

    // MARK: The fixed ranges

    @Test func theFixedRangesAreLinkLocalAndMulticastAndNothingWider() {
        let fixed = LocalNetworkCarveOut.fixedPrefixes
        #expect(fixed.contains("169.254.0.0/16"))
        #expect(fixed.contains("224.0.0.0/4"))
        #expect(fixed.contains("255.255.255.255/32"))
        #expect(fixed.contains("fe80::/10"))
        #expect(fixed.contains("ff00::/8"))
        // The whole safety argument in one assertion: no RFC 1918 space is asserted
        // just because somebody MIGHT be on it, and nothing is a default route.
        for cidr in fixed {
            #expect(!cidr.hasSuffix("/0"), "\(cidr) is a default route, not a local network")
        }
        #expect(!fixed.contains("10.0.0.0/8"))
        #expect(!fixed.contains("192.168.0.0/16"))
        #expect(!fixed.contains("172.16.0.0/12"))
        // Loopback never reaches an interface, so an excluded route for it is noise.
        #expect(!fixed.contains("127.0.0.0/8"))
    }

    @Test func theCarveOutIsTheFixedRangesWhenNoInterfaceQualifies() {
        #expect(LocalNetworkCarveOut.prefixes(of: []) == LocalNetworkCarveOut.fixedPrefixes)
    }

    // MARK: Which interfaces count

    @Test func tunnelsAndLoopbackAndVirtualMachinesAreNotLocalNetworks() {
        for name in ["utun4", "ipsec0", "tun0", "lo0", "awdl0", "llw0", "anpi1",
                     "gif0", "stf0", "pktap0", "vmenet0", "vnic0", "vboxnet0", "vmnet8"] {
            #expect(!LocalNetworkCarveOut.isLocalNetworkInterface(name), "\(name) should not count")
        }
    }

    @Test func realLinksCountAndTheBridgeNumberIsTheDiscriminator() {
        for name in ["en0", "en5", "bridge0"] {
            #expect(LocalNetworkCarveOut.isLocalNetworkInterface(name), "\(name) should count")
        }
        // bridge0 is the ordinary Thunderbolt/Ethernet bridge — a real LAN. macOS
        // allocates vmnet bridges from bridge100 up, and those are guest networks with
        // their own offer, so this rule takes exactly the bridges
        // VirtualizationDiscovery rejects.
        #expect(!LocalNetworkCarveOut.isLocalNetworkInterface("bridge100"))
        #expect(!LocalNetworkCarveOut.isLocalNetworkInterface("bridge101"))
    }

    @Test func aTunnelsOwnSubnetIsNeverCarvedOutOfItself() {
        let carve = LocalNetworkCarveOut.prefixes(of: [
            .init(name: "utun4", subnets: ["10.8.0.2/24"]),
            .init(name: "en0", subnets: ["192.168.1.34/24"]),
        ])
        #expect(carve.contains("192.168.1.0/24"))
        #expect(!carve.contains("10.8.0.0/24"))
    }

    // MARK: Width

    @Test func hostBitsAreMaskedOffSoTheCarveOutSaysWhatItMeans() {
        // NE installs the MASKED prefix without complaint, so an unmasked entry would
        // quietly carve out a different network from the one displayed.
        #expect(LocalNetworkCarveOut.networkPrefix("192.168.1.34/24") == "192.168.1.0/24")
        #expect(LocalNetworkCarveOut.networkPrefix("10.11.12.13/8") == "10.0.0.0/8")
        #expect(LocalNetworkCarveOut.networkPrefix("172.16.34.200/20") == "172.16.32.0/20")
        #expect(LocalNetworkCarveOut.networkPrefix("192.168.1.34/32") == "192.168.1.34/32")
        #expect(LocalNetworkCarveOut.networkPrefix("fd00:1234:5678:9abc:dead::1/64")
                == "fd00:1234:5678:9abc::/64")
    }

    @Test func aDefaultRouteIsNeverALocalNetwork() {
        // The same refusal RoutingRule.routeDest makes, for the same reason: a
        // prefix-0 carve-out is a full VPN bypass.
        #expect(LocalNetworkCarveOut.networkPrefix("0.0.0.0/0") == nil)
        #expect(LocalNetworkCarveOut.networkPrefix("::/0") == nil)
        let carve = LocalNetworkCarveOut.prefixes(of: [.init(name: "en0", subnets: ["0.0.0.0/0"])])
        #expect(carve == LocalNetworkCarveOut.fixedPrefixes)
    }

    @Test func anAbsurdlyWideMaskIsDroppedRatherThanTrusted() {
        #expect(LocalNetworkCarveOut.networkPrefix("32.0.0.0/3") == nil)
        #expect(LocalNetworkCarveOut.networkPrefix("2000::/8") == nil)
        // …and the floor itself is accepted, so a genuine 10/8 LAN still works.
        #expect(LocalNetworkCarveOut.networkPrefix("10.1.2.3/8") == "10.0.0.0/8")
    }

    @Test func malformedSubnetsAreDroppedNotWidened() {
        for bad in ["", "/24", "192.168.1.0", "192.168.1.0/", "192.168.1.0/33",
                    "banana/24", "192.168.1.0/-1", "fd00::/129"] {
            #expect(LocalNetworkCarveOut.networkPrefix(bad) == nil, "\(bad) should be dropped")
        }
    }

    @Test func duplicatesCollapseAndOrderIsStable() {
        let carve = LocalNetworkCarveOut.prefixes(of: [
            .init(name: "en0", subnets: ["192.168.1.34/24", "192.168.1.99/24"]),
            .init(name: "en5", subnets: ["192.168.1.7/24", "10.0.0.5/24"]),
        ])
        #expect(carve == LocalNetworkCarveOut.fixedPrefixes + ["192.168.1.0/24", "10.0.0.0/24"])
        #expect(Set(carve).count == carve.count)
    }

    // MARK: Netmask → prefix length

    @Test func onlyAContiguousMaskBecomesAPrefix() {
        #expect(LocalNetworkCarveOut.prefixLength(mask: [255, 255, 255, 0], width: 4) == 24)
        #expect(LocalNetworkCarveOut.prefixLength(mask: [255, 255, 255, 255], width: 4) == 32)
        #expect(LocalNetworkCarveOut.prefixLength(mask: [255, 255, 240, 0], width: 4) == 20)
        #expect(LocalNetworkCarveOut.prefixLength(mask: [0, 0, 0, 0], width: 4) == 0)
        // Non-contiguous: summarising it as a prefix would mean a DIFFERENT set of
        // addresses, so it is refused rather than guessed at.
        #expect(LocalNetworkCarveOut.prefixLength(mask: [255, 0, 255, 0], width: 4) == nil)
        #expect(LocalNetworkCarveOut.prefixLength(mask: [255, 255, 0b1010_0000, 0], width: 4) == nil)
    }

    // MARK: The live read

    @Test func theLiveReadNeverProducesAnythingWiderThanTheFloors() {
        // Whatever this machine is plugged into, the OUTPUT contract holds for every
        // INTERFACE-DERIVED entry: it parses, it is not a default route, it is at or
        // inside the width floor, and it is already masked. (The set itself is
        // environment-dependent, so the set is not asserted — the shape is.)
        //
        // The fixed ranges are exempt by construction: `224.0.0.0/4`, `fe80::/10` and
        // `ff00::/8` are deliberately wider than the floors, which apply to a netmask
        // an interface reported and therefore to a network someone might be on.
        let fixed = Set(LocalNetworkCarveOut.fixedPrefixes)
        for cidr in LocalNetworkCarveOut.live() where !fixed.contains(cidr) {
            let parts = cidr.split(separator: "/")
            #expect(parts.count == 2, "\(cidr) is not a CIDR")
            let length = Int(parts[1]) ?? -1
            #expect(length > 0, "\(cidr) is a default route")
            if !cidr.contains(":") {
                #expect(length >= LocalNetworkCarveOut.ipv4PrefixFloor, "\(cidr) is too wide")
            } else {
                #expect(length >= LocalNetworkCarveOut.ipv6PrefixFloor, "\(cidr) is too wide")
            }
            #expect(LocalNetworkCarveOut.networkPrefix(cidr) == cidr, "\(cidr) is not masked")
        }
        // The fixed ranges are always there — the part that does not depend on the
        // machine, and the part that fixes Bonjour/AirPlay under a full tunnel.
        for cidr in LocalNetworkCarveOut.fixedPrefixes {
            #expect(LocalNetworkCarveOut.live().contains(cidr))
        }
    }

    @Test func theLiveReadNeverReturnsATunnelOrGuestInterface() {
        for interface in LocalNetworkCarveOut.liveInterfaces() {
            #expect(LocalNetworkCarveOut.isLocalNetworkInterface(interface.name),
                    "\(interface.name) should have been filtered out")
        }
    }

    // MARK: The session option

    @Test func theOptionKeyIsTheOneTheExtensionReads() {
        // A rename here silently turns the carve-out off (the extension reads the key
        // and finds nothing), which fails CLOSED but is invisible — so the name is
        // pinned rather than assumed.
        #expect(LocalNetworkCarveOut.optionKey == "localNetworks")
    }
}
