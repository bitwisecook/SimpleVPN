// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  NetworkIdentityTests.swift
//  Pins the one rule the whole "on network change" machinery rests on: BRINGING A
//  TUNNEL UP IS NOT A NETWORK MOVE. A full tunnel takes the default route, and if
//  identity followed the default route then connecting would re-snapshot "home"
//  from the far end of the VPN, re-probe every endpoint through the tunnel that
//  serves it, and re-file every cached lookup under a network that doesn't exist.
//  All of that happened. Walking to a different Wi-Fi must still count, though —
//  the fixtures below hold both halves down.
//

import Foundation
import NetworkExtension
import Testing
@testable import SimpleVPN

/// Parse-or-die, for fixtures. These are `ether_ntoa`'s unpadded spelling because
/// that is what `arp` reports and therefore what `RouteTableSource` decodes into —
/// `MACAddressTests` is where the spellings themselves are tried.
private func fixtureMAC(_ text: String) -> MACAddress {
    guard let parsed = MACAddress(text) else {
        preconditionFailure("fixture \u{201C}\(text)\u{201D} is not a hardware address")
    }
    return parsed
}

@MainActor
struct NetworkIdentityTests {

    // MARK: Fixtures — `netstat -rn` shaped, which RouteTableSnapshot parses.

    /// Home Wi-Fi, nothing else running.
    private let physicalOnly = """
    Internet:
    Destination        Gateway            Flags        Netif Expire
    default            192.168.87.1       UGScg          en0
    127                127.0.0.1          UCS            lo0
    192.168.87.0/24    link#4             UCS            en0
    """

    /// The same Wi-Fi with a FULL tunnel up: the tunnel's default route wins and
    /// the physical one is still there, interface-scoped (this is what macOS
    /// actually leaves behind, and it is what makes the fix possible).
    private let physicalPlusFullTunnel = """
    Internet:
    Destination        Gateway            Flags        Netif Expire
    0/1                10.8.0.5           UGScg          utun4
    default            10.8.0.5           UGScg          utun4
    default            192.168.87.1       UGScIg         en0
    10.8.0.5           10.8.0.6           UH             utun4
    127                127.0.0.1          UCS            lo0
    192.168.87.0/24    link#4             UCSI           en0
    """

    /// Tailscale as this app's author runs it: always on, advertising a scoped
    /// gatewayless default it isn't actually carrying anything for.
    private let physicalPlusTailscale = """
    Internet:
    Destination        Gateway            Flags        Netif Expire
    default            192.168.87.1       UGScg          en0
    default            link#20            UCSIg          utun1
    127                127.0.0.1          UCS            lo0
    """

    /// Tailscale WITH an exit node — an unscoped utun default. The Mac still has
    /// not moved, so identity still must not budge.
    private let physicalPlusTailscaleExitNode = """
    Internet:
    Destination        Gateway            Flags        Netif Expire
    default            link#20            UCSg           utun1
    default            192.168.87.1       UGScIg         en0
    127                127.0.0.1          UCS            lo0
    """

    /// A different network entirely: the café.
    private let otherNetwork = """
    Internet:
    Destination        Gateway            Flags        Netif Expire
    default            10.0.7.254         UGScg          en0
    127                127.0.0.1          UCS            lo0
    10.0.0.0/21        link#4             UCS            en0
    """

    private let homeARP: [RouteTableSource.ARPEntry] = [
        (ip: "192.168.87.1", mac: fixtureMAC("0:8:a2:e:dc:c7"), interface: "en0"),
    ]
    private let cafeARP: [RouteTableSource.ARPEntry] = [
        (ip: "10.0.7.254", mac: fixtureMAC("a0:99:9b:18:dc:93"), interface: "en0"),
    ]

    private func fingerprint(_ text: String, arp: [RouteTableSource.ARPEntry],
                             localNetwork: String? = "192.168.87.0/24",
                             fallback: String? = nil) -> NetworkFingerprint? {
        NetworkIdentity.fingerprint(
            routes: RouteTableSnapshot(netstatText: text), arp: arp,
            // Injected: getifaddrs describes the machine running the test, and
            // these fixtures describe someone else's Wi-Fi.
            localNetwork: { _ in localNetwork }, fallbackInterface: { fallback })
    }

    // MARK: Virtual interfaces

    @Test func tunnelInterfacesAreRecognisedAsVirtual() {
        for name in ["utun0", "utun14", "tun0", "tap3", "gif0", "stf0",
                     "ipsec0", "ppp0", "feth1", "utun4%utun4"] {
            #expect(NetworkIdentity.isVirtualInterface(name), "\(name) carries a tunnel")
        }
    }

    @Test func realInterfacesAreNotVirtual() {
        for name in ["en0", "en7", "lo0", "bridge100", "awdl0", "llw0",
                     "vmenet0", "anpi0", "ap1", ""] {
            #expect(!NetworkIdentity.isVirtualInterface(name), "\(name) is a link, not a tunnel")
        }
    }

    // MARK: The invariant

    @Test func aFullTunnelDoesNotChangeTheNetworkKey() throws {
        let before = try #require(fingerprint(physicalOnly, arp: homeARP))
        let during = try #require(fingerprint(physicalPlusFullTunnel, arp: homeARP))
        #expect(during.interface == "en0", "the tunnel is not the network")
        #expect(during.key == before.key,
                "connecting a VPN must not read as a network change")
        // And back again, for the disconnect half.
        #expect(fingerprint(physicalOnly, arp: homeARP)?.key == before.key)
    }

    @Test func tailscaleNeverContributesToIdentity() throws {
        let plain = try #require(fingerprint(physicalOnly, arp: homeARP))
        #expect(fingerprint(physicalPlusTailscale, arp: homeARP)?.key == plain.key)
        #expect(fingerprint(physicalPlusTailscaleExitNode, arp: homeARP)?.key == plain.key,
                "an exit node changes egress, not which network the Mac is on")
    }

    @Test func movingToAnotherNetworkStillChangesTheKey() throws {
        let home = try #require(fingerprint(physicalOnly, arp: homeARP))
        let cafe = try #require(fingerprint(otherNetwork, arp: cafeARP,
                                            localNetwork: "10.0.0.0/21"))
        #expect(home.key != cafe.key)
        #expect(cafe.gatewayMAC == MACAddress("a0:99:9b:18:dc:93"))
    }

    @Test func theGatewayMACComesFromTheMatchingARPEntry() throws {
        // Two interfaces can hold the same gateway address (a scoped route per
        // link); the one on OUR interface is the right MAC.
        let arp: [RouteTableSource.ARPEntry] = [
            (ip: "192.168.87.1", mac: fixtureMAC("de:ad:be:ef:00:01"), interface: "en7"),
            (ip: "192.168.87.1", mac: fixtureMAC("0:8:a2:e:dc:c7"), interface: "en0"),
        ]
        #expect(fingerprint(physicalOnly, arp: arp)?.gatewayMAC == MACAddress("0:8:a2:e:dc:c7"))
    }

    // MARK: Route picking

    @Test func thePhysicalDefaultIsPickedOverTheTunnelsOne() throws {
        let snapshot = RouteTableSnapshot(netstatText: physicalPlusFullTunnel)
        let route = try #require(NetworkIdentity.underlayDefaultRoute(in: snapshot))
        #expect(route.interfaceName == "en0")
        #expect(route.gateway == "192.168.87.1")
    }

    @Test func anUnscopedPhysicalDefaultBeatsAScopedOne() throws {
        let twoLinks = """
        Internet:
        Destination        Gateway            Flags        Netif Expire
        default            10.0.7.254         UGScIg         en7
        default            192.168.87.1       UGScg          en0
        """
        let route = try #require(
            NetworkIdentity.underlayDefaultRoute(in: RouteTableSnapshot(netstatText: twoLinks)))
        #expect(route.interfaceName == "en0", "the route the kernel would really use")
    }

    // MARK: Physical egress for VPN-server probes

    @Test func theProbeEgressIsThePhysicalDefaultNotTheTunnel() throws {
        // A full tunnel owns the default route; a probe of the VPN's own server
        // must still go out the physical link, or it loops through the tunnel it
        // is testing and answers its own hello.
        let name = NetworkIdentity.physicalEgressInterface(
            in: RouteTableSnapshot(netstatText: physicalPlusFullTunnel))
        #expect(name == "en0")
        // Same with an always-on Tailscale utun in the table.
        #expect(NetworkIdentity.physicalEgressInterface(
            in: RouteTableSnapshot(netstatText: physicalPlusTailscaleExitNode)) == "en0")
    }

    @Test func theProbeEgressFallsBackToTheInterfaceHoldingOurAddress() throws {
        // Tunnel-only default (no physical default in the table): the egress is
        // the interface our address sits on, so the probe still leaves the tunnel.
        let tunnelOnly = """
        Internet:
        Destination        Gateway            Flags        Netif Expire
        default            10.8.0.5           UGScg          utun4
        127                127.0.0.1          UCS            lo0
        """
        let name = NetworkIdentity.physicalEgressInterface(
            in: RouteTableSnapshot(netstatText: tunnelOnly), fallbackInterface: { "en0" })
        #expect(name == "en0")
    }

    @Test func theProbeEgressIsNilWhenNothingPhysicalCanBeFound() {
        // Genuinely nothing to bind to ⇒ nil, and the probe runs unbound (honest
        // fallback to normal routing rather than failing).
        let tunnelOnly = """
        Internet:
        Destination        Gateway            Flags        Netif Expire
        default            10.8.0.5           UGScg          utun4
        127                127.0.0.1          UCS            lo0
        """
        #expect(NetworkIdentity.physicalEgressInterface(
            in: RouteTableSnapshot(netstatText: tunnelOnly), fallbackInterface: { nil }) == nil)
    }

    @Test func withNoPhysicalDefaultTheInterfaceHoldingOurAddressIsUsed() throws {
        // Tunnel-only default route: DHCP hasn't handed one out, or the physical
        // default was withdrawn. Falling back keeps the memory alive rather than
        // silently dropping the whole fingerprint.
        let tunnelOnly = """
        Internet:
        Destination        Gateway            Flags        Netif Expire
        default            10.8.0.5           UGScg          utun4
        127                127.0.0.1          UCS            lo0
        """
        let fp = try #require(fingerprint(tunnelOnly, arp: homeARP, fallback: "en0"))
        #expect(fp.interface == "en0")
        #expect(fp.gatewayIP.isEmpty, "no physical gateway is known in this state")
        #expect(fp.key == "net:en0|192.168.87.0/24")
    }

    @Test func genuinelyOfflineStillReportsNoFingerprint() {
        let nothing = """
        Internet:
        Destination        Gateway            Flags        Netif Expire
        127                127.0.0.1          UCS            lo0
        """
        #expect(fingerprint(nothing, arp: [], localNetwork: nil, fallback: nil) == nil)
    }

    @Test func aLoopbackOnlyDefaultIsNotANetwork() {
        // Seen while the machine is being reconfigured; naming lo0 as "the
        // network" would file everything under a fourth fictional key.
        let loopbackDefault = """
        Internet:
        Destination        Gateway            Flags        Netif Expire
        default            127.0.0.1          UGScg          lo0
        """
        #expect(fingerprint(loopbackDefault, arp: [], localNetwork: nil, fallback: nil) == nil)
    }

    // MARK: Where traffic actually leaves

    @Test func theEgressRouteIsRecognisedAsTunnelledOrNot() {
        #expect(!NetworkIdentity.defaultRouteIsVirtual(
            in: RouteTableSnapshot(netstatText: physicalOnly)))
        #expect(NetworkIdentity.defaultRouteIsVirtual(
            in: RouteTableSnapshot(netstatText: physicalPlusFullTunnel)),
            "a full tunnel IS where traffic leaves, whatever the fingerprint says")
        #expect(!NetworkIdentity.defaultRouteIsVirtual(
            in: RouteTableSnapshot(netstatText: physicalPlusTailscale)),
            "a scoped, gatewayless utun carries nothing")
        #expect(NetworkIdentity.defaultRouteIsVirtual(
            in: RouteTableSnapshot(netstatText: physicalPlusTailscaleExitNode)))
    }

    // MARK: The home snapshot

    @Test func connectingCountsAsEngaged() {
        #expect(VPNController.isEngaged(.connecting), "the tunnel owns the route before it says so")
        #expect(VPNController.isEngaged(.reasserting))
        #expect(VPNController.isEngaged(.connected))
        #expect(!VPNController.isEngaged(.disconnected))
        #expect(!VPNController.isEngaged(.disconnecting))
        #expect(!VPNController.isEngaged(.invalid))
    }

    @Test func homeIsOnlySnapshottedWithNothingInTheWay() {
        #expect(PublicIPMonitor.homeSnapshotIsTrustworthy(
            vpnEngaged: false, egressIsTunnelled: false))
        #expect(!PublicIPMonitor.homeSnapshotIsTrustworthy(
            vpnEngaged: true, egressIsTunnelled: false),
            "connecting/connected — the answer would be the tunnel's country")
        #expect(!PublicIPMonitor.homeSnapshotIsTrustworthy(
            vpnEngaged: false, egressIsTunnelled: true),
            "someone else's tunnel has the default route")
        #expect(!PublicIPMonitor.homeSnapshotIsTrustworthy(
            vpnEngaged: true, egressIsTunnelled: true))
    }

    // MARK: Probes while connected

    @Test func aMeasurementIsNotRecordedForAVPNThatIsUp() {
        let network = "mac:0:8:a2:e:dc:c7"
        let store = EndpointProbeStore(networkKey: { network })
        store.isProfileEngaged = { $0 == "grlab" }
        let id = VPNEndpoint(host: "tig-vpn.grlab.co.uk").id

        // What a sweep that started before the connect comes back with: the probe
        // hairpinned through the tunnel and timed out.
        store.record(EndpointMeasurement(reachable: false, detail: "No answer.", measuredAt: Date()),
                     for: id, network: network, profile: "grlab")
        #expect(store.measurement(for: id) == nil,
                "we are connected to it — 'unreachable' is provably wrong")

        // Another VPN's endpoints are measured as usual.
        store.record(EndpointMeasurement(rttMS: 12, reachable: true, measuredAt: Date()),
                     for: id, network: network, profile: "other")
        #expect(store.measurement(for: id)?.rttMS == 12)
    }

    @Test func theSweepIsSkippedForAVPNThatIsUp() {
        let store = EndpointProbeStore(networkKey: { "mac:0:8:a2:e:dc:c7" })
        store.isProfileEngaged = { _ in true }
        store.refresh([VPNEndpoint(host: "tig-vpn.grlab.co.uk")], kind: .openVPN,
                      profile: "grlab", force: true)
        #expect(store.probing.isEmpty, "no probe may be sent into the tunnel it asks about")
        #expect(store.results.isEmpty)
    }

    @Test func aMeasurementTakenBeforeConnectingSurvivesTheConnect() {
        // The two halves together: the key doesn't move (so the number is still
        // readable), and nothing overwrites it with a through-tunnel result.
        let network = "mac:0:8:a2:e:dc:c7"
        let store = EndpointProbeStore(networkKey: { network })
        store.isProfileEngaged = { _ in false }
        let id = VPNEndpoint(host: "tig-vpn.grlab.co.uk").id

        store.record(EndpointMeasurement(rttMS: 21, reachable: true, measuredAt: Date()),
                     for: id, network: network, profile: "grlab")
        // Connecting is a new answer to the same question, so the predicate is
        // replaced rather than a captured flag flipped under it.
        store.isProfileEngaged = { _ in true }
        store.record(EndpointMeasurement(reachable: false, measuredAt: Date()),
                     for: id, network: network, profile: "grlab")
        #expect(store.measurement(for: id)?.rttMS == 21)
        #expect(store.measurement(for: id)?.reachable == true)
    }

    // MARK: Wording

    @Test func theFootnoteDoesNotPromiseChecksThatArePaused() {
        let text = EndpointRegions.orderExplanation([], home: nil, connected: true)
        #expect(text.contains("paused"))
        #expect(!EndpointRegions.orderExplanation([], home: nil, connected: false).contains("paused"))
    }
}
