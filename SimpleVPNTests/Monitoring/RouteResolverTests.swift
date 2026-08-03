// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  RouteResolverTests.swift
//  Pins what "where does this IP go, and where could it go" is allowed to claim.
//  The fixtures are REAL `netstat -rn` output from a Mac carrying a full-tunnel
//  VPN (utun8) plus Tailscale (utun1) on top of Wi-Fi (en0), trimmed but not
//  edited, because every hard case here is a macOS quirk rather than a
//  hypothetical: three simultaneous default routes distinguished only by the
//  scoping flag, BSD shorthand destinations missing their trailing octets, ARP
//  clones with MAC addresses in the gateway column, and IPv6 rows carrying zone
//  suffixes.
//
//  The rules being defended:
//    • longest prefix wins; on a tie an UNSCOPED route beats an interface-scoped
//      one; still tied → table order;
//    • an alternative is only listed if it could actually carry the traffic — a
//      scoped default with no gateway (Tailscale advertising itself with no exit
//      node) is never offered;
//    • a CIDR that straddles several routes says so instead of picking one.
//

import Foundation
import Testing
@testable import SimpleVPN

struct RouteResolverTests {

    // MARK: Fixtures (live capture, trimmed)

    /// `netstat -rn -f inet`. Note the three defaults, in this order:
    /// unscoped utun8 (the winner), scoped en0 WITH a gateway (a real standby),
    /// scoped utun1 with none (Tailscale, no exit node — unusable).
    static let ipv4 = """
    Routing tables

    Internet:
    Destination        Gateway            Flags               Netif Expire
    default            link#27            UCSg                utun8
    default            10.0.7.254         UGScIg                en0
    default            link#20            UCSIg               utun1
    17.253.29.131      link#27            UHWIig              utun8
    10/21              link#16            UCS                   en0      !
    10.0.0.4           a0:99:9b:18:dc:93  UHLWI                 en0   1187
    10.0.5.27/32       link#16            UCS                   en0      !
    10.0.5.27          ba:b8:50:a8:96:9f  UHLWI                 lo0
    10.0.7.254/32      link#16            UCS                   en0      !
    10.0.7.254         cc:3:d9:fd:e4:d5   UHLWIir               en0   1187
    100.64/10          link#20            UCS                 utun1
    100.100.100.100/32 link#20            UCS                 utun1
    127                127.0.0.1          UCS                   lo0
    127.0.0.1          127.0.0.1          UH                    lo0
    169.254            link#16            UCS                   en0      !
    172.16.8.15        172.16.8.15        UH                  utun8
    192.168.9          link#20            UCS                 utun1
    224.0.0/4          link#27            UmCS                utun8
    224.0.0/4          link#16            UmCSI                 en0      !
    255.255.255.255/32 link#27            UCS                 utun8
    """

    /// `netstat -rn -f inet6`. Every default here is scoped — this Mac has no
    /// unscoped IPv6 egress — and the zone suffixes (`%lo0`, `%en0`) are the
    /// parsing hazard.
    static let ipv6 = """
    Routing tables

    Internet6:
    Destination                             Gateway                                 Flags               Netif Expire
    default                                 fe80::%utun0                            UGcIg               utun0
    default                                 fd7a:115c:a1e0::                        UGcIg               utun1
    default                                 fe80::%utun2                            UGcIg               utun2
    ::1                                     ::1                                     UHL                   lo0
    fd7a:115c:a1e0::/48                     fe80::b24f:13ff:feee:c4c2%utun1         Uc                  utun1
    fd7a:115c:a1e0::53/128                  link#20                                 UCS                 utun1
    fd7a:115c:a1e0::53                      link#20                                 UHWIi               utun1
    fe80::%lo0/64                           fe80::1%lo0                             UcI                   lo0
    fe80::1%lo0                             link#1                                  UHLI                  lo0
    fe80::%en0/64                           link#16                                 UCI                   en0
    fe80::1a:1a41:b26e:938b%en0             7a:6d:bb:cc:9b:5f                       UHLWI                 en0
    ff00::/8                                ::1                                     UmCI                  lo0
    ff01::%en0/32                           link#16                                 UmCI                  en0
    """

    static let resolver = RouteResolver(ipv4Text: ipv4, ipv6Text: ipv6)
    var resolver: RouteResolver { Self.resolver }

    // MARK: Prefix parsing — BSD shorthand and friends

    @Test func parsesBSDShorthandDestinations() {
        // Missing octets are implied zeros AND imply the length when none is given.
        #expect(IPPrefix.parseDestination("10/21", family: .v4)?.prefix.description == "10.0.0.0/21")
        #expect(IPPrefix.parseDestination("10.11/16", family: .v4)?.prefix.description == "10.11.0.0/16")
        #expect(IPPrefix.parseDestination("127", family: .v4)?.prefix.description == "127.0.0.0/8")
        #expect(IPPrefix.parseDestination("192.168.9", family: .v4)?.prefix.description == "192.168.9.0/24")
        // A bare four-octet destination is a host route even without /32.
        #expect(IPPrefix.parseDestination("10.0.0.4", family: .v4)?.prefix.description == "10.0.0.4/32")
        #expect(IPPrefix.parseDestination("default", family: .v4)?.prefix.description == "0.0.0.0/0")
        #expect(IPPrefix.parseDestination("default", family: .v6)?.prefix.description == "::/0")
        // Host bits are masked off, they don't make the prefix a different network.
        #expect(IPPrefix.parseQuery("192.168.9.77/24")?.prefix.description == "192.168.9.0/24")
    }

    @Test func parsesIPv6ZoneSuffixes() {
        let scoped = IPPrefix.parseDestination("fe80::%lo0/64", family: .v6)
        #expect(scoped?.prefix.description == "fe80::/64")
        #expect(scoped?.zone == "lo0")

        let host = IPPrefix.parseDestination("fe80::1%lo0", family: .v6)
        #expect(host?.prefix.description == "fe80::1/128")
        #expect(host?.zone == "lo0")

        #expect(IPPrefix.parseDestination("ff01::%en0/32", family: .v6)?.zone == "en0")
        #expect(IPPrefix.parseDestination("fd7a:115c:a1e0::/48", family: .v6)?.zone == nil)
    }

    @Test func rejectsMalformedInput() {
        for junk in ["", "   ", "hello", "1.2.3.999", "1.2.3.4.5", "10.0.0.0/33",
                     "::gg", "/24", "192.168.1", "10", "default", "-1.2.3.4",
                     "1.2.3.4/abc", "10.0.0.0/", "::1/129", "1.2.3.4%"] {
            #expect(resolver.resolve(junk) == nil, "\(junk) should not resolve")
        }
    }

    @Test func linkAndMACGatewaysAreNotAddresses() {
        // Only a genuine next hop counts as a gateway — this is what keeps a
        // gatewayless scoped route out of the alternatives list.
        #expect(IPPrefix.parseAddress("link#27") == nil)
        #expect(IPPrefix.parseAddress("a0:99:9b:18:dc:93") == nil)   // 6-group MAC
        #expect(IPPrefix.parseAddress("cc:3:d9:fd:e4:d5") == nil)    // MAC, short octets
        #expect(IPPrefix.parseAddress("utun8") == nil)
        #expect(IPPrefix.parseAddress("10.0.7.254")?.prefix.description == "10.0.7.254/32")
        #expect(IPPrefix.parseAddress("fe80::%utun0")?.prefix.description == "fe80::/128")
        #expect(IPPrefix.parseAddress("fd7a:115c:a1e0::")?.prefix.description == "fd7a:115c:a1e0::/128")
    }

    // MARK: Winner + alternatives — the headline case

    @Test func internetAddressTakesTheUnscopedDefaultAndOffersOnlyUsableStandbys() throws {
        let r = try #require(resolver.resolve("1.1.1.1"))
        #expect(r.kind == .address)
        #expect(r.winner?.interfaceName == "utun8")
        #expect(r.winner?.isDefault == true)
        #expect(r.winner?.isScoped == false)

        // The scoped en0 default has a real gateway, so it is a genuine standby.
        #expect(r.alternatives.map(\.interfaceName) == ["en0"])
        #expect(r.alternatives.first?.gateway == "10.0.7.254")

        // utun1's default is scoped AND gatewayless (Tailscale with no exit node).
        // It can carry nothing, so it must never be offered as somewhere it could go.
        #expect(!r.alternatives.contains { $0.interfaceName == "utun1" })
    }

    @Test func scopedGatewaylessDefaultIsStillInTheTableJustNotViable() throws {
        let scoped = try #require(
            resolver.snapshot.routes.first { $0.interfaceName == "utun1" && $0.isDefault && $0.family == .v4 })
        #expect(scoped.isScoped)
        #expect(!scoped.hasRealGateway)
        #expect(scoped.gatewayIsLink)
        #expect(!scoped.isViableAlternative)
    }

    @Test func pushedTunnelRouteBeatsTheDefault() throws {
        // 192.168.9/24 is pushed at us over utun1; the default lives on utun8.
        let r = try #require(resolver.resolve("192.168.9.5"))
        #expect(r.winner?.interfaceName == "utun1")
        #expect(r.winner?.destination == "192.168.9")
        #expect(r.winner?.prefix.description == "192.168.9.0/24")
        // Falling back means the defaults — the usable ones, in takeover order.
        #expect(r.alternatives.map(\.interfaceName) == ["utun8", "en0"])
    }

    @Test func localSubnetAddressUsesTheConnectedRoute() throws {
        let r = try #require(resolver.resolve("10.0.2.5"))
        #expect(r.winner?.interfaceName == "en0")
        #expect(r.winner?.destination == "10/21")            // shorthand for 10.0.0.0/21
        #expect(r.winner?.prefix.prefixLength == 21)
        #expect(r.alternatives.map(\.interfaceName) == ["utun8", "en0"])
    }

    @Test func hostRouteBeatsTheConnectedSubnet() throws {
        let r = try #require(resolver.resolve("10.0.0.4"))
        #expect(r.winner?.prefix.prefixLength == 32)
        #expect(r.winner?.interfaceName == "en0")
        // The less-specific covering routes are where it could go instead.
        #expect(r.alternatives.map(\.destination).first == "10/21")
    }

    @Test func unscopedBeatsScopedAtEqualPrefixLength() throws {
        // 10.0.5.27 appears twice at /32: unscoped UCS via en0, then a scoped ARP
        // clone via lo0. Equal length → the unscoped row wins.
        let r = try #require(resolver.resolve("10.0.5.27"))
        #expect(r.winner?.interfaceName == "en0")
        #expect(r.winner?.isScoped == false)
        // The lo0 row is scoped with a MAC in the gateway column — not viable.
        #expect(!r.alternatives.contains { $0.interfaceName == "lo0" })
    }

    @Test func multicastPrefersTheUnscopedCopy() throws {
        // 224.0.0/4 exists on utun8 (unscoped) and en0 (scoped, gatewayless).
        let r = try #require(resolver.resolve("224.0.0.251"))
        #expect(r.winner?.interfaceName == "utun8")
        #expect(r.winner?.prefix.prefixLength == 4)
        // The scoped, gatewayless en0 copy of 224.0.0/4 is dropped, so the only
        // places multicast could go instead are the two usable defaults.
        #expect(!r.alternatives.contains { $0.prefix.prefixLength == 4 })
        #expect(r.alternatives.map(\.interfaceName) == ["utun8", "en0"])
        #expect(r.alternatives.filter { !$0.isDefault }.isEmpty)
    }

    @Test func loopbackUsesTheShorthandClassARoute() throws {
        let r = try #require(resolver.resolve("127.0.0.53"))
        #expect(r.winner?.interfaceName == "lo0")
        #expect(r.winner?.destination == "127")
    }

    @Test func addressWithNoCoveringRouteIsUnroutable() throws {
        let tiny = RouteResolver(netstatText: """
        Internet:
        Destination        Gateway            Flags               Netif Expire
        10/8               link#1             UCS                   en0
        """, family: .v4)
        let r = try #require(tiny.resolve("8.8.8.8"))
        #expect(r.winner == nil)
        #expect(!r.isRoutable)
        #expect(r.segments.count == 1)
        #expect(r.segments.first?.source == .unroutable)
    }

    // MARK: CIDR queries — the honest split

    @Test func cidrSpanningAPushedRouteAndTheDefaultReportsBothParts() throws {
        // 192.168.8.0/23 is half Tailscale-pushed (192.168.9/24 → utun1) and half
        // nothing-in-particular (falls through to the default → utun8).
        let r = try #require(resolver.resolve("192.168.8.0/23"))
        #expect(r.kind == .network)
        #expect(r.spansMultipleRoutes)
        #expect(r.segments.count == 2)

        let byPrefix = Dictionary(uniqueKeysWithValues: r.segments.map { ($0.prefix.description, $0) })
        #expect(byPrefix["192.168.9.0/24"]?.interfaceName == "utun1")
        #expect(byPrefix["192.168.9.0/24"]?.source == .specific)
        #expect(byPrefix["192.168.8.0/24"]?.interfaceName == "utun8")
        #expect(byPrefix["192.168.8.0/24"]?.source == .covering)
        #expect(byPrefix["192.168.8.0/24"]?.isRemainder == true)

        // The whole-range answer is the covering route, plus its own standbys.
        #expect(r.winner?.interfaceName == "utun8")
        #expect(r.alternatives.map(\.interfaceName) == ["en0"])
        // …and the diverted part carries the alternatives that apply to IT.
        #expect(byPrefix["192.168.9.0/24"]?.alternatives.map(\.interfaceName) == ["utun8", "en0"])
    }

    @Test func cidrLandingWhollyInsideOneRouteIsNotSplit() throws {
        let r = try #require(resolver.resolve("10.0.2.0/24"))
        #expect(!r.spansMultipleRoutes)
        #expect(r.segments.count == 1)
        #expect(r.segments.first?.prefix.description == "10.0.2.0/24")
        #expect(r.segments.first?.interfaceName == "en0")
    }

    @Test func wholeInternetSplitsByDivertingRoutesOnly() throws {
        // 0.0.0.0/0 across the real table. Every genuinely diverting prefix must
        // appear; the ARP clones and host routes that land on the SAME interface
        // as the route enclosing them must not, or the answer becomes noise.
        let r = try #require(resolver.resolve("0.0.0.0/0"))
        #expect(r.winner?.interfaceName == "utun8")
        #expect(!r.segmentsTruncated)

        let specifics = r.segments.filter { $0.source == .specific }
        let diverted = Dictionary(uniqueKeysWithValues: specifics.map { ($0.prefix.description, $0.interfaceName) })
        #expect(diverted["10.0.0.0/21"] == "en0")
        #expect(diverted["100.64.0.0/10"] == "utun1")
        #expect(diverted["192.168.9.0/24"] == "utun1")
        #expect(diverted["127.0.0.0/8"] == "lo0")
        #expect(diverted["169.254.0.0/16"] == "en0")
        #expect(diverted.count == 5)

        // Dropped as redundant: same interface as the route they sit inside.
        #expect(diverted["10.0.0.4/32"] == nil)
        #expect(diverted["100.100.100.100/32"] == nil)
        #expect(diverted["224.0.0.0/4"] == nil)
        #expect(diverted["172.16.8.15/32"] == nil)

        #expect(Set(r.interfaceNames) == ["utun8", "en0", "utun1", "lo0"])
        // The remainder is real prefixes, not a hand-wave.
        #expect(r.segments.contains { $0.source == .covering && $0.interfaceName == "utun8" })
    }

    @Test func cidrShorthandQueryResolvesLikeTheTableWritesIt() throws {
        let r = try #require(resolver.resolve("10.0/21"))
        #expect(r.prefix.description == "10.0.0.0/21")
        #expect(r.winner?.interfaceName == "en0")
        #expect(!r.spansMultipleRoutes)
    }

    // MARK: IPv6

    @Test func ipv6AddressMatchesItsSpecificRoute() throws {
        let r = try #require(resolver.resolve("fd7a:115c:a1e0::53"))
        #expect(r.prefix.family == .v6)
        #expect(r.winner?.interfaceName == "utun1")
        #expect(r.winner?.prefix.prefixLength == 128)
        #expect(r.winner?.isScoped == false)     // the UCS row, not the scoped clone
    }

    @Test func ipv6FallsBackToTheEnclosingPrefix() throws {
        let r = try #require(resolver.resolve("fd7a:115c:a1e0::99"))
        #expect(r.winner?.interfaceName == "utun1")
        #expect(r.winner?.prefix.description == "fd7a:115c:a1e0::/48")
    }

    @Test func ipv6DefaultsAreAllScopedSoTableOrderDecides() throws {
        let r = try #require(resolver.resolve("2606:4700:4700::1111"))
        #expect(r.winner?.interfaceName == "utun0")
        #expect(r.winner?.isDefault == true)
        // Every other default names a real next hop, so all of them are viable.
        #expect(r.alternatives.map(\.interfaceName) == ["utun1", "utun2"])
    }

    @Test func ipv6LinkLocalZonesParseAndScopeTheAnswer() throws {
        // fe80::/64 exists on lo0, en0 and (in the full table) several utuns with
        // identical bytes — only the zone tells them apart.
        let lo = try #require(resolver.resolve("fe80::1%lo0"))
        #expect(lo.winner?.interfaceName == "lo0")
        #expect(lo.winner?.prefix.prefixLength == 128)

        let en = try #require(resolver.resolve("fe80::1a:1a41:b26e:938b%en0"))
        #expect(en.winner?.interfaceName == "en0")

        // A link-local with no zone at all must still answer, not crash.
        let bare = try #require(resolver.resolve("fe80::1"))
        #expect(bare.prefix.family == .v6)
        #expect(bare.winner != nil)
    }

    @Test func ipv6QueryIgnoresTheIPv4Table() throws {
        let r = try #require(resolver.resolve("::1"))
        #expect(r.winner?.interfaceName == "lo0")
        #expect(r.segments.allSatisfy { $0.route?.family == .v6 })
    }

    @Test func ipv6CidrSplitsLikeIPv4() throws {
        // ff00::/8 is on lo0; ff01::%en0/32 diverts a slice of it to en0.
        let r = try #require(resolver.resolve("ff00::/8"))
        #expect(r.winner?.interfaceName == "lo0")
        #expect(r.spansMultipleRoutes)
        #expect(r.segments.contains { $0.prefix.description == "ff01::/32" && $0.interfaceName == "en0" })
    }

    // MARK: Snapshot plumbing

    @Test func parsesCombinedNetstatOutputIntoBothFamilies() {
        let combined = Self.ipv4 + "\n" + Self.ipv6
        let snapshot = RouteTableSnapshot(netstatText: combined)
        #expect(snapshot.routes(family: .v4).count == 20)
        #expect(snapshot.routes(family: .v6).count == 13)
        // Order is global and monotonic — it is the kernel's tie-break.
        #expect(snapshot.routes.map(\.order) == Array(0..<snapshot.routes.count))
        // The header rows never become routes.
        #expect(!snapshot.routes.contains { $0.destination == "Destination" })
    }

    @Test func resolvesFromALiveTopologyWithoutASnapshot() throws {
        // The fallback path: a topology whose IPv4 RouteEntry list is all we have.
        let entries = Self.resolver.snapshot.routes(family: .v4).map {
            RouteEntry(destination: $0.destination, gateway: $0.gateway,
                       interfaceName: $0.interfaceName, flags: $0.flags)
        }
        let topology = NetworkTopology(routes: entries)
        let r = try #require(RouteResolver(topology: topology).resolve("1.1.1.1"))
        #expect(r.winner?.interfaceName == "utun8")
        #expect(r.alternatives.map(\.interfaceName) == ["en0"])
    }

    @Test func egressInterfaceAgreesWithTheResolverEverywhere() {
        // egressInterface once had its own inline scan (no scoping, last-match-wins
        // on ties) and answered utun1 — Tailscale's gatewayless scoped default — for
        // internet addresses. It now DELEGATES to RouteResolver, so this test flipped
        // from documenting the divergence to guaranteeing it can never return: the
        // two must agree on the tie-broken case and the plain case alike.
        let entries = Self.resolver.snapshot.routes(family: .v4).map {
            RouteEntry(destination: $0.destination, gateway: $0.gateway,
                       interfaceName: $0.interfaceName, flags: $0.flags)
        }
        let topology = NetworkTopology(
            interfaces: ["utun8", "en0", "utun1"].map {
                NetInterface(name: $0, kind: .tunnel, displayName: $0)
            },
            routes: entries)

        #expect(topology.egressInterface(forIPv4: "1.1.1.1")?.name == "utun8")
        #expect(RouteResolver(topology: topology).resolve("1.1.1.1")?.winner?.interfaceName == "utun8")

        // They agree wherever there is no tie to break.
        #expect(topology.egressInterface(forIPv4: "192.168.9.5")?.name == "utun1")
        #expect(RouteResolver(topology: topology).resolve("192.168.9.5")?.winner?.interfaceName == "utun1")
    }

    // MARK: Prefix arithmetic

    @Test func prefixSubtractionTilesExactly() throws {
        let base = try #require(IPPrefix.parseQuery("10.0.0.0/24")?.prefix)
        let hole = try #require(IPPrefix.parseQuery("10.0.0.128/25")?.prefix)
        #expect(IPPrefix.subtracting(hole, from: base).map(\.description) == ["10.0.0.0/25"])

        // A /24 minus a single /32 is 255 addresses = one sibling prefix per level
        // between /32 and /24, i.e. /25 + /26 + … + /32.
        let host = try #require(IPPrefix.parseQuery("10.0.0.0/32")?.prefix)
        let pieces = IPPrefix.subtracting(host, from: base)
        #expect(pieces.count == 8)
        #expect(Set(pieces.map(\.prefixLength)) == Set(25...32))
        #expect(!pieces.contains { $0.overlaps(host) })

        // Disjoint holes change nothing; a hole that swallows the base empties it.
        let elsewhere = try #require(IPPrefix.parseQuery("11.0.0.0/8")?.prefix)
        #expect(IPPrefix.subtracting(elsewhere, from: base) == [base])
        let bigger = try #require(IPPrefix.parseQuery("10.0.0.0/8")?.prefix)
        #expect(IPPrefix.subtracting(bigger, from: base).isEmpty)
    }

    @Test func prefixContainmentIsFamilyAware() throws {
        let v4 = try #require(IPPrefix.parseQuery("10.0.0.0/8")?.prefix)
        let v6 = try #require(IPPrefix.parseQuery("::/0")?.prefix)
        #expect(!v6.contains(v4))
        #expect(!v4.contains(v6))
        #expect(v6.contains(try #require(IPPrefix.parseQuery("2001:db8::1")?.prefix)))
    }
}
