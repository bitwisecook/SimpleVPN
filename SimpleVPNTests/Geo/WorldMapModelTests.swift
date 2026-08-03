// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  WorldMapModelTests.swift
//  Pins the live-topology builder: a connected tunnel is ALWAYS drawn as a tunnel
//  link, including the corporate/lab case where the gateway sits on RFC1918 space
//  and can never be geolocated (that was the bug — such a VPN only ever rendered
//  as the dashed "not through the VPN" bypass line). Also covers the address-scope
//  classifier and the egress attribution rules, with the GeoIP lookup injected so
//  nothing here depends on the bundled database.
//
//  And the position ladder behind that case: when the live gateway address can't
//  be geolocated, the concentrator is placed from the endpoint's OWN configuration
//  (the country the user set, or where its hostname resolves from — here or on
//  another network this Mac remembers) and the pin says "approximate". What must
//  never happen is a country nothing in the configuration names, or a live tunnel
//  that renders as the client dot merely having moved.
//

import Foundation
import Testing
@testable import SimpleVPN

struct IPAddressScopeTests {

    @Test func rfc1918AndCGNATAreNotGeolocatable() {
        for ip in ["10.0.0.1", "10.255.255.255",
                   "172.16.0.1", "172.31.255.254",
                   "192.168.0.1", "192.168.32.137",
                   "100.64.0.1", "100.127.255.255"] {
            #expect(IPAddressScope.isPrivateOrReserved(ip), "\(ip) should be private")
        }
    }

    @Test func loopbackLinkLocalAndReservedV4() {
        for ip in ["127.0.0.1", "127.255.255.255", "169.254.1.1", "0.0.0.0",
                   "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
                   "192.0.0.1", "192.0.2.5", "198.18.0.1", "198.19.255.255",
                   "198.51.100.4", "203.0.113.9"] {
            #expect(IPAddressScope.isPrivateOrReserved(ip), "\(ip) should be reserved")
        }
    }

    @Test func publicV4IsGeolocatable() {
        // The near-misses matter: an off-by-one in the mask would quietly hide real
        // gateways behind the "location not public" treatment.
        for ip in ["8.8.8.8", "1.1.1.1", "81.2.69.142",
                   "172.15.255.255", "172.32.0.1",
                   "100.63.255.255", "100.128.0.1",
                   "192.169.0.1", "192.1.2.3", "198.17.255.255", "198.20.0.1",
                   "203.0.114.1", "223.255.255.255"] {
            #expect(!IPAddressScope.isPrivateOrReserved(ip), "\(ip) should be public")
        }
    }

    @Test func privateV6() {
        for ip in ["::", "::1", "fc00::1", "fd12:3456:789a::1",
                   "fe80::1", "fe80::1%en0", "febf::1",
                   "ff02::1", "2001:db8::1"] {
            #expect(IPAddressScope.isPrivateOrReserved(ip), "\(ip) should be private")
        }
    }

    @Test func publicV6() {
        for ip in ["2606:4700:4700::1111", "2a00:1450:4001:81f::200e",
                   "2001:4860:4860::8888", "fec0::1"] {
            #expect(!IPAddressScope.isPrivateOrReserved(ip), "\(ip) should be public")
        }
    }

    @Test func v4MappedV6IsJudgedAsItsV4() {
        #expect(IPAddressScope.isPrivateOrReserved("::ffff:192.168.1.1"))
        #expect(!IPAddressScope.isPrivateOrReserved("::ffff:8.8.8.8"))
    }

    @Test func nonNumericInputIsUnresolvedNotPrivate() {
        // "we haven't resolved it" and "it can never be resolved" are different
        // messages on the map, so they must be different answers here.
        for text in ["", "vpn.example.com", "not-an-ip", "999.1.1.1", "10.0.0"] {
            #expect(!IPAddressScope.isPrivateOrReserved(text), "\(text) should not be private")
        }
    }
}

@MainActor
struct WorldMapModelTests {

    // MARK: Fixtures

    /// Home in Germany; egress unset unless a test supplies it.
    private let home = WorldMapModel.Vantage(
        homeLat: 51.2, homeLon: 10.4, homeCountryCode: "DE", homeCountryName: "Germany")

    private func vantage(egressCC: String?, lat: Double? = nil, lon: Double? = nil,
                         ip: String? = "203.0.113.7") -> WorldMapModel.Vantage {
        var v = home
        v.egressCountryCode = egressCC
        v.egressCountryName = egressCC.flatMap { CountryCentroids.name(for: $0) }
        let c = egressCC.flatMap { CountryCentroids.coordinate(for: $0) }
        v.egressLat = lat ?? c?.lat
        v.egressLon = lon ?? c?.lon
        v.egressIP = ip
        return v
    }

    private func stats(_ id: String, serverIP: String?, endpoint: String = "vpn.example.com",
                       tunnelIPv4: String = "10.8.0.2") -> TunnelStats {
        TunnelStats(profile: id, timestamp: 1_000, connectedSince: 900, reconnects: 0,
                    bytesIn: 10, bytesOut: 10,
                    serverEndpoint: endpoint, tunnelIPv4: tunnelIPv4,
                    dnsServers: ["10.8.0.1"], proxies: [],
                    serverIP: serverIP)
    }

    /// A stand-in GeoIP: only the addresses handed to it resolve.
    private func locator(_ map: [String: WorldMapModel.GeoPlace]) -> @MainActor (String) -> WorldMapModel.GeoPlace? {
        { map[$0] }
    }

    private let gbPlace = WorldMapModel.GeoPlace(countryCode: "GB", lat: 54.0, lon: -2.5)
    private let frPlace = WorldMapModel.GeoPlace(countryCode: "FR", lat: 46.2, lon: 2.2)

    private func pin(_ r: WorldMapModel.Result, _ id: String) -> MapPin? {
        r.pins.first { $0.id == id }
    }
    private func link(_ r: WorldMapModel.Result, from: String, to: String) -> MapConnection? {
        r.connections.first { $0.from == from && $0.to == to }
    }

    // MARK: The bug: an ungeolocatable gateway must still read as connected

    @Test func privateGatewayStillYieldsALiveTunnel() {
        let r = WorldMapModel.build(vantage: home,
                                    stats: ["p1": stats("p1", serverIP: "192.168.32.137")],
                                    locate: locator([:]),
                                    name: { _ in "Lab VPN" })

        let node = pin(r, "vpn.p1")
        #expect(node != nil)
        #expect(node?.kind == .endpoint(selected: true))
        // Never invent a foreign location: it is placed AT home, and offset only in
        // screen points so it can't be read as a coordinate.
        #expect(node?.lat == home.homeLat)
        #expect(node?.lon == home.homeLon)
        #expect(node?.locationKnown == false)
        #expect(node?.screenOffset != .zero)

        let tunnel = link(r, from: "home", to: "vpn.p1")
        #expect(tunnel?.kind == .tunnel)
        #expect(tunnel?.isTunnel == true)
        // Nothing about this topology may be dashed — dashed means "not through the VPN".
        #expect(!r.connections.contains { $0.kind == MapConnection.Kind.bypass })
        #expect(r.hasUnlocatableTunnel)
    }

    @Test func gatewaySubtitleSaysWhyItIsUnplaced() {
        let r = WorldMapModel.build(vantage: home,
                                    stats: ["p1": stats("p1", serverIP: "192.168.32.137")],
                                    locate: locator([:]),
                                    name: { _ in "Lab VPN" })
        let subtitle = pin(r, "vpn.p1")?.subtitle ?? ""
        #expect(subtitle.contains("Gateway 192.168.32.137"))
        #expect(subtitle.contains("location not public"))
        #expect(subtitle.contains("private network"))
        #expect(subtitle.contains("tunnel 10.8.0.2"))
    }

    @Test func publicGatewayThatGeoIPMissesIsUnplacedButStillLive() {
        // A public address the DB simply doesn't cover: same live treatment, but
        // the tooltip must not claim it is on a private network.
        let r = WorldMapModel.build(vantage: home,
                                    stats: ["p1": stats("p1", serverIP: "198.20.0.7")],
                                    locate: locator([:]),
                                    name: { _ in "VPN" })
        #expect(pin(r, "vpn.p1")?.locationKnown == false)
        #expect(link(r, from: "home", to: "vpn.p1")?.kind == .tunnel)
        let subtitle = pin(r, "vpn.p1")?.subtitle ?? ""
        #expect(subtitle.contains("location not public"))
        #expect(!subtitle.contains("private network"))
    }

    @Test func tunnelWithNoResolvedAddressYetIsStillLive() {
        // The 1 Hz sample can land before the transport publishes serverIP; the map
        // must show the tunnel immediately rather than wait for geolocation.
        let r = WorldMapModel.build(vantage: home,
                                    stats: ["p1": stats("p1", serverIP: nil)],
                                    locate: locator([:]),
                                    name: { _ in "VPN" })
        #expect(pin(r, "vpn.p1")?.locationKnown == false)
        #expect(link(r, from: "home", to: "vpn.p1")?.kind == .tunnel)
        #expect(pin(r, "vpn.p1")?.subtitle.contains("vpn.example.com") == true)
    }

    @Test func severalUnplacedTunnelsDoNotStackOnTopOfEachOther() {
        let r = WorldMapModel.build(
            vantage: home,
            stats: ["p1": stats("p1", serverIP: "10.0.0.1"),
                    "p2": stats("p2", serverIP: "192.168.5.1")],
            locate: locator([:]),
            name: { $0 })
        let a = pin(r, "vpn.p1")?.screenOffset
        let b = pin(r, "vpn.p2")?.screenOffset
        #expect(a != nil && b != nil)
        #expect(a != b)
    }

    @Test func unplacedTunnelNeedsAHomeToSitBeside() {
        // With no home pin there is nothing to anchor to — and guessing would be a lie.
        let r = WorldMapModel.build(vantage: WorldMapModel.Vantage(),
                                    stats: ["p1": stats("p1", serverIP: "192.168.32.137")],
                                    locate: locator([:]),
                                    name: { _ in "VPN" })
        #expect(r.pins.isEmpty)
        #expect(r.connections.isEmpty)
    }

    // MARK: Geolocatable gateways keep the original behaviour

    @Test func geolocatableGatewayKeepsItsPinAndSolidArc() {
        let r = WorldMapModel.build(vantage: home,
                                    stats: ["p1": stats("p1", serverIP: "81.2.69.142")],
                                    locate: locator(["81.2.69.142": gbPlace]),
                                    name: { _ in "UK VPN" })
        let node = pin(r, "vpn.p1")
        #expect(node?.lat == gbPlace.lat)
        #expect(node?.lon == gbPlace.lon)
        #expect(node?.locationKnown == true)
        #expect(node?.screenOffset == .zero)
        #expect(node?.subtitle.contains("location not public") == false)
        #expect(link(r, from: "home", to: "vpn.p1")?.kind == .tunnel)
        #expect(!r.hasUnlocatableTunnel)
    }

    @Test func homePinPrefersTheDevicePositionWhenOptedIn() {
        let r = WorldMapModel.build(vantage: home,
                                    stats: [:],
                                    device: (lat: 1.5, lon: 2.5, place: "On “Wi-Fi”"),
                                    locate: locator([:]),
                                    name: { $0 })
        #expect(pin(r, "home")?.lat == 1.5)
        #expect(pin(r, "home")?.subtitle == "On “Wi-Fi”")
    }

    @Test func nothingConnectedDrawsNoTunnelLinks() {
        let r = WorldMapModel.build(vantage: home, stats: [:],
                                    locate: locator([:]), name: { $0 })
        #expect(r.pins.map(\.id) == ["home"])
        #expect(r.connections.isEmpty)
        #expect(!r.hasUnlocatableTunnel)
    }

    // MARK: Egress attribution

    @Test func egressIsAttributedToTheGatewayInThatCountry() {
        let r = WorldMapModel.build(vantage: vantage(egressCC: "GB"),
                                    stats: ["p1": stats("p1", serverIP: "81.2.69.142")],
                                    locate: locator(["81.2.69.142": gbPlace]),
                                    name: { $0 })
        #expect(link(r, from: "vpn.p1", to: "egress")?.kind == .tunnel)
        #expect(link(r, from: "home", to: "egress") == nil)
    }

    @Test func egressIsAttributedToTheOnlyUnplaceableTunnel() {
        // Egress moved off home's country and the private-gateway tunnel is the only
        // thing that could have moved it — so it gets the credit, solid.
        let r = WorldMapModel.build(vantage: vantage(egressCC: "GB"),
                                    stats: ["p1": stats("p1", serverIP: "192.168.32.137")],
                                    locate: locator([:]),
                                    name: { $0 })
        #expect(link(r, from: "vpn.p1", to: "egress")?.kind == .tunnel)
        #expect(!r.connections.contains { $0.kind == MapConnection.Kind.bypass })
    }

    @Test func ambiguousEgressFallsBackToADashedBypass() {
        // Two unplaceable tunnels: crediting either would be a guess, so say the
        // honest thing — we can't tell this egress goes through a VPN.
        let r = WorldMapModel.build(
            vantage: vantage(egressCC: "GB"),
            stats: ["p1": stats("p1", serverIP: "10.0.0.1"),
                    "p2": stats("p2", serverIP: "10.0.0.2")],
            locate: locator([:]),
            name: { $0 })
        #expect(link(r, from: "home", to: "egress")?.kind == .bypass)
        #expect(link(r, from: "vpn.p1", to: "egress") == nil)
        // The tunnels themselves still read as live.
        #expect(link(r, from: "home", to: "vpn.p1")?.kind == .tunnel)
        #expect(link(r, from: "home", to: "vpn.p2")?.kind == .tunnel)
    }

    @Test func egressThroughNoTunnelIsADashedBypass() {
        let r = WorldMapModel.build(vantage: vantage(egressCC: "GB"),
                                    stats: [:],
                                    locate: locator([:]),
                                    name: { $0 })
        #expect(link(r, from: "home", to: "egress")?.kind == .bypass)
        #expect(pin(r, "egress") != nil)
    }

    @Test func splitTunnelEgressElsewhereIsDashedEvenWithAPlacedGateway() {
        // VPN lands in GB, but traffic reaches the internet from FR: it is not going
        // through that tunnel, and that is exactly what the dash is for.
        let r = WorldMapModel.build(vantage: vantage(egressCC: "FR"),
                                    stats: ["p1": stats("p1", serverIP: "81.2.69.142")],
                                    locate: locator(["81.2.69.142": gbPlace]),
                                    name: { $0 })
        #expect(link(r, from: "home", to: "egress")?.kind == .bypass)
        #expect(link(r, from: "home", to: "vpn.p1")?.kind == .tunnel)
    }

    @Test func egressInHomeCountryGetsNoSeparatePin() {
        var v = vantage(egressCC: "DE")
        v.homeCountryCode = "DE"
        let r = WorldMapModel.build(vantage: v,
                                    stats: ["p1": stats("p1", serverIP: "192.168.32.137")],
                                    locate: locator([:]),
                                    name: { $0 })
        #expect(pin(r, "egress") == nil)
        // …and the tunnel is still shown live, which is the whole point: this used
        // to leave the map with nothing to draw at all.
        #expect(link(r, from: "home", to: "vpn.p1")?.kind == .tunnel)
    }

    @Test func attributionIsStableAcrossRebuilds() {
        // Dictionary order is undefined; the arcs must not flip between frames.
        let s = ["p2": stats("p2", serverIP: "81.2.69.142"),
                 "p1": stats("p1", serverIP: "81.2.69.143")]
        let places = ["81.2.69.142": gbPlace, "81.2.69.143": gbPlace]
        let first = WorldMapModel.build(vantage: vantage(egressCC: "GB"), stats: s,
                                        locate: locator(places), name: { $0 })
        for _ in 0..<5 {
            let again = WorldMapModel.build(vantage: vantage(egressCC: "GB"), stats: s,
                                            locate: locator(places), name: { $0 })
            #expect(again == first)
        }
        #expect(link(first, from: "vpn.p1", to: "egress")?.kind == .tunnel)
    }

    // MARK: The concentrator-position ladder

    /// The live address, when it is public and the database knows it, beats
    /// everything the configuration says — it is the only exact answer.
    @Test func liveAddressWinsOverEveryConfiguredHint() {
        let hint = WorldMapModel.GatewayHint(
            host: "vpn.example.com", countryOverride: "FR",
            resolvedCountryHere: "NL", resolvedCountryElsewhere: "US",
            addresses: ["203.0.113.9"])
        let fix = WorldMapModel.locateGateway(serverIP: "81.2.69.142", hint: hint,
                                              locate: locator(["81.2.69.142": gbPlace]))
        #expect(fix?.source == .liveAddress)
        #expect(fix?.place == gbPlace)
        #expect(fix?.source.isExact == true)
    }

    /// The user's country correction beats every database — and a PRIVATE live
    /// address must fall through to it rather than end the ladder. This is the
    /// reported bug: a split-horizon corporate VPN hands out 192.168 space, so
    /// there is nothing to geolocate and the endpoint's own country is the answer.
    @Test func privateLiveAddressFallsThroughToTheCountryOverride() {
        let hint = WorldMapModel.GatewayHint(host: "vpn.example.com", countryOverride: "FR",
                                             resolvedCountryHere: "NL")
        let fix = WorldMapModel.locateGateway(
            serverIP: "192.168.32.137", hint: hint,
            // Even if something claimed to place the private address, it must not
            // be used: a private address has no public location, ever.
            locate: locator(["192.168.32.137": gbPlace]))
        #expect(fix?.source == .countryOverride)
        #expect(fix?.place == frPlace)
        #expect(fix?.source.isExact == false)
    }

    @Test func thisNetworksAnswerBeatsAnotherNetworks() {
        let hint = WorldMapModel.GatewayHint(host: "vpn.example.com",
                                             resolvedCountryHere: "GB",
                                             resolvedCountryElsewhere: "US")
        let fix = WorldMapModel.locateGateway(serverIP: "10.0.0.1", hint: hint,
                                              locate: locator([:]))
        #expect(fix?.source == .resolvedHere)
        #expect(fix?.place == gbPlace)
    }

    /// Inside the building the name answers with an inside address, so this
    /// network can't place it — but the answer learned on some other network
    /// still describes the same concentrator.
    @Test func anotherNetworksAnswerIsUsedWhenThisOneCannotPlaceIt() {
        let hint = WorldMapModel.GatewayHint(host: "vpn.example.com",
                                             resolvedCountryElsewhere: "GB")
        let fix = WorldMapModel.locateGateway(serverIP: "192.168.32.137", hint: hint,
                                              locate: locator([:]))
        #expect(fix?.source == .resolvedElsewhere)
        #expect(fix?.place == gbPlace)
    }

    @Test func aRememberedPublicAddressIsTheLastRung() {
        // The first remembered address is the inside one; the public one behind it
        // still places the server.
        let hint = WorldMapModel.GatewayHint(host: "vpn.example.com",
                                             addresses: ["192.168.32.137", "81.2.69.142"])
        let fix = WorldMapModel.locateGateway(serverIP: "", hint: hint,
                                              locate: locator(["81.2.69.142": gbPlace,
                                                               "192.168.32.137": frPlace]))
        #expect(fix?.source == .configuredAddress)
        #expect(fix?.place == gbPlace)
    }

    @Test func anIPLiteralEndpointPlacesItself() {
        let hint = WorldMapModel.GatewayHint(host: "81.2.69.142")
        let fix = WorldMapModel.locateGateway(serverIP: "", hint: hint,
                                              locate: locator(["81.2.69.142": gbPlace]))
        #expect(fix?.place == gbPlace)
    }

    @Test func nothingInTheConfigurationPlacesItAndNothingIsInvented() {
        let hint = WorldMapModel.GatewayHint(host: "vpn.example.com",
                                             addresses: ["192.168.32.137", "10.0.0.1"])
        #expect(WorldMapModel.locateGateway(serverIP: "192.168.32.137", hint: hint,
                                            locate: locator([:])) == nil)
    }

    // MARK: An approximate concentrator still draws a pin and an arc

    @Test func approximateGatewayIsPinnedAtItsCountryWithAnArcFromHome() {
        // The reported setup: gateway on 192.168/16, endpoint's country set to GB.
        let r = WorldMapModel.build(
            vantage: home,
            stats: ["p1": stats("p1", serverIP: "192.168.32.137")],
            hints: ["p1": WorldMapModel.GatewayHint(host: "vpn.example.com",
                                                    countryOverride: "GB")],
            locate: locator([:]),
            name: { _ in "Work VPN" })

        let node = pin(r, "vpn.p1")
        #expect(node?.lat == gbPlace.lat)
        #expect(node?.lon == gbPlace.lon)
        // Approximate, not exact: country-level, from the server's own settings.
        #expect(node?.placement == .approximate)
        #expect(node?.locationKnown == false)
        // Distinct from home, so the arc has real length and no tether is needed.
        #expect(node?.tetheredTo == nil)
        #expect(node?.screenOffset == .zero)
        #expect(link(r, from: "home", to: "vpn.p1")?.kind == .tunnel)
        #expect(!r.hasUnlocatableTunnel)
        #expect(r.hasApproximateTunnel)
        #expect(!r.hasCoincidentTunnel)
    }

    @Test func approximateGatewaySubtitleSaysItIsApproximate() {
        let r = WorldMapModel.build(
            vantage: home,
            stats: ["p1": stats("p1", serverIP: "192.168.32.137")],
            hints: ["p1": WorldMapModel.GatewayHint(host: "vpn.example.com",
                                                    resolvedCountryElsewhere: "GB")],
            locate: locator([:]),
            name: { _ in "Work VPN" })
        let subtitle = pin(r, "vpn.p1")?.subtitle ?? ""
        #expect(subtitle.contains("Gateway 192.168.32.137"))
        #expect(subtitle.contains("shown near United Kingdom"))
        #expect(subtitle.contains("approximate"))
        // It is placed, so it must not also claim to be unplaceable.
        #expect(!subtitle.contains("location not public"))
    }

    @Test func aCountryTheUserChoseSaysSoRatherThanJustApproximate() {
        let r = WorldMapModel.build(
            vantage: home,
            stats: ["p1": stats("p1", serverIP: "192.168.32.137")],
            hints: ["p1": WorldMapModel.GatewayHint(host: "vpn.example.com",
                                                    countryOverride: "GB")],
            locate: locator([:]),
            name: { _ in "Work VPN" })
        #expect(pin(r, "vpn.p1")?.subtitle.contains("the country you chose for this server") == true)
    }

    // MARK: Same place as home — the "did anything happen?" case

    @Test func aGatewayOnHomesOwnCentroidIsTetheredBesideTheClientPin() {
        // Home is Germany and so is the VPN: the arc would be zero-length, which is
        // exactly how a live tunnel came to look like "the dot moved".
        let r = WorldMapModel.build(
            vantage: home,
            stats: ["p1": stats("p1", serverIP: "192.168.32.137")],
            hints: ["p1": WorldMapModel.GatewayHint(host: "vpn.example.com",
                                                    countryOverride: "DE")],
            locate: locator([:]),
            name: { _ in "Work VPN" })

        let node = pin(r, "vpn.p1")
        #expect(node?.placement == .approximate)
        #expect(node?.tetheredTo == "home")
        #expect(node?.isTethered == true)
        #expect(node?.screenOffset != .zero)
        #expect(r.hasCoincidentTunnel)
        #expect(link(r, from: "home", to: "vpn.p1")?.kind == .tunnel)
    }

    @Test func anExactGatewayInHomesOwnCountryIsTetheredToo() {
        // Nothing approximate about this one — it is simply next door, and the two
        // pins would still land on top of each other.
        let r = WorldMapModel.build(
            vantage: home,
            stats: ["p1": stats("p1", serverIP: "5.4.3.2")],
            locate: locator(["5.4.3.2": WorldMapModel.GeoPlace(countryCode: "DE",
                                                               lat: 51.2, lon: 10.4)]),
            name: { _ in "Home lab" })
        let node = pin(r, "vpn.p1")
        #expect(node?.placement == .exact)          // still an exact position
        #expect(node?.tetheredTo == "home")         // …just not a distinguishable one
        #expect(r.hasCoincidentTunnel)
        #expect(!r.hasApproximateTunnel)
    }

    @Test func aPlaceholderTunnelIsAlsoTethered() {
        let r = WorldMapModel.build(vantage: home,
                                    stats: ["p1": stats("p1", serverIP: "192.168.32.137")],
                                    locate: locator([:]),
                                    name: { _ in "Lab VPN" })
        #expect(pin(r, "vpn.p1")?.placement == .placeholder)
        #expect(pin(r, "vpn.p1")?.tetheredTo == "home")
        #expect(r.hasCoincidentTunnel)
        #expect(r.hasUnlocatableTunnel)
    }

    @Test func tetheredAndPlaceholderTunnelsShareTheSatelliteSlots() {
        // One VPN sits on home's centroid, one can't be placed at all: both are
        // parked beside home, and they must not land on the same spot.
        let r = WorldMapModel.build(
            vantage: home,
            stats: ["p1": stats("p1", serverIP: "192.168.32.137"),
                    "p2": stats("p2", serverIP: "10.0.0.1")],
            hints: ["p1": WorldMapModel.GatewayHint(host: "a.example.com",
                                                    countryOverride: "DE")],
            locate: locator([:]),
            name: { $0 })
        let a = pin(r, "vpn.p1")?.screenOffset
        let b = pin(r, "vpn.p2")?.screenOffset
        #expect(a != nil && b != nil)
        #expect(a != b)
    }

    // MARK: Egress attribution with approximate gateways

    @Test func anApproximateGatewayInTheEgressCountryStillEarnsTheArc() {
        let r = WorldMapModel.build(
            vantage: vantage(egressCC: "GB"),
            stats: ["p1": stats("p1", serverIP: "192.168.32.137")],
            hints: ["p1": WorldMapModel.GatewayHint(host: "vpn.example.com",
                                                    countryOverride: "GB")],
            locate: locator([:]),
            name: { $0 })
        #expect(link(r, from: "vpn.p1", to: "egress")?.kind == .tunnel)
        #expect(!r.connections.contains { $0.kind == MapConnection.Kind.bypass })
    }

    @Test func anExactGatewayOutranksAnApproximateOneForTheEgressArc() {
        let r = WorldMapModel.build(
            vantage: vantage(egressCC: "GB"),
            stats: ["p1": stats("p1", serverIP: "192.168.32.137"),
                    "p2": stats("p2", serverIP: "81.2.69.142")],
            hints: ["p1": WorldMapModel.GatewayHint(host: "vpn.example.com",
                                                    countryOverride: "GB")],
            locate: locator(["81.2.69.142": gbPlace]),
            name: { $0 })
        #expect(link(r, from: "vpn.p2", to: "egress")?.kind == .tunnel)
        #expect(link(r, from: "vpn.p1", to: "egress") == nil)
    }

    @Test func placedGatewayWinsOverAnUnplaceableOne() {
        let r = WorldMapModel.build(
            vantage: vantage(egressCC: "FR"),
            stats: ["p1": stats("p1", serverIP: "192.168.32.137"),
                    "p2": stats("p2", serverIP: "81.2.69.142")],
            locate: locator(["81.2.69.142": frPlace]),
            name: { $0 })
        #expect(link(r, from: "vpn.p2", to: "egress")?.kind == .tunnel)
        #expect(link(r, from: "vpn.p1", to: "egress") == nil)
        #expect(r.hasUnlocatableTunnel)
    }
}
