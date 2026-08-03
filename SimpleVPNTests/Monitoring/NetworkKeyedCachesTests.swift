// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  NetworkKeyedCachesTests.swift
//  Pins the rule that everything the app measures or resolves belongs to the
//  network it was learned on. Endpoints are routinely split-horizon — one name,
//  a private address inside the office and a public one outside — so a cached
//  answer, a probe timing or a "the address changed" warning carried across a
//  Wi-Fi hop is not stale, it is wrong.
//

import Foundation
import Testing
@testable import SimpleVPN

/// The network the caches are asked about, in a box. The `networkKey` closures are
/// @MainActor — hence Sendable — and a captured `var` may not be mutated once such
/// a closure has it; moving network mid-test is exactly what this file exercises,
/// so the moving part lives here instead.
@MainActor final class MovingNetwork {
    var key: String
    init(_ key: String) { self.key = key }
}

@MainActor
struct NetworkKeyedCachesTests {

    // Two networks, in the shape NetworkFingerprint.key produces.
    private let office = "mac:0:8:a2:e:dc:c7"
    private let cafe = "mac:aa:bb:cc:dd:ee:ff"

    /// A defaults suite of its own per test — nothing here may see, or scribble
    /// on, the developer's real cache. Named (not random) and emptied on the way
    /// in, so repeated runs neither leak domains nor inherit each other's state;
    /// tests run in parallel, so no two may share a name.
    private func scratchDefaults(_ name: String) -> UserDefaults {
        let suite = "test.NetworkKeyedCaches.\(name)"
        UserDefaults.standard.removePersistentDomain(forName: suite)
        return UserDefaults(suiteName: suite)!
    }

    // MARK: EndpointLocator — one host, two networks, two answers

    @Test func hostCacheKeepsOneAnswerPerNetwork() {
        let network = MovingNetwork(office)
        let locator = EndpointLocator(defaults: scratchDefaults("perNetwork"),
                                      networkKey: { network.key })

        locator.store(host: "vpn.example.com", network: office,
                      addresses: ["10.1.2.3"], countryCode: "GB")
        locator.store(host: "vpn.example.com", network: cafe,
                      addresses: ["203.0.113.9"], countryCode: "DE")

        let endpoint = [Endpoint(host: "vpn.example.com")]

        let inOffice = locator.locations(for: endpoint)[0]
        #expect(inOffice.ip == "10.1.2.3")
        #expect(inOffice.countryCode == "GB")

        network.key = cafe
        let inCafe = locator.locations(for: endpoint)[0]
        #expect(inCafe.ip == "203.0.113.9")
        #expect(inCafe.countryCode == "DE")

        // Going back must find the office answer still there — the whole point
        // of keying rather than clearing.
        network.key = office
        #expect(locator.locations(for: endpoint)[0].ip == "10.1.2.3")
    }

    @Test func hostCacheSurvivesRelaunchPerNetwork() {
        let defaults = scratchDefaults("relaunch")
        let network = MovingNetwork(office)
        let first = EndpointLocator(defaults: defaults, networkKey: { network.key })
        first.store(host: "vpn.example.com", network: office,
                    addresses: ["10.1.2.3"], countryCode: "GB")
        first.store(host: "vpn.example.com", network: cafe,
                    addresses: ["203.0.113.9"], countryCode: "DE")

        let reloaded = EndpointLocator(defaults: defaults, networkKey: { network.key })
        #expect(reloaded.cached(host: "vpn.example.com")?.ip == "10.1.2.3")
        network.key = cafe
        #expect(reloaded.cached(host: "vpn.example.com")?.ip == "203.0.113.9")
    }

    @Test func everyAddressIsKeptAndTheFirstStaysPrimary() {
        let locator = EndpointLocator(defaults: scratchDefaults("multiAddress"), networkKey: { self.office })
        locator.store(host: "multi.example.com", network: office,
                      addresses: ["198.51.100.1", "198.51.100.2", "2001:db8::1"],
                      countryCode: "US")

        let location = locator.locations(for: [Endpoint(host: "multi.example.com")])[0]
        #expect(location.ip == "198.51.100.1")
        #expect(location.addresses == ["198.51.100.1", "198.51.100.2", "2001:db8::1"])
    }

    @Test func legacyHostKeyedCacheIsIgnoredNotCrashedOn() throws {
        // What a version keyed by host alone wrote: host → info, one level deep.
        let legacy = """
        {"vpn.example.com":{"ip":"10.9.9.9","countryCode":"FR","timestamp":1}}
        """
        let defaults = scratchDefaults("legacy")
        defaults.set(Data(legacy.utf8), forKey: "geoip.hostCache")

        let locator = EndpointLocator(defaults: defaults, networkKey: { self.office })
        // Dropped rather than guessed at: nobody can say which network answered.
        #expect(locator.cached(host: "vpn.example.com") == nil)
    }

    @Test func entriesOlderThanTheTTLArePrunedOnEveryNetwork() {
        let now = Date().timeIntervalSince1970
        let day: TimeInterval = 24 * 3600
        let cache: [String: [String: EndpointLocator.HostInfo]] = [
            office: [
                "fresh.example.com": .init(ip: "10.0.0.1", addresses: ["10.0.0.1"],
                                           countryCode: "GB", timestamp: now - day),
                "ancient.example.com": .init(ip: "10.0.0.2", addresses: ["10.0.0.2"],
                                             countryCode: "GB", timestamp: now - 30 * day),
            ],
            cafe: [
                "ancient.example.com": .init(ip: "10.0.0.3", addresses: ["10.0.0.3"],
                                             countryCode: "DE", timestamp: now - 8 * day),
            ],
        ]
        let pruned = EndpointLocator.pruned(cache, now: now)
        #expect(pruned[office]?.keys.sorted() == ["fresh.example.com"])
        #expect(pruned[cafe] == nil)     // nothing left to say → the network goes too
    }

    @Test func anEntryWithoutTheAddressListStillReportsItsAddress() throws {
        // Written before multi-address caching: `ip` only, no `addresses`.
        let json = #"{"ip":"192.0.2.7","timestamp":1}"#
        let info = try JSONDecoder().decode(EndpointLocator.HostInfo.self, from: Data(json.utf8))
        #expect(info.allAddresses == ["192.0.2.7"])
    }

    // MARK: EndpointProbeStore — timings belong to one network

    @Test func measurementsAreOnlyVisibleOnTheNetworkTheyWereTakenOn() {
        let network = MovingNetwork(office)
        let store = EndpointProbeStore(networkKey: { network.key })
        let id = VPNEndpoint(host: "vpn.example.com").id

        store.record(EndpointMeasurement(rttMS: 3, reachable: true, measuredAt: Date()),
                     for: id, network: office)
        #expect(store.measurement(for: id)?.rttMS == 3)

        network.key = cafe
        #expect(store.measurement(for: id) == nil, "3 ms from the office is a lie in a café")

        store.record(EndpointMeasurement(rttMS: 84, reachable: true, measuredAt: Date()),
                     for: id, network: cafe)
        #expect(store.measurement(for: id)?.rttMS == 84)

        network.key = office
        #expect(store.measurement(for: id)?.rttMS == 3)
    }

    @Test func movingNetworkDropsTheMeasurementsThatCanNeverBeReadAgain() {
        let network = MovingNetwork(office)
        let store = EndpointProbeStore(networkKey: { network.key })
        let id = VPNEndpoint(host: "vpn.example.com").id
        store.record(EndpointMeasurement(rttMS: 3, reachable: true, measuredAt: Date()),
                     for: id, network: office)
        store.record(EndpointMeasurement(rttMS: 84, reachable: true, measuredAt: Date()),
                     for: id, network: cafe)
        #expect(store.results.count == 2)

        network.key = cafe
        store.dropMeasurements(notOn: cafe)
        #expect(store.results.count == 1)
        #expect(store.measurement(for: id)?.rttMS == 84)
    }

    @Test func resultKeysSeparateNetworksThatSharePrefixes() {
        // Prefix matching is what the purge uses, so keys must not blur into
        // each other when one network's key starts with another's.
        let a = EndpointProbeStore.resultKey(network: "if:en0", endpoint: "host:1194:udp")
        let b = EndpointProbeStore.resultKey(network: "if:en01", endpoint: "host:1194:udp")
        #expect(a != b)
        #expect(!b.hasPrefix(EndpointProbeStore.resultKey(network: "if:en0", endpoint: "")))
    }

    // MARK: Baseline — "the address changed" only means something on one network

    @Test func addressChangeIsOnlyReportedOnTheSameNetwork() {
        #expect(ConnectionDiagnostics.addressChangeIsMeaningful(
            baselineNetwork: office, currentNetwork: office))
        #expect(!ConnectionDiagnostics.addressChangeIsMeaningful(
            baselineNetwork: office, currentNetwork: cafe),
            "split-horizon DNS answers differently per network — that isn't a change")
        #expect(!ConnectionDiagnostics.addressChangeIsMeaningful(
            baselineNetwork: nil, currentNetwork: office),
            "a baseline that predates network recording can't establish sameness")
        #expect(!ConnectionDiagnostics.addressChangeIsMeaningful(
            baselineNetwork: office, currentNetwork: nil),
            "no fingerprint yet — nothing to compare against")
    }

    @Test func aBaselineWithoutANetworkStillDecodes() throws {
        let legacy = #"{"serverIP":"198.51.100.1","resolvedIPs":[],"date":1}"#
        let baseline = try JSONDecoder().decode(ConnectionBaseline.self, from: Data(legacy.utf8))
        #expect(baseline.serverIP == "198.51.100.1")
        #expect(baseline.networkKey == nil)
        #expect(!ConnectionDiagnostics.addressChangeIsMeaningful(
            baselineNetwork: baseline.networkKey, currentNetwork: office))
    }

    @Test func aBaselineRoundTripsItsNetwork() throws {
        let baseline = ConnectionBaseline(serverIP: "198.51.100.1", resolvedIPs: ["198.51.100.1"],
                                          tlsFingerprint: "ab:cd", networkKey: cafe, date: .now)
        let decoded = try JSONDecoder().decode(
            ConnectionBaseline.self, from: JSONEncoder().encode(baseline))
        #expect(decoded.networkKey == cafe)
        #expect(decoded.tlsFingerprint == "ab:cd")
    }

    // MARK: LatencyMonitor — when to ask the name again

    @Test func latencyTargetIsReresolvedOnANetworkChange() {
        #expect(LatencyMonitor.shouldReresolve(networkKey: cafe, resolvedOn: office, age: 1))
        #expect(LatencyMonitor.shouldReresolve(networkKey: nil, resolvedOn: office, age: 1))
    }

    @Test func latencyTargetIsReresolvedWhenTheAnswerGoesStale() {
        // Plain DNS changes don't move the fingerprint, so age is the only signal.
        #expect(!LatencyMonitor.shouldReresolve(networkKey: office, resolvedOn: office, age: 5))
        #expect(LatencyMonitor.shouldReresolve(networkKey: office, resolvedOn: office,
                                               age: LatencyMonitor.reresolveAfter))
    }

    // MARK: The identity itself

    @Test func signingIntoACaptivePortalDoesNotChangeTheKey() {
        // Documented ceiling: same gateway, same MAC, same key — before and
        // after the sign-in page. Portals are resolved by the captive rechecks,
        // never by watching this key.
        let before = NetworkFingerprint(interface: "en0", gatewayIP: "192.168.87.1",
                                        gatewayMAC: "0:8:a2:e:dc:c7",
                                        localNetwork: "192.168.87.0/24", ssid: nil)
        let after = NetworkFingerprint(interface: "en0", gatewayIP: "192.168.87.1",
                                       gatewayMAC: "0:8:a2:e:dc:c7",
                                       localNetwork: "192.168.87.0/24", ssid: "Hotel Wi-Fi")
        #expect(before.key == after.key)
    }
}
