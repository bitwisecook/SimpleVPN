// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  EndpointPeerKeyTests.swift
//  THE INVARIANT THIS WHOLE FEATURE TURNS ON: a WireGuard server's address and its
//  peer public key move together, or neither moves.
//
//  WHY IT IS PINNED HERE RATHER THAN TRUSTED. Getting it wrong does not crash, does
//  not leak and does not produce an error. The handshake fails closed — WireGuard
//  sends an initiation the relay cannot decrypt, and the relay says nothing back —
//  so the entire symptom is a tunnel that connects to nothing, for ever, after the
//  user changed a menu. There is no log line and nothing to look at. A silent
//  failure with no signal is precisely the thing a test has to hold.
//
//  Mullvad is why it matters: every one of its 567 relays carries its own key
//  (Docs/ServiceBundles.md §2), so its server list is a list of PAIRS, and Mullvad
//  is the provider the user actually has an account with.
//

import Foundation
import Testing
@testable import SimpleVPN

@MainActor
struct EndpointPeerKeyTests {

    // Two real-shaped Curve25519 public keys — 44 base64 characters decoding to 32
    // bytes. Different from each other, which is the entire point of every test below.
    static let keyA = "ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8="
    static let keyB = "V1WC7wt34kcSDyqPuUhN56NJ0v+GlqY9TwZR5WlzzB4="

    static func relay(_ host: String, key: String?) -> VPNEndpoint {
        VPNEndpoint(host: host, port: 51820, peerPublicKey: key, fromProvider: "mullvad")
    }

    // MARK: - The swap

    /// THE CENTRAL TEST. Selecting relay B while pointed at relay A must leave the
    /// configuration on B's address AND B's key. The assertion that catches the bug
    /// is the last one: B's address with A's key is the failure mode, and it is what
    /// a two-line "set the endpoint" call site produces.
    @Test("choosing another relay moves the address and the key together")
    func selectingSwapsBoth() throws {
        var config = WireGuardConfig()
        config.endpoint = "se-got-wg-001.relays.mullvad.net:51820"
        config.peerPublicKey = Self.keyA
        let all = [Self.relay("se-got-wg-001.relays.mullvad.net", key: Self.keyA),
                   Self.relay("gb-lon-wg-002.relays.mullvad.net", key: Self.keyB)]

        let outcome = WireGuardEndpointSelection.selecting(all[1], from: all, in: config)
        guard case .applied(let next) = outcome else {
            Issue.record("selecting a keyed relay must apply")
            return
        }
        #expect(next.endpoint == "gb-lon-wg-002.relays.mullvad.net:51820")
        #expect(next.peerPublicKey == Self.keyB)
        #expect(next.peerPublicKey != Self.keyA, "server B is carrying server A's key")
    }

    /// The other half of "together": nothing else about the tunnel moves. A relay
    /// change must not quietly rewrite the user's own addresses, allowed networks or
    /// DNS — those came from the `.conf` Mullvad issued against their account.
    @Test("choosing another relay changes nothing but the address and the key")
    func selectingTouchesNothingElse() throws {
        var config = WireGuardConfig()
        config.endpoint = "se-got-wg-001.relays.mullvad.net:51820"
        config.peerPublicKey = Self.keyA
        config.addresses = ["10.64.0.2/32"]
        config.dns = ["10.64.0.1"]
        config.allowedIPs = ["0.0.0.0/0"]
        config.mtu = 1380
        let all = [Self.relay("se-got-wg-001.relays.mullvad.net", key: Self.keyA),
                   Self.relay("gb-lon-wg-002.relays.mullvad.net", key: Self.keyB)]

        guard case .applied(let next) =
                WireGuardEndpointSelection.selecting(all[1], from: all, in: config) else {
            Issue.record("selecting a keyed relay must apply")
            return
        }
        #expect(next.addresses == ["10.64.0.2/32"])
        #expect(next.dns == ["10.64.0.1"])
        #expect(next.allowedIPs == ["0.0.0.0/0"])
        #expect(next.mtu == 1380)
    }

    // MARK: - The refusal

    /// A row with no key, in a list where other rows have one, cannot be selected.
    ///
    /// The only thing that COULD be done with it is keep the key already there — and
    /// that is exactly the mismatch. Refusing is the loud failure; applying would be
    /// the quiet one.
    @Test("a keyless relay in a keyed list is refused rather than half-applied")
    func keylessRelayInKeyedListIsRefused() {
        var config = WireGuardConfig()
        config.endpoint = "se-got-wg-001.relays.mullvad.net:51820"
        config.peerPublicKey = Self.keyA
        let all = [Self.relay("se-got-wg-001.relays.mullvad.net", key: Self.keyA),
                   Self.relay("gb-lon-wg-002.relays.mullvad.net", key: nil)]

        let outcome = WireGuardEndpointSelection.selecting(all[1], from: all, in: config)
        guard case .refused(let why) = outcome else {
            Issue.record("a keyless relay beside keyed ones must be refused")
            return
        }
        // The sentence has to be actionable, not "invalid server".
        #expect(why.contains("public key"))
        #expect(why.lowercased().contains("refresh") || why.lowercased().contains("add the key"))
    }

    /// …but the ORDINARY single-peer WireGuard VPN still works. One relay, one key,
    /// straight out of an imported `.conf`, and the user typing a second address for
    /// the same peer is a legitimate thing to do. The rule keys off the LIST having
    /// keys, not off the row lacking one.
    @Test("with no keys anywhere, changing the address alone is right")
    func keylessListMovesTheAddressOnly() throws {
        var config = WireGuardConfig()
        config.endpoint = "vpn.example.com:51820"
        config.peerPublicKey = Self.keyA
        let all = [VPNEndpoint(host: "vpn.example.com", port: 51820),
                   VPNEndpoint(host: "vpn2.example.com", port: 51820, userAdded: true)]

        guard case .applied(let next) =
                WireGuardEndpointSelection.selecting(all[1], from: all, in: config) else {
            Issue.record("a plain single-peer VPN must still be able to change address")
            return
        }
        #expect(next.endpoint == "vpn2.example.com:51820")
        #expect(next.peerPublicKey == Self.keyA, "the profile's own key must survive")
    }

    // MARK: - Which row is selected

    /// The picker's tick reads the CONFIGURATION, and a row whose address matches but
    /// whose key does not is NOT the selection. Showing it as selected would hide the
    /// exact mismatch this file exists to prevent behind a tick.
    @Test("a matching address with the wrong key does not read as selected")
    func selectionRequiresBothToAgree() {
        var config = WireGuardConfig()
        config.endpoint = "gb-lon-wg-002.relays.mullvad.net:51820"
        config.peerPublicKey = Self.keyA          // ← A's key on B's address
        let all = [Self.relay("gb-lon-wg-002.relays.mullvad.net", key: Self.keyB)]
        #expect(WireGuardEndpointSelection.selected(in: all, config: config) == nil)

        config.peerPublicKey = Self.keyB
        #expect(WireGuardEndpointSelection.selected(in: all, config: config)?.host
                == "gb-lon-wg-002.relays.mullvad.net")
    }

    /// An IPv6 relay gets bracketed, because `[address]:port` is the grammar both
    /// `WireGuardConfig.endpointProblem` and the engine's resolver take — and an
    /// unbracketed one parses as a host ending in a colon with port "1".
    @Test("an IPv6 relay is written [address]:port")
    func ipv6IsBracketed() {
        let s = WireGuardEndpointSelection.endpointString(host: "2a04:27c0:0:e::f001", port: 51820)
        #expect(s == "[2a04:27c0:0:e::f001]:51820")
        #expect(WireGuardConfig.endpointProblem(s) == nil)
    }

    /// A relay with no port of its own keeps the port the user's own `.conf` chose,
    /// rather than silently reverting to the well-known one. Mullvad issues
    /// configurations on ports other than 51820 and losing that is a tunnel that
    /// stops working for no visible reason.
    @Test("a relay with no port keeps the configuration's own port")
    func portIsInheritedFromTheConfiguration() throws {
        var config = WireGuardConfig()
        config.endpoint = "se-got-wg-001.relays.mullvad.net:3333"
        config.peerPublicKey = Self.keyA
        let target = VPNEndpoint(host: "gb-lon-wg-002.relays.mullvad.net",
                                 peerPublicKey: Self.keyB, fromProvider: "mullvad")
        guard case .applied(let next) =
                WireGuardEndpointSelection.selecting(target, from: [target], in: config) else {
            Issue.record("must apply")
            return
        }
        #expect(next.endpoint == "gb-lon-wg-002.relays.mullvad.net:3333")
    }

    // MARK: - Storage and export

    /// The key survives the annotation blob. It has to be part of `hasAnnotations`,
    /// or a provider relay — which carries nothing else the user authored — is
    /// dropped on the way to disk and the whole fetched list vanishes on relaunch.
    @Test("a relay carrying only an address and a key survives being stored")
    func peerKeySurvivesTheBlob() throws {
        let list = VPNEndpointList(endpoints: [Self.relay("se-got-wg-001.relays.mullvad.net",
                                                          key: Self.keyA)])
        let blob = try #require(list.encodedBlob(), "a relay with a key must be worth storing")
        let back = VPNEndpointList.decode(from: blob)
        #expect(back.endpoints.first?.peerPublicKey == Self.keyA)
        #expect(back.endpoints.first?.fromProvider == "mullvad")
    }

    /// A key that is not 32 bytes decodes to NO key rather than to a bad one. This
    /// blob is reachable from an imported file, an MDM payload and a hand edit, and a
    /// 31-byte key is accepted by every layer until the handshake — where it fails
    /// with nothing to look at. Same rule as `WireGuardConfig.keyProblem`.
    @Test("a malformed peer key in a stored blob decodes to no key at all")
    func malformedKeyIsDropped() {
        let json = """
            {"endpoints":[{"host":"a.relays.mullvad.net","peerPublicKey":"tooshort",
            "fromProvider":"mullvad"},
            {"host":"b.relays.mullvad.net","peerPublicKey":"AAAA","fromProvider":"mullvad"}]}
            """
        let list = VPNEndpointList.decode(from: Data(json.utf8))
        #expect(list.endpoints.allSatisfy { $0.peerPublicKey == nil })
    }

    /// A provider name this build does not know is dropped rather than carried:
    /// provenance that cannot be resolved would put an unanswerable "from ?" on a row.
    @Test("an unknown provider name in a stored blob is dropped")
    func unknownProviderIsDropped() {
        let json = """
            {"endpoints":[{"host":"a.example.com","fromProvider":"notaprovider","label":"x"}]}
            """
        let list = VPNEndpointList.decode(from: Data(json.utf8))
        #expect(list.endpoints.first?.fromProvider == nil)
    }

    /// EXPORT/IMPORT CARRIES IT FREE, and this test is what proves the claim rather
    /// than assuming it. The endpoints section goes through
    /// `structuralMapRedacting`, i.e. the type's own `Encodable` keys — so a new
    /// field rides along exactly as the manual server order does. The half that is
    /// NOT free is the classification: a field whose name contains "key" has to be
    /// deliberately reviewed, or the redactor could withhold it and export an address
    /// with nothing to check it against.
    @Test("the peer key survives an export/import round trip and is not withheld")
    func peerKeySurvivesExport() throws {
        var snapshot = ConfigSnapshot()
        var vpn = ConfigSnapshot.VPN(id: "wg1", name: "Mullvad", kind: .wireGuard,
                                     server: "se-got-wg-001.relays.mullvad.net")
        vpn.endpoints = VPNEndpointList(endpoints: [
            Self.relay("se-got-wg-001.relays.mullvad.net", key: Self.keyA),
        ])
        snapshot.vpns = [vpn]

        let text = ConfigDocument.text(from: snapshot, format: .yaml)
        #expect(text.contains(Self.keyA), "a peer PUBLIC key must be written, not withheld")

        let plan = ConfigImport.plan(text: text, current: ConfigSnapshot())
        #expect(plan.fatal.isEmpty)
        let imported = try #require(plan.vpns.first?.vpn.endpoints?.endpoints.first)
        #expect(imported.peerPublicKey == Self.keyA)
        #expect(imported.fromProvider == "mullvad")
    }

    /// …and it is classified deliberately rather than by accident of spelling.
    @Test("the peer public key is a reviewed non-secret, with a reason")
    func peerKeyIsReviewed() {
        #expect(!ConfigSecrets.isSecret("peerPublicKey"))
        #expect(ConfigSecrets.reviewedNotSecret["peerPublicKey"] != nil)
    }

    // MARK: - Provenance

    /// A provider row is REMOVABLE and a configuration row is not. The button used to
    /// refuse a provider row with a sentence about a configuration that never
    /// mentioned it.
    @Test("a provider row can be removed; a configuration row cannot")
    func provenanceDecidesRemovability() {
        #expect(Self.relay("a.relays.mullvad.net", key: Self.keyA).isRemovable)
        #expect(VPNEndpoint(host: "a.example.com", userAdded: true).isRemovable)
        #expect(!VPNEndpoint(host: "a.example.com").isRemovable)
    }

    /// A provider's relays are shown even though the configuration names none of
    /// them — which is the whole point of a Mullvad list: the imported `.conf` names
    /// one relay and the other 566 exist only in the annotation blob.
    @Test("provider relays appear in the merged list without the configuration naming them")
    func providerRowsSurviveTheMerge() {
        let stored = VPNEndpointList(endpoints: [
            Self.relay("se-got-wg-001.relays.mullvad.net", key: Self.keyA),
            Self.relay("gb-lon-wg-002.relays.mullvad.net", key: Self.keyB),
        ])
        let merged = VPNEndpointList.merged(
            scanned: [Endpoint(host: "se-got-wg-001.relays.mullvad.net", port: 51820, proto: nil)],
            stored: stored)
        #expect(merged.count == 2)
        #expect(merged.contains { $0.host == "gb-lon-wg-002.relays.mullvad.net" })
        // …and the one the configuration DOES name keeps its key, rather than being
        // rebuilt from the scan as a bare address.
        #expect(merged.first { $0.host == "se-got-wg-001.relays.mullvad.net" }?
            .peerPublicKey == Self.keyA)
    }
}
