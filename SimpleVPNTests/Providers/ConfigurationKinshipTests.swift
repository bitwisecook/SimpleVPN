// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConfigurationKinshipTests.swift
//  THE THREE CATEGORIES, PINNED. An endpoint-only difference merges; a credential
//  difference merges the endpoint and leaves the stored sign-in alone; a CA or
//  verification difference REFUSES.
//
//  The third is the one that matters, and it is worth saying why in a test file:
//  merging a configuration with a different `<ca>` would take a VPN the user trusts
//  and quietly repoint its trust at somebody else's certificate authority, with the
//  user's own name still on the row. Every other failure here costs an inconvenience.
//  That one costs the thing the app is for.
//

import Foundation
import Testing
@testable import SimpleVPN

struct ConfigurationKinshipTests {

    /// The IPVanish template, verbatim from Docs/ServiceBundles.md §2 — the real one,
    /// because the whole idea rests on the measurement that all 3,576 of their files
    /// are this with one word changed.
    static func ipvanish(server: String, extra: String = "") -> String {
        """
        client
        dev tun
        proto udp
        remote \(server) 443
        resolv-retry infinite
        nobind
        persist-key
        persist-tun
        persist-remote-ip
        ca ca.ipvanish.com.crt
        verify-x509-name \(server) name
        auth-user-pass
        comp-lzo
        verb 3
        auth SHA256
        cipher AES-256-CBC
        keysize 256
        \(extra)
        """
    }

    static func endpoints(_ hosts: [String]) -> [VPNEndpoint] {
        hosts.map { VPNEndpoint(host: $0, port: 443, proto: "udp") }
    }

    // MARK: - Category 1: the same VPN, elsewhere

    /// THE FEATURE. Two files from the same provider differing only in which server
    /// they name: merge the second as another endpoint rather than making a duplicate
    /// VPN. Note `verify-x509-name` also differs — it names the server — and that is
    /// correct rather than a trust difference, which is why it is in this test.
    @Test("two configurations differing only in their server merge as a new endpoint")
    func endpointOnlyDifferenceMerges() throws {
        let verdict = ConfigurationKinship.compare(
            dropped: Self.ipvanish(server: "lon-c01.ipvanish.com"),
            against: Self.ipvanish(server: "ams-c02.ipvanish.com"),
            existingEndpoints: Self.endpoints(["ams-c02.ipvanish.com"]))
        guard case .sameVPNElsewhere(let added, let credentialsDiffer) = verdict else {
            Issue.record("expected a merge, got \(verdict)")
            return
        }
        #expect(added.map(\.host) == ["lon-c01.ipvanish.com"])
        #expect(added.first?.port == 443)
        #expect(!credentialsDiffer)
    }

    /// Dropping a file naming a server the VPN already has says so, rather than
    /// silently adding a second identical row.
    @Test("a file naming a server you already have says so")
    func alreadyHaveIt() {
        let verdict = ConfigurationKinship.compare(
            dropped: Self.ipvanish(server: "ams-c02.ipvanish.com"),
            against: Self.ipvanish(server: "ams-c02.ipvanish.com"),
            existingEndpoints: Self.endpoints(["ams-c02.ipvanish.com"]))
        #expect(verdict == .alreadyHaveIt)
    }

    // MARK: - Category 2: credentials

    /// A file carrying a different sign-in still merges its endpoint — and the
    /// difference is REPORTED so the caller can say "your saved sign-in was left
    /// alone" instead of quietly replacing something that works.
    @Test("a credential difference merges the endpoint and is reported, never applied")
    func credentialDifferenceMergesAndIsReported() throws {
        let verdict = ConfigurationKinship.compare(
            dropped: Self.ipvanish(server: "lon-c01.ipvanish.com", extra: "auth-nocache"),
            against: Self.ipvanish(server: "ams-c02.ipvanish.com"),
            existingEndpoints: Self.endpoints(["ams-c02.ipvanish.com"]))
        guard case .sameVPNElsewhere(let added, let credentialsDiffer) = verdict else {
            Issue.record("a credential difference must not block the merge; got \(verdict)")
            return
        }
        #expect(added.map(\.host) == ["lon-c01.ipvanish.com"])
        #expect(credentialsDiffer, "the difference has to be surfaced, not swallowed")
    }

    // MARK: - Category 3: THE ONE THAT MATTERS

    /// A different `<ca>` block is NOT the same VPN somewhere else. It is a different
    /// trust anchor wearing a familiar name, and merging it would repoint the user's
    /// trust with nothing on screen to say so.
    @Test("a different certificate authority refuses the merge")
    func differentCARefuses() throws {
        let mine = """
            client
            dev tun
            remote a.example.com 1194
            <ca>
            -----BEGIN CERTIFICATE-----
            REAL-CA-THE-USER-ALREADY-TRUSTS
            -----END CERTIFICATE-----
            </ca>
            """
        let theirs = """
            client
            dev tun
            remote b.example.com 1194
            <ca>
            -----BEGIN CERTIFICATE-----
            SOMEBODY-ELSES-CA
            -----END CERTIFICATE-----
            </ca>
            """
        let verdict = ConfigurationKinship.compare(dropped: theirs, against: mine,
                                                   existingEndpoints: Self.endpoints(["a.example.com"]))
        guard case .trustDiffers(let why) = verdict else {
            Issue.record("A DIFFERENT CA MUST REFUSE. Got \(verdict)")
            return
        }
        #expect(why.contains { $0.lowercased().contains("trusts a different signer") })
    }

    /// The same, for the directive form rather than the inline block — `ca <path>`
    /// pointing somewhere else is the same substitution by another spelling.
    @Test("a different ca directive refuses the merge")
    func differentCADirectiveRefuses() {
        let verdict = ConfigurationKinship.compare(
            dropped: Self.ipvanish(server: "lon-c01.ipvanish.com")
                .replacingOccurrences(of: "ca ca.ipvanish.com.crt", with: "ca somewhere-else.crt"),
            against: Self.ipvanish(server: "ams-c02.ipvanish.com"),
            existingEndpoints: Self.endpoints(["ams-c02.ipvanish.com"]))
        guard case .trustDiffers = verdict else {
            Issue.record("a changed ca path must refuse; got \(verdict)")
            return
        }
    }

    /// Every directive that decides who is trusted or how traffic is protected
    /// refuses. Walked as a table so a future edit that drops one from the set fails
    /// here rather than in the wild.
    @Test("every trust-determining difference refuses",
          arguments: [("cipher AES-256-CBC", "cipher AES-128-CBC"),
                      ("auth SHA256", "auth SHA1"),
                      ("proto udp", "proto tcp"),
                      // Dropping the name check entirely is the difference that reads
                      // most like an omission and is in fact a weakening.
                      ("verify-x509-name lon-c01.ipvanish.com name", "")])
    func trustDifferencesRefuse(_ change: (from: String, to: String)) {
        let mine = Self.ipvanish(server: "ams-c02.ipvanish.com")
        let theirs = Self.ipvanish(server: "lon-c01.ipvanish.com")
            .replacingOccurrences(of: change.from, with: change.to)
        let verdict = ConfigurationKinship.compare(dropped: theirs, against: mine,
                                                   existingEndpoints: Self.endpoints(["ams-c02.ipvanish.com"]))
        guard case .trustDiffers = verdict else {
            Issue.record("changing \(change.from.debugDescription) must refuse; got \(verdict)")
            return
        }
    }

    /// A changed PORT refuses too, and this one is worth its own line because it is
    /// the difference most likely to be waved through as harmless. It is not: the
    /// port is part of what the server is, and a merge that silently accepts one is a
    /// merge that would accept a redirect to a different service on the same name.
    @Test("a different port refuses, and says which two ports")
    func differentPortRefuses() throws {
        let verdict = ConfigurationKinship.compare(
            dropped: Self.ipvanish(server: "lon-c01.ipvanish.com")
                .replacingOccurrences(of: "remote lon-c01.ipvanish.com 443",
                                      with: "remote lon-c01.ipvanish.com 443\nport 1194"),
            against: Self.ipvanish(server: "ams-c02.ipvanish.com"),
            existingEndpoints: Self.endpoints(["ams-c02.ipvanish.com"]))
        guard case .trustDiffers(let why) = verdict else {
            Issue.record("a changed port must refuse; got \(verdict)")
            return
        }
        #expect(why.contains { $0.contains("1194") })
    }

    // MARK: - When it is simply not the same VPN

    /// A wholly different configuration fails USEFULLY: the caller uses this to offer
    /// "import it as a separate VPN", which is what the user would otherwise have
    /// done by hand. A drop that only says "no" wastes the gesture.
    @Test("an unrelated configuration is named as different, not merged")
    func unrelatedConfigurationIsDifferent() throws {
        let verdict = ConfigurationKinship.compare(
            dropped: Self.ipvanish(server: "lon-c01.ipvanish.com", extra: "comp-lzo no\ntun-mtu 1200"),
            against: Self.ipvanish(server: "ams-c02.ipvanish.com"),
            existingEndpoints: Self.endpoints(["ams-c02.ipvanish.com"]))
        guard case .differentVPN(let why) = verdict else {
            Issue.record("expected differentVPN, got \(verdict)")
            return
        }
        #expect(why.contains("tun-mtu") || why.contains("comp-lzo"))
    }

    // MARK: - Normalisation

    /// The measurement this whole file rests on, reproduced in miniature: two
    /// IPVanish configs are byte-identical once the hostname becomes a placeholder,
    /// which is exactly what made all 3,576 of the real ones hash the same.
    @Test("two provider configs are identical once the server is set aside")
    func normalisationMatchesTheMeasurement() {
        let a = ConfigurationKinship.normalised(Self.ipvanish(server: "a.ipvanish.com"))
        let b = ConfigurationKinship.normalised(Self.ipvanish(server: "b.ipvanish.com"))
        #expect(a == b)
        #expect(a.contains("remote \(ConfigurationKinship.serverPlaceholder) 443"))
        // The name check names the server, so it normalises too — that is why two of
        // their files are the same file.
        #expect(a.contains("verify-x509-name \(ConfigurationKinship.serverPlaceholder) name"))
    }

    /// THE LIMIT OF THAT SUBSTITUTION, and it is the reason it is per-file rather
    /// than a blanket "ignore the name check". A file that dials one host but
    /// name-checks ANOTHER has not merely moved server — it would accept a
    /// certificate for a name it is not talking to — so the placeholder does not
    /// cover it and the merge refuses.
    @Test("a name check pointing at a different host than the file dials refuses")
    func mismatchedNameCheckRefuses() throws {
        let theirs = Self.ipvanish(server: "lon-c01.ipvanish.com")
            .replacingOccurrences(of: "verify-x509-name lon-c01.ipvanish.com name",
                                  with: "verify-x509-name somewhere-else.example name")
        let verdict = ConfigurationKinship.compare(
            dropped: theirs,
            against: Self.ipvanish(server: "ams-c02.ipvanish.com"),
            existingEndpoints: Self.endpoints(["ams-c02.ipvanish.com"]))
        guard case .trustDiffers(let why) = verdict else {
            Issue.record("a mismatched name check must refuse; got \(verdict)")
            return
        }
        #expect(why.contains { $0.contains("verify-x509-name") })
    }

    /// Nord's `remote` is an IP LITERAL with the hostname on the name check, so its
    /// files normalise on both — which is what the doc measured when it found
    /// `us5063` and `uk2000` byte-identical.
    @Test("an IP literal remote normalises too, so Nord's files compare equal")
    func literalRemotesNormalise() {
        let a = ConfigurationKinship.normalised("""
            client
            remote 185.245.87.59 1194
            verify-x509-name CN=us5063.nordvpn.com
            """)
        let b = ConfigurationKinship.normalised("""
            client
            remote 31.13.191.5 1194
            verify-x509-name CN=uk2000.nordvpn.com
            """)
        #expect(a.contains(ConfigurationKinship.addressPlaceholder))
        // The hostnames differ and are NOT on a remote line, so they survive — which
        // is correct: for Nord the name check is the second value a substitution has
        // to fill in, and a merge has to see that it moved.
        #expect(a != b)
    }

    /// A certificate is compared by hash, not by bytes, so a re-download with
    /// different line endings is not read as a new trust anchor.
    @Test("an inline block is compared by hash, so whitespace is not a trust change")
    func inlineBlocksAreHashed() {
        let a = ConfigurationKinship.inlineBlocks(in: "<ca>\nAAAA\nBBBB\n</ca>")
        let b = ConfigurationKinship.inlineBlocks(in: "<ca>\n  AAAA  \n\nBBBB\n</ca>")
        #expect(a["ca"] == b["ca"])
        let c = ConfigurationKinship.inlineBlocks(in: "<ca>\nAAAA\nCCCC\n</ca>")
        #expect(a["ca"] != c["ca"])
    }

    /// Directive values keep their ORDER. `data-ciphers A:B` and `data-ciphers B:A`
    /// are different preferences, and treating them as the same is exactly the "close
    /// enough" this comparison must not do.
    @Test("a reordered cipher preference is a difference, not a match")
    func cipherOrderMatters() {
        let a = ConfigurationKinship.directives(in: "data-ciphers AES-256-GCM:AES-128-GCM")
        let b = ConfigurationKinship.directives(in: "data-ciphers AES-128-GCM:AES-256-GCM")
        #expect(!ConfigurationKinship.trustDifferences(a, b).isEmpty)
    }

    // MARK: - WireGuard

    /// A second Mullvad `.conf` is the same tunnel reaching a different relay, so the
    /// peer key is part of WHERE and rides onto the endpoint row — not over the
    /// profile's own key.
    @Test("a second WireGuard config merges as an endpoint carrying its own peer key")
    func wireGuardMergeCarriesTheKey() throws {
        let keyA = "ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8="
        let keyB = "V1WC7wt34kcSDyqPuUhN56NJ0v+GlqY9TwZR5WlzzB4="
        var mine = WireGuardConfig()
        mine.addresses = ["10.64.0.2/32"]
        mine.allowedIPs = ["0.0.0.0/0", "::/0"]
        mine.endpoint = "se-got-wg-001.relays.mullvad.net:51820"
        mine.peerPublicKey = keyA
        var theirs = mine
        theirs.endpoint = "gb-lon-wg-002.relays.mullvad.net:51820"
        theirs.peerPublicKey = keyB

        let verdict = ConfigurationKinship.compare(
            droppedWireGuard: theirs, against: mine,
            existingEndpoints: [VPNEndpoint(host: "se-got-wg-001.relays.mullvad.net", port: 51820)])
        guard case .sameVPNElsewhere(let added, _) = verdict else {
            Issue.record("expected a merge, got \(verdict)")
            return
        }
        #expect(added.first?.host == "gb-lon-wg-002.relays.mullvad.net")
        #expect(added.first?.peerPublicKey == keyB, "the relay's key must ride with its address")
    }

    /// A `.conf` with a different tunnel address is a different tunnel wearing a
    /// familiar name — the provider issued it against a different key registration —
    /// and it does not merge.
    @Test("a WireGuard config with a different tunnel address refuses")
    func wireGuardDifferentTunnelAddressRefuses() {
        var mine = WireGuardConfig()
        mine.addresses = ["10.64.0.2/32"]
        mine.endpoint = "a.relays.mullvad.net:51820"
        var theirs = mine
        theirs.addresses = ["10.64.9.9/32"]
        theirs.endpoint = "b.relays.mullvad.net:51820"

        let verdict = ConfigurationKinship.compare(
            droppedWireGuard: theirs, against: mine,
            existingEndpoints: [VPNEndpoint(host: "a.relays.mullvad.net", port: 51820)])
        guard case .trustDiffers(let why) = verdict else {
            Issue.record("a different tunnel address must refuse; got \(verdict)")
            return
        }
        #expect(why.contains { $0.contains("tunnel address") })
    }
}
