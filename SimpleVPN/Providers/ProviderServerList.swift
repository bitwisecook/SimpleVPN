// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProviderServerList.swift
//  THE SEAM BETWEEN A TRUSTED TEMPLATE AND AN UNTRUSTED LIST, and the only place
//  the difference is enforced.
//
//  ONE SENTENCE DECIDES EVERYTHING IN THIS FILE: the connection template is trusted
//  because SimpleVPN ships it inside a signed update, and the server list is
//  untrusted because it arrived over the network. So a list entry is never a string
//  that gets interpolated into a configuration — every field is PARSED INTO A TYPED
//  VALUE and re-rendered from that value, and a field that will not parse is
//  dropped rather than repaired.
//
//  WHAT THAT BUYS, concretely: a list entry containing a newline cannot inject an
//  OpenVPN directive, because it never reaches the rendered file as text — it fails
//  `ProviderHostname` first. An entry naming somebody else's domain cannot survive,
//  because the provider's hostname suffix ships with the app and a fetch cannot
//  widen it. An entry with a malformed peer key cannot become a 31-byte key that
//  silently fails to hand shake, because the key is decoded to exactly 32 bytes and
//  re-encoded canonically.
//
//  THE ASYMMETRY WORTH KNOWING (Docs/ServiceBundles.md §3). For OpenVPN the shipped
//  CA does the work: a substituted hostname reaches a machine that cannot present a
//  certificate from the provider's CA, and the connection FAILS CLOSED. For
//  WireGuard nothing does — there is no certificate, the peer public key IS the
//  authentication, and it arrives in the same payload as the address it
//  authenticates. Swap both together and every packet goes to the attacker with no
//  error at all. That is why `ProviderServerListDiff` holds a changed key pending
//  instead of applying it.
//
//  NOTHING HERE TOUCHES THE NETWORK and nothing here is a secret. A peer PUBLIC key
//  is public by construction; the user's private key never comes near this file.
//

import Foundation
import Network

// MARK: - A validated hostname

/// A DNS name that came off the network and survived being checked.
///
/// Deliberately a type rather than a validated `String`, so that "did anyone check
/// this?" is answered by the type system at every later use instead of by a comment.
/// The only way to make one is `init?(_:allowedSuffix:)`, and it returns nil rather
/// than throwing because a bad row in a list of three thousand is a row to drop, not
/// a reason to reject the provider's whole list.
nonisolated struct ProviderHostname: Sendable, Hashable, Comparable, CustomStringConvertible {

    let value: String

    var description: String { value }

    static func < (a: ProviderHostname, b: ProviderHostname) -> Bool { a.value < b.value }

    /// The rules, and every one of them is here because of something a hostile list
    /// could otherwise do:
    ///
    ///  • lowercase ASCII letters, digits, `-` and `.` ONLY. This is the rule that
    ///    stops directive injection: a newline, a space, a quote or a `#` cannot get
    ///    through, so nothing a list contains can become a second line of an `.ovpn`.
    ///  • at most 253 characters overall and 63 per label, which is the DNS limit and
    ///    also stops a megabyte-long "hostname" reaching a config file.
    ///  • no empty label, and no label starting or ending with `-`.
    ///  • **it must end with the provider's own suffix**, which ships with the app.
    ///    The cheapest control in the feature: a fully compromised list still cannot
    ///    point the user at an unrelated domain.
    ///
    /// Note there is no IDN handling and no uppercase folding: a provider that starts
    /// publishing either should be handled deliberately, not silently normalised into
    /// something that no longer matches what the user was shown.
    init?(_ raw: String, allowedSuffix: String) {
        guard !raw.isEmpty, raw.count <= 253 else { return nil }
        guard raw.hasSuffix(allowedSuffix) else { return nil }
        guard raw.utf8.allSatisfy({ byte in
            (byte >= 0x61 && byte <= 0x7A)      // a-z
                || (byte >= 0x30 && byte <= 0x39)   // 0-9
                || byte == 0x2D                     // -
                || byte == 0x2E                     // .
        }) else { return nil }
        let labels = raw.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2 else { return nil }
        for label in labels {
            guard !label.isEmpty, label.count <= 63 else { return nil }
            guard label.first != "-", label.last != "-" else { return nil }
        }
        value = raw
    }
}

// MARK: - A validated peer public key

/// A WireGuard peer public key: exactly 32 bytes, re-encoded canonically.
///
/// The canonical re-encoding is the point, not a nicety. Two different base64
/// spellings of the same key would compare unequal, and `ProviderServerListDiff`
/// decides whether to raise a confirmation by comparing keys — so a provider
/// changing its whitespace or padding must not look like a provider changing its
/// key, and vice versa.
nonisolated struct ProviderPeerKey: Sendable, Hashable, CustomStringConvertible {

    /// Canonical base64, 44 characters. Public by construction; safe to log, though
    /// there is no reason to.
    let base64: String

    var description: String { base64 }

    init?(_ raw: String) {
        guard raw.count == 44 else { return nil }
        guard let data = Data(base64Encoded: raw), data.count == 32 else { return nil }
        base64 = data.base64EncodedString()
    }
}

// MARK: - One server

/// One server from a provider's published list.
///
/// Everything on it either survived validation or is `nil`. There is no "raw" field
/// and no escape hatch back to the bytes that arrived, because the moment one exists
/// somebody will use it (that is the lesson `ConnectListing` records about a second
/// notion of "configured").
nonisolated struct ProviderServer: Sendable, Hashable, Identifiable {

    let hostname: ProviderHostname
    /// Re-serialised from the parsed address, never echoed from the payload.
    let ipv4: String?
    let ipv6: String?
    /// ISO 3166-1 alpha-2, lowercased.
    let countryCode: String?
    /// The provider's own city code (`tia`, `dxb`). Not a display string.
    let cityCode: String?
    /// A display label only. It is escaped wherever it is shown and NEVER reaches a
    /// configuration file, which is why it is the one field allowed to be free text.
    let cityName: String?
    /// WireGuard only. The single most security-determining thing in a fetched list.
    let peerKey: ProviderPeerKey?
    /// The provider says this server is in service. A list that marks servers out of
    /// service is more useful than one that silently drops them, and we keep both.
    let active: Bool

    var id: String { hostname.value }

    /// Parses and re-serialises an IPv4 literal, so nothing from the payload is
    /// carried through as text. `nil` in ⇒ `nil` out; garbage in ⇒ `nil` out.
    static func normalisedIPv4(_ raw: String?) -> String? {
        guard let raw, let addr = IPv4Address(raw) else { return nil }
        return "\(addr)"
    }

    /// The IPv6 counterpart. Note this also canonicalises `2A04:...` to lowercase and
    /// collapses zero runs, which is what makes address comparison in the diff mean
    /// what it looks like it means.
    static func normalisedIPv6(_ raw: String?) -> String? {
        guard let raw, let addr = IPv6Address(raw) else { return nil }
        return "\(addr)"
    }

    /// A two-letter country code, or nil. Anything else is dropped rather than
    /// truncated: a three-letter code silently cut to two would put a server on the
    /// wrong flag, and the Servers table treats a country as a fact.
    static func normalisedCountry(_ raw: String?) -> String? {
        guard let raw, raw.count == 2 else { return nil }
        let lower = raw.lowercased()
        guard lower.utf8.allSatisfy({ $0 >= 0x61 && $0 <= 0x7A }) else { return nil }
        return lower
    }
}

// MARK: - A whole list

/// What one fetch produced, plus what it cost to produce it.
///
/// `dropped` is not diagnostics decoration. It is the number the integrity rules
/// read: a payload that parsed but discarded most of its rows is a payload we do not
/// understand, and quietly keeping the handful that survived would be the worst of
/// both worlds — a shrunken list that looks deliberate.
nonisolated struct ProviderServerList: Sendable, Equatable {

    let providerID: VPNServiceProviderID
    /// Sorted by hostname, so two lists of the same servers are the same value and
    /// a diff is not fooled by the provider reordering its JSON.
    let servers: [ProviderServer]
    /// Rows the payload contained that did not survive validation.
    let dropped: Int
    /// When this list was fetched. Shown as staleness; never used to trigger a fetch.
    let fetchedAt: Date

    init(providerID: VPNServiceProviderID, servers: [ProviderServer],
         dropped: Int, fetchedAt: Date) {
        self.providerID = providerID
        self.servers = servers.sorted { $0.hostname < $1.hostname }
        self.dropped = dropped
        self.fetchedAt = fetchedAt
    }

    var isEmpty: Bool { servers.isEmpty }

    /// Countries present, sorted — what the "which places do you want?" filter offers.
    /// A 3,576-row Servers table is not a feature; it is the feature failing.
    var countries: [String] {
        Array(Set(servers.compactMap(\.countryCode))).sorted()
    }

    func server(_ hostname: String) -> ProviderServer? {
        servers.first { $0.hostname.value == hostname }
    }
}
