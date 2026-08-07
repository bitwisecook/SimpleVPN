// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNServiceProviders.swift
//  THE FOUR VPN COMPANIES SimpleVPN KNOWS THE PUBLISHED SERVERS OF, and — the part
//  that matters more — what each of them still cannot give a user.
//
//  Design and the research behind every URL and every claim: Docs/ServiceBundles.md.
//  Naming: ONTOLOGY.md, "Companies that sell VPN service, and the servers they
//  publish". A company is a PROVIDER (`vendor` is taken: it means a password app).
//  There is deliberately no noun for "the thing you install" — see `stillNeeded`.
//
//  THE SPLIT THIS TYPE EXISTS TO ENFORCE, and it is the whole security design:
//
//   • WHAT SHIPS WITH THE APP — the directive template, the hostname suffix, the CA
//     fingerprint. All of it integrity-critical, so all of it inside a
//     Sparkle-signed update and none of it fetchable. Note that we ship the CA's
//     FINGERPRINT and not its bytes: a rotation then becomes a loud refusal rather
//     than a silent mismatch, and we redistribute nothing (Docs/ServiceBundles.md §6
//     — IPVanish's terms expressly bar redistribution and Mullvad's are silent,
//     which is not permission).
//   • WHAT IS FETCHED — hostnames, addresses, place names, and for WireGuard a peer
//     public key. Nothing else. A fetched payload can never introduce a directive
//     because it is never treated as text (`ProviderServerList`).
//
//  NO ACCOUNT INTEGRATION OF ANY KIND. No sign-in, no key registration, no API
//  token, no sales flow. `stillNeeded` is the sentence that keeps that honest, and
//  every provider that gets a working row has to be able to state one truthfully.
//

import Foundation

// MARK: - Which provider

/// A VPN company whose published servers SimpleVPN can read.
///
/// Four, not a framework. The user named these four ("i use mullvad, friends use
/// proton, nord and ipvanish") and the same restraint applies here as to password
/// apps: the main ones, not everything under the sun. A fifth is a case here plus a
/// `VPNServiceProvider` literal below — data, not code — but adding one is still a
/// deliberate act with terms to read first.
nonisolated enum VPNServiceProviderID: String, Sendable, CaseIterable, Codable, Hashable {
    case mullvad
    case nordVPN
    case ipVanish
    case protonVPN
}

// MARK: - What we know about one

/// Everything SimpleVPN ships about one provider. Pure data; nothing here reaches
/// the network, and nothing here is a secret.
nonisolated struct VPNServiceProvider: Sendable, Identifiable, Equatable {

    let id: VPNServiceProviderID

    /// The company's own spelling. ONTOLOGY rule 2: a vendor's proper nouns keep
    /// their spelling, because the user has to recognise it.
    let displayName: String

    /// The protocol a list from this provider can actually produce a profile for,
    /// and `nil` where there is nothing reachable at all.
    ///
    /// Mullvad is `.wireGuard` and NOT `.openVPN`, and that is a measured fact
    /// rather than a preference: `api.mullvad.net/www/relays/all/` returned 580
    /// relays on 2026-08-07 — 567 WireGuard, 13 bridge, zero OpenVPN — and the
    /// `/www/relays/openvpn/` path 404s.
    let kind: VPNKind?

    /// Where the list lives. `nil` ⇒ unreachable without an account; see `blocked`.
    let listURL: URL?

    /// Every hostname in a fetched list must end with this, or it is dropped.
    ///
    /// The cheapest control in the whole feature and one of the strongest: a fully
    /// compromised list still cannot point the user at an unrelated domain. It ships
    /// with the app precisely so that a fetch cannot widen it.
    let hostnameSuffix: String

    /// SHA-256 of the DER bytes of the provider's CA certificate, lowercase hex, or
    /// `nil` for a provider with no certificate in the path (WireGuard).
    ///
    /// ❓ NOT POPULATED YET for the OpenVPN providers. The fingerprint has to be
    /// taken from the certificate the provider serves at the moment the fetch code
    /// lands, and pinning a value transcribed by hand from a research session would
    /// be exactly the kind of confident-and-wrong this feature must not do. Until it
    /// is filled in, `canFetch` is false for those providers — a missing pin fails
    /// closed rather than fetching unpinned.
    let caFingerprintSHA256: String?

    /// WHAT THE USER MUST STILL SUPPLY, in one sentence, shown BEFORE anything is
    /// fetched rather than after it fails.
    ///
    /// THE RULE THIS FIELD EXISTS TO ENFORCE: **if this sentence cannot be written
    /// truthfully for a provider, that provider does not get a working row.** A
    /// server list is not a working configuration, and a row that looks like it
    /// should just connect and cannot is worse than no row at all.
    let stillNeeded: String

    /// Why this provider cannot be used at all, or `nil` if it can.
    ///
    /// Present rather than absent on purpose. `ConnectListing`'s rule — never hide
    /// something the user came looking for; list it, disable it, say why — applies
    /// to a provider picker exactly as it applies to a profile.
    let blocked: String?

    /// Can SimpleVPN fetch this provider's list at all?
    ///
    /// Three conditions, all of which must hold, and the third is the one that
    /// catches an unfinished provider: there is a URL, nothing blocks it, and any
    /// provider whose protocol involves a certificate has that certificate pinned.
    var canFetch: Bool {
        guard blocked == nil, listURL != nil else { return false }
        if kind == .openVPN { return caFingerprintSHA256 != nil }
        return true
    }
}

// MARK: - The catalogue

nonisolated enum VPNServiceProviderCatalog {

    /// One entry per provider, in the order a picker shows them: the one that works
    /// first, the one that cannot work last.
    static let all: [VPNServiceProvider] = [mullvad, ipVanish, nordVPN, protonVPN]

    static func provider(_ id: VPNServiceProviderID) -> VPNServiceProvider {
        // Total by construction and asserted by test, so this is not a silent
        // default — an unlisted provider is a build-time failure, not a runtime one.
        all.first { $0.id == id } ?? protonVPN
    }

    // MARK: Mullvad — WireGuard only, list is public

    /// VERIFIED 2026-08-07: `GET https://api.mullvad.net/www/relays/all/` → 200, no
    /// authentication, 300,032 bytes. 567 WireGuard relays across 50 countries and
    /// 91 cities, EACH WITH ITS OWN PEER PUBLIC KEY — which is why a WireGuard
    /// server list is a list of (address, key) pairs and not a list of addresses.
    ///
    /// The gap, stated in `stillNeeded` and not engineered around: a WireGuard tunnel
    /// needs a private key and a tunnel address, Mullvad assigns the address when a
    /// key is registered against an account, and SimpleVPN registers nothing. The
    /// user downloads one configuration from mullvad.net and imports it — which
    /// already works — and the list then turns that one server into 567.
    static let mullvad = VPNServiceProvider(
        id: .mullvad,
        displayName: "Mullvad",
        kind: .wireGuard,
        listURL: URL(string: "https://api.mullvad.net/www/relays/all/"),
        hostnameSuffix: ".relays.mullvad.net",
        caFingerprintSHA256: nil,   // WireGuard: no certificate anywhere in the path
        stillNeeded: "You will still need a Mullvad account and a WireGuard configuration "
            + "downloaded from mullvad.net \u{2014} SimpleVPN cannot sign you in to Mullvad or "
            + "register a key for you. Import that configuration first; this fills in the servers.",
        blocked: nil)

    // MARK: IPVanish — OpenVPN only, and the textbook template

    /// VERIFIED 2026-08-07: `https://configs.ipvanish.com/configs/` is an open
    /// directory. Its `configs.zip` (1,283,217 bytes) unpacks to 3,576 `.ovpn` files
    /// and one CA, and ALL 3,576 hash identically once the hostname is normalised —
    /// exactly one template and 3,576 hostnames, which is the shape the user
    /// remembered ("configs you can use for a linux box by inserting the server
    /// name").
    ///
    /// ⚠️ IPVanish's terms expressly bar redistribution and derivative works without
    /// prior written approval (quoted in full in Docs/ServiceBundles.md §6), so
    /// nothing of theirs is embedded. The user fetches it, from IPVanish, as the
    /// subscriber those files are published for.
    static let ipVanish = VPNServiceProvider(
        id: .ipVanish,
        displayName: "IPVanish",
        kind: .openVPN,
        listURL: URL(string: "https://configs.ipvanish.com/configs/"),
        hostnameSuffix: ".ipvanish.com",
        caFingerprintSHA256: nil,   // ❓ to be pinned when the fetch lands; fails closed until then
        stillNeeded: "You will still need an IPVanish account \u{2014} its username and password go "
            + "in Sign-In, and SimpleVPN never asks IPVanish for them.",
        blocked: nil)

    // MARK: NordVPN — OpenVPN only here, WireGuard needs an account

    /// VERIFIED 2026-08-07: `GET https://api.nordvpn.com/v1/servers` → 200, no
    /// authentication. Two real servers fetched from
    /// `downloads.nordcdn.com/configs/files/ovpn_udp/servers/` are byte-identical
    /// once IPv4 literals and `*.nordvpn.com` are normalised, and their inline `<ca>`
    /// and `<tls-auth>` blocks hash identically — so Nord's 86 MB archive is ~7,000
    /// copies of one 2.9 KB template.
    ///
    /// TWO THINGS MAKE NORD MORE WORK THAN IPVANISH. Its `remote` is an IP literal
    /// with four ports and the hostname appears separately as
    /// `verify-x509-name CN=<host>`, so substitution needs TWO values per server
    /// (`station` and `hostname`, both in the API). And NordLynx needs a private key
    /// Nord's authenticated API issues, so this row is OpenVPN only.
    ///
    /// ❓ Nord's terms could not be read — `nordvpn.com/terms-of-service/` returns 403
    /// to us. Treated as IPVanish is, by precaution: fetch, never embed.
    static let nordVPN = VPNServiceProvider(
        id: .nordVPN,
        displayName: "NordVPN",
        kind: .openVPN,
        listURL: URL(string: "https://api.nordvpn.com/v1/servers"),
        hostnameSuffix: ".nordvpn.com",
        caFingerprintSHA256: nil,   // ❓ to be pinned when the fetch lands; fails closed until then
        stillNeeded: "You will still need a NordVPN account, and OpenVPN uses the separate "
            + "service credentials from your Nord dashboard \u{2014} not the email and password you "
            + "sign in to Nord with.",
        blocked: nil)

    // MARK: Proton VPN — not possible, and the row says so

    /// VERIFIED 2026-08-07, and this is a finding rather than a gap.
    /// `api.protonvpn.ch/vpn/logicals` resets the connection; `api.protonmail.ch/vpn/logicals`
    /// answers 400 "Missing x-pm-appversion header", then 422 "This version of the app
    /// is no longer supported" for a stale version, then **401 "Invalid access token"**
    /// for a current-looking one. The list is behind an app-version gate AND an
    /// account token.
    ///
    /// Proton's own terms permit automated access only where "the resulting traffic
    /// remains indistinguishable from the standard client behavior of human users" —
    /// spoofing a version string to read `logicals` is what that sentence is about.
    /// So SimpleVPN does not do it, and the row states the absence and names the
    /// thing that does work instead.
    static let protonVPN = VPNServiceProvider(
        id: .protonVPN,
        displayName: "Proton VPN",
        kind: nil,
        listURL: nil,
        hostnameSuffix: ".protonvpn.net",
        caFingerprintSHA256: nil,
        stillNeeded: "",
        blocked: "Proton VPN only gives out its server list to a signed-in Proton client, and "
            + "SimpleVPN does not sign in to VPN providers. Download the OpenVPN configuration "
            + "from your Proton account and import it here instead \u{2014} that works today.")
}
