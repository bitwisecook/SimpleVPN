// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNEndpoints.swift
//  A VPN's list of places it can be reached — separate from what the VPN is
//  CALLED. The name a user gives a VPN ("Work", "Mum's house") lives in the
//  manager's localizedDescription and never has to be a hostname again; the
//  hosts live here, one entry per address the profile can dial, each with an
//  optional port, an optional label ("London — fastest") and a country the user
//  can correct when GeoIP places it wrongly.
//
//  Stored as providerConfiguration["endpoints"], the same lenient JSON-blob
//  pattern as VPNAuthConfig / OpenVPNOverrides: every field is optional, a
//  corrupt or missing blob decodes to "nothing saved", and an older build's
//  config keeps working untouched. The blob holds only what the user AUTHORED —
//  labels, country corrections and any endpoint they typed in themselves. The
//  addresses a profile advertises are still read from the .ovpn on every use,
//  so re-importing a config picks up the provider's new servers automatically.
//
//  Choosing an endpoint writes OpenVPNOverrides.server/port/proto — and, for a
//  WireGuard profile, the peer's endpoint AND its public key together
//  (`WireGuardEndpointSelection`). This model decides what the list SHOWS and in
//  what ORDER; it never becomes a second way to configure the connection.
//
//  TWO FIELDS EXIST FOR PROVIDERS' PUBLISHED SERVER LISTS (Docs/ServiceBundles.md
//  §5), and both are annotations like any other in this blob:
//
//   • `peerPublicKey` — WireGuard has no certificate, so the peer's public key IS
//     the authentication, and MULLVAD GIVES EVERY RELAY ITS OWN. A WireGuard
//     server list is therefore a list of (address, key) PAIRS, and a list that
//     could hold only the address would connect to server A carrying server B's
//     key: a handshake that fails closed, silently, with nothing to look at. The
//     pair moves together or not at all — see `WireGuardEndpointSelection`.
//   • `fromProvider` — a THIRD provenance beside "the configuration advertises
//     this" and "the user typed it in". It deliberately does not borrow
//     `userAdded`, because a list refresh would then look like the user's own work
//     and survive when it should not.
//

import Foundation

/// One address a VPN can be reached at.
nonisolated struct VPNEndpoint: Codable, Sendable, Equatable, Identifiable {

    /// Hostname or IP literal. The one required field.
    var host: String
    /// nil ⇒ whatever the profile/engine default is (1194 for OpenVPN).
    var port: Int?
    /// "udp" / "tcp", normalized. nil ⇒ profile/engine default.
    var proto: String?
    /// The user's own name for this endpoint. Never invented — an endpoint with
    /// no label shows its host.
    var label: String?
    /// Country override (ISO 3166-1 alpha-2), set by clicking the flag. Wins
    /// over GeoIP, which is only ever a guess from an address.
    var country: String?
    /// Region override, for the rare endpoint whose region the user knows but
    /// whose country they don't (anycast, a provider's own naming). Wins over
    /// everything.
    var region: RegionBucket?
    /// true ⇒ the user typed this endpoint in, so it survives even when the
    /// .ovpn doesn't mention it. false/nil ⇒ this is an annotation attached to
    /// an address the profile itself advertises, and it disappears with it.
    var userAdded: Bool?
    /// Where the user PUT this server, 0-based. nil ⇒ they never said, so the
    /// automatic ranking decides (measured, else nearest — `EndpointRanking`).
    ///
    /// An annotation like any other in this blob, and stored the same way: a
    /// server the configuration advertises can carry one exactly as it can carry
    /// a name or a corrected country. What it changes is the order the app OFFERS
    /// its servers in; it never rewrites the configuration's own `remote` lines,
    /// which is why moving a configuration-provided server is honest — the lock
    /// travels with the row and the address is still the file's.
    ///
    /// Sparse and self-healing on purpose: a server that appears later (a
    /// re-imported .ovpn with a new remote) has no order and sorts after the ones
    /// that do, rather than silently taking somebody's first-choice slot.
    var order: Int?
    /// The WireGuard peer public key THIS server answers with, base64, or nil.
    ///
    /// Not a secret and never treated as one: a peer PUBLIC key is public by
    /// construction, it is what a `.conf` carries in the clear, and it is
    /// integrity-critical — so it belongs in an exported file where a diff can see
    /// it, exactly as a certificate fingerprint does (`ConfigSecrets`).
    ///
    /// Nil on every OpenVPN endpoint and on the ordinary single-peer WireGuard VPN,
    /// where the one key lives in the profile's own configuration. It is set when a
    /// server came from a provider whose relays each carry their own key — which is
    /// every Mullvad relay — and the moment ANY server in a list has one, a server
    /// WITHOUT one can no longer be selected: see `WireGuardEndpointSelection`.
    var peerPublicKey: String?
    /// Which provider's published list this server came from
    /// (`VPNServiceProviderID.rawValue`), or nil for a server the configuration
    /// advertises or the user typed in.
    ///
    /// Provenance, not permission: it changes what the Servers table SAYS about a
    /// row and whether a list refresh may touch it. It is deliberately separate from
    /// `userAdded` — "the user typed this in" is a different claim, and a refresh
    /// that inherited it would make the provider's work look like the user's.
    var fromProvider: String?

    /// Same shape as `Endpoint.id`, so a stored annotation and a scanned remote
    /// identify each other, and so existing override matching keeps working.
    ///
    /// The peer key is deliberately NOT part of it. A provider rotating a relay's
    /// key must read as the SAME server with a changed key — which is a pending
    /// confirmation (`ProviderServerListDiff`) — and not as one server vanishing
    /// while an unrelated one appears, which is the shape that hides a substitution.
    var id: String { "\(host):\(port.map(String.init) ?? "*"):\(proto ?? "*")" }

    init(host: String, port: Int? = nil, proto: String? = nil, label: String? = nil,
         country: String? = nil, region: RegionBucket? = nil, userAdded: Bool? = nil,
         order: Int? = nil, peerPublicKey: String? = nil, fromProvider: String? = nil) {
        self.host = host
        self.port = port
        self.proto = proto
        self.label = label
        self.country = country
        self.region = region
        self.userAdded = userAdded
        self.order = order
        self.peerPublicKey = peerPublicKey
        self.fromProvider = fromProvider
    }

    /// From a `remote` line scanned out of an .ovpn.
    init(_ endpoint: Endpoint) {
        self.init(host: endpoint.host, port: endpoint.port, proto: endpoint.proto)
    }

    /// The plain `Endpoint` the rest of the app (overrides, GeoIP lookup) speaks.
    var endpoint: Endpoint { Endpoint(host: host, port: port, proto: proto) }

    /// What to call this endpoint in a menu when there's no room for detail.
    var displayLabel: String {
        let l = label?.trimmingCharacters(in: .whitespaces) ?? ""
        return l.isEmpty ? host : l
    }

    /// Whether the user has said anything about this endpoint worth storing.
    ///
    /// `order` counts. It is the whole reason a manual order survives a relaunch:
    /// `VPNEndpointList.encodedBlob()` drops entries that say nothing, so an entry
    /// carrying only a position would otherwise be thrown away on the way to disk.
    /// `order` counts, and so do the two provider fields — for the same reason and
    /// with a sharper failure: a provider-supplied WireGuard relay carries nothing
    /// but an address and a key, so an entry that said "nothing worth storing" would
    /// be dropped on the way to disk and the whole fetched list would vanish on
    /// relaunch. Worse, the key would vanish while the address survived in some
    /// other form, which is the one state this model must never reach.
    var hasAnnotations: Bool {
        !(label?.isEmpty ?? true) || country != nil || region != nil || userAdded == true
            || order != nil || peerPublicKey != nil || fromProvider != nil
    }

    /// May the user delete this row? The configuration owns its own `remote` lines,
    /// so those are locked — but a server that arrived from a provider's list is one
    /// the user asked for and can therefore take back, exactly like one they typed.
    var isRemovable: Bool { userAdded == true || fromProvider != nil }

    // Hand-written so a blob written by a newer build (or a hand-edited one)
    // never fails the whole list: unknown fields are ignored, a port that
    // arrived as a string is still read, and an unrecognised region name
    // degrades to "no override" rather than throwing.
    private enum CodingKeys: String, CodingKey {
        case host, port, proto, label, country, region, userAdded, order
        case peerPublicKey, fromProvider
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        host = (try? c.decode(String.self, forKey: .host)) ?? ""
        if let p = try? c.decode(Int.self, forKey: .port) {
            port = p
        } else if let s = try? c.decode(String.self, forKey: .port) {
            port = Int(s)
        }
        proto = (try? c.decode(String.self, forKey: .proto)).map(EndpointScanner.normalizedProto)
        label = try? c.decode(String.self, forKey: .label)
        country = (try? c.decode(String.self, forKey: .country))?.uppercased()
        region = (try? c.decode(String.self, forKey: .region)).flatMap(RegionBucket.init(rawValue:))
        userAdded = try? c.decode(Bool.self, forKey: .userAdded)
        // Lenient like `port`: a hand-edited or MDM-written blob may say "2".
        // A negative position is nonsense and decodes to "no position" rather
        // than sorting ahead of everything.
        if let n = try? c.decode(Int.self, forKey: .order) {
            order = n >= 0 ? n : nil
        } else if let s = try? c.decode(String.self, forKey: .order), let n = Int(s), n >= 0 {
            order = n
        }
        // VALIDATED ON THE WAY IN, and not merely trimmed. This blob is reachable
        // from an imported file, an MDM payload and a hand edit, so a key that is
        // not exactly 32 bytes must become "no key" here rather than a 31-byte value
        // that every layer accepts until the handshake, where it fails with nothing
        // for the user to look at (the same reasoning as
        // `WireGuardConfig.keyProblem`, and the same reasoning as the port above).
        // Re-encoded canonically so two spellings of one key compare equal, which is
        // what makes "did this relay's key change?" mean what it looks like.
        peerPublicKey = (try? c.decode(String.self, forKey: .peerPublicKey))
            .flatMap(VPNEndpoint.canonicalPeerKey)
        // Only a provider this build knows. An unknown name is dropped rather than
        // carried: it would put an unanswerable "from ?" on a row, and provenance
        // that cannot be resolved is worse than none.
        fromProvider = (try? c.decode(String.self, forKey: .fromProvider))
            .flatMap { VPNServiceProviderID(rawValue: $0)?.rawValue }
    }

    /// A base64 WireGuard key re-encoded canonically, or nil if it is not one.
    /// Shared by the decoder and by anything building an endpoint from a fetched
    /// list, so there is exactly one definition of "this is a usable peer key".
    static func canonicalPeerKey(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard s.count == 44, let data = Data(base64Encoded: s),
              data.count == WireGuardConfig.keyByteCount else { return nil }
        return data.base64EncodedString()
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(host, forKey: .host)
        try c.encodeIfPresent(port, forKey: .port)
        try c.encodeIfPresent(proto, forKey: .proto)
        try c.encodeIfPresent(label, forKey: .label)
        try c.encodeIfPresent(country, forKey: .country)
        try c.encodeIfPresent(region?.rawValue, forKey: .region)
        try c.encodeIfPresent(userAdded, forKey: .userAdded)
        try c.encodeIfPresent(order, forKey: .order)
        try c.encodeIfPresent(peerPublicKey, forKey: .peerPublicKey)
        try c.encodeIfPresent(fromProvider, forKey: .fromProvider)
    }
}

/// The stored blob: what the user authored about a VPN's endpoints.
nonisolated struct VPNEndpointList: Codable, Sendable, Equatable {

    var endpoints: [VPNEndpoint] = []

    init(endpoints: [VPNEndpoint] = []) {
        self.endpoints = endpoints
    }

    private enum CodingKeys: String, CodingKey { case endpoints }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let raw = (try? c.decode([VPNEndpoint].self, forKey: .endpoints)) ?? []
        // A hostless entry is meaningless and unfixable in the UI — drop it
        // rather than show a blank row somebody can't get rid of.
        endpoints = raw.filter { !$0.host.trimmingCharacters(in: .whitespaces).isEmpty }
    }

    var isDefault: Bool { endpoints.isEmpty }

    /// Only annotations are worth persisting; a list that merely restates the
    /// .ovpn's remotes is dropped so re-importing keeps picking up new servers.
    func encodedBlob() -> Data? {
        let meaningful = endpoints.filter(\.hasAnnotations)
        guard !meaningful.isEmpty else { return nil }
        return try? JSONEncoder().encode(VPNEndpointList(endpoints: meaningful))
    }

    static func decode(from blob: Data?) -> VPNEndpointList {
        guard let blob else { return VPNEndpointList() }
        return (try? JSONDecoder().decode(VPNEndpointList.self, from: blob)) ?? VPNEndpointList()
    }

    /// The list to show: every address the profile advertises, wearing whatever
    /// the user said about it, followed by the endpoints the user added by hand and
    /// the ones a provider's published list supplied.
    ///
    /// Matching is by `id` (host + port + protocol), which is what the override
    /// machinery matches on too — so an annotation follows its endpoint exactly
    /// as far as a selection does, and no further.
    static func merged(scanned: [Endpoint], stored: VPNEndpointList) -> [VPNEndpoint] {
        var annotations: [String: VPNEndpoint] = [:]
        for e in stored.endpoints { annotations[e.id] = e }

        var out: [VPNEndpoint] = []
        var seen = Set<String>()
        for remote in scanned {
            let base = VPNEndpoint(remote)
            guard seen.insert(base.id).inserted else { continue }
            if var saved = annotations[base.id] {
                // The profile owns the address; the user owns the description.
                saved.host = base.host
                saved.port = base.port
                saved.proto = base.proto
                saved.userAdded = nil
                out.append(saved)
            } else {
                out.append(base)
            }
        }
        // Everything the profile does NOT advertise but somebody deliberately put
        // here: typed in by hand, or taken from a provider's published list. Both
        // are the same kind of thing to this function — a row that exists because a
        // person asked for it — and both must survive a configuration that never
        // mentions them, which is the whole point of a Mullvad list: the imported
        // `.conf` names one relay, and the other 566 are only here.
        for e in stored.endpoints where e.isRemovable && !seen.contains(e.id) {
            seen.insert(e.id)
            out.append(e)
        }
        return out
    }
}
