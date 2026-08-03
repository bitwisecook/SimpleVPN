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
//  Choosing an endpoint still writes OpenVPNOverrides.server/port/proto. This
//  model decides what the list SHOWS and in what ORDER; it never becomes a
//  second way to configure the connection.
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

    /// Same shape as `Endpoint.id`, so a stored annotation and a scanned remote
    /// identify each other, and so existing override matching keeps working.
    var id: String { "\(host):\(port.map(String.init) ?? "*"):\(proto ?? "*")" }

    init(host: String, port: Int? = nil, proto: String? = nil, label: String? = nil,
         country: String? = nil, region: RegionBucket? = nil, userAdded: Bool? = nil) {
        self.host = host
        self.port = port
        self.proto = proto
        self.label = label
        self.country = country
        self.region = region
        self.userAdded = userAdded
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
    var hasAnnotations: Bool {
        !(label?.isEmpty ?? true) || country != nil || region != nil || userAdded == true
    }

    // Hand-written so a blob written by a newer build (or a hand-edited one)
    // never fails the whole list: unknown fields are ignored, a port that
    // arrived as a string is still read, and an unrecognised region name
    // degrades to "no override" rather than throwing.
    private enum CodingKeys: String, CodingKey {
        case host, port, proto, label, country, region, userAdded
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
    /// the user said about it, followed by the endpoints the user added by hand.
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
        for e in stored.endpoints where e.userAdded == true && !seen.contains(e.id) {
            seen.insert(e.id)
            out.append(e)
        }
        return out
    }
}
