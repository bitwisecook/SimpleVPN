// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// The packet provider receives the negotiated mode and exact IKE identities here. Credentials travel only in start options.
nonisolated struct OwnedIPsecConfiguration: Codable, Equatable, Sendable {
    static let providerKind = "owned-ipsec-v1"
    static let configurationKey = "ownedIPsec"
    static let eapPasswordOption = "ipsecEAPPassword"
    static let pppPasswordOption = "ipsecPPPPassword"
    static let pskOption = "ipsecPSK"
    static let xauthPasswordOption = "ipsecXAuthPassword"

    var version: Int = 1
    var profileID: String
    var kind: VPNKind
    var server: String
    var localID: String
    var remoteID: String
    var username: String?
    var usesXAuth: Bool
    var usesEAP: Bool? = nil
    var usesL2TP: Bool? = nil

    var adapterID: String? {
        switch kind {
        case .ikev2: "ikev2-strongswan"
        case .ipsec: "ipsec-strongswan"
        case .l2tp where usesL2TP == true: "l2tp-strongswan"
        default: nil
        }
    }

    var problem: String? {
        guard version == 1, adapterID != nil else { return "This IPsec configuration requires a different provider version." }
        let strings = [profileID, server, localID, remoteID] + (username.map { [$0] } ?? [])
        guard strings.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 1024 && $0.rangeOfCharacter(from: .controlCharacters) == nil }) else {
            return "Enter the server, local identity and authenticated gateway identity."
        }
        guard [localID, remoteID].allSatisfy({ !$0.contains("*") && !$0.hasPrefix("%") && $0 == $0.trimmingCharacters(in: .whitespacesAndNewlines) }) else {
            return "Use exact IKE identities for the client and the authenticated gateway."
        }
        if usesL2TP == true {
            var address = in_addr()
            guard kind == .l2tp, !usesXAuth, usesEAP != true, let username, Self.validPPPCredential(username),
                  server.withCString({ inet_pton(AF_INET, $0, &address) == 1 }) else {
                return "Built-in L2TP requires an IPv4 server address and a printable ASCII PPP username of 1–255 bytes."
            }
        } else if usesEAP == true {
            guard kind == .ikev2, !usesXAuth, username != nil else { return "IKEv2 EAP-MSCHAPv2 requires a username." }
        } else if !(usesXAuth ? kind == .ipsec && username != nil : username == nil) {
            return "XAuth requires an IKEv1 profile with a username."
        }
        return nil
    }

    static func validPPPCredential(_ value: String) -> Bool {
        (1...255).contains(value.utf8.count) && value.utf8.allSatisfy { (32...126).contains($0) }
    }

    static func decode(from configuration: [String: Any]) -> Self? {
        guard configuration["vpnType"] as? String == providerKind,
              configuration["ovpn"] == nil, let bytes = configuration[configurationKey] as? Data,
              bytes.count <= 16_384, let value = try? JSONDecoder().decode(Self.self, from: bytes),
              configuration["profile"] as? String == value.profileID, value.problem == nil else { return nil }
        return value
    }
}
