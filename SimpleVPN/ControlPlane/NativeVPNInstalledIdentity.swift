// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
@preconcurrency import NetworkExtension

/// Public installed protocol metadata, never passwords or persistent references.
/// A name/server alone cannot identify two native profiles reliably.
nonisolated struct NativeVPNInstalledIdentity: Codable, Equatable {
    var id: String
    var kind: String
    var server: String
    var username: String
    var remote: String
    var local: String
    var authentication: Int
    var extended: Bool

    init?(id: String, protocol proto: NEVPNProtocol?) {
        guard let proto else { return nil }
        self.id = id; server = proto.serverAddress ?? ""; username = proto.username ?? ""
        if let p = proto as? NEVPNProtocolIKEv2 {
            kind = "ikev2"; remote = p.remoteIdentifier ?? ""; local = p.localIdentifier ?? ""
            authentication = p.authenticationMethod.rawValue; extended = p.useExtendedAuthentication
        } else if let p = proto as? NEVPNProtocolIPSec {
            kind = "ipsec"; remote = p.remoteIdentifier ?? ""; local = p.localIdentifier ?? ""
            authentication = p.authenticationMethod.rawValue; extended = p.useExtendedAuthentication
        } else { return nil }
    }
    func matches(_ proto: NEVPNProtocol?) -> Bool { Self(id: id, protocol: proto) == self }
}
