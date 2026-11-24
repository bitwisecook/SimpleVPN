// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import CryptoKit
import Foundation

nonisolated struct DNSQueryCounts: Codable, Equatable, Sendable {
    var matches: UInt64 = 0
    var answered: UInt64 = 0
    var failed: UInt64 = 0
    var queryBytes: UInt64 = 0
    var replyBytes: UInt64 = 0
}

/// The row index is its ordinal in the acknowledged policy. The last row counts
/// queries that retained the original resolver because no rule matched.
nonisolated struct DNSQueryActivity: Codable, Sendable {
    let session: UUID
    let generation: Data
    let rows: [DNSQueryCounts]

    static func digest(_ configuration: Data) -> Data { Data(SHA256.hash(data: configuration)) }

    static func configurationData(_ policy: DNSQueryPolicy) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(policy)
    }

    func agrees(with digest: Data, ruleCount: Int) -> Bool {
        (0...256).contains(ruleCount) && rows.count == ruleCount + 1 && generation == digest
    }
}

@objc(SimpleVPNQueryActivityReading)
nonisolated protocol DNSQueryActivityReading {
    func readCounts(_ generation: Data, withReply reply: @escaping @Sendable (Data?) -> Void)
}

nonisolated enum DNSQueryActivityWire {
    // Matches NetworkExtension.NEMachServiceName in the system extension.
    static let serviceName = "group.com.bragi0.SimpleVPN"
    static let clientRequirement = SourceIdentityWire.signer + " and identifier \"com.bragi0.SimpleVPN\""
    static let providerRequirement = SourceIdentityWire.signer + " and identifier \"com.bragi0.SimpleVPN.PacketTunnel\""
    static let maximumBytes = 128 * 1024
    static let ownerUIDKey = "queryActivityOwnerUID"
}
