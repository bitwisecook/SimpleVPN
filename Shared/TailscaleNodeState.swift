// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import CryptoKit

/// Private credential channel. Excluded from TunnelStats and every diagnostic
/// model. The revision is acknowledged only after saving and reading it back.
nonisolated struct TailscaleNodeState: Codable, Sendable, Equatable {
    var revision: UInt64
    var data: String
    var generation: UUID? = nil

    struct Cursor: Sendable, Equatable {
        let revision: UInt64
        let generation: UUID?
        let legacyDigest: Data?

        var wireValue: String {
            generation.map { "\($0.uuidString):\(revision)" } ?? String(revision)
        }

        /// Previous apps acknowledge the bare UInt64. Modern requests always
        /// bind a revision to the UUID that issued it.
        static func parse(_ value: Substring) -> Cursor? {
            let parts = value.split(separator: ":", omittingEmptySubsequences: false)
            if parts.count == 1, let revision = UInt64(parts[0]) {
                return Cursor(revision: revision, generation: nil, legacyDigest: nil)
            }
            guard parts.count == 2, let generation = UUID(uuidString: String(parts[0])),
                  let revision = UInt64(parts[1]) else { return nil }
            return Cursor(revision: revision, generation: generation, legacyDigest: nil)
        }
    }

    var cursor: Cursor {
        Cursor(revision: revision, generation: generation,
               legacyDigest: generation == nil ? Data(SHA256.hash(data: Data(data.utf8))) : nil)
    }

    var acknowledgement: Data { Data("tsstate:ack:\(cursor.wireValue)".utf8) }

    static func request(after cursor: Cursor?) -> Data {
        guard let cursor, cursor.generation != nil else { return Data("tsstate".utf8) }
        return Data("tsstate:since:\(cursor.wireValue)".utf8)
    }

    enum Reply: Equatable, Sendable {
        case starting
        case unchanged
        case snapshot(TailscaleNodeState)
    }

    static func decodeReply(_ bytes: Data, after cursor: Cursor?) -> Reply? {
        if bytes == Data("starting".utf8) { return .starting }
        if let cursor, cursor.generation != nil, bytes == Data("unchanged:\(cursor.wireValue)".utf8) {
            return .unchanged
        }
        guard let state = try? JSONDecoder().decode(Self.self, from: bytes), state.isValid else { return nil }
        return .snapshot(state)
    }

    var isValid: Bool {
        guard data.utf8.count <= 1024 * 1024, let bytes = data.data(using: .utf8),
              let value = try? JSONSerialization.jsonObject(with: bytes) as? [String: String] else { return false }
        return value.values.allSatisfy { Data(base64Encoded: $0) != nil }
    }
}

nonisolated struct TailscaleLegacyNodeState: Codable, Sendable {
    var data: String
    var checksum: String
    var isValid: Bool {
        TailscaleNodeState(revision: 0, data: data).isValid && checksum == Self.checksum(Data(data.utf8))
    }
    static func checksum(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
