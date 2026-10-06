// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import CryptoKit

/// Private credential channel. Excluded from TunnelStats and every diagnostic
/// model. The revision is acknowledged only after saving and reading it back.
nonisolated struct TailscaleNodeState: Codable, Sendable, Equatable {
    var revision: UInt64
    var data: String
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
