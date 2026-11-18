// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import CryptoKit
import Foundation

/// A profile can have one Keychain writer across all app installations. The
/// kernel releases the lock if its process exits. Keep the lock file in place
/// so simultaneous attempts always contend for the same inode.
@MainActor
final class TailscaleBrokerLeases {
    private let directory: URL
    private struct Holder {
        weak var lease: Installation.Lease?
    }
    private var held: [String: Holder] = [:]

    init(directory: URL = URL.applicationSupportDirectory.appending(path: "SimpleVPN/TailscaleBrokers")) {
        self.directory = directory
    }

    func current(_ id: String) -> Installation.Lease? { held[id]?.lease }

    func acquire(_ id: String) throws -> Installation.Lease {
        if let current = current(id) { return current }
        let digest = SHA256.hash(data: Data(id.utf8)).map { String(format: "%02x", $0) }.joined()
        let lease: Installation.Lease?
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
            lease = try Installation.Lease(at: directory.appending(path: digest))
        } catch { throw BrokerError.unavailable }
        guard let lease else { throw BrokerError.owned }
        held = held.filter { $0.value.lease != nil }
        held[id] = Holder(lease: lease)
        return lease
    }

    enum BrokerError: LocalizedError {
        case unavailable, owned

        nonisolated var errorDescription: String? {
            switch self {
            case .unavailable: "SimpleVPN could not open the identity lock for this VPN in Application Support."
            case .owned: "Another copy of SimpleVPN is managing this VPN. Use that copy to change the connection."
            }
        }
    }
}
