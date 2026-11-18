// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Testing
@testable import SimpleVPN

@MainActor
struct TailscaleBrokerLeaseTests {
    @Test func independentClientsCannotManageTheSameProfileUntilTheLastWriterExits() throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let first = TailscaleBrokerLeases(directory: directory)
        let second = TailscaleBrokerLeases(directory: directory)
        // Reconnect, migration and the writer task overlap within one client.
        var migration: Installation.Lease? = try first.acquire("../first VPN")
        var broker: Installation.Lease? = try first.acquire("../first VPN")
        #expect(migration === broker)
        #expect(throws: (any Error).self) { try second.acquire("../first VPN") }

        let independent = try second.acquire("different VPN")
        defer { withExtendedLifetime(independent) {} }
        migration = nil
        #expect(broker != nil)
        #expect(throws: (any Error).self) { try second.acquire("../first VPN") }
        broker = nil
        let replacement = try second.acquire("../first VPN")
        #expect(first.current("../first VPN") == nil)
        #expect(second.current("../first VPN") === replacement)
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).count == 2)
    }
}
