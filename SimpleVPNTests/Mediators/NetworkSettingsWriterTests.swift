// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
@preconcurrency import NetworkExtension
import Testing
@testable import SimpleVPN

private nonisolated struct SettingsInstall: Sendable {
    let dns: [String]
    let routes: [String]
    let complete: @Sendable (Error?) -> Void
}

private nonisolated final class ControlledSettingsInstaller: @unchecked Sendable {
    let events = AsyncStream<SettingsInstall>.makeStream()
    private let lock = NSLock()
    private var active = 0
    private var maximum = 0
    var maximumConcurrent: Int { lock.withLock { maximum } }
    func install(_ settings: NETunnelNetworkSettings?, done: @escaping NetworkSettingsWriter.Completion) {
        lock.withLock { active += 1; maximum = max(maximum, active) }
        let packet = settings as? NEPacketTunnelNetworkSettings
        events.continuation.yield(SettingsInstall(dns: packet?.dnsSettings?.servers ?? [],
            routes: packet?.ipv4Settings?.includedRoutes?.map(\.destinationAddress) ?? [],
            complete: { error in
                self.lock.withLock { self.active -= 1 }
                done(error)
            }))
    }
}

@MainActor
struct NetworkSettingsWriterTests {
    private func settings() -> NEPacketTunnelNetworkSettings {
        let result = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "203.0.113.1")
        let v4 = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
        v4.includedRoutes = [.default(), NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.0.0.0")]
        v4.excludedRoutes = [NEIPv4Route(destinationAddress: "203.0.113.1", subnetMask: "255.255.255.255")]
        result.ipv4Settings = v4
        result.dnsSettings = NEDNSSettings(servers: ["10.0.0.53"])
        return result
    }

    private func sample() -> TunnelStats {
        TunnelStats(profile: "test", timestamp: 0, connectedSince: 0, reconnects: 0,
                    bytesIn: 0, bytesOut: 0, serverEndpoint: "", tunnelIPv4: "", dnsServers: [], proxies: [])
    }

    @Test func reportsOnlyAcknowledgedSettingsAndSerializesOverlappingWrites() async throws {
        let installer = ControlledSettingsInstaller()
        let writer = NetworkSettingsWriter(install: installer.install)
        var events = installer.events.stream.makeAsyncIterator()
        let first = Task { await withCheckedContinuation { continuation in
            writer.submit(settings()) { continuation.resume(returning: $0 == nil) }
        } }
        let firstApply = try #require(await events.next())
        #expect(writer.enrich(sample()).effectiveDefaultOwned == false)
        let second = Task { await withCheckedContinuation { continuation in
            writer.applyDNS(DNSApplyRequest(servers: ["10.42.0.53"], matchDomains: ["corp.example"])) {
                continuation.resume(returning: $0 == nil)
            }
        } }
        firstApply.complete(nil)
        #expect(await first.value)
        let next = try #require(await events.next())
        #expect(next.dns == ["10.42.0.53"])
        next.complete(nil)
        #expect(await second.value)
        #expect(installer.maximumConcurrent == 1)
        #expect(writer.enrich(sample()).settingsRevision == 2)
        #expect(writer.enrich(sample()).effectiveDefaultOwned == true)
        // Intent telemetry remains the unmodified engine push, not our override.
        #expect(writer.enrich(sample()).dnsServers == ["10.0.0.53"])
    }

    @Test func emptyDNSRequestSuppressesAndNilRestores() async throws {
        let installer = ControlledSettingsInstaller()
        let writer = NetworkSettingsWriter(install: installer.install)
        var events = installer.events.stream.makeAsyncIterator()
        let establish = Task { await withCheckedContinuation { continuation in
            writer.submit(settings()) { _ in continuation.resume() }
        } }
        let initial = try #require(await events.next())
        initial.complete(nil)
        await establish.value
        for (request, expected) in [(DNSApplyRequest?.some(DNSApplyRequest()), []), (nil, ["10.0.0.53"])] {
            let update = Task { await withCheckedContinuation { continuation in
                writer.applyDNS(request) { _ in continuation.resume() }
            } }
            let install = try #require(await events.next())
            #expect(install.dns == expected)
            install.complete(nil)
            await update.value
        }
    }

    @Test func timedOutWriteCannotStartAnotherOrPublishItsLateCompletion() async throws {
        let installer = ControlledSettingsInstaller()
        let writer = NetworkSettingsWriter(timeout: 0.02, install: installer.install)
        var events = installer.events.stream.makeAsyncIterator()
        let apply = Task { await withCheckedContinuation { continuation in
            writer.submit(settings()) { continuation.resume(returning: $0 != nil) }
        } }
        let stuck = try #require(await events.next())
        #expect(await apply.value)
        stuck.complete(nil)
        let refused = await withCheckedContinuation { continuation in
            writer.submit(settings()) { continuation.resume(returning: $0 != nil) }
        }
        #expect(refused)
        #expect(writer.enrich(sample()).settingsRevision == 0)
        #expect(writer.enrich(sample()).effectiveDefaultOwned == false)
    }

    @Test func routeOverridesPreserveDefaultAddressesAndCarrierExclusions() throws {
        let source = settings()
        RouteApplyRequest(prefixes: ["10.42.0.0/16"]).apply(to: source)
        #expect(source.ipv4Settings?.addresses == ["10.0.0.2"])
        #expect(source.ipv4Settings?.includedRoutes?.map(\.destinationAddress) == ["0.0.0.0", "10.42.0.0"])
        #expect(source.ipv4Settings?.excludedRoutes?.first?.destinationAddress == "203.0.113.1")
        #expect(!RouteApplyRequest(prefixes: ["broken/999"]).isValid)
    }

    @Test func stoppedWriterReleasesWaitersAndRejectsLateAcknowledgement() async throws {
        let installer = ControlledSettingsInstaller()
        let writer = NetworkSettingsWriter(install: installer.install)
        var events = installer.events.stream.makeAsyncIterator()
        let first = Task { await withCheckedContinuation { continuation in
            writer.submit(settings()) { continuation.resume(returning: $0 != nil) }
        } }
        let active = try #require(await events.next())
        writer.close()
        #expect(await first.value)
        active.complete(nil)
        let rejected = await withCheckedContinuation { continuation in
            writer.applyDNS(DNSApplyRequest(servers: ["10.9.0.53"])) {
                continuation.resume(returning: $0 != nil)
            }
        }
        #expect(rejected)
        #expect(writer.enrich(sample()).settingsRevision == 0)
    }

    @Test func failedInstallPreservesLastConfirmedState() async throws {
        let installer = ControlledSettingsInstaller()
        let writer = NetworkSettingsWriter(install: installer.install)
        var events = installer.events.stream.makeAsyncIterator()
        let first = Task { await withCheckedContinuation { continuation in
            writer.submit(settings()) { _ in continuation.resume() }
        } }
        let initial = try #require(await events.next())
        initial.complete(nil)
        await first.value
        let replacement = settings()
        replacement.ipv4Settings?.includedRoutes = []
        let second = Task { await withCheckedContinuation { continuation in
            writer.submit(replacement) { continuation.resume(returning: $0 != nil) }
        } }
        let rejected = try #require(await events.next())
        rejected.complete(NSError(domain: "test", code: 1))
        #expect(await second.value)
        #expect(writer.enrich(sample()).effectiveDefaultOwned == true)
        #expect(writer.enrich(sample()).settingsRevision == 1)
    }

    @Test func routeRewriteRetainsPairedHalfDefaults() {
        let source = settings()
        source.ipv4Settings?.includedRoutes = [
            NEIPv4Route(destinationAddress: "0.0.0.0", subnetMask: "128.0.0.0"),
            NEIPv4Route(destinationAddress: "128.0.0.0", subnetMask: "128.0.0.0"),
            NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.0.0.0")]
        RouteApplyRequest(prefixes: []).apply(to: source)
        #expect(source.ipv4Settings?.includedRoutes?.map(\.destinationAddress) == ["0.0.0.0", "128.0.0.0"])
    }
}
