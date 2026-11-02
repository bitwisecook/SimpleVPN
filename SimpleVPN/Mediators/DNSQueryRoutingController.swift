// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Observation
@preconcurrency import NetworkExtension

@MainActor
protocol DNSQueryRoutingBackend {
    func configure(_ policy: DNSQueryPolicy) async throws
    func observeConfiguration(_ handler: @escaping @MainActor (Bool) -> Void)
}
extension DNSQueryRoutingBackend {
    func observeConfiguration(_ handler: @escaping @MainActor (Bool) -> Void) {}
}

/// Configuration acknowledgement is deliberately not called provider liveness.
@MainActor
@Observable
final class DNSQueryRoutingController {
    private(set) var configuration = DNSQueryPolicy()
    private(set) var configured = false
    private(set) var lastError: String?
    private(set) var updating = false
    @ObservationIgnored private let backend: any DNSQueryRoutingBackend
    @ObservationIgnored private let loop = MediatorApplyLoop<DNSQueryPolicy>()
    @ObservationIgnored private var requested: DNSQueryPolicy?
    @ObservationIgnored private var externallyDisabled = false
    init(backend: (any DNSQueryRoutingBackend)? = nil) {
        self.backend = backend ?? SystemDNSQueryRoutingBackend()
        self.backend.observeConfiguration { [weak self] enabled in
            guard let self, !configuration.routes.isEmpty else { return }
            configured = enabled
            externallyDisabled = !enabled
            if !enabled { lastError = "DNS query proxy was disabled in macOS or by another app. Reapply explicitly to enable it again." }
        }
    }
    func update(_ policy: DNSQueryPolicy, force: Bool = false) {
        guard force || requested != policy else { return }
        requested = policy
        guard !externallyDisabled || policy.routes.isEmpty || force else { return }
        if force || policy.routes.isEmpty { externallyDisabled = false }
        loop.enqueue(policy, force: force) { [weak self] next, _, revision in
            guard let self else { return false }
            updating = true
            defer { updating = false }
            do {
                if let problem = next.problem { throw Self.error(problem) }
                try await backend.configure(next)
                guard loop.isCurrent(revision) else { return false }
                configuration = next; configured = !next.routes.isEmpty; lastError = nil
                return true
            } catch {
                guard loop.isCurrent(revision) else { return false }
                lastError = error.localizedDescription
                configured = false
                return false
            }
        }
    }
    func waitUntilIdle() async { await loop.waitUntilIdle() }
    static func error(_ description: String) -> NSError {
        NSError(domain: "SimpleVPN.DNSQueryRouting", code: 1,
                userInfo: [NSLocalizedDescriptionKey: description])
    }
}

@MainActor
private final class SystemDNSQueryRoutingBackend: DNSQueryRoutingBackend {
    private let providerID = "com.bragi0.SimpleVPN.PacketTunnel"
    private let ownedKey = "dns-query-routing.owned-configuration"
    private var observer: NSObjectProtocol?
    private var onConfiguration: (@MainActor (Bool) -> Void)?
    private var applying = false
    private var generation: UInt64 = 0
    func observeConfiguration(_ handler: @escaping @MainActor (Bool) -> Void) { onConfiguration = handler }
    private func startObserving() {
        guard observer == nil else { return }
        observer = NotificationCenter.default.addObserver(forName: .NEDNSProxyConfigurationDidChange, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self, !applying else { return }
                let revision = generation
                let manager = NEDNSProxyManager.shared()
                do {
                    try await manager.loadFromPreferences()
                    guard !applying, revision == generation else { return }
                    onConfiguration?(manager.isEnabled && manager.providerProtocol?.providerBundleIdentifier == providerID)
                } catch { onConfiguration?(false) }
            }
        }
    }
    isolated deinit { if let observer { NotificationCenter.default.removeObserver(observer) } }
    func configure(_ policy: DNSQueryPolicy) async throws {
        // Tests/previews must never change this Mac's DNS proxy preferences.
        let environment = ProcessInfo.processInfo.environment
        if environment["XCTestConfigurationFilePath"] != nil || environment["XCTestBundlePath"] != nil || environment["SIMPLEVPN_UI_TEST_SUPPRESS_DNS_PROXY_ACTIVATION"] == "1" {
            if !policy.routes.isEmpty { throw DNSQueryRoutingController.error("DNS proxy activation is unavailable in the test host.") }
            return
        }
        let owned = UserDefaults.standard.bool(forKey: ownedKey)
        // Hard off-by-default boundary: no NE calls, prompts or writes for normal DNS setup.
        guard owned || !policy.routes.isEmpty else { return }
        startObserving()
        applying = true
        generation &+= 1
        defer { applying = false }
        let manager = NEDNSProxyManager.shared()
        try await manager.loadFromPreferences()
        if policy.routes.isEmpty {
            if manager.providerProtocol?.providerBundleIdentifier == providerID, manager.isEnabled {
                manager.isEnabled = false
                try await manager.saveToPreferences()
            }
            UserDefaults.standard.removeObject(forKey: ownedKey)
            return
        }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(policy)
        guard data.count <= 1_048_576 else { throw DNSQueryRoutingController.error("DNS query policy is too large.") }
        if manager.isEnabled, manager.providerProtocol?.providerBundleIdentifier == providerID,
           manager.providerProtocol?.providerConfiguration?["queryPolicy"] as? Data == data { return }
        if manager.isEnabled {
            // Query policy is a startProxy option. Restart the DNS proxy, never VPN sessions.
            manager.isEnabled = false
            try await manager.saveToPreferences()
        }
        let proto = NEDNSProxyProviderProtocol()
        proto.providerBundleIdentifier = providerID
        proto.providerConfiguration = ["queryPolicy": data]
        proto.serverAddress = "DNS Query Routing"
        manager.providerProtocol = proto
        manager.localizedDescription = "SimpleVPN DNS Query Routing"
        manager.isEnabled = true
        UserDefaults.standard.set(true, forKey: ownedKey)
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        guard manager.isEnabled,
              manager.providerProtocol?.providerConfiguration?["queryPolicy"] as? Data == data else {
            throw DNSQueryRoutingController.error("DNS query configuration was not acknowledged by macOS.")
        }
    }
}
