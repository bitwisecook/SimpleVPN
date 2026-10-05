// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
@preconcurrency import NetworkExtension
import Darwin

/// A policy override distinguishes restoring engine DNS (nil) from suppressing it
/// (an empty request). Settings objects are copied at the ingress and confined to
/// this writer's queue. Only successful completions advance observed state.
nonisolated final class NetworkSettingsWriter: @unchecked Sendable {
    typealias Completion = @Sendable (Error?) -> Void
    typealias Install = @Sendable (NETunnelNetworkSettings?, @escaping Completion) -> Void
    private final class Job: @unchecked Sendable {
        let settings: NEPacketTunnelNetworkSettings?
        let createdAt = DispatchTime.now()
        let completion: (Error?) -> Void
        init(_ settings: NEPacketTunnelNetworkSettings?, _ completion: @escaping (Error?) -> Void) {
            self.settings = settings
            self.completion = completion
        }
    }
    private let queue = DispatchQueue(label: "com.bragi0.SimpleVPN.network-settings")
    private let queueKey = DispatchSpecificKey<Bool>()
    private let install: Install
    private let fatal: Completion
    private let timeout: TimeInterval
    private var jobs: [Job] = []
    private var active: Job?
    private var poisoned = false
    private var base: NEPacketTunnelNetworkSettings?
    private var dnsOverride: DNSApplyRequest?
    private var routeOverride: RouteApplyRequest?
    private var confirmed: NEPacketTunnelNetworkSettings?
    private var revision: UInt64 = 0

    init(timeout: TimeInterval = 5, install: @escaping Install,
         fatal: @escaping Completion = { _ in }) {
        self.timeout = timeout
        self.install = install
        self.fatal = fatal
        queue.setSpecific(key: queueKey, value: true)
    }

    func submit(_ settings: NETunnelNetworkSettings?, completion: @escaping (Error?) -> Void) {
        let job = Job(settings.flatMap(Self.snapshot), completion)
        queue.async { self.enqueue(job, replaceBase: true) }
    }

    func applyDNS(_ request: DNSApplyRequest?, completion: @escaping (Error?) -> Void) {
        let job = Job(nil, completion)
        queue.async {
            guard self.canAccept(job) else { return }
            guard self.base != nil else { job.completion(Self.problem("No tunnel settings to update.")); return }
            self.dnsOverride = request
            self.enqueue(job, replaceBase: false)
        }
    }

    func applyRoutes(_ request: RouteApplyRequest, completion: @escaping (Error?) -> Void) {
        let job = Job(nil, completion)
        queue.async {
            guard self.canAccept(job) else { return }
            guard request.isValid else { job.completion(Self.problem("Invalid route prefix.")); return }
            guard self.base != nil else { job.completion(Self.problem("No tunnel settings to update.")); return }
            self.routeOverride = request
            self.enqueue(job, replaceBase: false)
        }
    }

    private func enqueue(_ job: Job, replaceBase: Bool) {
        guard canAccept(job) else { return }
        if replaceBase { base = job.settings }
        // Resolve queued requests from the latest engine snapshot and policy at
        // dispatch, so an old netmap/proxy callback cannot erase a new DNS rule.
        jobs.append(job)
        startNext()
    }

    private func canAccept(_ job: Job) -> Bool {
        guard !poisoned else { job.completion(Self.problem("Tunnel settings writer stopped.")); return false }
        guard jobs.count < 64 else { job.completion(Self.problem("Too many pending settings updates.")); return false }
        return true
    }

    /// Release bridge waits before engine teardown. A late OS completion cannot
    /// acknowledge a stopped session or advance its confirmed settings.
    func close() {
        queue.async {
            self.poisoned = true
            let active = self.active
            self.active = nil
            let waiting = self.jobs
            self.jobs.removeAll()
            self.confirmed = nil
            let error = Self.problem("Tunnel stopped during settings update.")
            active?.completion(error)
            for job in waiting { job.completion(error) }
        }
    }

    private func startNext() {
        guard active == nil, !jobs.isEmpty, !poisoned else { return }
        let job = jobs.removeFirst()
        let elapsed = Double(DispatchTime.now().uptimeNanoseconds - job.createdAt.uptimeNanoseconds) / 1_000_000_000
        guard elapsed < timeout else {
            job.completion(Self.problem("Queued tunnel settings update timed out."))
            startNext()
            return
        }
        active = job
        let settings = base.flatMap(Self.snapshot)
        if let dnsOverride { settings?.dnsSettings = dnsOverride.makeNEDNSSettings() }
        if let routeOverride, let settings { routeOverride.apply(to: settings) }
        let owned = Job(settings, { _ in }) // owns immutable settings during the OS call
        install(owned.settings) { error in
            self.queue.async {
                guard self.active === job, !self.poisoned else { return }
                if error == nil {
                    self.confirmed = owned.settings
                    self.revision += 1
                }
                self.active = nil
                job.completion(error)
                self.startNext()
            }
        }
        queue.asyncAfter(deadline: job.createdAt + timeout) {
            guard self.active === job else { return }
            // A timeout cannot cancel the OS request. Never overlap another apply
            // with it: fail the session and reject all queued writes instead.
            self.poisoned = true
            self.active = nil
            let error = Self.problem("Tunnel settings update timed out.")
            job.completion(error)
            let waiting = self.jobs
            self.jobs.removeAll()
            for next in waiting { next.completion(error) }
            self.fatal(error)
        }
    }

    func enrich(_ sample: TunnelStats) -> TunnelStats {
        let read = {
            var out = sample
            out.settingsRevision = self.revision
            out.effectiveDefaultOwned = Self.ownsDefault(self.confirmed)
            out.advertisedPrefixes = Self.prefixes(self.base)
            if let dns = self.base?.dnsSettings {
                out.dnsServers = dns.servers
                out.searchDomains = dns.searchDomains ?? []
                out.dnsMatchDomains = dns.matchDomains ?? []
            }
            return out
        }
        return DispatchQueue.getSpecific(key: queueKey) == true ? read() : queue.sync(execute: read)
    }

    private static func snapshot(_ source: NETunnelNetworkSettings) -> NEPacketTunnelNetworkSettings? {
        guard let result = source.copy() as? NEPacketTunnelNetworkSettings else { return nil }
        result.ipv4Settings = result.ipv4Settings?.copy() as? NEIPv4Settings
        result.ipv6Settings = result.ipv6Settings?.copy() as? NEIPv6Settings
        result.dnsSettings = result.dnsSettings?.copy() as? NEDNSSettings
        result.proxySettings = result.proxySettings?.copy() as? NEProxySettings
        return result
    }

    private static func ownsDefault(_ settings: NEPacketTunnelNetworkSettings?) -> Bool {
        let routes = Set(prefixes(settings))
        return routes.contains("0.0.0.0/0") || routes.contains("::/0") ||
            routes.isSuperset(of: ["0.0.0.0/1", "128.0.0.0/1"]) ||
            routes.isSuperset(of: ["::/1", "8000::/1"])
    }

    private static func prefixes(_ settings: NEPacketTunnelNetworkSettings?) -> [String] {
        let v4 = (settings?.ipv4Settings?.includedRoutes ?? []).compactMap { route -> String? in
            var mask = in_addr()
            guard route.destinationSubnetMask.withCString({ inet_pton(AF_INET, $0, &mask) }) == 1 else { return nil }
            return "\(route.destinationAddress)/\(mask.s_addr.nonzeroBitCount)"
        }
        let v6 = (settings?.ipv6Settings?.includedRoutes ?? []).map {
            "\($0.destinationAddress)/\($0.destinationNetworkPrefixLength.intValue)"
        }
        return Array(Set(v4 + v6)).sorted()
    }

    private static func problem(_ message: String) -> NSError {
        NSError(domain: "com.bragi0.SimpleVPN.NetworkSettings", code: 1,
                userInfo: [NSLocalizedDescriptionKey: message])
    }
}
