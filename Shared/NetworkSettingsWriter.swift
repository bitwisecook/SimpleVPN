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
    private enum Change {
        case base(NEPacketTunnelNetworkSettings?)
        case dns(DNSApplyRequest?)
        case routes(RouteApplyRequest)
    }

    private struct Configuration {
        var base: NEPacketTunnelNetworkSettings?
        var dns: DNSApplyRequest?
        var routes: RouteApplyRequest?
    }

    private final class Job: @unchecked Sendable {
        let change: Change
        let createdAt = DispatchTime.now()
        let completion: (Error?) -> Void
        init(_ change: Change, _ completion: @escaping (Error?) -> Void) {
            self.change = change
            self.completion = completion
        }
    }

    private final class Installation: @unchecked Sendable {
        let configuration: Configuration
        let settings: NEPacketTunnelNetworkSettings?

        init?(_ configuration: Configuration) {
            self.configuration = configuration
            let settings = configuration.base.flatMap(NetworkSettingsWriter.snapshot)
            if let dns = configuration.dns { settings?.dnsSettings = dns.makeNEDNSSettings() }
            if let routes = configuration.routes, let settings { routes.apply(to: settings) }
            if let settings, configuration.dns != nil || configuration.routes?.prefixes != nil,
               !NetworkSettingsWriter.keepResolverRoutes(in: settings, base: configuration.base) { return nil }
            self.settings = settings
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
    private var configuration = Configuration()
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
        enqueue(Job(.base(settings.flatMap(Self.snapshot)), completion))
    }

    func applyDNS(_ request: DNSApplyRequest?, completion: @escaping (Error?) -> Void) {
        enqueue(Job(.dns(request), completion))
    }

    func applyRoutes(_ request: RouteApplyRequest, completion: @escaping (Error?) -> Void) {
        enqueue(Job(.routes(request), completion))
    }

    private func enqueue(_ job: Job) {
        queue.async {
            guard !self.poisoned else { job.completion(Self.problem("Tunnel settings writer stopped.")); return }
            guard self.jobs.count < 64 else { job.completion(Self.problem("Too many pending settings updates.")); return }
            self.jobs.append(job)
            self.startNext()
        }
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
        // Compose each request with the last acknowledged configuration. A failed
        // override must not be installed by a later, unrelated engine update.
        var next = configuration
        var problem: String?
        switch job.change {
        case .base(let settings):
            if let override = next.dns, !override.isEmpty, !override.isScoped,
               Self.ownsDefault(next.base), !Self.ownsDefault(settings) {
                // A gateway demotion must also release its catch-all override.
                next.dns = nil
            }
            next.base = settings
        case .dns(let request):
            if next.base == nil { problem = "No tunnel settings to update." }
            if request?.isValid == false { problem = "Invalid DNS settings." }
            next.dns = request
        case .routes(let request):
            if next.base == nil { problem = "No tunnel settings to update." }
            if !request.isValid { problem = "Invalid route prefix." }
            next.routes = request
        }
        if let problem {
            job.completion(Self.problem(problem))
            startNext()
            return
        }
        guard let owned = Installation(next) else {
            job.completion(Self.problem("The VPN cannot route one of its DNS resolvers with these settings."))
            startNext()
            return
        }
        active = job
        install(owned.settings) { error in
            self.queue.async {
                guard self.active === job, !self.poisoned else { return }
                if error == nil {
                    self.configuration = owned.configuration
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
            out.advertisedPrefixes = Self.prefixes(self.configuration.base)
            if let dns = self.configuration.base?.dnsSettings {
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
        return !RoutePrefixMath.defaultRoutePrefixes(in: Array(routes)).isEmpty
    }

    private static func keepResolverRoutes(in settings: NEPacketTunnelNetworkSettings,
                                           base: NEPacketTunnelNetworkSettings?) -> Bool {
        guard let servers = settings.dnsSettings?.servers, !servers.isEmpty else { return true }
        let proposed = prefixes(settings)
        let original = prefixes(base)
        let excluded = prefixes(settings, excluded: true)
        for server in servers {
            guard let cidr = RoutePrefixMath.canonicalNetwork(server), let host = TailscaleNetworkSettings.parse(cidr),
                  !excluded.contains(where: { RoutePrefixMath.overlaps($0, cidr) }) else { return false }
            if proposed.contains(where: { RoutePrefixMath.overlaps($0, cidr) }) { continue }
            guard original.contains(where: { RoutePrefixMath.overlaps($0, cidr) }) else { return false }
            if host.isIPv6, let ipv6 = settings.ipv6Settings {
                var included = ipv6.includedRoutes ?? []
                included.append(NEIPv6Route(destinationAddress: host.address, networkPrefixLength: 128))
                ipv6.includedRoutes = included
                settings.ipv6Settings = ipv6
            } else if !host.isIPv6, let ipv4 = settings.ipv4Settings {
                var included = ipv4.includedRoutes ?? []
                included.append(NEIPv4Route(destinationAddress: host.address, subnetMask: host.ipv4Mask))
                ipv4.includedRoutes = included
                settings.ipv4Settings = ipv4
            } else { return false }
        }
        return true
    }

    private static func prefixes(_ settings: NEPacketTunnelNetworkSettings?, excluded: Bool = false) -> [String] {
        let ipv4 = settings?.ipv4Settings
        let ipv6 = settings?.ipv6Settings
        let v4 = ((excluded ? ipv4?.excludedRoutes : ipv4?.includedRoutes) ?? []).compactMap { route -> String? in
            var mask = in_addr()
            guard route.destinationSubnetMask.withCString({ inet_pton(AF_INET, $0, &mask) }) == 1 else { return nil }
            return "\(route.destinationAddress)/\(mask.s_addr.nonzeroBitCount)"
        }
        let v6 = ((excluded ? ipv6?.excludedRoutes : ipv6?.includedRoutes) ?? []).map {
            "\($0.destinationAddress)/\($0.destinationNetworkPrefixLength.intValue)"
        }
        return Array(Set(v4 + v6)).sorted()
    }

    private static func problem(_ message: String) -> NSError {
        NSError(domain: "com.bragi0.SimpleVPN.NetworkSettings", code: 1,
                userInfo: [NSLocalizedDescriptionKey: message])
    }
}
