// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
@preconcurrency import NetworkExtension
import Darwin
import Network

/// The capture owner: exactly one NE flow, one settings writer, and scoped VPN
/// ports in Go. VPN devices cannot read or configure the host interface here.
final class VirtualRoutingEngine: @unchecked Sendable {
    /// NetworkExtension's callback is not Sendable in the SDK. Transfer it to
    /// the engine queue once; that queue owns and consumes the start reply.
    private final class StartReply: @unchecked Sendable {
        let completion: (Error?) -> Void
        init(_ completion: @escaping (Error?) -> Void) { self.completion = completion }
    }
    private final class Job: @unchecked Sendable {
        let request: VirtualRoutingMessage
        let reply: (Data?) -> Void
        init(_ request: VirtualRoutingMessage, _ reply: @escaping (Data?) -> Void) {
            self.request = request; self.reply = reply
        }
    }
    private static let callbacks = EngineCallbackRegistry<VirtualRoutingEngine>()
    private weak var provider: PacketTunnelProvider?
    private let config: VirtualRoutingConfig
    private let queue = DispatchQueue(label: "com.bragi0.SimpleVPN.virtual-routing")
    private let lock = NSLock()
    private var handle: UInt64 = 0
    private var context: UInt64 = 0
    private var stopped = false
    private var pumping = false
    private var policy: VirtualRoutingPolicy
    private var prefixes: [String: [String]] = [:]
    private var dns: [String: DNSApplyRequest] = [:]
    private var jobs: [Job] = []
    private var active: Job?
    private var since = Date().timeIntervalSince1970
    private var pathMonitor: NWPathMonitor?
    private var startReply: StartReply?
    private var starting = false
    private var began = false

    init(provider: PacketTunnelProvider, config: VirtualRoutingConfig) {
        self.provider = provider; self.config = config; policy = config.policy
        for member in config.members {
            prefixes[member.id] = member.prefixes
            dns[member.id] = member.id == config.policy.defaultOwner
                ? .init(servers: member.wireGuard.dns.filter(WireGuardConfig.isIPLiteral),
                        searchDomains: member.wireGuard.searchDomains, matchDomains: [""])
                : .init()
        }
    }

    func start(_ start: VirtualRoutingStartConfig, completion: @escaping (Error?) -> Void) {
        let reply = StartReply(completion)
        queue.async { [self] in
            guard !starting, !lock.withLock({ stopped }) else {
                reply.completion(Self.error("The virtual connection was cancelled.")); return
            }
            starting = true; startReply = reply
            let monitor = NWPathMonitor()
            pathMonitor = monitor
            monitor.pathUpdateHandler = { [weak self] path in
                guard let self else { return }
                let physical = path.availableInterfaces.first {
                    $0.type == .wifi || $0.type == .wiredEthernet || $0.type == .cellular
                }
                let index = path.status == .satisfied ? physical.map { UInt32($0.index) } ?? 0 : 0
                guard !self.lock.withLock({ self.stopped }) else { return }
                let owned = self.lock.withLock { self.handle }
                if owned != 0 {
                    if VRSetUnderlayInterface(owned, index) != 0 {
                        self.provider?.cancelTunnelWithError(Self.error("The VPN transport could not follow the physical network."))
                    }
                } else if index != 0, self.startReply != nil, !self.began {
                    self.began = true
                    var payload = start; payload.underlayInterfaceIndex = index
                    self.begin(payload) { [weak self] error in
                        self?.queue.async { [weak self] in self?.finishStart(error) }
                    }
                }
            }
            monitor.start(queue: queue)
            queue.asyncAfter(deadline: .now() + 5) { [weak self] in
                guard let self, self.startReply != nil else { return }
                self.stop(); self.finishStart(Self.error("A physical network is required for this virtual connection."))
            }
        }
    }

    private func finishStart(_ error: Error?) {
        let reply = startReply; startReply = nil
        reply?.completion(error)
    }

    private func begin(_ start: VirtualRoutingStartConfig, completion: @escaping (Error?) -> Void) {
        guard config.problem == nil,
              start.members.map(\.id) == config.members.map(\.id), start.policy == config.policy,
              zip(start.members, config.members).allSatisfy({ live, stored in
                  let expected = WireGuardStartConfig(config: stored.wireGuard, privateKey: live.wireGuard.privateKey,
                                                      presharedKey: live.wireGuard.presharedKey)
                  return live.addresses == stored.wireGuard.addresses && live.wireGuard == expected
              }),
              start.captureAddresses == VirtualRoutingConfig.captureAddresses,
              let data = try? JSONEncoder().encode(start), let text = String(data: data, encoding: .utf8) else {
            completion(Self.error("Invalid virtual connection configuration.")); return
        }
        let registered = Self.callbacks.register(self)
        let response = text.withCString { Self.take(VRCreateInstance($0, registered, Self.packetOut)) }
        let created = EngineCallbackRegistry<VirtualRoutingEngine>.handle(from: response)
        guard created != 0 else {
            Self.callbacks.remove(registered)
            completion(Self.error(Self.problem(response) ?? "The virtual connection could not start.")); return
        }
        let accepted = lock.withLock {
            guard !stopped else { return false }
            handle = created; context = registered; return true
        }
        guard accepted else {
            Self.callbacks.remove(registered); _ = Self.take(VRStopInstance(created))
            completion(Self.error("The virtual connection was cancelled.")); return
        }
        guard let status = status(), let settings = settings(policy: policy, dns: dns, status: status) else {
            stop(); completion(Self.error("The VPN endpoints could not be kept outside the virtual connection.")); return
        }
        provider?.applyNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            let run = self.lock.withLock {
                guard !self.stopped, error == nil else { return false }
                self.pumping = true; return true
            }
            if run { self.readMore() }
            else { self.stop() }
            completion(error ?? (run ? nil : Self.error("The virtual connection was cancelled.")))
        }
    }

    func stop() {
        let (owned, registered) = lock.withLock {
            stopped = true; pumping = false
            let values = (handle, context); handle = 0; context = 0; return values
        }
        queue.async { [self] in
            pathMonitor?.cancel(); pathMonitor = nil
            finishStart(Self.error("The virtual connection was stopped."))
        }
        Self.callbacks.remove(registered)
        if owned != 0 { _ = Self.take(VRStopInstance(owned)) }
        queue.async {
            self.active?.reply(Data("error:Virtual connection stopped.".utf8)); self.active = nil
            self.jobs.forEach { $0.reply(Data("error:Virtual connection stopped.".utf8)) }
            self.jobs.removeAll()
        }
    }

    private func status() -> VirtualRoutingStatus? {
        let owned = lock.withLock { stopped ? 0 : handle }
        guard owned != 0, let text = Self.take(VRStatus(owned)), let data = text.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(VirtualRoutingStatus.self, from: data)
    }

    private func settings(policy: VirtualRoutingPolicy, dns: [String: DNSApplyRequest],
                          status: VirtualRoutingStatus, prefixes: [String: [String]]? = nil) -> NEPacketTunnelNetworkSettings? {
        let owner = dns.first { !$0.value.servers.isEmpty }
        var complete = policy
        // Capture stopped members' private prefixes too. Removing an egress must
        // never turn its private traffic into an implicit physical connection.
        complete.rules = config.members.flatMap { member in
            ((prefixes ?? self.prefixes)[member.id] ?? member.prefixes)
                .filter { TailscaleNetworkSettings.parse($0)?.isDefaultRoute == false }
                .map { .init(prefix: $0, port: member.id) }
        }
        if let owner {
            complete.rules.insert(contentsOf: owner.value.servers.map {
                .init(prefix: $0 + ($0.contains(":") ? "/128" : "/32"), port: owner.key)
            }, at: 0)
        }
        return config.settings(policy: complete, endpoints: status.ports.values.map(\.endpoint).sorted(), dns: owner?.value)
    }

    private func compiled(_ candidate: VirtualRoutingPolicy, prefixes: [String: [String]],
                          dns: [String: DNSApplyRequest], activePorts: Set<String>) -> VirtualRoutingPolicy {
        var next = candidate
        next.rules = config.members.filter { activePorts.contains($0.id) }.flatMap { member in
            (prefixes[member.id] ?? member.prefixes).filter { TailscaleNetworkSettings.parse($0)?.isDefaultRoute == false }
                .map { .init(prefix: $0, port: member.id) }
        }
        if let owner = dns.first(where: { activePorts.contains($0.key) && !$0.value.servers.isEmpty }) {
            next.rules.insert(contentsOf: owner.value.servers.map {
                .init(prefix: $0 + ($0.contains(":") ? "/128" : "/32"), port: owner.key)
            }, at: 0)
        }
        return next
    }

    func message(_ request: VirtualRoutingMessage, reply: @escaping (Data?) -> Void) {
        let job = Job(request, reply)
        queue.async {
            guard self.config.members.contains(where: { $0.id == request.profile }), !self.lock.withLock({ self.stopped }) else {
                job.reply(Data("error:VPN port unavailable.".utf8)); return
            }
            if request.message == "wgstatus" {
                job.reply(self.status()?.ports[request.profile].flatMap { try? JSONEncoder().encode($0) }); return
            }
            if request.message == "stats" {
                job.reply(self.sample(request.profile).flatMap { try? JSONEncoder().encode($0) }); return
            }
            guard self.jobs.count < 64 else { job.reply(Data("error:Too many routing changes.".utf8)); return }
            self.jobs.append(job); self.next()
        }
    }

    private func next() {
        guard active == nil, !jobs.isEmpty else { return }
        let job = jobs.removeFirst(); active = job
        let request = job.request
        let owned = lock.withLock { stopped ? 0 : handle }
        guard owned != 0, let status = status(), status.ports[request.profile] != nil else {
            finish(job, "error:VPN port unavailable."); return
        }
        if request.message == "router:stop-port" {
            let result = request.profile.withCString { Self.take(VRStopPort(owned, $0)) }
            finish(job, Self.problem(result).map { "error:\($0)" } ?? "ok"); return
        }
        var candidate = policy
        var nextPrefixes = prefixes
        var nextDNS = dns
        if request.message.hasPrefix("router:apply-plan:"),
           let data = String(request.message.dropFirst("router:apply-plan:".count)).data(using: .utf8),
           let change = try? JSONDecoder().decode(VirtualRouteApplyRequest.self, from: data),
           change.owner.isEmpty || status.ports[change.owner] != nil,
           change.routes.allSatisfy({ key, value in config.members.contains(where: { $0.id == key }) && value.isValid }) {
            candidate = change.applying(to: policy)
            for (id, route) in change.routes {
                nextPrefixes[id] = route.prefixes ?? config.members.first { $0.id == id }?.prefixes
            }
            if let owner = config.members.first(where: { $0.id == candidate.defaultOwner }) {
                nextDNS = [owner.id: .init(servers: owner.wireGuard.dns.filter(WireGuardConfig.isIPLiteral),
                    searchDomains: owner.wireGuard.searchDomains, matchDomains: [""])]
            } else if !candidate.capturesDefault {
                nextDNS = [:]
            }
        } else if request.message.hasPrefix("dns:"), policy.capturesDefault, policy.defaultOwner.isEmpty {
            finish(job, "error:DNS remains captured while the default VPN is unavailable."); return
        } else if request.message == "dns:clear" {
            let member = config.members.first { $0.id == request.profile }!
            nextDNS[request.profile] = request.profile == candidate.defaultOwner ? .init(servers: member.wireGuard.dns.filter(WireGuardConfig.isIPLiteral),
                searchDomains: member.wireGuard.searchDomains, matchDomains: [""])
                : .init()
        } else if request.message.hasPrefix("dns:apply:"),
                  let data = String(request.message.dropFirst("dns:apply:".count)).data(using: .utf8),
                  let change = try? JSONDecoder().decode(DNSApplyRequest.self, from: data),
                  change.matchDomains.allSatisfy({ $0.isEmpty }), change.servers.allSatisfy(WireGuardConfig.isIPLiteral) {
            nextDNS[request.profile] = change
        } else if request.message == "proxy:clear" {
            finish(job, "ok"); return
        } else {
            finish(job, "error:This setting is unavailable in a virtual connection."); return
        }
        guard nextDNS.values.filter({ !$0.servers.isEmpty }).count <= 1 else {
            finish(job, "error:Only one DNS resolver configuration can own this virtual connection."); return
        }
        candidate.revision = policy.revision + 1
        candidate = compiled(candidate, prefixes: nextPrefixes, dns: nextDNS, activePorts: Set(status.ports.keys))
        guard let data = try? JSONEncoder().encode(candidate), let text = String(data: data, encoding: .utf8) else {
            finish(job, "error:Invalid routing policy."); return
        }
        let check = text.withCString { Self.take(VRCheckPolicy(owned, $0)) }
        guard Self.problem(check) == nil, let settings = settings(policy: candidate, dns: nextDNS, status: status, prefixes: nextPrefixes), let provider else {
            finish(job, "error:\(Self.problem(check) ?? "Invalid network settings.")"); return
        }
        let commit = candidate, savedPrefixes = nextPrefixes, savedDNS = nextDNS
        provider.applyNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            self.queue.async {
                guard self.active === job, !self.lock.withLock({ self.stopped }) else { return }
                if let error { self.finish(job, "error:\(error.localizedDescription)"); return }
                let result = text.withCString { Self.take(VRApplyPolicy(owned, $0)) }
                guard Self.problem(result) == nil else {
                    provider.cancelTunnelWithError(Self.error("Routing policy could not be committed."))
                    self.finish(job, "error:Routing policy could not be committed."); return
                }
                self.policy = commit; self.prefixes = savedPrefixes; self.dns = savedDNS
                self.finish(job, "ok")
            }
        }
    }

    private func finish(_ job: Job, _ result: String) {
        guard active === job else { return }
        active = nil; job.reply(Data(result.utf8)); next()
    }

    private func sample(_ id: String) -> TunnelStats? {
        guard let status = status(), let port = status.ports[id], let member = config.members.first(where: { $0.id == id }) else { return nil }
        var sample = TunnelStats(profile: id, timestamp: Date().timeIntervalSince1970, connectedSince: since, reconnects: 0,
            bytesIn: port.rxBytes, bytesOut: port.txBytes, serverEndpoint: port.endpoint,
            tunnelIPv4: VirtualRoutingConfig.captureAddresses[0], dnsServers: member.wireGuard.dns, proxies: [])
        sample.tunnelIPv6 = VirtualRoutingConfig.captureAddresses[1]
        sample.advertisedPrefixes = member.prefixes
        sample.searchDomains = member.wireGuard.searchDomains
        sample.effectiveDefaultOwned = policy.defaultOwner == id
        sample.defaultRouteV4 = member.wireGuard.allowedIPs.contains("0.0.0.0/0")
        sample.defaultRouteV6 = member.wireGuard.allowedIPs.contains("::/0")
        sample.settingsRevision = policy.revision
        sample.virtualRoutingSession = config.id
        sample.defaultCaptureBlocked = policy.capturesDefault && (policy.defaultOwner.isEmpty || status.ports[policy.defaultOwner] == nil)
        sample.mtu = 1280
        return sample
    }

    private func readMore() {
        guard lock.withLock({ pumping && !stopped }), let provider else { return }
        provider.packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            let owned = self.lock.withLock { self.stopped ? 0 : self.handle }
            if owned != 0 {
                for packet in packets where !packet.isEmpty && packet.count <= 65535 {
                    _ = packet.withUnsafeBytes { VRPacketIn(owned, $0.baseAddress, Int32(packet.count)) }
                }
            }
            if self.lock.withLock({ self.pumping && !self.stopped }) { self.readMore() }
        }
    }

    private static let packetOut: @convention(c) (UInt64, UnsafePointer<UInt8>?, Int32) -> Void = { context, bytes, length in
        guard length > 0, length <= 65535, let bytes, let engine = callbacks.lookup(context),
              engine.lock.withLock({ !engine.stopped }), let provider = engine.provider else { return }
        let packet = Data(bytes: bytes, count: Int(length))
        guard let version = packet.first.map({ $0 >> 4 }), version == 4 || version == 6 else { return }
        provider.packetFlow.writePackets([packet], withProtocols: [NSNumber(value: version == 6 ? AF_INET6 : AF_INET)])
    }
    private static func take(_ text: UnsafeMutablePointer<CChar>?) -> String? {
        guard let text else { return nil }; defer { VRFree(text) }; return String(cString: text)
    }
    private static func problem(_ response: String?) -> String? {
        guard let data = response?.data(using: .utf8), let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              value["ok"] as? Bool == true else {
            let data = response?.data(using: .utf8) ?? Data()
            let value = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
            return (value?["error"] as? [String: Any])?["message"] as? String ?? "The virtual connection could not apply this change."
        }
        return nil
    }
    private static func error(_ message: String) -> NSError {
        NSError(domain: "SimpleVPN.VirtualRouting", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
