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
    private var admission: ApplicationPacketAdmission?
    private let inspectionSession = UUID().uuidString
    private var policy: VirtualRoutingPolicy
    private var prefixes: [String: [String]] = [:]
    private var negotiatedDNS: [String: [String]] = [:]
    private var dns: [String: DNSApplyRequest] = [:]
    private var jobs: [Job] = []
    private var active: Job?
    private var since = Date().timeIntervalSince1970
    private var pathMonitor: NWPathMonitor?
    private var startReply: StartReply?
    // A single point-to-point profile uses its real local addresses, including for unsolicited replies.
    private let identityPolicy: SVPPacketPolicy?
    private var identityOwnsGateway: Bool
    private let identityExclusions: [String]
    var isIdentityTunnel: Bool { identityPolicy != nil }
    private var starting = false
    private var began = false
    private var pendingStart: VirtualRoutingStartConfig?
    // The lock guards callback lookup and generation removal. Never call a child or Go while holding it.
    private var children: [UInt32: (generation: UInt64, port: any VirtualChildPacketPort)] = [:]
    private var negotiatedChildren: [String: VirtualPortNegotiation] = [:]
    private var childUnderlay: UInt32?
    private let childShutdown = DispatchGroup()
    // Accessed only by queue. Authenticated facts must arrive for every child before capture begins.
    private var negotiating: VirtualRoutingStartConfig?



    init(provider: PacketTunnelProvider, config: VirtualRoutingConfig, gatewayOwned: Bool,
         identityPolicy: SVPPacketPolicy? = nil, identityExclusions: [String] = []) {
        self.identityPolicy = identityPolicy; self.identityExclusions = identityExclusions
        self.identityOwnsGateway = gatewayOwned
        self.provider = provider; self.config = config
        policy = config.initialPolicy(gatewayOwned: gatewayOwned)
        for member in config.members {
            prefixes[member.id] = member.prefixes
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
            pendingStart = start
            monitor.pathUpdateHandler = { [weak self] path in
                guard let self else { return }
                let physical = path.availableInterfaces.first {
                    $0.type == .wifi || $0.type == .wiredEthernet || $0.type == .cellular
                }
                let index = path.status == .satisfied ? physical.map { UInt32($0.index) } ?? 0 : 0
                guard !self.lock.withLock({ self.stopped }) else { return }
                let owned = self.lock.withLock { self.handle }
                if let required = self.childUnderlay, index != required {
                    self.stop()
                    self.provider?.cancelTunnelWithError(Self.error("The physical interface changed. Reconnect the virtual connection."))
                } else if owned != 0 {
                    if VRSetUnderlayInterface(owned, index) != 0 {
                        self.provider?.cancelTunnelWithError(Self.error("The VPN transport could not follow the physical network."))
                    }
                } else if index != 0, self.startReply != nil, !self.began {
                    self.began = true
                    guard var payload = self.pendingStart else { return }
                    self.pendingStart = nil
                    payload.underlayInterfaceIndex = index
                    self.begin(payload) { [weak self] error in
                        self?.queue.async { [weak self] in self?.finishStart(error); if error != nil { self?.stop() } }
                    }
                }
            }
            monitor.start(queue: queue)
            queue.asyncAfter(deadline: .now() + 5) { [weak self] in
                guard let self, self.startReply != nil, !self.began else { return }
                self.finishStart(Self.error("A physical network is required for this virtual connection.")); self.stop()
            }
        }
    }

    private func finishStart(_ error: Error?) {
        let reply = startReply; startReply = nil
        reply?.completion(error)
    }

    private func begin(_ start: VirtualRoutingStartConfig, completion: @escaping (Error?) -> Void) {
        let tokens = start.processTokens ?? [:]
        guard config.applicationCapture?.accepts(processTokens: tokens) ?? tokens.isEmpty else {
            completion(Self.error("The selected process identities are missing or invalid.")); return
        }
        var effectiveStart = start
        effectiveStart.processTokens = nil
        effectiveStart.childOptions = nil
        guard config.problem == nil, start.version == config.wireVersion,
              Set(start.childOptions?.keys.map { $0 } ?? []) == Set(config.members.filter { $0.externalAdapter != nil }.map(\.id)),
              start.members.map(\.id) == config.members.map(\.id), start.policy == config.policy,
              zip(start.members, config.members).allSatisfy({ live, stored in
                  guard live.eventSource == stored.eventSource, live.adapter == stored.adapter,
                        live.vpnKind == stored.vpnKind, live.exitNodeID == nil else { return false }
                  if let adapter = stored.externalAdapter {
                      return live.external?.adapter == adapter && live.external?.generation == 1 && live.addresses.isEmpty &&
                          live.mtu == nil && live.allowed == nil && live.proxy == nil && live.wireGuard == nil
                  }
                  guard live.external == nil, live.mtu == nil, live.addresses == stored.addresses else { return false }
                  if let proxy = stored.proxy, let payload = live.proxy {
                      guard live.wireGuard == nil, live.allowed == stored.allowed,
                            ProxyTunnelStartConfig.authenticationProblem(config: proxy, username: payload.username, password: payload.password) == nil else { return false }
                      return payload == ProxyTunnelStartConfig(config: proxy, username: payload.username, password: payload.password)
                  }
                  guard let wg = stored.wireGuard, let payload = live.wireGuard, live.proxy == nil, live.allowed == nil else { return false }
                  var expected = WireGuardStartConfig(config: wg, privateKey: payload.privateKey, presharedKey: payload.presharedKey)
                  if wg.usesTeleport {
                      guard payload.teleport?.isValid == true else { return false }
                      expected.teleport = payload.teleport
                      expected.clientName = "SimpleVPN"
                  }
                  return payload == expected
              }),
              start.captureAddresses == VirtualRoutingConfig.captureAddresses else {
            completion(Self.error("Invalid virtual connection configuration.")); return
        }
        let externalSlots = config.members.indices.filter { config.members[$0].externalAdapter != nil }
        guard !externalSlots.isEmpty else {
            do { try prepareDNS(&effectiveStart) }
            catch { completion(error); return }
            installRouter(effectiveStart, tokens: tokens, completion: completion)
            return
        }
        let reply = StartReply(completion)
        childUnderlay = start.underlayInterfaceIndex
        negotiating = effectiveStart
        for index in externalSlots {
            let member = config.members[index]
            guard let external = start.members[index].external, let options = start.childOptions?[member.id] else {
                reply.completion(Self.error("A VPN port is missing its start configuration.")); stop(); return
            }
            let slot = UInt32(index), generation = external.generation
            let received: @Sendable (Data) -> Void = { [weak self] packet in self?.returned(packet, slot: slot, generation: generation) }
            let failed: @Sendable (Error) -> Void = { [weak self] error in self?.childFailed(error, slot: slot, generation: generation) }
            let port: any VirtualChildPacketPort
            if let ipsec = member.ownedIPsec {
                port = VirtualIPsecPort(config: ipsec, options: options, interfaceIndex: start.underlayInterfaceIndex, received: received, failed: failed)
            } else if let kind = member.openConnect {
                port = VirtualOpenConnectPort(profileID: member.id, kind: kind, options: options, interfaceIndex: start.underlayInterfaceIndex, received: received, failed: failed)
            } else if member.openVPN == true {
                port = VirtualOpenVPNPort(options: options, interfaceIndex: start.underlayInterfaceIndex, received: received, failed: failed)
            } else if let tun = member.sshTun {
                do { port = try VirtualSSHTunPort(config: tun, options: options, interfaceIndex: start.underlayInterfaceIndex, received: received, failed: failed) }
                catch { reply.completion(error); stop(); return }
            } else if let ssh = member.sshNetwork {
                do {
                    port = try VirtualSSHNetworkPort(config: ssh, options: options, interfaceIndex: start.underlayInterfaceIndex, received: received, failed: failed)
                } catch { reply.completion(error); stop(); return }
            } else if let mesh = member.tailscale {
                port = VirtualTailscalePort(profileID: member.id, config: mesh, options: options, interfaceIndex: start.underlayInterfaceIndex, received: received, failed: failed)
            } else { reply.completion(Self.error("This provider has no shared-interface driver.")); stop(); return }
            let registered = lock.withLock {
                guard !stopped else { return false }
                children[slot] = (generation, port)
                childShutdown.enter()
                return true
            }
            guard registered else { port.stop {}; return }
            port.start { [weak self] result in
                self?.queue.async { [weak self] in
                    guard let self, lock.withLock({ !stopped && children[slot]?.generation == generation }), negotiating != nil else { return }
                    do {
                        let facts = try result.get()
                        if let issue = facts.problem(physicallyBoundMesh: member.tailscale != nil) { throw Self.error(issue) }
                        let intent = member.routeIntent(advertised: facts.allowed)
                        if config.policy.defaultOwner == member.id && !intent.canOwnDefault {
                            throw Self.error("The selected full tunnel has no default route after applying its destination filters.")
                        }
                        negotiating?.members[index].addresses = facts.addresses
                        negotiating?.members[index].allowed = facts.allowed
                        negotiating?.members[index].mtu = facts.mtu
                        negotiating?.members[index].adapter = member.transportAdapter
                        negotiating?.members[index].vpnKind = member.transportKind?.rawValue
                        negotiating?.members[index].exitNodeID = facts.exitNodeID
                        negotiatedChildren[member.id] = facts
                        negotiatedDNS[member.id] = facts.dns
                        prefixes[member.id] = intent.advertisedPrefixes
                        guard negotiatedChildren.count == externalSlots.count, var payload = negotiating else { return }
                        negotiating = nil
                        if identityPolicy != nil {
                            applyIdentitySettings(gatewayOwned: identityOwnsGateway) { [weak self] error in
                                guard let self else { reply.completion(CancellationError()); return }
                                let start = lock.withLock {
                                    guard !stopped, error == nil else { return false }
                                    pumping = true; return true
                                }
                                if start { readMore() }
                                reply.completion(error ?? (start ? nil : CancellationError()))
                            }
                        } else {
                            try prepareDNS(&payload)
                            installRouter(payload, tokens: tokens, completion: reply.completion)
                        }
                    } catch { reply.completion(error); stop() }
                }
            }
        }
    }

    private func dnsRequests(for policy: VirtualRoutingPolicy, filters: [String: DNSCustomization]? = nil) -> [String: DNSApplyRequest] {
        let intents = config.members.map { member in
            let facts = negotiatedChildren[member.id]
            return config.dnsIntent(for: member, servers: negotiatedDNS[member.id], searches: facts?.searchDomains,
                                    scopes: facts?.matchDomains, filter: filters.map { $0[member.id] ?? DNSCustomization() })
        }
        let owner = policy.defaultOwner.isEmpty ? nil : policy.defaultOwner
        return DNSArbiter.plan(intents: intents, policy: .init(defaultOwner: owner)).applyRequests()
    }

    private func prepareDNS(_ start: inout VirtualRoutingStartConfig) throws {
        if config.applicationCapture == nil {
            let requests = dnsRequests(for: policy)
            if let problem = config.dnsProblem(requests, capturesDefault: policy.capturesDefault) { throw Self.error(problem) }
            dns = requests
        }
        policy = config.withMemberRoutes(policy, prefixes: prefixes, dns: dns)
        start.policy = policy
    }

    private func returned(_ packet: Data, slot: UInt32, generation: UInt64) {
        if let identityPolicy {
            guard slot == 0, lock.withLock({ pumping && !stopped && children[0]?.generation == generation }),
                  let ip = identityPolicy.routeInbound(packet), let version = ip.first.map({ $0 >> 4 }), version == 4 || version == 6 else { return }
            provider?.packetFlow.writePackets([ip], withProtocols: [NSNumber(value: version == 6 ? AF_INET6 : AF_INET)])
            return
        }
        let owned = lock.withLock { stopped || children[slot]?.generation != generation ? 0 : handle }
        guard owned != 0, !packet.isEmpty, packet.count <= 65535 else { return }
        _ = packet.withUnsafeBytes { VRPortReturn(owned, slot, generation, $0.baseAddress, Int32(packet.count)) }
    }

    private func childFailed(_ error: Error, slot: UInt32, generation: UInt64) {
        let (owned, wasRouting, child) = lock.withLock { () -> (UInt64, Bool, (any VirtualChildPacketPort)?) in
            guard !stopped, children[slot]?.generation == generation else { return (0, false, nil) }
            return (handle, pumping, children.removeValue(forKey: slot)?.port)
        }
        guard let child else { return }
        if isIdentityTunnel {
            child.stop { [childShutdown] in childShutdown.leave() }
            queue.async { [self] in finishStart(error); stop(); provider?.cancelTunnelWithError(error) }
            return
        }
        let revoked = owned != 0 && VRRevokePort(owned, slot, generation) != 0
        child.stop { [childShutdown] in childShutdown.leave() }
        // Leave the capture routes installed. Another member can continue and
        // even the last lost default must not return traffic to the physical NIC.
        if wasRouting && revoked { return }
        queue.async { [weak self] in
            guard let self else { return }
            finishStart(error)
            stop()
            provider?.cancelTunnelWithError(error)
        }
    }

    private func installRouter(_ start: VirtualRoutingStartConfig, tokens: [String: Data], completion: @escaping (Error?) -> Void) {
        guard let data = try? JSONEncoder().encode(start), let text = String(data: data, encoding: .utf8) else {
            completion(Self.error("Could not encode the negotiated member configuration.")); return
        }
        let registered = Self.callbacks.register(self)
        let response = text.withCString { Self.take(VRCreateInstanceWithPorts($0, registered, Self.packetOut, Self.portSend)) }
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
        guard let status = status() else {
            completion(Self.error("The VPN ports could not be inspected.")); return
        }
        let teleportMembers = config.members.filter { $0.wireGuard?.usesTeleport == true }
        for member in teleportMembers {
            negotiatedDNS[member.id] = status.ports[member.id]?.dns ?? []
        }
        if let capture = config.applicationCapture {
            guard let sharedDNS = config.applicationDNS(servers: negotiatedDNS, searches: negotiatedChildren.mapValues(\.searchDomains),
                                                        scopes: negotiatedChildren.compactMapValues(\.matchDomains)) else {
                completion(Self.error("The selected apps need identical DNS settings on every VPN.")); return
            }
            dns = [config.members[0].id: sharedDNS]
            admission = ApplicationPacketAdmission(queue: queue, capture: capture, tokens: tokens,
                resolve: { await SourceIdentityService.matchedRoute(auditToken: $0, candidates: $1, processTokens: tokens) },
                forward: { [weak self] packet, source, owner in
                    guard let self, let owned = self.lock.withLock({ self.stopped ? nil : self.handle }) else { return }
                    _ = packet.withUnsafeBytes { bytes in
                        (source ?? "").withCString { VRPacketInWithSource(owned, bytes.baseAddress, Int32(packet.count), $0, owner) }
                    }
                })
        } else if !teleportMembers.isEmpty {
            dns = dnsRequests(for: policy)
            if let problem = config.dnsProblem(dns, capturesDefault: policy.capturesDefault) { completion(Self.error(problem)); return }
            policy.revision += 1
            policy = config.withMemberRoutes(policy, prefixes: prefixes, dns: dns)
            guard let data = try? JSONEncoder().encode(policy), let text = String(data: data, encoding: .utf8),
                  Self.problem(text.withCString { Self.take(VRApplyPolicy(created, $0)) }) == nil else {
                completion(Self.error("The Teleport DNS routes could not be installed.")); return
            }
        }
        guard let settings = settings(policy: policy, dns: dns, status: status) else {
            completion(Self.error("The VPN endpoints could not be kept outside the virtual connection.")); return
        }
        guard let provider else { completion(CancellationError()); return }
        provider.applyNetworkSettings(settings) { [weak self] error in
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

    private func applyIdentitySettings(gatewayOwned: Bool, completion: @escaping @Sendable (Error?) -> Void) {
        guard let provider, let member = config.members.first, let tun = member.sshTun,
              let facts = negotiatedChildren[member.id], !lock.withLock({ stopped }) else { completion(CancellationError()); return }
        var ip = WireGuardConfig()
        ip.addresses = facts.addresses; ip.allowedIPs = facts.allowed
        ip.mtu = facts.mtu; ip.endpoint = tun.endpoint
        guard let settings = WireGuardNetworkSettings.settings(for: ip, resolvedEndpoint: tun.endpoint,
                suppressDefaultRoute: !gatewayOwned,
                extraExcludedRoutes: identityExclusions + [OwnedIPsecNetworkSettings.hostCIDR(tun.server)]) else {
            completion(Self.error("The SSH tunnel supplied unusable IP settings.")); return
        }
        provider.applyNetworkSettings(settings, completionHandler: completion)
    }

    func setIdentityGateway(_ owned: Bool, completion: @escaping @Sendable (Error?) -> Void) {
        queue.async { [self] in
            guard isIdentityTunnel else { completion(Self.error("This VPN has no independent gateway.")); return }
            applyIdentitySettings(gatewayOwned: owned) { error in
                self.queue.async {
                    if error == nil { self.identityOwnsGateway = owned }
                    completion(error)
                }
            }
        }
    }

    func identityStats(completion: @escaping @Sendable (TunnelStats?) -> Void) {
        struct Direction: Decodable { let forwardedBytes: UInt64 }
        struct Counts: Decodable { let inbound, outbound: Direction }
        queue.async { [self] in
            guard let tun = config.members.first?.sshTun, let facts = negotiatedChildren[config.id],
                  let bytes = identityPolicy?.snapshot(), let counts = try? JSONDecoder().decode(Counts.self, from: bytes),
                  lock.withLock({ pumping && !stopped }) else { completion(nil); return }
            let addresses = TailscaleNetworkSettings.parseAll(facts.addresses)
            let defaults = RoutePrefixMath.defaultRoutePrefixes(in: facts.allowed)
            var value = TunnelStats(profile: config.id, timestamp: Date().timeIntervalSince1970, connectedSince: since, reconnects: 0,
                                    bytesIn: Int64(clamping: counts.inbound.forwardedBytes), bytesOut: Int64(clamping: counts.outbound.forwardedBytes),
                                    serverEndpoint: tun.endpoint, tunnelIPv4: addresses.first { !$0.isIPv6 }?.address ?? "", dnsServers: [], proxies: [])
            value.tunnelIPv6 = addresses.first { $0.isIPv6 }?.address
            value.serverIP = tun.server; value.serverProto = "tcp"; value.mtu = facts.mtu
            value.defaultRouteV4 = defaults.contains { !$0.contains(":") }
            value.defaultRouteV6 = defaults.contains { $0.contains(":") }
            value.advertisedPrefixes = facts.allowed; value.suppressDefaultRoute = !identityOwnsGateway
            completion(value)
        }
    }

    func packetPolicySnapshot() -> Data? {
        if let identityPolicy { return identityPolicy.snapshot() }
        let owned = lock.withLock { stopped ? 0 : handle }
        guard owned != 0, let json = Self.take(VRPacketStats(owned)) else { return nil }
        return Data(json.utf8)
    }

    func trafficLogSnapshot() -> Data? {
        identityPolicy?.trafficLogSnapshot()
    }

    func stop(completion: @escaping @Sendable () -> Void = {}) {
        let (owned, registered, ports) = lock.withLock {
            stopped = true; pumping = false
            let values = (handle, context, children.values.map(\.port)); handle = 0; context = 0; children.removeAll(); return values
        }
        queue.async { [self] in
            pendingStart = nil; negotiating = nil
            admission?.stop(); admission = nil
            pathMonitor?.cancel(); pathMonitor = nil
            finishStart(Self.error("The virtual connection was stopped."))
        }
        Self.callbacks.remove(registered)
        for port in ports { port.stop { [childShutdown] in childShutdown.leave() } }
        if owned != 0 { _ = Self.take(VRStopInstance(owned)) }
        queue.async {
            self.active?.reply(Data("error:Virtual connection stopped.".utf8)); self.active = nil
            self.jobs.forEach { $0.reply(Data("error:Virtual connection stopped.".utf8)) }
            self.jobs.removeAll()
            self.childShutdown.notify(queue: self.queue, execute: completion)
        }
    }

    private func status() -> VirtualRoutingStatus? {
        let owned = lock.withLock { stopped ? 0 : handle }
        guard owned != 0, let text = Self.take(VRStatus(owned)), let data = text.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(VirtualRoutingStatus.self, from: data)
    }

    private func settings(policy: VirtualRoutingPolicy, dns: [String: DNSApplyRequest],
                          status: VirtualRoutingStatus) -> NEPacketTunnelNetworkSettings? {
        let owner = dns.first { !$0.value.servers.isEmpty }
        return config.settings(policy: policy, endpoints: (status.ports.compactMap { negotiatedChildren[$0.key] == nil ? $0.value.endpoint : nil } + negotiatedChildren.values.flatMap(\.endpoints)).sorted(), dns: owner?.value)
    }

    func message(_ request: VirtualRoutingMessage, reply: @escaping (Data?) -> Void) {
        let job = Job(request, reply)
        queue.async {
            guard self.config.members.contains(where: { $0.id == request.profile }), !self.lock.withLock({ self.stopped }) else {
                job.reply(Data("error:VPN port unavailable.".utf8)); return
            }
            if request.message == "packet-policy:status" {
                guard let index = self.config.members.firstIndex(where: { $0.id == request.profile }),
                      let json = Self.take(VRPortPacketStats(self.lock.withLock { self.handle }, UInt32(index))) else { job.reply(nil); return }
                job.reply(Data(json.utf8)); return
            }
            if request.message == "sshnetstatus" || request.message.hasPrefix("sshnetagent:") {
                guard let index = self.config.members.firstIndex(where: { $0.id == request.profile && $0.sshNetwork != nil }),
                      let port = self.lock.withLock({ self.children[UInt32(index)]?.port }) as? VirtualSSHNetworkPort else { job.reply(nil); return }
                port.agentMessage(request.message) { data in job.reply(data) }; return
            }
            if let index = self.config.members.firstIndex(where: { $0.id == request.profile && $0.tailscale != nil }),
               ["tsstate", "tsstatus", "tsauth"].contains(request.message) || request.message.hasPrefix("tsstate:ack:") || request.message.hasPrefix("tsstate:since:") {
                let port = self.lock.withLock { self.children[UInt32(index)]?.port }
                job.reply(port?.message(request.message)); return
            }
            if request.message.hasPrefix("router:inspect:") {
                let text = String(request.message.dropFirst("router:inspect:".count))
                let owned = self.lock.withLock { self.handle }
                guard owned != 0, text.utf8.count <= 2048, !text.utf8.contains(0),
                      let query = try? JSONDecoder().decode(RoutingInspectionRequest.self, from: Data(text.utf8)), query.isValid,
                      let raw = text.withCString({ Self.take(VRInspect(owned, $0)) }),
                      var page = try? JSONDecoder().decode(RoutingInspectionPage.self, from: Data(raw.utf8))
                else { job.reply(nil); return }
                page.sessionID = self.inspectionSession
                job.reply(try? JSONEncoder().encode(page))
                return
            }
            if request.message == "wgstatus", self.config.members.first(where: { $0.id == request.profile })?.wireGuard != nil {
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
            if let i = config.members.firstIndex(where: { $0.id == request.profile }),
               let entry = lock.withLock({ children.removeValue(forKey: UInt32(i)) }) {
                _ = VRRevokePort(owned, UInt32(i), entry.generation)
                entry.port.stop { [childShutdown] in childShutdown.leave() }
            }
            let result = request.profile.withCString { Self.take(VRStopPort(owned, $0)) }
            finish(job, Self.problem(result).map { "error:\($0)" } ?? "ok"); return
        }
        // A selected-app interface cannot participate in whole-Mac gateway,
        // resolver or proxy elections. Only member lifecycle messages apply.
        guard config.applicationCapture == nil else {
            finish(job, "error:Reconnect the app-routed composition to change its routes."); return
        }
        var candidate = policy
        var nextPrefixes = prefixes
        var nextDNS = dns
        let stoppedPorts = Set(status.ports.filter { $0.value.state == "stopped" }.keys)
        let stoppedScopes = VirtualRoutingConfig.stoppedDNSScopes(dns, stopped: stoppedPorts)
        if request.message.hasPrefix("router:apply-plan:"),
           let data = String(request.message.dropFirst("router:apply-plan:".count)).data(using: .utf8),
           let change = try? JSONDecoder().decode(VirtualRouteApplyRequest.self, from: data),
           change.owner.isEmpty || status.ports[change.owner].map({ $0.state != "stopped" }) == true,
           change.routes.allSatisfy({ key, value in config.members.contains(where: { $0.id == key }) && value.isValid }),
           change.dnsFilters?.values.allSatisfy({ $0 == $0.nativeSettings }) != false {
            candidate = change.applying(to: policy)
            for (id, route) in change.routes where status.ports[id] != nil {
                let advertised = negotiatedChildren[id]?.allowed ?? config.members.first { $0.id == id }?.allowed ?? []
                nextPrefixes[id] = route.prefixes ?? RoutePrefixMath.specificRoutes(in: advertised)
            }
            if candidate.defaultOwner != policy.defaultOwner || candidate.capturesDefault != policy.capturesDefault {
                if !candidate.capturesDefault || !candidate.defaultOwner.isEmpty {
                    nextDNS = dnsRequests(for: candidate, filters: change.dnsFilters)
                    nextDNS.merge(stoppedScopes) { _, retained in retained }
                }
            }
        } else if (request.message.hasPrefix("dns:") || request.message.hasPrefix("router:dns-plan:")),
                  policy.capturesDefault, policy.defaultOwner.isEmpty || status.ports[policy.defaultOwner]?.state == "stopped" {
            finish(job, "error:DNS remains captured while the default VPN is unavailable."); return
        } else if request.message.hasPrefix("router:dns-plan:"),
                  let change = try? JSONDecoder().decode([String: DNSApplyRequest].self, from: Data(request.message.dropFirst("router:dns-plan:".count).utf8)) {
            nextDNS = change
        } else if request.message == "dns:clear" {
            nextDNS[request.profile] = dnsRequests(for: candidate)[request.profile]
        } else if request.message.hasPrefix("dns:apply:"),
                  let data = String(request.message.dropFirst("dns:apply:".count)).data(using: .utf8),
                  let change = try? JSONDecoder().decode(DNSApplyRequest.self, from: data) {
            nextDNS[request.profile] = change
        } else if request.message == "proxy:clear" {
            finish(job, "ok"); return
        } else {
            finish(job, "error:This setting is unavailable in a virtual connection."); return
        }
        if VirtualRoutingConfig.stoppedDNSScopes(nextDNS, stopped: stoppedPorts) != stoppedScopes {
            finish(job, "error:DNS remains captured for the disconnected VPN’s private domains."); return
        }
        if let problem = config.dnsProblem(nextDNS, capturesDefault: candidate.capturesDefault) {
            finish(job, "error:\(problem)"); return
        }
        candidate.revision = policy.revision + 1
        candidate = config.withMemberRoutes(candidate, prefixes: nextPrefixes, dns: nextDNS)
        guard let data = try? JSONEncoder().encode(candidate), let text = String(data: data, encoding: .utf8) else {
            finish(job, "error:Invalid routing policy."); return
        }
        let check = text.withCString { Self.take(VRCheckPolicy(owned, $0)) }
        guard Self.problem(check) == nil, let settings = settings(policy: candidate, dns: nextDNS, status: status), let provider else {
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
                    self.stop()
                    provider.cancelTunnelWithError(Self.error("Routing policy could not be committed."))
                    return
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
            bytesIn: port.rxBytes, bytesOut: port.txBytes, serverEndpoint: negotiatedChildren[id]?.endpoints.first ?? port.endpoint,
            tunnelIPv4: VirtualRoutingConfig.captureAddresses[0], dnsServers: negotiatedDNS[id] ?? member.dns, proxies: [])
        sample.tunnelIPv6 = VirtualRoutingConfig.captureAddresses[1]
        sample.advertisedPrefixes = negotiatedChildren[id]?.allowed ?? member.allowed
        sample.searchDomains = negotiatedChildren[id]?.searchDomains ?? member.searchDomains
        sample.dnsMatchDomains = negotiatedChildren[id]?.matchDomains ?? ([""] + (sample.searchDomains ?? []))
        let defaults = RoutePrefixMath.defaultRoutePrefixes(in: negotiatedChildren[id]?.allowed ?? member.allowed)
        sample.effectiveDefaultOwned = policy.defaultOwner == id && port.state != "stopped"
        sample.defaultRouteV4 = config.applicationCapture == nil && defaults.contains { !$0.contains(":") }
        sample.defaultRouteV6 = config.applicationCapture == nil && defaults.contains { $0.contains(":") }
        sample.settingsRevision = policy.revision
        sample.virtualRoutingSession = config.id
        sample.virtualPortStopped = port.state == "stopped"
        sample.defaultCaptureBlocked = config.applicationCapture == nil && policy.capturesDefault && (policy.defaultOwner.isEmpty || status.ports[policy.defaultOwner]?.state == "stopped" || status.ports[policy.defaultOwner] == nil)
        sample.mtu = 1280
        return sample
    }

    private func readMore() {
        guard lock.withLock({ pumping && !stopped }), let provider else { return }
        if config.applicationCapture != nil {
            provider.packetFlow.readPacketObjects { [weak self] packets in
                guard let self else { return }
                self.queue.async {
                    guard self.lock.withLock({ self.pumping && !self.stopped }), let admission = self.admission else { return }
                    for packet in packets where !packet.data.isEmpty && packet.data.count <= 65535 {
                        let metadata = packet.metadata
                        admission.submit(packet.data, token: metadata?.sourceAppAuditToken,
                                         signer: metadata?.sourceAppSigningIdentifier ?? "",
                                         binary: metadata?.sourceAppUniqueIdentifier ?? Data())
                    }
                    self.readMore()
                }
            }
            return
        }
        provider.packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            if let identity = self.identityPolicy {
                guard let port = self.lock.withLock({ self.pumping && !self.stopped ? self.children[0]?.port : nil }) else { return }
                identity.routeOutbound(packets) { _ = port.send($0) }
                self.readMore()
                return
            }
            self.queue.async {
                let owned = self.lock.withLock { self.stopped ? 0 : self.handle }
                // A capture update and the matching Go policy commit straddle an
                // OS acknowledgement. Discard packets during that interval.
                if owned != 0, self.active == nil {
                    for packet in packets where !packet.isEmpty && packet.count <= 65535 {
                        _ = packet.withUnsafeBytes { VRPacketIn(owned, $0.baseAddress, Int32(packet.count)) }
                    }
                }
                self.readMore()
            }
        }
    }

    private static let portSend: @convention(c) (UInt64, UInt32, UInt64, UnsafePointer<UInt8>?, Int32) -> Int32 = { context, slot, generation, bytes, length in
        guard length > 0, length <= 65535, let bytes, let engine = callbacks.lookup(context),
              let entry = engine.lock.withLock({ engine.stopped ? nil : engine.children[slot] }),
              entry.generation == generation else { return 0 }
        return entry.port.send(Data(bytes: bytes, count: Int(length))) ? 1 : 0
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
