// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Network

/// Owns one node identity and one callback TUN. Only the parent virtual router
/// can deliver its inner packets to macOS. The node's control, DERP and UDP
/// carriers use the physical interface selected for this composition.
final class VirtualTailscalePort: VirtualChildPacketPort, TailscaleEngineDelegate, @unchecked Sendable {
    private let profileID: String
    private let config: TailscaleConfig
    private let index: UInt32
    private let received: @Sendable (Data) -> Void
    private let lost: @Sendable (Error) -> Void
    private let queue = DispatchQueue(label: "com.bragi0.SimpleVPN.tailscale-member")
    private let lock = NSLock()
    private var node: TailscaleEngine?
    private var active = false
    private var revision: UInt64 = 0
    private var stopped = false
    private var options: [String: Data]?
    // Only the serial queue coordinates readiness and settings revisions.
    private var completion: (@Sendable (Result<VirtualPortNegotiation, Error>) -> Void)?
    private var running = false
    private var negotiated: TailscaleTunnelConfig?
    private var accepted: TailscaleTunnelConfig?
    private var acceptedExitNodeID: String?
    private var exitStatusDeadline: ContinuousClock.Instant?
    private var exitStatusRetryEpoch: UInt64?
    private var exitStatusRetryScheduled = false

    init(profileID: String, config: TailscaleConfig, options: [String: Data], interfaceIndex: UInt32,
         received: @escaping @Sendable (Data) -> Void, failed: @escaping @Sendable (Error) -> Void) {
        self.profileID = profileID
        self.config = config
        self.options = options
        self.index = interfaceIndex
        self.received = received
        lost = failed
    }

    func start(completion: @escaping @Sendable (Result<VirtualPortNegotiation, Error>) -> Void) {
        queue.async { [self] in
            guard !self.lock.withLock({ self.stopped }), let options = self.options,
                  options["broker"] == Data([1]), self.index != 0 else {
                completion(.failure(Self.issue("The Tailscale member needs its Keychain broker and a physical interface.")))
                return
            }
            self.options = nil
            self.completion = completion
            let node = TailscaleEngine(delegate: self, received: { [weak self] packet in
                guard let self, self.lock.withLock({ self.active && !self.stopped }) else { return }
                self.received(packet)
            }, negotiated: { [weak self] map in self?.update(map) })
            self.lock.withLock { self.node = node }
            var request = TailscaleStartConfig(config: self.config,
                authKey: options["authKey"].flatMap { String(data: $0, encoding: .utf8) } ?? "",
                stateDir: PacketTunnelProvider.tailscaleStateDir(profile: self.profileID))
            request.underlayInterfaceIndex = self.index
            if let snapshot = options["nodeState"] {
                guard let state = String(data: snapshot, encoding: .utf8), TailscaleNodeState(revision: 0, data: state).isValid else {
                    self.fail(Self.issue("The member's saved Tailscale identity is invalid."))
                    return
                }
                request.nodeState = state
            }
            node.start(config: request) { [weak self] error in
                if let error { self?.reportFailure(error) }
            }
        }
    }

    // Fence traffic on the callback thread and enqueue in the same order that
    // updates acquired the lock. An older queued callback cannot reopen the port.
    private func transition(_ work: @escaping @Sendable (UInt64) -> Void) {
        lock.withLock {
            guard !stopped else { return }
            revision &+= 1
            active = false
            let epoch = revision
            queue.async { work(epoch) }
        }
    }
    private func update(_ map: TailscaleTunnelConfig) {
        transition { epoch in
            guard !self.lock.withLock({ self.stopped }) else { return }
            if let previous = self.accepted, previous != map {
                self.fail(Self.issue("The tailnet's routes or DNS changed. Reconnect this virtual connection."))
                return
            }
            self.negotiated = map
            self.checkReady(epoch)
        }
    }

    private func checkReady(_ epoch: UInt64) {
        guard running, let map = negotiated, !map.localAddrs.isEmpty else { return }
        guard map.localRoutes.isEmpty, map.subnetRoutes.isEmpty else {
            fail(Self.issue("This tailnet requests local exclusions or subnet advertisement. Use compatible member settings."))
            return
        }
        var exitNodeID: String?
        let hasDefault = map.carriesDefaultRoute
        if hasDefault && !config.useExitNode {
            fail(Self.issue("This tailnet supplied an internet exit that was not selected for this member."))
            return
        }
        if config.useExitNode {
            guard hasDefault, let node = lock.withLock({ self.node }) else {
                waitForExitStatus(epoch)
                return
            }
            let status = node.status()
            guard status.backendState == .running, !status.exitNodeID.isEmpty,
                  status.exitNodes.contains(where: { $0.id == status.exitNodeID && $0.active && matchesConfiguredExit($0) }) else {
                waitForExitStatus(epoch)
                return
            }
            exitNodeID = status.exitNodeID
        }
        guard !map.routes.isEmpty else { return }
        if accepted != nil && acceptedExitNodeID != exitNodeID {
            fail(Self.issue("The active exit node changed. Reconnect this virtual connection."))
            return
        }
        let settings = VirtualPortNegotiation(addresses: map.localAddrs, allowed: map.routes,
            endpoints: [], dns: map.dns.nameservers, searchDomains: map.dns.searchDomains,
            mtu: map.mtu, exitNodeID: exitNodeID, matchDomains: map.dns.matchDomains)
        exitStatusRetryEpoch = nil
        exitStatusDeadline = nil
        accepted = map
        acceptedExitNodeID = exitNodeID
        guard lock.withLock({ if stopped || epoch != revision { return false }; active = true; return true }) else { return }
        let reply = completion
        completion = nil
        reply?(.success(settings))
    }

    private func matchesConfiguredExit(_ peer: TailscalePeer) -> Bool {
        let requested = config.exitNode.trimmingCharacters(in: .whitespacesAndNewlines)
        if let address = IPv4Address(requested) {
            return peer.ips.contains { IPv4Address($0) == address }
        }
        if let address = IPv6Address(requested) {
            return peer.ips.contains { IPv6Address($0) == address }
        }
        return peer.id == requested
    }

    private func waitForExitStatus(_ epoch: UInt64) {
        // The route callback and the engine's peer status can converge on
        // different turns. Retry only during initial negotiation and never
        // acknowledge a route without peer identity evidence.
        let now = ContinuousClock.now
        let deadline = exitStatusDeadline ?? (now + .seconds(10))
        guard accepted == nil, now < deadline else {
            fail(Self.issue("The selected exit node did not supply a usable internet route."))
            return
        }
        exitStatusDeadline = deadline
        exitStatusRetryEpoch = epoch
        guard !exitStatusRetryScheduled else { return }
        exitStatusRetryScheduled = true
        queue.asyncAfter(deadline: .now() + .milliseconds(250)) { [weak self] in
            guard let self else { return }
            self.exitStatusRetryScheduled = false
            guard let epoch = self.exitStatusRetryEpoch,
                  self.lock.withLock({ !self.stopped && self.revision == epoch }) else { return }
            self.checkReady(epoch)
        }
    }

    func send(_ packet: Data) -> Bool {
        let receiver = lock.withLock { active && !stopped ? node : nil }
        return receiver?.sendPacket(packet) == true
    }

    func message(_ request: String) -> Data? {
        guard let node = lock.withLock({ stopped ? nil : self.node }) else {
            return request.hasPrefix("tsstate") ? Data("starting".utf8) : nil
        }
        switch request {
        case "tsstate": return node.nodeStateReply(after: nil)
        case "tsstatus": return try? JSONEncoder().encode(node.status())
        case "tsauth": return Data(node.authURL().utf8)
        default:
            let ack = request.hasPrefix("tsstate:ack:")
            let prefix = ack ? "tsstate:ack:" : "tsstate:since:"
            guard request.hasPrefix(prefix), let cursor = TailscaleNodeState.Cursor.parse(request.dropFirst(prefix.count)),
                  cursor.generation != nil else { return nil }
            return ack ? Data((node.acknowledgeNodeState(cursor) ? "ok" : "error").utf8) : node.nodeStateReply(after: cursor)
        }
    }

    func tailscaleEngine(_ engine: TailscaleEngine, didChange state: TailscaleBackendState, event: TailscaleStateEvent) {
        transition { epoch in
            guard !self.lock.withLock({ self.stopped }) else { return }
            self.running = state == .running
            if !self.running, self.accepted != nil {
                self.fail(Self.issue("The Tailscale member lost its authenticated connection."))
            } else { self.checkReady(epoch) }
        }
    }

    func tailscaleEngine(_ engine: TailscaleEngine, needsSignIn url: String) {}
    func tailscaleEngine(_ engine: TailscaleEngine, didLog line: String) {}
    func tailscaleEngine(_ engine: TailscaleEngine, didFailWithError error: Error) { reportFailure(error) }

    private func reportFailure(_ error: Error) {
        transition { _ in self.fail(error) }
    }
    private func fail(_ error: Error) {
        guard lock.withLock({ if stopped { return false }; active = false; stopped = true; return true }) else { return }
        let node = lock.withLock { let n = self.node; self.node = nil; return n }
        node?.stop()
        if let completion { self.completion = nil; completion(.failure(error)) }
        else { lost(error) }
    }
    func stop(completion: @escaping @Sendable () -> Void) {
        lock.withLock { active = false; stopped = true }
        queue.async {
            self.options = nil
            let node = self.lock.withLock { let n = self.node; self.node = nil; return n }
            node?.stop()
            let reply = self.completion
            self.completion = nil
            reply?(.failure(CancellationError()))
            completion()
        }
    }

    private static func issue(_ message: String) -> NSError {
        NSError(domain: "SimpleVPN.TailscaleMember", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
