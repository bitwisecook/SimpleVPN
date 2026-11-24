// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
@preconcurrency import NetworkExtension

/// The C callbacks borrow their native data. State and outbound operations run
/// on the lifecycle queue. Inbound packets pass straight to NE to preserve
/// backpressure without retaining an unbounded queue of decrypted datagrams.
final class OwnedIPsecEngine: @unchecked Sendable {
    private weak var provider: PacketTunnelProvider?
    private let policy: SVPPacketPolicy
    private let queue = DispatchQueue(label: "com.bragi0.SimpleVPN.owned-ipsec")
    private let state = NSLock()
    private var epoch: UInt64 = 0
    private var admitted = false
    private var stopped = false
    private var handle: UInt64 = 0
    private var callbacks: OwnedIPsecNativeCallbacks?
    private var reading = false
    private var gateway = ""
    private var negotiated: OwnedIPsecNetworkSettings?
    private var usesL2TP = false
    private var confirmed = false
    private var connectedAt: TimeInterval = 0
    private var ownsGateway: Bool
    private let excluded: [String]
    private let report: @Sendable (Error?) -> Void

    init(provider: PacketTunnelProvider, policy: SVPPacketPolicy, ownsGateway: Bool, excluded: [String],
         report: @escaping @Sendable (Error?) -> Void) {
        self.provider = provider
        self.policy = policy
        self.ownsGateway = ownsGateway
        self.excluded = excluded
        self.report = report
    }

    func start(_ config: OwnedIPsecConfiguration, credentials: OwnedIPsecCredentials) {
        queue.async { [self] in
            guard !self.state.withLock({ self.stopped }) else { return }
            guard let first = ProxyTunnelNetworkSettings.proxyExclusions(host: config.server).first,
                  let address = TailscaleNetworkSettings.parse(first)?.address else {
                self.fail("The IPsec gateway address could not be resolved.")
                return
            }
            self.gateway = address
            self.usesL2TP = config.usesL2TP == true
            let callbacks = OwnedIPsecNativeCallbacks(stateChanged: { [weak self] settings in
                self?.stateChanged(settings)
            }, receive: { [weak self] bytes, count in
                self?.receive(bytes, count: count)
            })
            self.callbacks = callbacks
            self.handle = OwnedIPsecNative.start(config: config, address: address, credentials: credentials,
                                                 callbackTarget: callbacks)
            guard self.handle != 0 else { self.fail("The built-in IPsec engine could not initialize this session."); return }
            self.queue.asyncAfter(deadline: .now() + 45) { [weak self] in
                if let self, !self.confirmed, !self.state.withLock({ self.stopped }) {
                    self.fail(self.usesL2TP ? "The gateway did not finish IPsec and PPP sign-in in time." :
                                "The IPsec gateway did not establish an authenticated child security association in time.")
                }
            }
        }
    }

    private func stateChanged(_ settings: OwnedIPsecNetworkSettings?) {
        let sequence = state.withLock { epoch &+= 1; admitted = false; return epoch }
        queue.async {
            guard self.current(sequence) else { return }
            guard var settings else { self.fail("The gateway ended the session or rejected authentication."); return }
            if self.usesL2TP {
                settings.pppMTU = Int(SVL2TPMTU(self.handle))
            }
            self.negotiated = settings
            self.apply(sequence) { error in
                if let error, self.current(sequence) { self.fail(error.localizedDescription) }
            }
        }
    }

    private func current(_ sequence: UInt64) -> Bool { state.withLock { !stopped && epoch == sequence } }

    func setGateway(_ owned: Bool, completion: @escaping @Sendable (Error?) -> Void) {
        queue.async {
            self.ownsGateway = owned
            let sequence = self.state.withLock { self.epoch }
            guard self.current(sequence), self.negotiated != nil else {
                completion(OwnedIPsecNetworkSettings.error("IPsec has not negotiated its routes.")); return
            }
            self.apply(sequence, completion: completion)
        }
    }

    private func apply(_ sequence: UInt64, completion: @escaping @Sendable (Error?) -> Void) {
        guard let negotiated, let provider else { completion(CancellationError()); return }
        do {
            let settings = try negotiated.settings(gateway: gateway, excluded: excluded, ownsGateway: ownsGateway)
            provider.applyNetworkSettings(settings) { [weak self] error in
                guard let self else { completion(CancellationError()); return }
                self.queue.async {
                    guard self.current(sequence) else { completion(CancellationError()); return }
                    if error == nil {
                        self.state.withLock { self.admitted = true }
                        if !self.confirmed {
                            self.confirmed = true
                            self.connectedAt = Date().timeIntervalSince1970
                            self.report(nil)
                        }
                        self.read()
                    }
                    completion(error)
                }
            }
        } catch { completion(error) }
    }

    /// Read the core's directional counters only when the app requests telemetry.
    func stats(profile: String, completion: @escaping @Sendable (TunnelStats?) -> Void) {
        struct Counters: Decodable {
            struct Direction: Decodable { let forwardedBytes: UInt64 }
            let inbound: Direction
            let outbound: Direction
        }
        queue.async {
            guard self.confirmed, let negotiated = self.negotiated,
                  let bytes = self.policy.snapshot(), let totals = try? JSONDecoder().decode(Counters.self, from: bytes)
            else { completion(nil); return }
            let routes = TailscaleNetworkSettings.parseAll(negotiated.routes)
            let defaults = RoutePrefixMath.defaultRoutePrefixes(in: negotiated.routes)
            let v4 = negotiated.addresses.first { !$0.contains(":") }
            let v6 = negotiated.addresses.first { $0.contains(":") }
            var sample = TunnelStats(profile: profile, timestamp: Date().timeIntervalSince1970,
                                     connectedSince: self.connectedAt, reconnects: 0,
                                     bytesIn: Int64(clamping: totals.inbound.forwardedBytes),
                                     bytesOut: Int64(clamping: totals.outbound.forwardedBytes),
                                     serverEndpoint: self.gateway, tunnelIPv4: v4 ?? "",
                                     dnsServers: negotiated.dns, proxies: [])
            sample.tunnelIPv6 = v6
            sample.serverProto = "udp"
            sample.serverIP = self.gateway
            sample.defaultRouteV4 = v4 != nil && defaults.contains { !$0.contains(":") }
            sample.defaultRouteV6 = v6 != nil && defaults.contains { $0.contains(":") }
            sample.advertisedPrefixes = routes.filter { $0.isIPv6 ? v6 != nil : v4 != nil }.map { "\($0.address)/\($0.length)" }
            sample.suppressDefaultRoute = !self.ownsGateway
            completion(sample)
        }
    }

    private func read() {
        guard !reading, state.withLock({ admitted && !stopped }), let flow = provider?.packetFlow else { return }
        reading = true
        flow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            self.queue.async {
                self.reading = false
                guard self.state.withLock({ self.admitted && !self.stopped }) else { return }
                self.policy.routeOutbound(packets) { packet in
                    packet.withUnsafeBytes { buffer in
                        _ = SVIKESend(self.handle, buffer.bindMemory(to: UInt8.self).baseAddress, buffer.count)
                    }
                }
                self.read()
            }
        }
    }

    private func receive(_ bytes: UnsafePointer<UInt8>, count: Int) {
        let version = bytes.pointee >> 4
        guard (version == 4 || version == 6), state.withLock({ admitted && !stopped }),
              let packet = policy.routeInbound(Data(bytes: bytes, count: count)) else { return }
        _ = provider?.packetFlow.writePackets([packet], withProtocols: [NSNumber(value: version == 4 ? AF_INET : AF_INET6)])
    }

    private func fail(_ reason: String) {
        let reportFailure = state.withLock {
            guard !stopped else { return false }
            stopped = true; admitted = false
            return true
        }
        if reportFailure {
            close()
            report(OwnedIPsecNetworkSettings.error(reason))
        }
    }

    private func close() {
        if handle != 0 { SVIKEStop(handle); handle = 0 }
        callbacks = nil
    }

    func stop(completion: @escaping @Sendable () -> Void) {
        state.withLock { stopped = true; admitted = false; epoch &+= 1 }
        queue.async { self.close(); completion() }
    }
}
