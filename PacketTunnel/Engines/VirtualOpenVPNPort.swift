// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
@preconcurrency import NetworkExtension

/// The client library negotiates the same profile and keys as the standalone
/// tunnel. Only this member's private datagram socket is handed to its TUN builder.
final class VirtualOpenVPNPort: NSObject, VirtualChildPacketPort, OpenVPN3BridgeDelegate, @unchecked Sendable {
    private let index: UInt32
    private let received: @Sendable (Data) -> Void
    private let failed: @Sendable (Error) -> Void
    private let queue = DispatchQueue(label: "com.bragi0.SimpleVPN.openvpn-member")
    private let lock = NSLock()
    private var active = false
    private var stopped = false
    private var bridge: OpenVPN3Bridge?
    private var options: [String: Data]?
    private var reply: (@Sendable (Result<VirtualPortNegotiation, Error>) -> Void)?

    init(options: [String: Data], interfaceIndex: UInt32, received: @escaping @Sendable (Data) -> Void,
         failed: @escaping @Sendable (Error) -> Void) {
        self.options = options
        index = interfaceIndex
        self.received = received
        self.failed = failed
    }

    func start(completion: @escaping @Sendable (Result<VirtualPortNegotiation, Error>) -> Void) {
        queue.async { [self] in
            guard !lock.withLock({ stopped }), let options else { completion(.failure(CancellationError())); return }
            self.options = nil
            reply = completion
            do {
                let profileOption = VirtualRoutingStartConfig.openVPNProfileOption
                let supported = [profileOption, "overrides", "username", "password", "proxyPassword", "privateKeyPassword", "challengeResponse"]
                guard index != 0, options.keys.allSatisfy(supported.contains) else { throw Self.error("Invalid OpenVPN member options.") }
                func string(_ key: String, limit: Int = 8192) throws -> String? {
                    guard let bytes = options[key] else { return nil }
                    guard bytes.count <= limit, !bytes.contains(0), let result = String(data: bytes, encoding: .utf8) else {
                        throw Self.error("An OpenVPN member option has an invalid length or encoding.")
                    }
                    return result
                }
                guard let profile = try string(profileOption, limit: 1_048_576), !profile.isEmpty else {
                    throw Self.error("The OpenVPN member requires its complete profile at startup.")
                }
                let overrides: OpenVPNOverrides
                if let bytes = options["overrides"] {
                    guard bytes.count <= 65536 else { throw Self.error("The OpenVPN overrides are too long.") }
                    overrides = try JSONDecoder().decode(OpenVPNOverrides.self, from: bytes)
                } else { overrides = OpenVPNOverrides() }
                guard overrides.allowLocalLanAccess != true, overrides.proxyHost == nil else {
                    throw Self.error("The selected OpenVPN local network or carrier proxy settings require an independent VPN.")
                }
                var settings = try overrides.bridgeSettings(proxyPassword: string("proxyPassword"),
                                                            privateKeyPassword: string("privateKeyPassword"))
                if let value = try string("challengeResponse"), !value.isEmpty {
                    let s = settings ?? OVPNClientSettings()
                    s.challengeResponse = value
                    settings = s
                }
                let client = OpenVPN3Bridge(interfaceIndex: index, delegate: self) { [weak self] packet in
                    guard let self, self.lock.withLock({ self.active && !self.stopped }) else { return }
                    self.received(packet)
                }
                lock.withLock { bridge = client }
                try client.connect(withProfile: profile, username: string("username") ?? "", password: string("password") ?? "",
                                   settings: settings)
                queue.asyncAfter(deadline: .now() + 45) { [weak self] in
                    guard let self, self.reply != nil else { return }
                    self.refuse(Self.error("The shared OpenVPN connection did not finish authentication in time."))
                }
            } catch { refuse(error) }
        }
    }

    func send(_ packet: Data) -> Bool {
        let client = lock.withLock { active && !stopped ? bridge : nil }
        return client?.sendMemberPacket(packet) ?? false
    }

    func stop(completion: @escaping @Sendable () -> Void) {
        lock.withLock { stopped = true; active = false }
        queue.async {
            self.options = nil
            let done = self.reply
            self.reply = nil
            done?(.failure(CancellationError()))
            let client = self.lock.withLock { self.bridge }
            if let client { client.stopMember(completion: completion) } else { completion() }
        }
    }

    func bridge(_ client: OpenVPN3Bridge, didChange status: OVPNStatus, event name: String, info: String) {
        if status == .reconnecting || status == .disconnected || status == .disconnecting {
            lock.withLock { active = false }
            queue.async { self.refuse(Self.error("The shared OpenVPN session ended. Reconnect to negotiate a fresh member.")) }
            return
        }
        guard status == .connected else { return }
        queue.async {
            guard let done = self.reply, !self.lock.withLock({ self.stopped }) else { return }
            do {
                let info = client.connectionInfo()
                guard let server = info["serverIP"] as? String, WireGuardConfig.isIPLiteral(server),
                      let text = info["serverPort"] as? String, let port = UInt16(text), port > 0,
                      (info["proxies"] as? [String])?.isEmpty == true else {
                    throw Self.error("The peer supplied an unsupported proxy or an invalid OpenVPN endpoint.")
                }
                let endpoints = [NetworkEndpoint.authority(host: server, port: Int(port))]
                let network = try VirtualPortNegotiation.authenticated(client.memberNetworkSettings(), endpointHost: server,
                    endpoints: endpoints, dns: info["dns"] as? [String] ?? [], searchDomains: info["searchDomains"] as? [String] ?? [])
                guard self.lock.withLock({ if self.stopped { return false }; self.active = true; return true }) else { return }
                self.reply = nil
                done(.success(network))
            } catch { self.refuse(error) }
        }
    }

    func bridge(_ client: OpenVPN3Bridge, didFailWithError error: Error) {
        lock.withLock { active = false }
        queue.async { self.refuse(error) }
    }
    func bridge(_ client: OpenVPN3Bridge, didLog line: String) {}

    private func refuse(_ error: Error) {
        let notify = lock.withLock { let live = !stopped; stopped = true; active = false; return live }
        guard notify else { return }
        let client = lock.withLock { bridge }
        client?.disconnect()
        if let done = reply { reply = nil; done(.failure(error)) } else { failed(error) }
    }
    private static func error(_ text: String) -> NSError {
        NSError(domain: "SimpleVPN.OpenVPNMember", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
}

extension VirtualPortNegotiation {
    /// Turn authenticated native TUN-builder output into router evidence.
    /// A split exclusion cannot simply be removed from a broader peer claim.
    static func authenticated(_ settings: NEPacketTunnelNetworkSettings, endpointHost: String, endpoints: [String],
                              dns: [String], searchDomains: [String]) throws -> Self {
        var ips: [String] = []
        var routes: [String] = []
        let invalid = NSError(domain: "SimpleVPN.VirtualPort", code: 1,
            userInfo: [NSLocalizedDescriptionKey: "The VPN supplied unsupported routes, exclusions, DNS or interface settings."])
        func net(_ address: String, _ prefix: Int, v6: Bool) throws -> String {
            var bytes = [UInt8](repeating: 0, count: v6 ? 16 : 4)
            guard (0...(bytes.count * 8)).contains(prefix), !address.utf8.contains(0),
                  address.withCString({ inet_pton(v6 ? AF_INET6 : AF_INET, $0, &bytes) }) == 1 else { throw invalid }
            return "\(RoutePrefixMath.masked(address: bytes, prefix: prefix, isV6: v6))/\(prefix)"
        }
        func prefix(_ mask: String) throws -> Int {
            var bytes = [UInt8](repeating: 0, count: 4)
            guard mask.withCString({ inet_pton(AF_INET, $0, &bytes) }) == 1,
                  let length = LocalNetworkCarveOut.prefixLength(mask: bytes, width: 4) else { throw invalid }
            return length
        }
        if let ip = settings.ipv4Settings {
            guard ip.addresses.count == ip.subnetMasks.count,
                  (ip.excludedRoutes ?? []).allSatisfy({ $0.destinationAddress == endpointHost && $0.destinationSubnetMask == "255.255.255.255" })
            else { throw invalid }
            for (address, mask) in zip(ip.addresses, ip.subnetMasks) {
                ips.append(address)
                routes.append(try net(address, prefix(mask), v6: false))
            }
            for route in ip.includedRoutes ?? [] { routes.append(try net(route.destinationAddress, prefix(route.destinationSubnetMask), v6: false)) }
        }
        if let ip = settings.ipv6Settings {
            guard ip.addresses.count == ip.networkPrefixLengths.count,
                  (ip.excludedRoutes ?? []).allSatisfy({ $0.destinationAddress == endpointHost && $0.destinationNetworkPrefixLength.intValue == 128 })
            else { throw invalid }
            for (address, length) in zip(ip.addresses, ip.networkPrefixLengths) {
                ips.append(address)
                routes.append(try net(address, length.intValue, v6: true))
            }
            for route in ip.includedRoutes ?? [] { routes.append(try net(route.destinationAddress, route.destinationNetworkPrefixLength.intValue, v6: true)) }
        }
        let allowed = Array(Set(routes)).sorted()
        let network = Self(addresses: ips, allowed: allowed, endpoints: endpoints, dns: dns,
                           searchDomains: searchDomains, mtu: settings.mtu?.intValue ?? 0)
        guard network.problem == nil, dns.allSatisfy({ resolver in
            allowed.contains { RoutePrefixMath.overlaps($0, OwnedIPsecNetworkSettings.hostCIDR(resolver)) }
        }) else { throw invalid }
        return network
    }
}
