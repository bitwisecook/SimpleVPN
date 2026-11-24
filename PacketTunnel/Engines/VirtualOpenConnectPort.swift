// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// A fresh authentication helper result binds the second TLS connection to
/// exactly its signed-in URL, public key and numeric endpoint.
final class VirtualOpenConnectPort: NSObject, VirtualChildPacketPort, OpenConnectBridgeDelegate, @unchecked Sendable {
    private let profileID: String
    private let kind: VPNKind
    private let index: UInt32
    private let received: @Sendable (Data) -> Void
    private let failed: @Sendable (Error) -> Void
    private let queue = DispatchQueue(label: "com.bragi0.SimpleVPN.openconnect-member")
    private let lock = NSLock()
    private var live = false
    private var stopped = false
    private var bridge: OpenConnectBridge?
    private var options: [String: Data]?
    private var endpointHost = ""
    private var endpointPort: UInt16 = 0
    private var reply: (@Sendable (Result<VirtualPortNegotiation, Error>) -> Void)?

    init(profileID: String, kind: VPNKind, options: [String: Data], interfaceIndex: UInt32, received: @escaping @Sendable (Data) -> Void,
         failed: @escaping @Sendable (Error) -> Void) {
        self.profileID = profileID
        self.kind = kind
        self.options = options
        self.index = interfaceIndex
        self.received = received
        self.failed = failed
    }

    func start(completion: @escaping @Sendable (Result<VirtualPortNegotiation, Error>) -> Void) {
        queue.async { [self] in
            guard !lock.withLock({ stopped }), let options else { completion(.failure(CancellationError())); return }
            self.options = nil
            reply = completion
            do {
                func plist(_ key: String) throws -> [String: Any] {
                    guard let bytes = options[key], bytes.count <= 262_144,
                          let value = try PropertyListSerialization.propertyList(from: bytes, format: nil) as? [String: Any] else {
                        throw Self.error("Invalid OpenConnect member start options.")
                    }
                    return value
                }
                let config = try plist("configuration"), session = try plist("startOptions")
                guard index != 0, options.count == 2, config["profile"] as? String == profileID,
                      config["vpnType"] as? String == kind.rawValue, let protocolName = kind.openconnectProtocol,
                      kind.supportsSharedOpenConnect, kind == .ciscoAnyConnect || config["disableDTLS"] as? Bool == true,
                      config["proxy"] == nil, config["routingRules"] == nil, config["routingIncludes"] == nil,
                      config["localLan"] as? Bool != true,
                      let cookie = session["cookie"] as? String, !cookie.isEmpty, !cookie.utf8.contains(0),
                      let pin = session["servercert"] as? String, pin.hasPrefix("pin-sha256:"),
                      let digest = Data(base64Encoded: String(pin.dropFirst("pin-sha256:".count))), digest.count == 32,
                      "pin-sha256:" + digest.base64EncodedString() == pin,
                      let url = session["connectURL"] as? String, !url.utf8.contains(0),
                      let parsed = URLComponents(string: url), parsed.scheme?.lowercased() == "https",
                      parsed.user == nil, parsed.password == nil, parsed.fragment == nil, let host = parsed.host,
                      let port = UInt16(exactly: parsed.port ?? 443), port > 0 else {
                    throw Self.error("This shared SSL VPN requires a fresh sign-in, matching profile, exact certificate and supported HTTPS gateway.")
                }
                let rawHost = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
                if let numeric = session["resolveIP"] as? String {
                    guard let named = session["resolveHost"] as? String, named.caseInsensitiveCompare(rawHost) == .orderedSame,
                          !numeric.utf8.contains(0), WireGuardConfig.isIPLiteral(numeric) else {
                        throw Self.error("The OpenConnect sign-in identified a different gateway.")
                    }
                    endpointHost = numeric
                } else {
                    guard session["resolveHost"] == nil, WireGuardConfig.isIPLiteral(rawHost) else {
                        throw Self.error("The sign-in helper did not supply a numeric OpenConnect gateway.")
                    }
                    endpointHost = rawHost
                }
                endpointPort = port
                let settings = OCClientSettings.make(configuration: config, options: session, fallbackServer: "", protocol: protocolName)
                let child = OpenConnectBridge(interfaceIndex: index, delegate: self) { [weak self] packet in
                    guard let self, self.lock.withLock({ self.live && !self.stopped }) else { return }
                    self.received(packet)
                }
                lock.withLock { bridge = child }
                try child.connect(with: settings)
                queue.asyncAfter(deadline: .now() + 45) { [weak self] in
                    guard let self, self.reply != nil else { return }
                    self.refuse(Self.error("The OpenConnect member did not negotiate its network in time."))
                }
            } catch { refuse(error) }
        }
    }

    func send(_ packet: Data) -> Bool {
        lock.withLock { live && !stopped ? bridge : nil }?.sendMemberPacket(packet) ?? false
    }

    func stop(completion: @escaping @Sendable () -> Void) {
        lock.withLock { stopped = true; live = false }
        queue.async {
            self.options = nil
            let done = self.reply
            self.reply = nil
            done?(.failure(CancellationError()))
            if let child = self.lock.withLock({ self.bridge }) { child.stopMember(completion: completion) }
            else { completion() }
        }
    }

    func ocBridge(_ child: OpenConnectBridge, didChange status: OCStatus, event name: String, info: String) {
        if status == .disconnected || status == .reconnecting {
            lock.withLock { live = false }
            queue.async { self.refuse(Self.error("The OpenConnect member lost its authenticated session.")) }
            return
        }
        guard status == .connected else { return }
        queue.async {
            guard let done = self.reply, !self.lock.withLock({ self.stopped }) else { return }
            do {
                let host = self.endpointHost, port = self.endpointPort
                let settings = child.memberNetworkSettings()
                let info = child.connectionInfo()
                let network = try VirtualPortNegotiation.authenticated(settings, endpointHost: host,
                    endpoints: [NetworkEndpoint.authority(host: host, port: Int(port))],
                    dns: info["dns"] as? [String] ?? [], searchDomains: info["searchDomains"] as? [String] ?? [])
                guard self.lock.withLock({ if self.stopped { return false }; self.live = true; return true }) else { return }
                self.reply = nil
                done(.success(network))
            } catch { self.refuse(error) }
        }
    }

    func ocBridge(_ child: OpenConnectBridge, didFailWithError error: Error) {
        lock.withLock { live = false }
        queue.async { self.refuse(error) }
    }
    func ocBridge(_ child: OpenConnectBridge, didLog line: String) {}
    private func refuse(_ error: Error) {
        let notify = lock.withLock { let active = !stopped; stopped = true; live = false; return active }
        guard notify else { return }
        lock.withLock { bridge }?.disconnect()
        if let done = reply { reply = nil; done(.failure(error)) } else { failed(error) }
    }
    private static func error(_ text: String) -> NSError {
        NSError(domain: "SimpleVPN.OpenConnectMember", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
}
