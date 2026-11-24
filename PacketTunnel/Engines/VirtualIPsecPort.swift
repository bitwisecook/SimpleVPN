// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Darwin
import Foundation
import Security

/// One isolated strongSwan process per shared IPsec member. The only packet
/// endpoints exposed to this driver are the router's generation-scoped callbacks.
final class VirtualIPsecPort: VirtualChildPacketPort, @unchecked Sendable {
    private let config: OwnedIPsecConfiguration
    private let index: UInt32
    private let received: @Sendable (Data) -> Void
    private let failed: @Sendable (Error) -> Void
    private let queue = DispatchQueue(label: "com.bragi0.SimpleVPN.ipsec-member")
    private let lock = NSLock()
    // Accessed only while holding lock. A state callback fences packets before
    // handing negotiated address and route changes to the serial queue.
    private var active: UInt64 = 0
    private var stopped = false
    private var epoch: UInt64 = 0
    // Owned by queue. The start payload is released as soon as the worker starts.
    private var options: [String: Data]?
    private var handle: UInt64 = 0
    private var callbacks: OwnedIPsecNativeCallbacks?
    private var reply: (@Sendable (Result<VirtualPortNegotiation, Error>) -> Void)?
    private var accepted: OwnedIPsecNetworkSettings?
    private var underlayMTU: Int = 0

    init(config: OwnedIPsecConfiguration, options: [String: Data], interfaceIndex: UInt32,
         received: @escaping @Sendable (Data) -> Void, failed: @escaping @Sendable (Error) -> Void) {
        self.config = config
        self.options = options
        self.index = interfaceIndex
        self.received = received
        self.failed = failed
    }

    func start(completion: @escaping @Sendable (Result<VirtualPortNegotiation, Error>) -> Void) {
        queue.async { [self] in
            guard !self.lock.withLock({ self.stopped }), let options = self.options else {
                completion(.failure(CancellationError())); return
            }
            self.options = nil
            self.reply = completion
            do {
                if let problem = self.config.problem { throw OwnedIPsecNetworkSettings.error(problem) }
                guard WireGuardConfig.isIPLiteral(self.config.server), !self.config.server.contains("%"),
                      let mtu = Self.interfaceMTU(self.index), mtu >= 1280 + 128 else {
                    throw OwnedIPsecNetworkSettings.error("A shared IPsec VPN needs a numeric gateway and a physical interface with room for encapsulation.")
                }
                self.underlayMTU = mtu
                let credentials = try OwnedIPsecCredentials(config: self.config, options: options)
                let worker = try Self.trustedWorker()
                let target = OwnedIPsecNativeCallbacks(stateChanged: { [weak self] in self?.stateChanged($0) },
                                                      receive: { [weak self] bytes, count in
                    guard let self, self.lock.withLock({ self.active != 0 && !self.stopped }) else { return }
                    self.received(Data(bytes: bytes, count: count))
                })
                self.callbacks = target
                self.handle = OwnedIPsecNative.start(config: self.config, address: self.config.server,
                                                     credentials: credentials, callbackTarget: target,
                                                     worker: .init(executable: worker, interfaceIndex: self.index))
                guard self.handle != 0 else {
                    throw OwnedIPsecNetworkSettings.error("The signed IPsec worker could not start on the selected interface.")
                }
                self.queue.asyncAfter(deadline: .now() + 45) { [weak self] in
                    guard let self, self.reply != nil else { return }
                    self.fail(OwnedIPsecNetworkSettings.error("The shared IPsec VPN did not complete authentication in time."))
                }
            } catch { self.fail(error) }
        }
    }

    private func stateChanged(_ settings: OwnedIPsecNetworkSettings?) {
        let revision = lock.withLock {
            active = 0
            epoch &+= 1
            return epoch
        }
        queue.async {
            guard !self.lock.withLock({ self.stopped }) else { return }
            guard var settings else {
                self.fail(OwnedIPsecNetworkSettings.error("The shared IPsec VPN lost its authenticated session."))
                return
            }
            guard self.lock.withLock({ self.epoch == revision }) else { return }
            do {
                if self.config.usesL2TP == true { settings.pppMTU = Int(SVWorkerMTU(self.handle)) }
                // Validate the engine's authenticated address/selector/DNS set
                // using the same checks as a standalone provider. Nothing is installed.
                _ = try settings.settings(gateway: self.config.server, excluded: [], ownsGateway: true)
                if let previous = self.accepted, previous != settings {
                    throw OwnedIPsecNetworkSettings.error("The IPsec member's negotiated network changed. Reconnect the virtual connection.")
                }
                let localFamilies = Set(settings.addresses.map { $0.contains(":") })
                let endpoint = NetworkEndpoint.authority(host: self.config.server, port: 4500)
                let network = VirtualPortNegotiation(addresses: settings.addresses,
                    allowed: settings.routes.filter { localFamilies.contains($0.contains(":")) },
                    endpoints: [endpoint], dns: settings.dns, searchDomains: [],
                    mtu: min(settings.pppMTU ?? 65535, self.underlayMTU - 128))
                if let issue = network.problem { throw OwnedIPsecNetworkSettings.error(issue) }
                guard self.lock.withLock({
                    guard !self.stopped, self.epoch == revision else { return false }
                    self.active = self.handle; return true
                }) else { return }
                self.accepted = settings
                let done = self.reply
                self.reply = nil
                done?(.success(network))
            } catch { self.fail(error) }
        }
    }

    func send(_ packet: Data) -> Bool {
        let handle = lock.withLock { active }
        guard handle != 0 else { return false }
        return packet.withUnsafeBytes { bytes in
            SVWorkerSend(handle, bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
        }
    }

    private func fail(_ error: Error) {
        let notify = lock.withLock { let live = !stopped; stopped = true; active = 0; return live }
        close()
        guard notify else { return }
        if let done = reply { reply = nil; done(.failure(error)) }
        else { failed(error) }
    }

    func stop(completion: @escaping @Sendable () -> Void) {
        lock.withLock { stopped = true; active = 0 }
        queue.async {
            self.options = nil
            self.close()
            let done = self.reply
            self.reply = nil
            done?(.failure(CancellationError()))
            completion()
        }
    }

    private func close() {
        if handle != 0 { SVWorkerStop(handle); handle = 0 }
        callbacks = nil
    }

    private static func trustedWorker() throws -> URL {
        let url = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/IPsecMemberWorker")
        let text = SourceIdentityWire.signer + " and identifier \"com.bragi0.SimpleVPN.IPsecMemberWorker\""
        var requirement: SecRequirement?
        var code: SecStaticCode?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, let requirement,
              SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else {
            throw OwnedIPsecNetworkSettings.error("The bundled IPsec worker's signature could not be verified.")
        }
        return url
    }

    private static func interfaceMTU(_ index: UInt32) -> Int? {
        guard index != 0 else { return nil }
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let head else { return nil }
        defer { freeifaddrs(head) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = head
        while let entry = cursor?.pointee {
            if entry.ifa_addr?.pointee.sa_family == sa_family_t(AF_LINK), if_nametoindex(entry.ifa_name) == index,
               let data = entry.ifa_data {
                return Int(data.assumingMemoryBound(to: if_data.self).pointee.ifi_mtu)
            }
            cursor = entry.ifa_next
        }
        return nil
    }
}
