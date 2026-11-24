// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

/// A point-to-point SSH child with its own authenticated channel and physical
/// carrier. The parent owns the capture interface and both packet-policy gates.
final class VirtualSSHTunPort: VirtualChildPacketPort, @unchecked Sendable {
    private let config: SSHTunConfiguration
    private let index: UInt32
    private let queue = DispatchQueue(label: "com.bragi0.SimpleVPN.ssh-tun")
    private let lock = NSLock()
    private let received: @Sendable (Data) -> Void
    private let failed: @Sendable (Error) -> Void
    private var options: [String: String]
    private var session: SSHSession?
    private var started = false
    private var stopping = false
    private var pending: [Data] = []

    private static func failure(_ text: String) -> NSError {
        NSError(domain: "SimpleVPN.SSHTun", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }

    init(config: SSHTunConfiguration, options: [String: Data], interfaceIndex: UInt32,
         received: @escaping @Sendable (Data) -> Void, failed: @escaping @Sendable (Error) -> Void) throws {
        if let issue = config.problem { throw Self.failure(issue) }
        guard interfaceIndex > 0 else { throw Self.failure("The SSH tunnel requires an available physical carrier.") }
        guard options.count <= 3, options.values.allSatisfy({ $0.count <= 1024 * 1024 }) else {
            throw Self.failure("The SSH credentials exceed this connection’s limits.")
        }
        let text = options.compactMapValues { String(data: $0, encoding: .utf8) }
        let key = text["key"] ?? "", certificate = text["certificate"] ?? "", password = text["password"] ?? ""
        guard options.count == text.count, Set(text.keys).isSubset(of: ["key", "certificate", "password"]),
              text.values.allSatisfy({ !$0.utf8.contains(0) }),
              (config.authMethod != "password") == !key.isEmpty,
              (config.authMethod == "certificate") == !certificate.isEmpty,
              config.authMethod != "password" || !password.isEmpty else {
            throw Self.failure("Supply the credentials for the SSH tunnel’s selected sign-in method.")
        }
        self.config = config
        self.options = text
        index = interfaceIndex
        self.received = received
        self.failed = failed
    }

    func start(completion: @escaping @Sendable (Result<VirtualPortNegotiation, Error>) -> Void) {
        let accepted = lock.withLock {
            guard !started, !stopping else { return false }
            started = true
            return true
        }
        guard accepted else { completion(.failure(Self.failure("This point-to-point tunnel already started or stopped."))); return }
        queue.async { [self] in
            let ssh = SSHSession()
            ssh.physicalInterfaceIndex = index
            defer {
                lock.withLock { session = nil; pending.removeAll() }
                ssh.disconnect()
                options.removeAll()
            }
            do {
                try ssh.connect(toHost: config.server, port: Int32(config.port), timeout: Int32(config.timeout),
                                kexAlgorithms: config.keyExchange.isEmpty ? nil : config.keyExchange,
                                compression: config.compression)
                guard ssh.checkHostKey(withKnownHosts: nil, pin: config.pin) == .match else {
                    throw Self.failure("The server’s SSH host key differs from the verified fingerprint.")
                }
                guard !lock.withLock({ stopping }) else { throw CancellationError() }
                if config.authMethod == "password" {
                    try ssh.authPassword(forUser: config.username, password: options["password"] ?? "")
                } else {
                    try ssh.authKey(forUser: config.username, privateKeyPEM: options["key"] ?? "",
                                    certificatePEM: options["certificate"], passphrase: options["password"])
                }
                options.removeAll()
                let channel = try ssh.openTun(remoteUnit: Int32(config.network.remoteUnit ?? -1),
                                               mtu: Int32(config.network.mtu), received: received)
                ssh.enterDataMode()
                guard ssh.waitForActivity(withTimeoutMs: 0) >= 0 else { throw Self.failure("The SSH packet channel closed.") }
                guard lock.withLock({ if stopping { return false }; session = ssh; return true }) else { throw CancellationError() }
                completion(.success(.init(addresses: config.network.addresses, allowed: config.network.routes,
                                          endpoints: [config.endpoint], dns: [], searchDomains: [], mtu: config.network.mtu)))
                if !run(ssh, channel: channel) {
                    let report = lock.withLock { let active = !stopping; session = nil; return active }
                    if report { failed(Self.failure("The SSH point-to-point channel closed.")) }
                }
            } catch { completion(.failure(error)) }
        }
    }

    func send(_ packet: Data) -> Bool {
        guard !packet.isEmpty, packet.count <= config.network.mtu else { return false }
        return lock.withLock {
            guard !stopping, let session, pending.count < 256 else { return false }
            pending.append(packet)
            if pending.count == 1 { session.wakeActivityWait() }
            return true
        }
    }

    private func run(_ ssh: SSHSession, channel: SSHChannel) -> Bool {
        let clock = ContinuousClock()
        let interval = Duration.seconds(config.keepalive)
        var next = clock.now.advanced(by: interval)
        var batch: [Data] = []
        while true {
            let stop = lock.withLock { swap(&batch, &pending); return stopping }
            if stop { return true }
            for packet in batch where channel.writeTunPacket(packet) < 0 { return false }
            batch.removeAll(keepingCapacity: true)
            if channel.isEOF() { return false }
            if config.keepalive > 0, clock.now >= next {
                guard ssh.sendKeepalive() else { return false }
                next = clock.now.advanced(by: interval)
            }
            let wait: Int32
            if config.keepalive == 0 { wait = -1 }
            else {
                let remaining = clock.now.duration(to: next).components
                wait = Int32(clamping: max(1, remaining.seconds * 1000 + remaining.attoseconds / 1_000_000_000_000_000))
            }
            if ssh.waitForActivity(withTimeoutMs: wait) < 0 { return false }
        }
    }

    func stop(completion: @escaping @Sendable () -> Void) {
        lock.withLock { stopping = true; session?.wakeActivityWait() }
        queue.async(execute: completion)
    }
}
