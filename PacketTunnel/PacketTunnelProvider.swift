// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

//
//  PacketTunnelProvider.swift
//  SimpleVPN system extension — drives the OpenVPN 3 engine via OpenVPN3Bridge.
//

import NetworkExtension
import os

final class PacketTunnelProvider: NEPacketTunnelProvider, OpenVPN3BridgeDelegate, @unchecked Sendable {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN.PacketTunnel", category: "tunnel")

    // Accessed from the NE thread and the bridge's callback queue; guarded by `lock`.
    nonisolated(unsafe) private var bridge: OpenVPN3Bridge?
    nonisolated(unsafe) private var startCompletion: ((Error?) -> Void)?
    private let lock = NSLock()

    // Telemetry (M6): 1 Hz throughput/topology samples published to the App Group.
    nonisolated(unsafe) private var statsTimer: DispatchSourceTimer?
    nonisolated(unsafe) private var profileID = "default"
    nonisolated(unsafe) private var connectedSince: Double = 0
    nonisolated(unsafe) private var reconnects = 0
    private let statsQueue = DispatchQueue(label: "com.bragi0.SimpleVPN.stats")

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        let info = Bundle.main.infoDictionary
        let ver = "\(info?["CFBundleShortVersionString"] as? String ?? "?") (build \(info?["CFBundleVersion"] as? String ?? "?"))"
        Self.log.log("startTunnel — PacketTunnel v\(ver, privacy: .public)")

        let proto = protocolConfiguration as? NETunnelProviderProtocol
        let conf = proto?.providerConfiguration

        // Config comes via providerConfiguration; credentials come via the shared keychain
        // (a read-once session secret the app wrote just before starting the tunnel).
        guard let ovpn = conf?["ovpn"] as? String, !ovpn.isEmpty else {
            completionHandler(NSError(domain: "PacketTunnel", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "missing ovpn configuration"]))
            return
        }
        let profile = (conf?["profile"] as? String) ?? "default"
        lock.lock(); profileID = profile; lock.unlock()
        guard let creds = KeychainCredentialStore.takeSession(profile: profile) else {
            Self.log.error("startTunnel: no session credentials in keychain for \(profile, privacy: .public)")
            completionHandler(NSError(domain: "PacketTunnel", code: 2,
                userInfo: [NSLocalizedDescriptionKey: "no credentials available"]))
            return
        }
        let username = creds.username
        let password = creds.password

        let b = OpenVPN3Bridge(provider: self, delegate: self)
        lock.lock(); bridge = b; startCompletion = completionHandler; lock.unlock()

        do {
            try b.connect(withProfile: ovpn, username: username, password: password)
            Self.log.log("openvpn3 connect() started")
        } catch {
            Self.log.error("connect failed: \(error.localizedDescription, privacy: .public)")
            finishStart(with: error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        Self.log.log("stopTunnel reason=\(reason.rawValue)")
        stopSampling()
        lock.lock(); let b = bridge; let p = profileID; lock.unlock()
        TunnelStatsStore.clear(profile: p)
        b?.disconnect()
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // "version" → reply with this running extension's version (the app's staleness check).
        if String(data: messageData, encoding: .utf8) == "version" {
            let info = Bundle.main.infoDictionary
            let v = "v\(info?["CFBundleShortVersionString"] as? String ?? "?") (build \(info?["CFBundleVersion"] as? String ?? "?"))"
            completionHandler?(Data(v.utf8))
        } else {
            completionHandler?(nil)
        }
    }

    private func finishStart(with error: Error?) {
        lock.lock(); let done = startCompletion; startCompletion = nil; lock.unlock()
        done?(error)
    }

    // MARK: Telemetry sampling (1 Hz → App Group)

    private func startSampling() {
        statsQueue.async { [weak self] in
            guard let self else { return }
            if self.statsTimer != nil { return }   // already running (e.g. reconnect)
            let timer = DispatchSource.makeTimerSource(queue: self.statsQueue)
            timer.schedule(deadline: .now(), repeating: 1.0)
            timer.setEventHandler { [weak self] in self?.sample() }
            self.statsTimer = timer
            timer.resume()
        }
    }

    private func stopSampling() {
        statsQueue.sync {
            statsTimer?.cancel()
            statsTimer = nil
        }
    }

    private func sample() {
        lock.lock()
        let b = bridge; let p = profileID; let since = connectedSince; let rc = reconnects
        lock.unlock()
        guard let b else { return }

        var bin: Int64 = 0, bout: Int64 = 0
        b.transportBytes(in: &bin, bytesOut: &bout)
        let info = b.connectionInfo()

        let stats = TunnelStats(
            profile: p,
            timestamp: Date().timeIntervalSince1970,
            connectedSince: since,
            reconnects: rc,
            bytesIn: bin,
            bytesOut: bout,
            serverEndpoint: info["server"] as? String ?? "",
            tunnelIPv4: info["tunnelIP"] as? String ?? "",
            dnsServers: info["dns"] as? [String] ?? [],
            proxies: info["proxies"] as? [String] ?? []
        )
        TunnelStatsStore.write(stats)
    }

    // MARK: OpenVPN3BridgeDelegate (called on the bridge's callback queue)

    func bridge(_ bridge: OpenVPN3Bridge, didChange status: OVPNStatus,
                event name: String, info: String) {
        Self.log.log("event \(name, privacy: .public) \(info, privacy: .public)")
        switch status {
        case .connected:
            lock.lock()
            if connectedSince == 0 { connectedSince = Date().timeIntervalSince1970 }
            lock.unlock()
            finishStart(with: nil)
            startSampling()
        case .reconnecting:
            lock.lock(); reconnects += 1; lock.unlock()
        default:
            break
        }
    }

    func bridge(_ bridge: OpenVPN3Bridge, didFailWithError error: Error) {
        Self.log.error("engine error: \(error.localizedDescription, privacy: .public)")
        finishStart(with: error)
        cancelTunnelWithError(error)
    }

    func bridge(_ bridge: OpenVPN3Bridge, didLog line: String) {
        Self.log.debug("ovpn: \(line, privacy: .public)")
    }
}
