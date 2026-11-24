// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

/// tun@openssh.com negotiates the mode and remote device number. Addresses and
/// routes are configured independently on the server and must agree with these.
nonisolated struct SSHTunNetworkSettings: Codable, Equatable, Sendable {
    var addresses: [String] = []
    var routes: [String] = []
    var remoteUnit: Int?
    var mtu = 1400

    var problem: String? {
        guard (1...2).contains(addresses.count), addresses.allSatisfy({ !$0.utf8.contains(0) }) else {
            return "Enter the local tunnel address assigned by the server administrator, including its prefix length."
        }
        let parsed = addresses.compactMap(TailscaleNetworkSettings.parse)
        guard parsed.count == addresses.count, Set(parsed.map(\.isIPv6)).count == parsed.count,
              addresses.allSatisfy(VirtualRoutingConfig.usableMemberAddress) else {
            return "Enter one unicast tunnel address per IP family, with its prefix length."
        }
        guard (1...256).contains(routes.count) else { return "Enter the destination prefixes reachable through the peer." }
        if let issue = ProxyTunnelConfig.routesProblem(routes) { return issue }
        guard routes.allSatisfy({ route in
            guard !route.utf8.contains(0), let prefix = TailscaleNetworkSettings.parse(route) else { return false }
            return parsed.contains { $0.isIPv6 == prefix.isIPv6 }
        }) else { return "Each destination prefix needs a local tunnel address in the same IP family." }
        if let remoteUnit, !(0...2147483646).contains(remoteUnit) { return "Enter a valid remote tunnel unit or leave it empty for automatic selection." }
        guard (1280...9000).contains(mtu) else { return "Enter an SSH tunnel MTU between 1280 and 9000 bytes." }
        return nil
    }
}

/// Public provider configuration. Keys, certificates and passwords are passed separately.
nonisolated struct SSHTunConfiguration: Codable, Sendable, Equatable {
    var server: String
    var port: Int
    var username: String
    var pin: String
    var authMethod: String
    var keyExchange: String
    var compression: Bool
    var timeout: Int
    var keepalive: Int
    var network: SSHTunNetworkSettings
    var endpoint: String { NetworkEndpoint.authority(host: server, port: port) }

    var problem: String? {
        if let issue = network.problem { return issue }
        guard !server.utf8.contains(0), !server.contains("%"), WireGuardConfig.isIPLiteral(server),
              (1...65535).contains(port) else { return "Enter the SSH server’s numeric IP address and port." }
        guard !username.isEmpty, username.utf8.count <= 255, !username.utf8.contains(0) else { return "Enter the SSH account name." }
        guard pin.utf8.count == 64, pin.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            return "Enter the server’s verified SHA-256 host-key fingerprint in Security."
        }
        guard ["password", "key", "keychain", "certificate"].contains(authMethod) else {
            return "Choose Password, Private Key, Keychain Key or Certificate for the point-to-point tunnel."
        }
        guard (1...600).contains(timeout), (0...86400).contains(keepalive),
              !keyExchange.utf8.contains(0), keyExchange.utf8.count <= 4096 else { return "Check the SSH connection timers and key exchange settings." }
        return nil
    }
}

extension SubprocessTunnelConfig {
    nonisolated private var candidateSSHTun: SSHTunConfiguration {
        .init(server: server.trimmingCharacters(in: .whitespacesAndNewlines), port: port ?? 22,
              username: username, pin: SSHHostKeyDecision.normalize(sshPinnedHostKey ?? ""), authMethod: sshAuthMethod ?? "",
              keyExchange: sshKexAlgorithms ?? "", compression: compression, timeout: connectTimeout ?? 15,
              keepalive: serverAliveInterval, network: sshTun ?? .init())
    }

    nonisolated var sshTunProblem: String? {
        guard kind == .ssh, sshMode == .netTunnel else { return "Select SSH Point-to-Point Tunnel." }
        if useJumpHost || sshExtraOptions.contains(where: { !$0.isEmpty }) || allowLocalNetworkAccess == true {
            return "The point-to-point tunnel requires a direct SSH carrier, explicit routes and no additional OpenSSH options."
        }
        return candidateSSHTun.problem
    }

    nonisolated var sshTunConfiguration: SSHTunConfiguration? {
        sshTunProblem == nil ? candidateSSHTun : nil
    }
}
