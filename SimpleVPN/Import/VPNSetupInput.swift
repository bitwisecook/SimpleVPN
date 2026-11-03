// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Network

/// Recognition is deliberately separate from ConfigDetector's import fallback:
/// an email or an unknown file must never be presented as a known OpenVPN file.
nonisolated enum VPNSetupFormat: Sendable, Equatable {
    case openVPN, wireGuard, cisco, ssh
}

nonisolated struct VPNSetupServer: Sendable, Equatable {
    let host: String
    let port: Int?

    var address: String {
        WireGuardEndpointSelection.endpointString(host: host, port: port)
    }

    static func parse(_ value: String) -> Self? {
        var raw = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if IPv6Address(raw) != nil {
            raw = WireGuardEndpointSelection.endpointString(host: raw, port: nil)
        }
        guard !raw.isEmpty, !raw.contains(where: { $0.isWhitespace || $0.isNewline }),
              !raw.contains("@"), !raw.hasPrefix("-"),
              let components = URLComponents(string: raw.contains("://") ? raw : "//" + raw),
              let rawHost = components.host, !rawHost.isEmpty,
              components.user == nil, components.password == nil else { return nil }
        if let scheme = components.scheme,
           !["https", "http", "ssh", "tcp", "udp", "socks5", "socks5h", "openvpn", "wireguard"].contains(scheme.lowercased()) { return nil }
        let host = rawHost.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        guard !host.hasPrefix("-"), host.unicodeScalars.allSatisfy({
            CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-:_")).contains($0)
        }), components.port.map({ (1...65535).contains($0) }) ?? true else { return nil }
        return Self(host: host, port: components.port)
    }
}

nonisolated struct VPNSetupAnalysis: Sendable, Equatable {
    var format: VPNSetupFormat?
    var kind: VPNKind?
    var server: VPNSetupServer?
    var evidence = ""
    var invitation: String?
    var isTeleport = false
    var headscaleURL: String?
}

nonisolated enum VPNSetupInput {
    static let maximumBytes = 1_048_576

    static func analyse(_ text: String) -> VPNSetupAnalysis {
        let lower = text.lowercased()
        let lines = lower.components(separatedBy: .newlines).map {
            $0.trimmingCharacters(in: .whitespaces)
        }
        if lower.contains("[interface]"), lower.contains("[peer]") || lower.contains("privatekey") {
            let config = WireGuardConfig.parse(text, name: "")
            return .init(format: .wireGuard, kind: .wireGuard,
                         server: VPNSetupServer.parse(config.endpoint), evidence: "WireGuard configuration")
        }
        if lower.contains("<anyconnectprofile") || lower.contains("<serverlist") {
            return .init(format: .cisco, kind: .ciscoAnyConnect, evidence: "Cisco AnyConnect configuration")
        }
        if lower.contains("[main]"), lines.contains(where: { $0.hasPrefix("host=") }) {
            return .init(format: .cisco, kind: .ipsec, evidence: "Cisco IPsec configuration")
        }
        if lines.contains(where: { $0 == "client" || $0.hasPrefix("dev ") || $0.hasPrefix("proto ") }) {
            let remote = EndpointScanner.endpoints(in: text.replacingOccurrences(of: "\r\n", with: "\n")).first
            let server = remote.flatMap { endpoint in
                VPNSetupServer.parse(endpoint.host).map {
                    VPNSetupServer(host: $0.host, port: endpoint.port ?? $0.port)
                }
            }
            // Connection blocks belong to the OpenVPN engine parser. Recognize
            // the format here without guessing which block supplies the endpoint.
            if remote != nil || lines.contains("<connection>") {
                return .init(format: .openVPN, kind: .openVPN, server: server, evidence: "OpenVPN configuration")
            }
        }
        if lines.contains(where: { $0.hasPrefix("host ") || $0.hasPrefix("host\t") }),
           let host = SSHConfigImport.parse(text).first {
            return .init(format: .ssh, kind: .ssh,
                         server: .init(host: host.effectiveHostName, port: host.port), evidence: "SSH configuration")
        }
        let tokens = text.split { $0.isWhitespace || "<>\"'(),;".contains($0) }
        let headscaleURL = lower.contains("headscale") ? text.components(separatedBy: .newlines)
            .compactMap { line -> String? in
                guard let match = line.firstMatch(of: /(?i)^\s*(?:headscale(?: server)?(?: url)?|control (?:server|url)|server url)\s*:\s*(\S+)\s*$/) else {
                    return nil
                }
                let value = String(match.1)
                return isHeadscaleControlURL(value) ? value : nil
            }.first : nil
        if let headscaleURL {
            let key = text.firstMatch(of: /(?im)^\s*(?:pre[- ]?auth(?:entication)?|setup|auth)[ -]?key\s*:\s*([A-Za-z0-9_-]+)\s*$/)
            return .init(kind: .tailscale, evidence: "Headscale setup instructions",
                         invitation: key.map { String($0.1) }, headscaleURL: headscaleURL)
        }
        for token in tokens {
            let value = String(token).trimmingCharacters(in: CharacterSet(charactersIn: "."))
            if value.hasPrefix("https://"), TeleportSession.inviteProblem(value) == nil {
                return .init(kind: .wireGuard, evidence: "UniFi Teleport invitation",
                             invitation: value, isTeleport: true)
            }
            if value.wholeMatch(of: /tskey-auth-[A-Za-z0-9_-]+/) != nil {
                return .init(kind: .tailscale, evidence: "Tailscale setup key", invitation: value)
            }
            if let url = URLComponents(string: value), url.scheme == "https",
               url.host == "login.tailscale.com", url.user == nil, url.password == nil,
               url.port == nil, url.path.hasPrefix("/admin/invite/") {
                return .init(kind: .tailscale, evidence: "Tailscale invitation", invitation: value)
            }
        }
        // Explicit names are useful evidence in setup instructions. Port numbers
        // alone are never used as proof of a VPN type.
        let names: [(String, VPNKind)] = [
            ("wireguard", .wireGuard), ("openvpn", .openVPN), ("fortigate", .fortinet),
            ("fortinet", .fortinet), ("f5 big-ip", .f5apm), ("anyconnect", .ciscoAnyConnect),
            ("globalprotect", .globalProtect), ("pulse connect", .pulse), ("juniper", .juniper),
            ("array networks", .arrayNetworks), ("tailscale", .tailscale), ("headscale", .tailscale),
            ("ikev2", .ikev2), ("l2tp", .l2tp), ("ipsec", .ipsec), ("ssh", .ssh)
        ]
        let match = names.first { lower.contains($0.0) }
        return .init(kind: match?.1, server: firstServer(in: text),
                     evidence: match.map { "Your instructions mention \($0.1.displayName)." } ?? "")
    }

    static func isHeadscaleControlURL(_ value: String) -> Bool {
        guard let url = URLComponents(string: value),
              url.scheme == "https" || url.scheme == "http",
              let host = url.host, !host.isEmpty else { return false }
        return url.user == nil && url.password == nil && url.query == nil && url.fragment == nil
    }

    static func firstServer(in text: String) -> VPNSetupServer? {
        let lines = text.components(separatedBy: .newlines)
        let prioritised = lines.filter {
            let lower = $0.lowercased()
            return lower.contains("server") || lower.contains("address") || lower.contains("vpn.")
        } + lines
        let pattern = #"(?:[a-zA-Z][a-zA-Z0-9+.-]*://)?(?:\[[0-9a-fA-F:]+\]|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]+)(?::[0-9]{1,5})?(?:/[^\s<>\"']*)?"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
        for line in prioritised {
            let range = NSRange(line.startIndex..., in: line)
            for match in regex.matches(in: line, range: range) {
                guard let r = Range(match.range, in: line) else { continue }
                // Do not reinterpret the domain half of an email as a server.
                if r.lowerBound > line.startIndex, line[line.index(before: r.lowerBound)] == "@" { continue }
                let value = String(line[r]).trimmingCharacters(in: CharacterSet(charactersIn: ".,;()"))
                if let server = VPNSetupServer.parse(value) { return server }
            }
        }
        return nil
    }
}

struct VPNSetupSubmission {
    var name: String
    var kind: VPNKind
    var text: String
    var format: VPNSetupFormat?
    var server: VPNSetupServer?
    var sshHost: SSHConfigHost?
    var discovery: DiscoveryCandidate?
    var usesTeleport: Bool
    var invitation = ""
    var headscaleURL = ""
    var signInBrowser: BrowserSelection = .osDefault
    var startSignIn = false
}
