// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  TunnelIncidents.swift
//  Why a tunnel failed, in a form the app can explain. The packet-tunnel
//  provider classifies OpenVPN 3 events (AUTH_FAILED, CONNECTION_TIMEOUT,
//  CERT_VERIFY_FAIL, TUN_SETUP_FAILED, …) into user-meaningful categories and
//  publishes the latest incident to the App Group; the app renders a rich
//  explanation with suggested fixes instead of a raw error string.
//

import Foundation

/// User-meaningful failure families. Raw-coded so app↔extension version skew
/// degrades to .unknown instead of failing to decode.
enum IncidentCategory: String, Codable, Sendable {
    case auth          // wrong/expired credentials, OTP, private-key password
    case dns           // couldn't resolve the server name
    case network       // no route / transport errors / send-recv failures
    case timeout       // server never answered
    case tlsIdentity   // server certificate / TLS policy failures
    case cipher        // no common cipher — legacy-algorithms territory
    case tunSetup      // macOS refused the tunnel network settings
    case conflict      // another VPN superseded/blocked this one
    case proxy         // HTTP proxy refused/failed
    case serverHalt    // server told us to go away (halt/restart)
    case unknown
}

struct TunnelIncident: Codable, Sendable, Equatable {
    var profile: String
    var timestamp: Double          // epoch seconds
    var categoryRaw: String        // IncidentCategory.rawValue (lenient)
    var event: String              // openvpn3 event name (e.g. AUTH_FAILED)
    var info: String               // engine-provided detail, may be empty
    var fatal: Bool

    var category: IncidentCategory { IncidentCategory(rawValue: categoryRaw) ?? .unknown }

    init(profile: String, category: IncidentCategory, event: String, info: String, fatal: Bool,
         timestamp: Double = Date().timeIntervalSince1970) {
        self.profile = profile
        self.timestamp = timestamp
        self.categoryRaw = category.rawValue
        self.event = event
        self.info = info
        self.fatal = fatal
    }

    /// Map an openvpn3 event name (with its info line) to a category.
    /// Event names per openvpn3 client/ovpncli event taxonomy.
    static func classify(event: String, info: String) -> IncidentCategory {
        switch event {
        case "AUTH_FAILED", "AUTH_PENDING", "DYNAMIC_CHALLENGE", "PROXY_NEED_CREDS":
            return .auth
        case "PEM_PASSWORD_FAIL", "EPKI_ERROR", "EPKI_INVALID_ALIAS":
            return .auth
        case "RESOLVE":
            return .dns
        case "CONNECTION_TIMEOUT", "INACTIVE_TIMEOUT":
            return .timeout
        case "TRANSPORT_ERROR", "NETWORK_RECV_ERROR", "NETWORK_SEND_ERROR",
             "NETWORK_EOF_ERROR", "NETWORK_UNAVAILABLE", "RELAY_ERROR":
            return .network
        case "CERT_VERIFY_FAIL", "TLS_VERSION_MIN", "TLS_ALERT_PROTOCOL_ERROR",
             "TLS_MIN_VERSION_FAILED":
            return .tlsIdentity
        case "TUN_SETUP_FAILED", "TUN_IFACE_CREATE", "TUN_IFACE_DISABLED",
             "TUN_ERROR", "TUN_HALT":
            return .tunSetup
        case "PROXY_ERROR":
            return .proxy
        case "CLIENT_HALT", "CLIENT_RESTART":
            return .serverHalt
        default:
            break
        }
        // TLS_ALERT_MISC and generic errors: sniff the info line.
        let lower = info.lowercased() + " " + event.lowercased()
        if lower.contains("cipher") || lower.contains("ncp") || lower.contains("data channel") {
            return .cipher
        }
        if lower.contains("certificate") || lower.contains("tls") || lower.contains("handshake") {
            return .tlsIdentity
        }
        if lower.contains("auth") { return .auth }
        if lower.contains("resolve") || lower.contains("dns") { return .dns }
        if lower.contains("timeout") { return .timeout }
        if lower.contains("network") || lower.contains("unreachable") || lower.contains("route") {
            return .network
        }
        return .unknown
    }
}

/// Latest incident per profile. The extension runs as ROOT in the system
/// context, the app as the user — app-group UserDefaults/containers do not
/// cross that boundary. Incidents must outlive the tunnel session (they're
/// read after disconnect, when IPC is gone), so they go through a fixed
/// world-readable path: the extension (root) writes files under
/// /Library/Application Support/SimpleVPN, the app just reads them.
enum TunnelIncidentStore {
    private static let dir = URL(fileURLWithPath: "/Library/Application Support/SimpleVPN", isDirectory: true)

    private static func url(_ profile: String) -> URL {
        let safe = profile.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? "profile"
        return dir.appendingPathComponent("incident-\(safe).json")
    }

    /// Extension-side (root). 0755 dir / 0644 file so the user-side app can read.
    static func write(_ incident: TunnelIncident) {
        guard let data = try? JSONEncoder().encode(incident) else { return }
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o755])
        try? data.write(to: url(incident.profile), options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o644],
                                               ofItemAtPath: url(incident.profile).path)
    }

    static func read(profile: String) -> TunnelIncident? {
        guard let data = try? Data(contentsOf: url(profile)),
              let i = try? JSONDecoder().decode(TunnelIncident.self, from: data) else { return nil }
        return i
    }

    /// Both sides may clear: the extension on a clean connect (as root it owns
    /// the file); the app's attempt is a harmless no-op if permissions deny it.
    static func clear(profile: String) {
        try? FileManager.default.removeItem(at: url(profile))
    }
}
