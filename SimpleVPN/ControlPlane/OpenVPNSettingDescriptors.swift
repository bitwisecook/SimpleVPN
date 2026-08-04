// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OpenVPNSettingDescriptors.swift
//  One entry per exposed OpenVPN override: the single source of truth for each
//  setting's stable id (CLI/MDM/manual key), display name, user-facing summary,
//  grouping, manual anchor, availability rules, and overridden-state helpers.
//  The Options form renders from this table; the manual's anchors are generated
//  from these ids; a future CLI addresses settings as e.g. "openvpn.compression".
//

import Foundation

/// THE canonical config-surface taxonomy (AGENTS.md "Config surfaces"): every
/// editor orders its groups Connection → Sign-In → Traffic → Security →
/// Advanced, omitting groups it has nothing for. Custom Routing stays its own
/// tab. Do not add per-engine groups — fit new settings into these five.
enum SettingGroup: String, CaseIterable, Sendable {
    case connection, signIn, traffic, security, advanced

    var title: String {
        switch self {
        case .connection: return "Connection"
        case .signIn: return "Sign-In"
        case .traffic: return "Traffic"
        case .security: return "Security"
        case .advanced: return "Advanced"
        }
    }
}

enum SettingAvailability: Equatable, Sendable {
    case available
    case disabled(reason: String)
    case hidden
}

/// Everything an availability rule may consult.
struct SettingsContext {
    var evaluation: ProfileEvaluation?
    var draft: OpenVPNOverrides
    var policy: Policy

    var proxyConfigured: Bool {
        !(draft.proxyHost ?? "").trimmingCharacters(in: .whitespaces).isEmpty
    }
    var proxyHasUsername: Bool {
        !(draft.proxyUsername ?? "").trimmingCharacters(in: .whitespaces).isEmpty
    }

    /// Whether the connection will actually run over UDP — the override when the
    /// user set one, otherwise the protocol the profile's own `remote` line names.
    /// Read by the proxy caveats: "Default (UDP)" is just as UDP as an explicit
    /// choice, and a proxy can carry neither.
    var usesUDP: Bool {
        if let p = draft.proto { return p == .udp }
        return evaluation?.remoteProtoDisplay == "UDP"
    }
}

struct SettingDescriptor: Identifiable {
    let id: String                 // stable, e.g. "openvpn.compression"
    let group: SettingGroup
    let name: String               // control label
    let summary: String            // plain-English footer copy
    let isSet: (OpenVPNOverrides) -> Bool
    let reset: (inout OpenVPNOverrides) -> Void
    private let availabilityRule: (SettingsContext) -> SettingAvailability

    /// Manual deep-link anchor, generated from the id ("openvpn.compression" → "openvpn-compression").
    var manualAnchor: String { id.replacingOccurrences(of: ".", with: "-") }

    /// Policy always wins; then the setting's own rule.
    func availability(in context: SettingsContext) -> SettingAvailability {
        if context.policy.forcedValue(for: id) != nil {
            return .disabled(reason: "Managed by your organisation")
        }
        return availabilityRule(context)
    }

    init<V: Equatable>(
        _ id: String,
        _ keyPath: WritableKeyPath<OpenVPNOverrides, V?>,
        group: SettingGroup,
        name: String,
        summary: String,
        availability: @escaping (SettingsContext) -> SettingAvailability = { _ in .available }
    ) {
        self.id = id
        self.group = group
        self.name = name
        self.summary = summary
        self.isSet = { $0[keyPath: keyPath] != nil }
        self.reset = { $0[keyPath: keyPath] = nil }
        self.availabilityRule = availability
    }

    /// For the exposed controls that are NOT one Optional field of the overrides
    /// blob: the two engine secrets (which live in the keychain — see the M7
    /// settings architecture) and the proxy master toggle (whose state is "is a
    /// proxy host set", and whose reset clears the whole sub-form). They still
    /// need a descriptor: an unspec'd control is invisible to SettingsSearch, has
    /// no manual anchor behind its help button, and cannot be addressed by the
    /// CLI or forced by MDM — which is exactly how the toggle that unhides five
    /// spec'd proxy rows ended up unfindable by searching "proxy".
    init(
        _ id: String,
        group: SettingGroup,
        name: String,
        summary: String,
        isSet: @escaping (OpenVPNOverrides) -> Bool = { _ in false },
        reset: @escaping (inout OpenVPNOverrides) -> Void = { _ in },
        availability: @escaping (SettingsContext) -> SettingAvailability = { _ in .available }
    ) {
        self.id = id
        self.group = group
        self.name = name
        self.summary = summary
        self.isSet = isSet
        self.reset = reset
        self.availabilityRule = availability
    }
}

@MainActor
enum OpenVPNSettings {

    static let all: [SettingDescriptor] = [

        // MARK: Connection

        SettingDescriptor("openvpn.server", \.server, group: .connection,
            name: "Server",
            summary: "Connect to a different server address than the one built into the configuration file."),

        SettingDescriptor("openvpn.port", \.port, group: .connection,
            name: "Port",
            summary: "Use a different port. Leave empty to use the configuration file's port."),

        SettingDescriptor("openvpn.protocol", \.proto, group: .connection,
            name: "Protocol",
            summary: "UDP is fastest. TCP gets through restrictive networks. Adaptive tries UDP first, then falls back to TCP."),

        SettingDescriptor("openvpn.ip-version", \.ipVersion, group: .connection,
            name: "Internet Protocol",
            summary: "Force the connection to the server over IPv4 or IPv6. Leave on Automatic unless one of them is broken on your network."),

        SettingDescriptor("openvpn.connect-timeout", \.connTimeout, group: .connection,
            name: "Connection Timeout",
            summary: "How long to keep trying before giving up when the server doesn't answer."),

        SettingDescriptor("openvpn.tun-persist", \.tunPersist, group: .connection,
            name: "Stay connected through interruptions",
            summary: "Keeps the VPN alive when your Mac changes Wi-Fi networks or wakes from sleep, instead of tearing it down and starting over."),

        // MARK: Connection — reaching the server through an HTTP proxy

        // The master toggle for the five rows below. It gates them, so it must be
        // findable BY ITSELF: searching "proxy" used to list the fields the toggle
        // hides and never the toggle that unhides them.
        SettingDescriptor("openvpn.proxy-enabled", group: .connection,
            name: "Connect through an HTTP proxy",
            summary: "Turn on when this network makes you reach the internet through a proxy. The proxy's address and sign-in appear below.",
            isSet: { $0.proxyHost != nil },
            reset: {
                $0.proxyHost = nil
                $0.proxyPort = nil
                $0.proxyUsername = nil
                $0.proxyAllowCleartextAuth = nil
            }),

        SettingDescriptor("openvpn.proxy-host", \.proxyHost, group: .connection,
            name: "Proxy Host",
            summary: "Reach the VPN server through an HTTP proxy on your network. Proxies carry TCP only — while a proxy is configured, UDP can't be used."),

        SettingDescriptor("openvpn.proxy-port", \.proxyPort, group: .connection,
            name: "Proxy Port",
            summary: "The port your proxy listens on.",
            availability: { $0.proxyConfigured ? .available : .disabled(reason: "Enter a proxy host first") }),

        SettingDescriptor("openvpn.proxy-username", \.proxyUsername, group: .connection,
            name: "Proxy Username",
            summary: "Only needed if your proxy asks you to sign in.",
            availability: { $0.proxyConfigured ? .available : .disabled(reason: "Enter a proxy host first") }),

        // Keychain-backed (never in the overrides blob), so it has no
        // overridden-state to track — but it is a control the user can find,
        // read about, and have MDM manage.
        SettingDescriptor("openvpn.proxy-password", group: .connection,
            name: "Proxy Password",
            summary: "The password your proxy asks for. Stored in your Keychain, never in this VPN's settings file.",
            availability: { ctx in
                guard ctx.proxyConfigured else { return .disabled(reason: "Enter a proxy host first") }
                return ctx.proxyHasUsername ? .available : .disabled(reason: "Enter a proxy username first")
            }),

        SettingDescriptor("openvpn.proxy-cleartext-auth", \.proxyAllowCleartextAuth, group: .connection,
            name: "Allow unencrypted proxy sign-in",
            summary: "Your proxy username and password may be visible to others on the local network.",
            availability: { ctx in
                guard ctx.proxyConfigured else { return .disabled(reason: "Enter a proxy host first") }
                return ctx.proxyHasUsername ? .available : .disabled(reason: "Enter a proxy username first")
            }),

        // MARK: Sign-In

        SettingDescriptor("openvpn.retry-on-auth-failed", \.retryOnAuthFailed, group: .signIn,
            name: "Keep retrying after a failed sign-in",
            summary: "Treat a rejected sign-in as temporary and try again. Useful with verification codes that expire."),

        // Also keychain-backed. Shown only for profiles whose private key is
        // actually protected — for anything else there is no passphrase to type.
        SettingDescriptor("openvpn.private-key-password", group: .signIn,
            name: "Private Key Password",
            summary: "The password that unlocks this configuration's private key. Stored in your Keychain, never in this VPN's settings file.",
            availability: { ctx in
                (ctx.evaluation?.privateKeyPasswordRequired ?? false) ? .available : .hidden
            }),

        SettingDescriptor("openvpn.autologin-sessions", \.autologinSessions, group: .signIn,
            name: "Use server session tokens",
            summary: "Lets the server hand out a temporary session pass so quick reconnects don't need a full sign-in.",
            availability: { ctx in
                // Only meaningful for profiles that sign in without credentials.
                (ctx.evaluation?.autologin ?? false) ? .available : .hidden
            }),

        // MARK: Traffic

        SettingDescriptor("openvpn.local-lan", \.allowLocalLanAccess, group: .traffic,
            name: "Allow local network access",
            summary: "Keep printers, file shares and other devices on your home or office network reachable while connected."),

        SettingDescriptor("openvpn.unused-families", \.allowUnusedAddrFamilies, group: .traffic,
            name: "Traffic the VPN doesn't carry",
            summary: "Some VPNs only carry IPv4 or only IPv6. Choose whether the other kind of traffic uses your normal connection (convenient) or is blocked (more private — nothing bypasses the VPN)."),

        SettingDescriptor("openvpn.google-dns-fallback", \.googleDnsFallback, group: .traffic,
            name: "Fall back to Google DNS",
            summary: "If the VPN takes over all traffic but doesn't provide DNS servers, use Google's public DNS so browsing still works. Google can then see your DNS lookups."),

        // MARK: Security

        SettingDescriptor("openvpn.tls-version-min", \.tlsVersionMin, group: .security,
            name: "Minimum TLS Version",
            summary: "The oldest encryption handshake version you'll accept from the server."),

        SettingDescriptor("openvpn.tls-cert-profile", \.tlsCertProfile, group: .security,
            name: "Certificate Strictness",
            summary: "How strict to be about the quality of the server's certificate."),

        SettingDescriptor("openvpn.compression", \.compression, group: .security,
            name: "Compression",
            summary: "\u{201C}Downloads only\u{201D} accepts compressed data from the server but never compresses what you send, avoiding the known attack."),

        SettingDescriptor("openvpn.legacy-algorithms", \.enableLegacyAlgorithms, group: .security,
            name: "Allow outdated encryption",
            summary: "Permits obsolete ciphers (Blowfish, DES) some very old servers still use. Leave off unless connecting fails with a cipher error."),

        SettingDescriptor("openvpn.non-preferred-ciphers", \.enableNonPreferredDCAlgorithms, group: .security,
            name: "Allow older data ciphers",
            summary: "Permits AES-CBC and other older-but-not-broken ciphers when the server can't use the modern ones (AES-GCM, ChaCha20)."),

        SettingDescriptor("openvpn.tls-cipher-list", \.tlsCipherList, group: .security,
            name: "TLS cipher list",
            summary: "Leave empty unless a server administrator gave you an exact string to paste."),

        SettingDescriptor("openvpn.tls-ciphersuites", \.tlsCiphersuitesList, group: .security,
            name: "TLS 1.3 ciphersuites",
            summary: "Leave empty unless a server administrator gave you an exact string to paste."),

        // MARK: Advanced

        SettingDescriptor("openvpn.ssl-debug", \.sslDebugLevel, group: .advanced,
            name: "TLS diagnostics",
            summary: "Adds TLS handshake detail to the log."),

        SettingDescriptor("openvpn.synchronous-dns", \.synchronousDnsLookup, group: .advanced,
            name: "Use blocking DNS lookups",
            summary: "Changes how the server's name is looked up. Can help on unusual network setups."),

        SettingDescriptor("openvpn.no-client-cert", \.disableClientCert, group: .advanced,
            name: "Don't send a client certificate",
            summary: "Connect without identifying this Mac with its certificate. Most servers will refuse this.",
            availability: { ctx in
                // Meaningless when the profile has no client certificate to withhold.
                (ctx.evaluation?.hasClientCert ?? true) ? .available : .hidden
            }),

        SettingDescriptor("openvpn.key-direction", \.defaultKeyDirection, group: .advanced,
            name: "Key Direction",
            summary: "Matches the \u{201C}key direction\u{201D} of the server's extra HMAC key. Only change if your administrator says so.",
            availability: { ctx in
                // Only applies to profiles using an extra HMAC key (tls-auth/tls-crypt).
                (ctx.evaluation?.usesTLSAuth ?? true) ? .available : .hidden
            }),
    ]

    static let byID: [String: SettingDescriptor] =
        Dictionary(uniqueKeysWithValues: all.map { ($0.id, $0) })

    static func descriptors(in group: SettingGroup) -> [SettingDescriptor] {
        all.filter { $0.group == group }
    }

    /// Count of overridden settings in a group — drives the "n changed" section badge.
    static func overriddenCount(in group: SettingGroup, for overrides: OpenVPNOverrides) -> Int {
        descriptors(in: group).count { $0.isSet(overrides) }
    }
}
