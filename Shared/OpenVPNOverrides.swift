// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OpenVPNOverrides.swift
//  Per-VPN overrides for the OpenVPN 3 client engine (ClientAPI::Config).
//
//  The core invariant: every field is an *override*. `nil` means "engine default,
//  the user never touched it" and is never serialized — so engine-default changes
//  in future OpenVPN3 releases flow through untouched, and round-tripping is
//  perfect by construction. There are no sentinel values ("" / 0 / -1 are real
//  engine values) and the enums deliberately have no `.default` case — default is
//  spelled `nil`.
//
//  Serialized as a single JSON blob in providerConfiguration["overrides"]
//  (omitted entirely when all fields are nil). Decoding is lenient: an unknown
//  key, wrong type, or unknown enum raw value degrades that one field to nil
//  ("engine default") instead of failing the whole blob — the app and the
//  system extension can be different versions and must never break each other.
//
//  Fields deliberately NOT exposed (see ovpncli.hpp ConfigCommon/Config):
//    dco (no Apple support), wintun / allowLocalDnsResolvers (Windows),
//    enableRouteEmulation (Android), generateTunBuilderCaptureEvent (Linux),
//    altProxy / gremlinConfig / clockTickMS (not user preferences),
//    guiVersion / platformVersion / hwAddrOverride / ssoMethods /
//    appCustomProtocols / peerInfo / echo / info (app plumbing),
//    dhcpSearchDomainsAsSplitDomains (macOS platform default is correct),
//    externalPkiAlias (engine is built with external PKI off).
//

import Foundation

struct OpenVPNOverrides: Codable, Sendable, Equatable {

    /// Bumped only on a *semantic* change to an existing key. Newer schemas are
    /// decoded best-effort and logged, never rejected.
    static let currentSchema = 1
    var schema: Int = Self.currentSchema

    // Raw values are the exact tokens ClientAPI::Config expects — bridging is `.rawValue`.

    enum TransportProto: String, Codable, Sendable, CaseIterable {
        case udp, tcp, adaptive
    }

    enum IPVersion: Int, Codable, Sendable, CaseIterable {
        case v4 = 4, v6 = 6            // engine protoVersionOverride; 0 (unset) is spelled nil
    }

    // TLS 1.0/1.1 minimums deliberately omitted: "disabled" already covers ancient
    // servers, and an explicit insecure minimum is a pointless middle ground.
    enum TLSVersionMin: String, Codable, Sendable, CaseIterable {
        case disabled
        case tls1_2 = "tls_1_2"
        case tls1_3 = "tls_1_3"
    }

    enum TLSCertProfile: String, Codable, Sendable, CaseIterable {
        case legacy, preferred, suiteb
        case legacyDefault = "legacy-default"        // apply only if profile doesn't specify
        case preferredDefault = "preferred-default"
    }

    enum Compression: String, Codable, Sendable, CaseIterable {
        case no, asym, yes
    }

    enum AddrFamilyPolicy: String, Codable, Sendable, CaseIterable {
        case allow = "yes", block = "no"             // engine "" (unset) is spelled nil
    }

    // MARK: Connection
    var server: String?                 // → serverOverride
    var port: Int?                      // → portOverride (engine takes a string); 1...65535
    var proto: TransportProto?          // → protoOverride
    var ipVersion: IPVersion?           // → protoVersionOverride
    var connTimeout: Int?               // seconds; 0 = keep trying forever

    // MARK: Reliability
    var tunPersist: Bool?
    var retryOnAuthFailed: Bool?
    var autologinSessions: Bool?        // engine default is TRUE — nil must never emit the key

    // MARK: Network & privacy
    var allowLocalLanAccess: Bool?
    var allowUnusedAddrFamilies: AddrFamilyPolicy?
    var googleDnsFallback: Bool?

    // MARK: Security
    var tlsVersionMin: TLSVersionMin?
    var tlsCertProfile: TLSCertProfile?
    var compression: Compression?
    var enableLegacyAlgorithms: Bool?
    var enableNonPreferredDCAlgorithms: Bool?
    var tlsCipherList: String?
    var tlsCiphersuitesList: String?
    var disableClientCert: Bool?
    var defaultKeyDirection: Int?       // -1 (bidirectional), 0, or 1

    // MARK: Proxy — passwords deliberately have NO field here (keychain only)
    var proxyHost: String?
    var proxyPort: Int?                 // 1...65535
    var proxyUsername: String?
    var proxyAllowCleartextAuth: Bool?

    // MARK: Troubleshooting
    var sslDebugLevel: Int?             // 0...9
    var synchronousDnsLookup: Bool?

    init() {}

    // MARK: Legal ranges (single source of truth for UI validation)

    static let portRange = 1...65535
    static let connTimeoutRange = 0...86_400
    static let sslDebugLevelRange = 0...9
    static let keyDirectionValues = [-1, 0, 1]

    // MARK: Engine defaults
    //
    // Mirrored from ovpncli.hpp (ConfigCommon/Config member initializers) so the UI
    // can rest toggles at the engine's value and normalize "user set it back to the
    // default" to nil. These are stable ClientAPI defaults; verify against the
    // pinned core's ovpncli.hpp when bumping the engine.
    enum EngineDefaults {
        static let connTimeout = 0                  // retry indefinitely
        static let tunPersist = false
        static let googleDnsFallback = false
        static let synchronousDnsLookup = false
        static let autologinSessions = true         // the one true-by-default bool
        static let retryOnAuthFailed = false
        static let disableClientCert = false
        static let sslDebugLevel = 0
        static let defaultKeyDirection = -1
        static let proxyAllowCleartextAuth = false
        static let allowLocalLanAccess = false
        static let enableLegacyAlgorithms = false
        static let enableNonPreferredDCAlgorithms = false
    }

    // MARK: Emptiness / normalization

    /// True when every override is nil — the blob is omitted from
    /// providerConfiguration entirely in that case.
    var isEmpty: Bool { self == OpenVPNOverrides() }

    /// Collapse values that exactly equal the engine default back to nil, and drop
    /// empty/invalid strings. Called once on save so "toggled on, then back off"
    /// round-trips as "never touched".
    func normalized() -> OpenVPNOverrides {
        var n = self
        n.schema = Self.currentSchema

        func clean(_ s: String?) -> String? {
            guard let t = s?.trimmingCharacters(in: .whitespacesAndNewlines), !t.isEmpty else { return nil }
            return t
        }
        n.server = clean(n.server)
        n.tlsCipherList = clean(n.tlsCipherList)
        n.tlsCiphersuitesList = clean(n.tlsCiphersuitesList)
        n.proxyHost = clean(n.proxyHost)
        n.proxyUsername = clean(n.proxyUsername)

        if let p = n.port, !Self.portRange.contains(p) { n.port = nil }
        if let p = n.proxyPort, !Self.portRange.contains(p) { n.proxyPort = nil }
        if let v = n.connTimeout, v == EngineDefaults.connTimeout || !Self.connTimeoutRange.contains(v) { n.connTimeout = nil }
        if let v = n.sslDebugLevel, v == EngineDefaults.sslDebugLevel || !Self.sslDebugLevelRange.contains(v) { n.sslDebugLevel = nil }
        if let v = n.defaultKeyDirection, v == EngineDefaults.defaultKeyDirection || !Self.keyDirectionValues.contains(v) { n.defaultKeyDirection = nil }

        if n.tunPersist == EngineDefaults.tunPersist { n.tunPersist = nil }
        if n.retryOnAuthFailed == EngineDefaults.retryOnAuthFailed { n.retryOnAuthFailed = nil }
        if n.autologinSessions == EngineDefaults.autologinSessions { n.autologinSessions = nil }
        if n.allowLocalLanAccess == EngineDefaults.allowLocalLanAccess { n.allowLocalLanAccess = nil }
        if n.googleDnsFallback == EngineDefaults.googleDnsFallback { n.googleDnsFallback = nil }
        if n.enableLegacyAlgorithms == EngineDefaults.enableLegacyAlgorithms { n.enableLegacyAlgorithms = nil }
        if n.enableNonPreferredDCAlgorithms == EngineDefaults.enableNonPreferredDCAlgorithms { n.enableNonPreferredDCAlgorithms = nil }
        if n.disableClientCert == EngineDefaults.disableClientCert { n.disableClientCert = nil }
        if n.synchronousDnsLookup == EngineDefaults.synchronousDnsLookup { n.synchronousDnsLookup = nil }
        if n.proxyAllowCleartextAuth == EngineDefaults.proxyAllowCleartextAuth { n.proxyAllowCleartextAuth = nil }

        // Proxy sub-settings are meaningless without a host.
        if n.proxyHost == nil {
            n.proxyPort = nil
            n.proxyUsername = nil
            n.proxyAllowCleartextAuth = nil
        }
        return n
    }

    // MARK: Serialization

    /// Encode for providerConfiguration; nil when there is nothing to store.
    func encodedBlob() -> Data? {
        guard !isEmpty else { return nil }
        return try? JSONEncoder().encode(self)
    }

    /// Decode from providerConfiguration; a missing or corrupt blob is "no overrides".
    static func decode(from blob: Data?) -> OpenVPNOverrides {
        guard let blob else { return OpenVPNOverrides() }
        return (try? JSONDecoder().decode(OpenVPNOverrides.self, from: blob)) ?? OpenVPNOverrides()
    }

    // MARK: Logging

    /// Compact log line of what is overridden — values are settings, not secrets.
    var logDescription: String {
        var parts: [String] = []
        if let v = server { parts.append("server=\(v)") }
        if let v = port { parts.append("port=\(v)") }
        if let v = proto { parts.append("proto=\(v.rawValue)") }
        if let v = ipVersion { parts.append("ipv=\(v.rawValue)") }
        if let v = connTimeout { parts.append("connTimeout=\(v)") }
        if let v = tunPersist { parts.append("tunPersist=\(v)") }
        if let v = retryOnAuthFailed { parts.append("retryOnAuthFailed=\(v)") }
        if let v = autologinSessions { parts.append("autologinSessions=\(v)") }
        if let v = allowLocalLanAccess { parts.append("localLan=\(v)") }
        if let v = allowUnusedAddrFamilies { parts.append("unusedFamilies=\(v.rawValue)") }
        if let v = googleDnsFallback { parts.append("googleDns=\(v)") }
        if let v = tlsVersionMin { parts.append("tlsMin=\(v.rawValue)") }
        if let v = tlsCertProfile { parts.append("certProfile=\(v.rawValue)") }
        if let v = compression { parts.append("compression=\(v.rawValue)") }
        if let v = enableLegacyAlgorithms { parts.append("legacyAlgs=\(v)") }
        if let v = enableNonPreferredDCAlgorithms { parts.append("nonPreferredDC=\(v)") }
        if tlsCipherList != nil { parts.append("tlsCipherList=set") }
        if tlsCiphersuitesList != nil { parts.append("tlsCiphersuites=set") }
        if let v = disableClientCert { parts.append("noClientCert=\(v)") }
        if let v = defaultKeyDirection { parts.append("keyDir=\(v)") }
        if let v = proxyHost { parts.append("proxy=\(v):\(proxyPort.map(String.init) ?? "?")") }
        if let v = sslDebugLevel { parts.append("sslDebug=\(v)") }
        if let v = synchronousDnsLookup { parts.append("syncDns=\(v)") }
        return parts.isEmpty ? "none" : parts.joined(separator: " ")
    }

    // MARK: Lenient Codable
    //
    // encode(to:) stays synthesized (encodeIfPresent already omits nil).
    // init(from:) is hand-written so any single bad field — unknown enum raw value
    // from a newer app, wrong type, missing key — decodes as nil instead of
    // throwing and nuking every other setting.

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        schema = c.lenient(.schema) ?? Self.currentSchema
        server = c.lenient(.server)
        port = c.lenient(.port)
        proto = c.lenient(.proto)
        ipVersion = c.lenient(.ipVersion)
        connTimeout = c.lenient(.connTimeout)
        tunPersist = c.lenient(.tunPersist)
        retryOnAuthFailed = c.lenient(.retryOnAuthFailed)
        autologinSessions = c.lenient(.autologinSessions)
        allowLocalLanAccess = c.lenient(.allowLocalLanAccess)
        allowUnusedAddrFamilies = c.lenient(.allowUnusedAddrFamilies)
        googleDnsFallback = c.lenient(.googleDnsFallback)
        tlsVersionMin = c.lenient(.tlsVersionMin)
        tlsCertProfile = c.lenient(.tlsCertProfile)
        compression = c.lenient(.compression)
        enableLegacyAlgorithms = c.lenient(.enableLegacyAlgorithms)
        enableNonPreferredDCAlgorithms = c.lenient(.enableNonPreferredDCAlgorithms)
        tlsCipherList = c.lenient(.tlsCipherList)
        tlsCiphersuitesList = c.lenient(.tlsCiphersuitesList)
        disableClientCert = c.lenient(.disableClientCert)
        defaultKeyDirection = c.lenient(.defaultKeyDirection)
        proxyHost = c.lenient(.proxyHost)
        proxyPort = c.lenient(.proxyPort)
        proxyUsername = c.lenient(.proxyUsername)
        proxyAllowCleartextAuth = c.lenient(.proxyAllowCleartextAuth)
        sslDebugLevel = c.lenient(.sslDebugLevel)
        synchronousDnsLookup = c.lenient(.synchronousDnsLookup)
    }
}

private extension KeyedDecodingContainer {
    /// nil on missing key, wrong type, or unknown enum raw value — never throws.
    func lenient<T: Decodable>(_ key: Key) -> T? {
        (try? decodeIfPresent(T.self, forKey: key)) ?? nil
    }
}
