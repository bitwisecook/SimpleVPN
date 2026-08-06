// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConfigImport.swift
//  Reading a settings file back — and the part that matters, WHICH IS NOT READING
//  IT.
//
//  An imported document is a file from outside every protection the app has. It
//  may have been mailed, edited by hand, fetched from a shared folder, or written
//  by something that is not SimpleVPN at all. Three consequences shape everything
//  below:
//
//  1. NOTHING IS COERCED. An unknown VPN kind is REFUSED, not guessed at; a value
//     of the wrong type is refused, not truthy-tested; a format version from the
//     future is refused outright rather than read best-effort, because its keys may
//     mean something else and a misread server address sends traffic somewhere
//     else. Everything refused is REPORTED — a silent drop is how a file half
//     applies and nobody knows which half.
//  2. VERIFICATION CANNOT BE WEAKENED BY A FILE. SimpleVPN has no
//     "don't check the certificate" option anywhere, and it must not acquire one
//     through a file format. `ConfigImportGuard` refuses the whole VPN if its
//     configuration carries one of the known ways of switching host-key or
//     certificate checking off — including inside the escape-hatch argument lists,
//     which is exactly where somebody would put it.
//  3. NOTHING IS DESTROYED. A VPN is ADDED ALONGSIDE what is here, never over the
//     top of it: two Macs' configurations of the same gateway are a normal thing to
//     have, and the app cannot know which one is wanted. App settings DO change
//     (that is what importing them means), so the current ones are written to a
//     recovery file and READ BACK before anything is applied — the same
//     write-verify-then-destroy order the keychain migration uses.
//
//  The result of reading a file is a PLAN, not a change. The plan is what the
//  confirmation sheet renders as a diff, because a server address and a pinned
//  certificate decide where your traffic goes and who it trusts (§4 of
//  Docs/SecretsAndSync.md: "security-determining changes need confirmation with a
//  diff").
//

import Foundation
import CryptoKit

// MARK: - What the file is refused for

/// The configurations SimpleVPN will not accept from a file, and why.
///
/// Every entry here is a way to STOP VERIFYING something. That is the only class
/// of value that gets this treatment: an odd MTU or a strange cipher list is the
/// user's business, but a file that can turn off host-key checking turns "import
/// my settings" into a way to hand somebody a tunnel that trusts anything.
nonisolated enum ConfigImportGuard {

    /// Tokens that switch verification off, matched case-insensitively anywhere in
    /// a text or list value. Both the SSH and the SSL-VPN kinds keep an escape
    /// hatch for extra command-line options, and that is precisely where one of
    /// these would arrive.
    static let unsafeTokens = [
        "stricthostkeychecking=no",
        "stricthostkeychecking no",
        "userknownhostsfile=/dev/null",
        "checkhostip=no",
        "--no-cert-check",
        "--no-system-trust",
        "--allow-insecure-crypto",
        "--tlsskipverify",
        "tlsskipverify",
        "--insecure",
        "verify-x509-name-off",
    ]

    /// `SubprocessTunnelConfig.strictHostKey` values that keep checking a host key.
    /// "no" is not among them, and an imported "no" costs the whole VPN.
    static let safeStrictHostKeyValues: Set<String> = ["accept-new", "yes", "ask"]

    /// The one setting id whose value is a host-key policy. Named rather than
    /// pattern-matched so the check cannot silently stop applying if a field is
    /// renamed — the id is the contract.
    static let hostKeyPolicyID = "ssh.strict-host-key"

    /// Why this VPN's settings are refused, or nil.
    static func refusal(in settings: ConfigMap, ovpn: String?) -> String? {
        for e in settings.entries {
            if e.key == hostKeyPolicyID, let value = e.value.stringValue,
               !safeStrictHostKeyValues.contains(value.lowercased()) {
                return "its settings ask SimpleVPN to stop checking the server\u{2019}s host key "
                    + "(\u{201C}\(value)\u{201D}). SimpleVPN has no such setting and won\u{2019}t take one "
                    + "from a file."
            }
            if let token = unsafeToken(in: e.value) {
                return "one of its settings (\(e.key)) contains \u{201C}\(token)\u{201D}, which would stop "
                    + "SimpleVPN checking who it is talking to. SimpleVPN has no such setting and "
                    + "won\u{2019}t take one from a file."
            }
        }
        if let ovpn, let token = unsafeToken(in: .text(ovpn)) {
            return "its OpenVPN configuration contains \u{201C}\(token)\u{201D}, which would stop SimpleVPN "
                + "checking who it is talking to."
        }
        return nil
    }

    private static func unsafeToken(in value: ConfigValue) -> String? {
        switch value {
        case .string(let s), .text(let s):
            let lower = s.lowercased()
            return unsafeTokens.first { lower.contains($0) }
        case .list(let items):
            for item in items { if let hit = unsafeToken(in: item) { return hit } }
            return nil
        case .map(let m):
            for e in m.entries { if let hit = unsafeToken(in: e.value) { return hit } }
            return nil
        default: return nil
        }
    }
}

// MARK: - The plan

/// What a file WOULD do, computed before anything is touched. Rendered as the
/// confirmation diff and then handed back to be applied — so what the user
/// confirmed and what is applied are the same object, not two derivations of it.
nonisolated struct ConfigImportPlan: Sendable {

    nonisolated struct SettingChange: Sendable, Equatable, Identifiable {
        let id: String
        /// The setting's display name, for the sentence a person reads.
        let name: String
        let from: String
        let to: String
    }

    nonisolated struct PlannedVPN: Sendable, Identifiable {
        var vpn: ConfigSnapshot.VPN
        /// The name it will be added under — the file's name, or that name with a
        /// suffix when this Mac already has a VPN called it.
        var addedName: String
        /// The values that decide where traffic goes and who is trusted, spelled out
        /// for the confirmation. A server address and a pinned certificate are the
        /// two the diff exists for.
        var securityNotes: [String]
        /// What the file says it left out, verbatim from its own `omitted:` list.
        var omitted: [String]
        var id: String { vpn.id }
    }

    nonisolated struct Refusal: Sendable, Equatable, Identifiable {
        let subject: String
        let reason: String
        var id: String { subject + reason }
    }

    var formatVersion = 0
    var writtenBy = ""
    var exported = ""
    /// Non-empty ⇒ the file cannot be applied at all and nothing will be.
    var fatal: [String] = []
    /// Refused parts. The rest of the file still applies — a file with one bad VPN
    /// in it is not a reason to make somebody re-type the other nine.
    var refusals: [Refusal] = []
    var settingChanges: [SettingChange] = []
    /// The value behind each change in `settingChanges`, keyed by setting id. Kept
    /// with the plan rather than re-read from the file when the user says yes: what
    /// was confirmed and what is written must be the same value, not two readings
    /// of the same bytes.
    var pendingValues: [String: ConfigValue] = [:]
    var newLabels: [ConfigLabel] = []
    /// Labels whose id this Mac already has: left exactly as they are, and said so.
    var keptLabels: [String] = []
    var vpns: [PlannedVPN] = []
    /// Keys the file carries that this build does not know. Reported, never applied
    /// — a newer SimpleVPN's extra setting is not an error, but it is not a secret
    /// either.
    var unknownKeys: [String] = []

    var isApplicable: Bool { fatal.isEmpty && !(settingChanges.isEmpty && vpns.isEmpty && newLabels.isEmpty) }

    /// The one-line summary the confirmation button and VoiceOver both use.
    var summary: String {
        guard fatal.isEmpty else { return fatal[0] }
        var parts: [String] = []
        if !vpns.isEmpty { parts.append("\(vpns.count) VPN\(vpns.count == 1 ? "" : "s") to add") }
        if !settingChanges.isEmpty {
            parts.append("\(settingChanges.count) setting\(settingChanges.count == 1 ? "" : "s") to change")
        }
        if !newLabels.isEmpty { parts.append("\(newLabels.count) label\(newLabels.count == 1 ? "" : "s") to add") }
        if parts.isEmpty { return "Nothing in this file would change anything." }
        return parts.joined(separator: ", ") + "."
    }
}

// MARK: - Reading

/// `@MainActor` for the same reason `ConfigDocument` is — the config structs'
/// `Codable` conformances are, and this is the layer that uses them. Parsing
/// itself (`ConfigYAML`, `ConfigJSON`) is not, so the grammar is testable and
/// usable with no app around it.
@MainActor
enum ConfigImport {

    /// Parse either encoding. Sniffed by the first non-blank, non-comment
    /// character, and then RETRIED as the other one — a person who saves JSON with a
    /// `.yaml` extension has made a naming mistake, not an unreadable file.
    static func parse(_ text: String) throws -> ConfigMap {
        let looksJSON = text.drop { $0 == " " || $0 == "\n" || $0 == "\r" || $0 == "\t" }.first == "{"
        do {
            return looksJSON ? try ConfigJSON.decode(text) : try ConfigYAML.decode(text)
        } catch {
            if let second = try? (looksJSON ? ConfigYAML.decode(text) : ConfigJSON.decode(text)) {
                return second
            }
            throw error
        }
    }

    /// The whole read: parse, validate, and diff against what is installed.
    static func plan(text: String, current: ConfigSnapshot) -> ConfigImportPlan {
        var plan = ConfigImportPlan()
        let root: ConfigMap
        do {
            root = try parse(text)
        } catch let error as ConfigCodingError {
            plan.fatal = [error.description]
            return plan
        } catch {
            plan.fatal = ["SimpleVPN couldn\u{2019}t read this file: \(error.localizedDescription)"]
            return plan
        }
        return self.plan(root: root, current: current)
    }

    static func plan(root: ConfigMap, current: ConfigSnapshot) -> ConfigImportPlan {
        var plan = ConfigImportPlan()
        plan.formatVersion = root[ConfigDocumentKeys.format]?.intValue ?? 0
        plan.writtenBy = root[ConfigDocumentKeys.app]?.stringValue ?? ""
        plan.exported = root[ConfigDocumentKeys.exported]?.stringValue ?? ""
        if let refusal = ConfigFormat.refusalForVersion(plan.formatVersion) {
            plan.fatal = [refusal]
            return plan
        }

        // App settings
        if let settings = root[ConfigDocumentKeys.appSettings]?.mapValue {
            let currentByID = Dictionary(current.appSettings.map { ($0.id, $0.value) },
                                         uniquingKeysWith: { first, _ in first })
            for e in settings.entries {
                guard let entry = ConfigAppSettings.entry(id: e.key) else {
                    plan.unknownKeys.append(e.key)
                    continue
                }
                if let refusal = ConfigAppSettings.refusal(applying: e.value, to: entry) {
                    plan.refusals.append(.init(subject: entry.name, reason: refusal))
                    continue
                }
                let now = currentByID[e.key]
                guard now != e.value else { continue }
                plan.settingChanges.append(.init(id: entry.id, name: entry.name,
                                                 from: now?.displayText ?? "(not set)",
                                                 to: e.value.displayText))
                plan.pendingValues[entry.id] = e.value
            }
        }

        // Labels: added when new, LEFT ALONE when this Mac already has that id.
        // Renaming somebody's label out from under them is a silent destruction of
        // the thing that organises their sidebar.
        if let labels = root[ConfigDocumentKeys.labels]?.listValue {
            let existing = Set(current.labels.map(\.id))
            for value in labels {
                guard let map = value.mapValue, let label = decode(ConfigLabel.self, from: map) else {
                    plan.refusals.append(.init(subject: "A label",
                                               reason: "one of the labels in the file isn\u{2019}t readable."))
                    continue
                }
                if existing.contains(label.id) { plan.keptLabels.append(label.name) }
                else { plan.newLabels.append(label) }
            }
        }

        // VPNs
        if let vpns = root[ConfigDocumentKeys.vpns]?.listValue {
            let existingNames = Set(current.vpns.map(\.name))
            var plannedNames: Set<String> = []
            for value in vpns {
                guard let map = value.mapValue else {
                    plan.refusals.append(.init(subject: "A VPN",
                                               reason: "one of the entries in the file isn\u{2019}t a VPN."))
                    continue
                }
                let fileName = map[ConfigDocumentKeys.name]?.stringValue ?? ""
                let subject = fileName.isEmpty ? "A VPN with no name" : fileName
                switch planVPN(map) {
                case .failure(let reason):
                    plan.refusals.append(.init(subject: subject, reason: reason))
                case .success(var planned):
                    var name = planned.addedName
                    if existingNames.contains(name) || plannedNames.contains(name) {
                        var candidate = "\(name) (imported)"
                        var n = 2
                        while existingNames.contains(candidate) || plannedNames.contains(candidate) {
                            candidate = "\(name) (imported \(n))"
                            n += 1
                        }
                        name = candidate
                    }
                    plannedNames.insert(name)
                    planned.addedName = name
                    planned.vpn.name = name
                    plan.vpns.append(planned)
                }
            }
        }
        return plan
    }

    // MARK: One VPN

    private enum VPNResult {
        case success(ConfigImportPlan.PlannedVPN)
        case failure(String)
    }

    private static func planVPN(_ map: ConfigMap) -> VPNResult {
        let name = (map[ConfigDocumentKeys.name]?.stringValue ?? "").trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else {
            return .failure("it has no name, and an unnamed VPN can\u{2019}t be found again.")
        }
        guard let rawKind = map[ConfigDocumentKeys.kind]?.stringValue else {
            return .failure("it doesn\u{2019}t say what kind of VPN it is.")
        }
        // REFUSED, never coerced. Defaulting an unrecognised kind to OpenVPN would
        // build a profile that cannot work out of settings that meant something else.
        guard let kind = VPNKind(rawValue: rawKind) else {
            return .failure("SimpleVPN doesn\u{2019}t know the kind of VPN \u{201C}\(rawKind)\u{201D}. It may need "
                + "a newer version of SimpleVPN.")
        }
        let settings = map[ConfigDocumentKeys.settings]?.mapValue ?? ConfigMap()
        let ovpn = map[ConfigDocumentKeys.openVPNConfiguration]?.stringValue

        if let refusal = ConfigImportGuard.refusal(in: settings, ovpn: ovpn) {
            return .failure(refusal)
        }

        var vpn = ConfigSnapshot.VPN(id: UUID().uuidString, name: name, kind: kind,
                                     server: map[ConfigDocumentKeys.server]?.stringValue ?? "")
        vpn.labelIDs = map[ConfigDocumentKeys.labelIDs]?.stringList ?? []

        // The engine's own settings, decoded by the engine's OWN decoder. Anything
        // it refuses costs the VPN rather than being patched up here: this layer has
        // no business deciding what a valid WireGuard configuration is.
        do {
            switch kind {
            case .openVPN:
                guard let ovpn, !ovpn.isEmpty else {
                    return .failure("it is an OpenVPN VPN with no configuration in the file.")
                }
                vpn.ovpn = ovpn
                vpn.overrides = try apply(settings, onto: OpenVPNOverrides(), namespace: "openvpn.").normalized()
            case .wireGuard:
                var config = try apply(settings, onto: WireGuardConfig(), namespace: "wg.")
                config.name = name
                vpn.wireGuard = config.redactedForStorage()
            case .tailscale:
                vpn.tailscale = try apply(settings, onto: TailscaleConfig(), namespace: "ts.")
            case .proxyTunnel:
                vpn.proxyTunnel = try apply(settings, onto: ProxyTunnelConfig(), namespace: "px.")
            case .sshNetworkTunnel:
                vpn.sshNetworkTunnel = try apply(settings, onto: SSHNetworkTunnelConfig(), namespace: "sshnet.")
            case .ikev2, .ipsec, .l2tp:
                var config = try apply(settings, onto: NativeVPNConfig(), namespace: "native.")
                config.name = name
                config.kind = kind
                vpn.native = config
            case .ssh, .fortinet, .f5apm, .ciscoAnyConnect, .globalProtect,
                 .juniper, .pulse, .arrayNetworks:
                var config = try apply(settings, onto: SubprocessTunnelConfig(),
                                       namespace: kind == .ssh ? "ssh." : "oc.")
                config.name = name
                config.kind = kind
                if config.server.isEmpty { config.server = vpn.server }
                vpn.subprocess = config.normalized()
            }
        } catch {
            return .failure("SimpleVPN couldn\u{2019}t read its settings, so it was left out.")
        }

        if let signIn = map[ConfigDocumentKeys.signIn]?.mapValue {
            vpn.auth = try? apply(signIn, onto: VPNAuthConfig(), namespace: "signin.")
            if let source = signIn["signin.source"] { vpn.credentialSourceJSON = source }
        }
        if let routing = map[ConfigDocumentKeys.customRouting]?.mapValue {
            vpn.customRouting = decode(CustomRoutingProfile.self, from: routing)
        }
        if let endpoints = map[ConfigDocumentKeys.endpoints]?.mapValue {
            vpn.endpoints = decode(VPNEndpointList.self, from: endpoints)
        }
        if let prefs = map[ConfigDocumentKeys.interfacePrefs]?.mapValue {
            vpn.uiPrefs = decode(VPNUIPrefs.self, from: prefs)
        }

        return .success(.init(vpn: vpn, addedName: name,
                              securityNotes: securityNotes(kind: kind, server: vpn.server,
                                                           settings: settings, vpn: vpn),
                              omitted: map[ConfigDocumentKeys.omitted]?.stringList ?? []))
    }

    /// The values a person has to SEE before a VPN is added, because they decide
    /// where the traffic goes and who is trusted. Everything else is a preference;
    /// these are the tunnel.
    static func securityNotes(kind: VPNKind, server: String,
                              settings: ConfigMap, vpn: ConfigSnapshot.VPN) -> [String] {
        var out: [String] = []
        if !server.isEmpty { out.append("Server address: \(server)") }
        /// id → how to say it. Only settings that decide trust or destination.
        let watched: [(String, String)] = [
            ("openvpn.server", "Server address override"),
            ("openvpn.port", "Port"),
            ("openvpn.proxy-host", "Connection proxy"),
            ("openvpn.tls-version-min", "Lowest TLS version accepted"),
            ("openvpn.no-client-cert", "Sign in without a client certificate"),
            ("openvpn.legacy-algorithms", "Allow legacy algorithms"),
            ("openvpn.unused-families", "Unused address families"),
            ("wg.endpoint", "Server address"),
            ("wg.public-key", "Peer public key"),
            ("wg.allowed-ips", "Allowed IPs"),
            ("ts.control-url", "Coordination server"),
            ("px.address", "Proxy address"),
            ("sshnet.server", "Server address"),
            ("sshnet.host-key-policy", "Host key checking"),
            ("sshnet.pinned-host-key", "Pinned host key"),
            ("ssh.server", "Server address"),
            ("ssh.strict-host-key", "Host key checking"),
            ("ssh.pinned-host-key", "Pinned host key"),
            ("ssh.proxy-jump", "Jump host"),
            ("oc.pinned-server-cert", "Pinned server certificate"),
            ("oc.cafile", "Certificate authority file"),
            ("oc.pfs", "Require perfect forward secrecy"),
            ("native.server", "Server address"),
            ("native.remote-id", "Server identifier checked in its certificate"),
        ]
        for (id, label) in watched {
            guard let value = settings[id] else { continue }
            out.append("\(label): \(value.displayText)")
        }
        if let ovpn = vpn.ovpn {
            if let ca = OVPNInline.block("ca", in: ovpn) {
                out.append("Certificate authority: a \(ca.count)-character certificate is included "
                    + "(fingerprint \(ConfigFingerprint.short(ca)))")
            } else {
                out.append("Certificate authority: none in the configuration")
            }
            for endpoint in EndpointScanner.endpoints(in: ovpn).prefix(6) {
                out.append("Connects to: \(endpoint.host)\(endpoint.port.map { ":\($0)" } ?? "")")
            }
        }
        if let routing = vpn.customRouting, !routing.isEmpty {
            out.append("Custom Routing: this VPN carries its own rules for where traffic goes")
        }
        return out
    }

    // MARK: Decoding helpers

    /// Apply an id-keyed settings map onto a config struct, and let the STRUCT'S OWN
    /// decoder judge every value. Unknown ids are skipped (a newer SimpleVPN's
    /// settings are not an error); secret fields are skipped even if the file
    /// carries one, so a file that has been hand-edited to include a private key
    /// still cannot put it into a stored profile.
    static func apply<T: Codable>(_ settings: ConfigMap, onto template: T,
                                  namespace: String) throws -> T {
        var json = ConfigDocument.jsonObject(template)
        let fields = ConfigDocument.fields(of: template)
        for e in settings.entries {
            guard let field = ConfigFieldNaming.field(forID: e.key, fields: fields, namespace: namespace),
                  !ConfigFieldNaming.skipped.contains(field),
                  !ConfigSecrets.isSecret(field) else { continue }
            json[field] = e.value.jsonObject
        }
        let data = try JSONSerialization.data(withJSONObject: json)
        return try JSONDecoder().decode(T.self, from: data)
    }

    /// A structural section back into its type, through the app's own decoder.
    static func decode<T: Decodable>(_ type: T.Type, from map: ConfigMap) -> T? {
        let clean = ConfigDocument.redact(map).map   // a file cannot smuggle a secret in either
        guard let data = try? JSONSerialization.data(withJSONObject: clean.jsonRepresentation) else { return nil }
        return try? JSONDecoder().decode(type, from: data)
    }
}

// MARK: - Fingerprints

/// A short, stable fingerprint of a public certificate, for the confirmation diff.
/// The CA is the thing that decides who the tunnel trusts, so "a certificate is
/// included" is not enough on its own — two files can differ in exactly that
/// block and look identical in every other line.
nonisolated enum ConfigFingerprint {
    static func short(_ text: String) -> String {
        let hex = SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
        return String(hex.prefix(16))
    }
}
