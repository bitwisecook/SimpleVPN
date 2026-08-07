// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  WireGuardConfig.swift
//  WireGuard configuration: parse/serialize the standard wg-quick .conf INI, so
//  SimpleVPN can import, edit and export real WireGuard configs — plus the
//  Swift half of the plain-WireGuard engine's JSON contract (the start payload
//  handed to WGStart and the WGStatus decoder; the engine is wireguard-go's
//  device package, compiled into libtsengine.a — see
//  Vendor/tailscale-engine/src/wireguard.go). Shared between the app (editor,
//  connect flow) and the extension (which runs the engine).
//
//  Invariant: the private key (and preshared key) are secrets — kept in the
//  keychain app-side under the "wg.<id>" profile, carried to the extension via
//  startTunnel(options:) in memory, and NEVER in providerConfiguration (the
//  persisted blob is always the redacted copy).
//

import Foundation
import Observation
#if canImport(Darwin)
import Darwin
#endif

nonisolated struct WireGuardConfig: Codable, Sendable, Equatable, Identifiable {
    var id = UUID().uuidString
    var name = "New WireGuard"

    // [Interface]
    var privateKey = ""
    var addresses: [String] = []     // e.g. "10.0.0.2/32"
    var dns: [String] = []
    /// Domains to append to a SHORT name before looking it up ("nas" →
    /// "nas.corp.example"). `wg-quick` has no field for a search list — its `DNS=`
    /// line carries resolvers only — so without this a short internal name never
    /// resolves over a WireGuard tunnel while its FQDN does (Docs/Networking.md
    /// §4.4). SimpleVPN's own key in the saved config; nothing is written to an
    /// exported `.conf`, because there is no wg-quick key to write it to.
    var searchDomains: [String] = []
    /// Keep this Mac's own network reachable while the tunnel is up: the networks
    /// its interfaces are on, plus link-local and multicast, become excluded routes.
    /// OFF by default because ON means traffic leaves the tunnel — see
    /// `Shared/LocalNetworkCarveOut.swift` for exactly which prefixes and why they
    /// are computed rather than guessed. (`wg-quick` has no equivalent either; the
    /// peer's cryptokey routing still permits these destinations, only this host's
    /// routing table stops handing them to the tunnel.)
    var allowLocalNetworkAccess: Bool = false
    var mtu: Int? = nil
    var listenPort: Int? = nil
    var fwMark: String = ""          // FwMark (hex/int) — mark on outgoing packets
    var table: String = ""           // Table = auto | off | <number>

    // [Peer] (single peer — the common client case; multi-peer round-trips via rawExtraPeers)
    var peerPublicKey = ""
    var presharedKey = ""
    var endpoint = ""                // host:port
    var allowedIPs: [String] = ["0.0.0.0/0", "::/0"]
    var persistentKeepalive: Int? = nil

    /// Additional [Peer] blocks preserved verbatim for lossless round-trip.
    var rawExtraPeers: [String] = []

    var isFullTunnel: Bool { allowedIPs.contains { $0 == "0.0.0.0/0" || $0 == "::/0" } }

    init() {}

    /// A fresh config under a given name — the shape `parse` builds. Spelled out
    /// because declaring the decoder below suppresses the memberwise initializer.
    init(name: String) { self.name = name }

    // LENIENT DECODING, and it is not a nicety. The synthesized `init(from:)` does
    // NOT fall back to a property's default value: a stored blob written before a
    // field existed fails with `keyNotFound`, and `decode(from:)` below turns that
    // into a BRAND-NEW EMPTY CONFIG — a WireGuard VPN silently losing its addresses,
    // peer key and endpoint the first time a newer app (or extension) reads it.
    // Every other config type in Shared already spells this out
    // (`ProxyTunnelConfig`, `SSHNetworkTunnelConfig`, `TailscaleConfig`,
    // `OpenVPNOverrides`); this one was the exception, and adding a field to it was a
    // latent data-loss bug waiting for the next release.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = (try? c.decodeIfPresent(String.self, forKey: .id)) ?? UUID().uuidString
        name = (try? c.decodeIfPresent(String.self, forKey: .name)) ?? "New WireGuard"
        privateKey = (try? c.decodeIfPresent(String.self, forKey: .privateKey)) ?? ""
        addresses = (try? c.decodeIfPresent([String].self, forKey: .addresses)) ?? []
        dns = (try? c.decodeIfPresent([String].self, forKey: .dns)) ?? []
        searchDomains = (try? c.decodeIfPresent([String].self, forKey: .searchDomains)) ?? []
        allowLocalNetworkAccess =
            (try? c.decodeIfPresent(Bool.self, forKey: .allowLocalNetworkAccess)) ?? false
        mtu = try? c.decodeIfPresent(Int.self, forKey: .mtu)
        listenPort = try? c.decodeIfPresent(Int.self, forKey: .listenPort)
        fwMark = (try? c.decodeIfPresent(String.self, forKey: .fwMark)) ?? ""
        table = (try? c.decodeIfPresent(String.self, forKey: .table)) ?? ""
        peerPublicKey = (try? c.decodeIfPresent(String.self, forKey: .peerPublicKey)) ?? ""
        presharedKey = (try? c.decodeIfPresent(String.self, forKey: .presharedKey)) ?? ""
        endpoint = (try? c.decodeIfPresent(String.self, forKey: .endpoint)) ?? ""
        // A stored config with no allowed IPs at all carries nothing; the type's own
        // default (a full tunnel) is the honest reading of "absent", and it is what
        // every wg-quick file that omits the key means.
        allowedIPs = (try? c.decodeIfPresent([String].self, forKey: .allowedIPs))
            ?? ["0.0.0.0/0", "::/0"]
        persistentKeepalive = try? c.decodeIfPresent(Int.self, forKey: .persistentKeepalive)
        rawExtraPeers = (try? c.decodeIfPresent([String].self, forKey: .rawExtraPeers)) ?? []
    }
}

extension WireGuardConfig {
    /// Parse a wg-quick .conf. Lenient: unknown keys are ignored, extra peers kept.
    nonisolated static func parse(_ text: String, name: String) -> WireGuardConfig {
        var c = WireGuardConfig(name: name)
        enum Section { case none, interface, peer }
        var section: Section = .none
        var peerIndex = 0

        func values(_ s: String) -> [String] {
            s.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        }

        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line.hasPrefix("[") {
                let tag = line.lowercased()
                if tag.hasPrefix("[interface]") { section = .interface }
                else if tag.hasPrefix("[peer]") { section = .peer; peerIndex += 1
                    if peerIndex > 1 { c.rawExtraPeers.append("[Peer]") }
                }
                continue
            }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let rawKey = line[..<eq].trimmingCharacters(in: .whitespaces)
            let key = rawKey.lowercased()
            let val = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)

            // Extra peers round-trip verbatim — keep the key's original case
            // rather than the lowercased copy used only to match known keys.
            if section == .peer && peerIndex > 1 { c.rawExtraPeers.append("\(rawKey) = \(val)"); continue }

            switch (section, key) {
            case (.interface, "privatekey"): c.privateKey = val
            case (.interface, "address"): c.addresses = values(val)
            case (.interface, "dns"): c.dns = values(val)
            case (.interface, "mtu"): c.mtu = Int(val)
            case (.interface, "listenport"): c.listenPort = Int(val)
            case (.interface, "fwmark"): c.fwMark = val
            case (.interface, "table"): c.table = val
            case (.peer, "publickey"): c.peerPublicKey = val
            case (.peer, "presharedkey"): c.presharedKey = val
            case (.peer, "endpoint"): c.endpoint = val
            case (.peer, "allowedips"): c.allowedIPs = values(val)
            case (.peer, "persistentkeepalive"): c.persistentKeepalive = Int(val)
            default: break
            }
        }
        return c
    }

    /// Serialize back to a wg-quick .conf.
    func serialize() -> String {
        var out = "[Interface]\n"
        if !privateKey.isEmpty { out += "PrivateKey = \(privateKey)\n" }
        if !addresses.isEmpty { out += "Address = \(addresses.joined(separator: ", "))\n" }
        if !dns.isEmpty { out += "DNS = \(dns.joined(separator: ", "))\n" }
        if let mtu { out += "MTU = \(mtu)\n" }
        if let listenPort { out += "ListenPort = \(listenPort)\n" }
        if !fwMark.isEmpty { out += "FwMark = \(fwMark)\n" }
        if !table.isEmpty { out += "Table = \(table)\n" }
        out += "\n[Peer]\n"
        if !peerPublicKey.isEmpty { out += "PublicKey = \(peerPublicKey)\n" }
        if !presharedKey.isEmpty { out += "PresharedKey = \(presharedKey)\n" }
        if !endpoint.isEmpty { out += "Endpoint = \(endpoint)\n" }
        if !allowedIPs.isEmpty { out += "AllowedIPs = \(allowedIPs.joined(separator: ", "))\n" }
        if let persistentKeepalive { out += "PersistentKeepalive = \(persistentKeepalive)\n" }
        if !rawExtraPeers.isEmpty { out += "\n" + rawExtraPeers.joined(separator: "\n") + "\n" }
        return out
    }

    /// Keychain identity for this profile's secrets — the "wg.<id>" convention
    /// the editor already used for the private key alone; now the one place
    /// every save/read path agrees on for both the key and the preshared key.
    var keychainProfile: String { "wg.\(id)" }

    /// This config with `privateKey`/`presharedKey` filled in from the keychain
    /// when the in-memory copy has them redacted — which is the normal case for
    /// anything loaded from `WireGuardStore` or providerConfiguration, since
    /// every save path strips them from the persisted copy. Used by anything
    /// that needs the real secret (export, the doctor/probe handshake), not
    /// just to display "set"/"not set".
    func withSecretsFromKeychain() -> WireGuardConfig {
        guard privateKey.isEmpty || presharedKey.isEmpty else { return self }
        let creds = KeychainCredentialStore.loadCredentials(profile: keychainProfile)
        var c = self
        if c.privateKey.isEmpty { c.privateKey = creds?.password ?? "" }
        if c.presharedKey.isEmpty { c.presharedKey = creds?.proxyPassword ?? "" }
        return c
    }

    /// The copy that may be PERSISTED (providerConfiguration / UserDefaults):
    /// same config, secrets stripped. The keys live in the keychain and ride
    /// startTunnel options — never storage.
    func redactedForStorage() -> WireGuardConfig {
        var c = self
        c.privateKey = ""
        c.presharedKey = ""
        return c
    }

    /// This config with an imported `.conf` applied over it. Every field the file
    /// carries wins — that is what importing means — with ONE exception: a file
    /// that carries no `PrivateKey` (or no `PresharedKey`) is not an instruction
    /// to DELETE the stored one. The editor used to replace the draft wholesale,
    /// so importing a `.conf` without a `PresharedKey` line blanked the draft's
    /// copy, and Save then wrote that blank over the key in the keychain.
    ///
    /// `name` is the imported file's name when there is one (a file import), nil
    /// when the text came from the paste sheet and the VPN keeps the name it has.
    ///
    /// The same reasoning covers the two settings that are OURS and have no wg-quick
    /// key at all — the search list and the local-network carve-out. A `.conf` cannot
    /// express either, so a file can never be an instruction to change them, and
    /// taking the imported (default) value would silently turn the carve-out off and
    /// throw the search list away on any re-import.
    func applyingImport(_ imported: WireGuardConfig, name: String?) -> WireGuardConfig {
        var next = imported
        next.id = id                                    // identity is never imported
        next.name = name ?? self.name
        if next.privateKey.isEmpty { next.privateKey = privateKey }
        if next.presharedKey.isEmpty { next.presharedKey = presharedKey }
        next.searchDomains = searchDomains
        next.allowLocalNetworkAccess = allowLocalNetworkAccess
        return next
    }

    // MARK: Export — the ONE place that decides what leaves the Mac
    //
    // THE DECISION, AND WHY IT IS NOT THE `.ovpn` ONE. `Export .ovpn…` omits its
    // secret blocks with no opt-out, because an `.ovpn` without a client key still
    // usefully describes the server and the material is recoverable — it is in the
    // keychain, and whoever issued the VPN can reissue it. Neither half holds here:
    //
    //  • `wg-quick up` REFUSES a configuration with no `PrivateKey`, so a
    //    secret-free WireGuard file cannot be used by the receiving client at all.
    //  • A WireGuard public key is DERIVED from the private key and registered
    //    against the peer on the server. "Ask them to reissue it" is not something
    //    the user can do alone the way an OpenVPN CA reissue is: a new key pair
    //    means the server's own peer entry has to change too.
    //
    // So omission-with-no-opt-out would mean the app can never move a working
    // WireGuard VPN onto a phone or a second Mac, which is the commonest reason
    // anyone exports one. The answer is EXPLICIT CONSENT, built so that the leaky
    // path cannot be reached by clicking through:
    //
    //  1. The default export (`includingSecrets: false`) leaves both keys out, and
    //     is what the plain `Export .conf…` button does. No dialog, so there is
    //     nothing to click through TO the leak.
    //  2. Writing the keys is a SEPARATE, differently-named action whose
    //     confirmation names the material, says what a holder of the file can do,
    //     and says the file cannot be recalled — and whose confirming button says
    //     what it will do, never "OK".
    //  3. EITHER file says what it contains in its own header. That is the `.ovpn`
    //     exporter's precedent and it is the half that survives the file being
    //     forwarded, renamed, or found in a backup two years later.

    /// The fields of a WireGuard configuration whose value is a secret. ONE list,
    /// and it lives here because `Shared/` cannot see the app target's
    /// `ConfigSecrets` — `WireGuardExportTests` asserts `ConfigSecrets.secretFields`
    /// is a superset of it, so the two cannot drift apart in silence.
    static let secretFieldNames = ["privateKey", "presharedKey"]

    /// The house term for one of them (ONTOLOGY): a noun phrase with no article, and
    /// deliberately the same nouns `ConfigSecrets.humanName` produces, so one VPN's
    /// key is called one thing everywhere in the app.
    static func humanName(forSecretField field: String) -> String {
        switch field {
        case "privateKey": "private key"
        case "presharedKey": "pre-shared key"
        default: field
        }
    }

    /// Which secrets this configuration actually holds, in `secretFieldNames` order.
    /// A key that was never set is nothing to warn about and nothing to explain —
    /// the same rule the JSON/YAML exporter follows.
    var presentSecretFields: [String] {
        Self.secretFieldNames.filter { field in
            switch field {
            case "privateKey": !privateKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            case "presharedKey": !presharedKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            default: false
            }
        }
    }

    /// The line left where a secret went, so a reader of the exported file knows the
    /// omission was deliberate and where the value belongs.
    ///
    /// It names the material in HOUSE TERMS and never writes the wg-quick key name,
    /// for the same reason `OVPNSecretMaterial`'s marker never writes `<key>`: an
    /// exported secret-free file must not contain the literal token `PrivateKey`
    /// anywhere, so that "does this file mention a private key line at all" is a
    /// question a plain grep — and the test that greps — can answer.
    static let secretMarkerPrefix = "# SimpleVPN: this VPN\u{2019}s "
    static let secretMarkerSuffix = " is kept in your keychain, not in this file."
    static func secretMarker(for field: String) -> String {
        "\(secretMarkerPrefix)\(humanName(forSecretField: field))\(secretMarkerSuffix)"
    }

    /// An English list of house terms ("private key and pre-shared key").
    static func humanList(_ fields: [String]) -> String {
        let names = fields.map { humanName(forSecretField: $0) }
        switch names.count {
        case 0: return ""
        case 1: return names[0]
        case 2: return "\(names[0]) and \(names[1])"
        default: return names.dropLast().joined(separator: ", ") + " and " + names[names.count - 1]
        }
    }

    /// The text `Export .conf…` writes.
    ///
    /// `includingSecrets: false` is the default everywhere and the only thing a
    /// plain click can produce. It is still a real wg-quick file for everything that
    /// is not a secret — the endpoint, the peer's public key, the allowed networks,
    /// DNS, MTU, the routing table and the firewall mark all round-trip.
    func exportText(includingSecrets: Bool) -> String {
        let present = presentSecretFields
        guard !present.isEmpty else {
            // Nothing secret to decide about: no header, no notes, no lecture about
            // a key this VPN never had.
            return serialize()
        }
        if includingSecrets {
            return Self.secretBearingHeader(present) + serialize()
        }
        return Self.secretFreeHeader(present) + Self.markedUpBody(redactedForStorage().serialize(),
                                                                  omitting: present)
    }

    /// The redacted body with a marker line under the section each omitted key
    /// belongs to, so the gap is visible where it matters rather than only in the
    /// header.
    private static func markedUpBody(_ body: String, omitting fields: [String]) -> String {
        var out: [String] = []
        for line in body.components(separatedBy: "\n") {
            out.append(line)
            let tag = line.trimmingCharacters(in: .whitespaces).lowercased()
            if tag == "[interface]", fields.contains("privateKey") {
                out.append(secretMarker(for: "privateKey"))
            }
            if tag == "[peer]", fields.contains("presharedKey") {
                out.append(secretMarker(for: "presharedKey"))
            }
        }
        return out.joined(separator: "\n")
    }

    /// The header of a file with the keys LEFT OUT. It has to say the receiving
    /// client will refuse the file, because that is the whole difference from an
    /// `.ovpn`: a silently unusable configuration that fails on the other machine
    /// with no explanation is worse than one that explains itself.
    private static func secretFreeHeader(_ omitted: [String]) -> String {
        """
        # ----------------------------------------------------------------------
        # Exported by SimpleVPN. No secrets are in this file.
        #
        # Left out on purpose, because they are secrets: this VPN\u{2019}s
        # \(humanList(omitted)). SimpleVPN keeps \(omitted.count == 1 ? "it" : "them") in your keychain and
        # did not write \(omitted.count == 1 ? "it" : "them") here.
        #
        # wg-quick REFUSES a configuration with no private-key line, so put yours
        # back under [Interface] before using this file \u{2014} paste it in by hand,
        # or ask whoever set up this VPN.
        # ----------------------------------------------------------------------

        """
    }

    /// The header of a file that DOES carry the keys. Blunt on purpose: this is the
    /// half of the consent that survives the file being forwarded, renamed, or found
    /// in a backup by somebody who never saw the dialog.
    private static func secretBearingHeader(_ present: [String]) -> String {
        """
        # ----------------------------------------------------------------------
        # Exported by SimpleVPN. THIS FILE CONTAINS SECRETS.
        #
        # In the clear, below: this VPN\u{2019}s \(humanList(present)).
        # Anyone who can read this file can connect to this VPN as this Mac.
        #
        # It has none of the protection SimpleVPN gave \(present.count == 1 ? "it" : "them") \u{2014} nothing here
        # is encrypted, and a copy in mail, a shared folder, a repository or a
        # backup cannot be recalled. Delete it once the other client has it.
        # ----------------------------------------------------------------------

        """
    }

    // MARK: The consent, in words

    /// What the app asks before it writes a file with the keys in it.
    ///
    /// SPECIFIC, not generic. A consent dialog is a thing people click through, so
    /// "Are you sure?" buys nothing: this names the material, says what someone
    /// holding the file can do with it, says the file cannot be recalled, and points
    /// at the safe action instead. The confirming button says what it does.
    var exportConsentTitle: String {
        "Write this VPN\u{2019}s \(Self.humanList(presentSecretFields)) to a file?"
    }

    var exportConsentMessage: String {
        let present = presentSecretFields
        let it = present.count == 1 ? "it" : "them"
        return """
            The file will contain this VPN\u{2019}s \(Self.humanList(present)) in the clear. \
            Anyone who can read the file can connect to this VPN as this Mac.

            It leaves every protection SimpleVPN has \u{2014} mail, a shared folder, a repository, \
            a Time Machine backup \u{2014} and once the file exists it cannot be recalled. \
            Delete it as soon as the other client has \(it).

            To hand someone the settings without the \(present.count == 1 ? "key" : "keys"), \
            use \u{201C}Export .conf…\u{201D} instead.
            """
    }

    /// The confirming button. Never \u{201C}OK\u{201D}: it says the thing it will do, which is
    /// the only wording a person skimming a dialog actually reads.
    var exportConsentConfirmTitle: String {
        switch presentSecretFields {
        case ["privateKey"]: "Export With Private Key"
        case ["presharedKey"]: "Export With Pre-shared Key"
        default: "Export With Keys"
        }
    }

    /// The sentence the app says after a secret-free export. Empty when there was
    /// nothing to leave out — mirrors `OVPNSecretMaterial.exportOmissionNotice`,
    /// because a note inside a file nobody reopens tells nobody anything.
    var exportOmissionNotice: String {
        let omitted = presentSecretFields
        guard !omitted.isEmpty else { return "" }
        return "Exported without this VPN\u{2019}s \(Self.humanList(omitted)) \u{2014} "
            + "\(omitted.count == 1 ? "it stays" : "those stay") in your keychain. "
            + "wg-quick refuses a configuration with no private-key line, so whoever "
            + "receives this file has to paste one back in. The file says so too."
    }

    /// What `setWireGuardSecrets` must be handed for the pre-shared key: nil =
    /// leave the stored one alone, "" = remove it, a value = replace it.
    ///
    /// The private key already followed this rule and the pre-shared key did not:
    /// it was passed as a plain value, so an EMPTY draft (an import that carried
    /// no key) read as "replace with nothing" and destroyed the stored key. Only
    /// the explicit Remove button clears it now.
    static func presharedKeyToSave(draft: String, removing: Bool) -> String? {
        if removing { return "" }
        let s = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        return s.isEmpty ? nil : s
    }
}

// MARK: - providerConfiguration blob

nonisolated extension WireGuardConfig {
    /// Decode the providerConfiguration["wireguard"] blob. A missing or corrupt
    /// blob degrades to an empty config — a settings problem must never crash
    /// the dispatch (the connect gate reports it as unconfigured instead).
    static func decode(from blob: Data?) -> WireGuardConfig {
        guard let blob, let c = try? JSONDecoder().decode(WireGuardConfig.self, from: blob) else {
            return WireGuardConfig()
        }
        return c
    }

    func encodedBlob() -> Data? { try? JSONEncoder().encode(self) }
}

// MARK: - Validation

nonisolated extension WireGuardConfig {

    // MARK: Legal ranges (single source of truth for UI validation)
    //
    // Mirrors OpenVPNOverrides's block: the editor's bound and the stored bound
    // are the same constant, so they cannot drift.

    /// Tunnel MTU. The floor is IPv4's minimum reassembly buffer (RFC 791), the
    /// same floor `SubprocessTunnelConfig.ocMTURange` uses: sub-1280 MTUs are
    /// LEGAL WireGuard and common in the wild — PPPoE and double-NAT providers
    /// ship 1200/1240 in the `.conf` they hand you, and wg-quick honours it. The
    /// floor used to be 1280 (IPv6's minimum link MTU), which meant `normalized()`
    /// silently threw a working 1200 away on the next save and left the tunnel
    /// hanging on large packets. Below 1280 is a CAVEAT (no IPv6), not a refusal —
    /// see `mtuBelowIPv6MinimumCaveat`. The ceiling is standard Ethernet: anything
    /// larger can't leave the Mac.
    static let mtuRange = 576...1500
    /// The IPv6 minimum link MTU (RFC 8200). Legal to go below — it just costs
    /// IPv6 inside the tunnel.
    static let ipv6MinimumMTU = 1280
    /// Local UDP port wireguard-go binds. 0 = let the system choose one.
    static let listenPortRange = 0...65535
    /// Ports only root may bind. Legal WireGuard, but not for OUR extension —
    /// hence a caveat on the row rather than a refusal.
    static let privilegedPortRange = 1...1023
    /// `PersistentKeepalive` is a uint16 number of seconds on the wire.
    /// 0 = off; 25 is the usual value behind NAT.
    static let keepaliveRange = 0...65535
    /// A WireGuard key is a Curve25519 scalar or point — exactly 32 bytes,
    /// which is 44 characters of base64 (43 + one "=" of padding).
    static let keyByteCount = 32

    /// The non-blocking caveat for an MTU below the IPv6 minimum, or nil. The
    /// tunnel works — it just can't carry IPv6, because no IPv6 link may have an
    /// MTU under 1280 (RFC 8200 §5).
    static func mtuBelowIPv6MinimumCaveat(_ mtu: Int?) -> String? {
        guard let mtu, mtu < ipv6MinimumMTU else { return nil }
        return "\(mtu) is below 1280, the smallest MTU IPv6 allows, so this tunnel can carry IPv4 only — anything IPv6 inside it will fail. That is fine (and sometimes necessary) on a link that can't carry more; raise it to 1280 or above if you need IPv6."
    }

    /// Why this MTU can't be stored, in the user's language, or nil. BLOCKING
    /// (the editor's Save), which is the alternative to what `normalized()` used
    /// to do: silently replace the number with "engine default" and let the user
    /// discover it later.
    static func mtuProblem(_ mtu: Int?) -> String? {
        guard let mtu, !mtuRange.contains(mtu) else { return nil }
        return "Enter an MTU between \(mtuRange.lowerBound) and \(mtuRange.upperBound), or leave it empty for the engine's own \(WireGuardStartConfig.defaultMTU)."
    }

    /// Trim, drop empties, and collapse out-of-range numbers back to "engine
    /// default" (nil). Called from every save path so the stored value can
    /// never be one the editor's own ranges would refuse — the same shape as
    /// `OpenVPNOverrides.normalized()`.
    ///
    /// It is a BACKSTOP for values that arrive from an import, the CLI or MDM, not
    /// the thing that decides what a user's Save does: the editor blocks Save on
    /// an out-of-range MTU or an unusable `Table` (`mtuProblem`, `tableProblem`)
    /// rather than letting this quietly rewrite what they typed. A silent rewrite
    /// here is how a working 1200-byte MTU became "engine default 1420" on an
    /// unrelated save.
    func normalized() -> WireGuardConfig {
        var n = self
        func clean(_ s: String) -> String { s.trimmingCharacters(in: .whitespacesAndNewlines) }
        func cleanList(_ l: [String]) -> [String] {
            l.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        }
        n.name = clean(name)
        n.endpoint = clean(endpoint)
        n.peerPublicKey = clean(peerPublicKey)
        n.privateKey = clean(privateKey)
        n.presharedKey = clean(presharedKey)
        n.fwMark = clean(fwMark)
        n.table = clean(table)
        n.addresses = cleanList(addresses)
        n.allowedIPs = cleanList(allowedIPs)
        n.dns = cleanList(dns)
        n.searchDomains = DNSSearchDomains.normalized(searchDomains)
        if let v = n.mtu, !Self.mtuRange.contains(v) { n.mtu = nil }
        if let v = n.listenPort, !Self.listenPortRange.contains(v) { n.listenPort = nil }
        if let v = n.persistentKeepalive, !Self.keepaliveRange.contains(v) { n.persistentKeepalive = nil }
        // Both have a grammar in wg-quick, and only a value OUTSIDE it collapses
        // to "not set" — the editor blocks Save on one (so this is the CLI/MDM/
        // import backstop, never the thing that rewrites what a user typed).
        // `Table` accepts rt_tables NAMES as well as numbers: `Table = main` is
        // valid wg-quick and used to be blanked here, dropping the line from any
        // exported .conf.
        if !n.table.isEmpty, !Self.isValidTable(n.table) { n.table = "" }
        if !n.fwMark.isEmpty, !Self.isValidFwMark(n.fwMark) { n.fwMark = "" }
        return n
    }

    /// wg-quick's `Table` grammar: `auto`, `off`, a routing-table NUMBER, or a
    /// routing-table NAME. wg-quick passes anything else straight to
    /// `ip route … table <value>`, which resolves names out of `rt_tables` — so
    /// `Table = main` is perfectly good wg-quick and used to be blanked on save,
    /// silently dropping the line from an exported `.conf`.
    static let tableNumberRange = 0...0xFFFF_FFFF
    static func isValidTable(_ raw: String) -> Bool {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if s == "auto" || s == "off" { return true }
        if let n = Int(s) { return tableNumberRange.contains(n) }
        return isValidTableName(s)
    }

    /// An `rt_tables` name: what iproute2 will look up. Its own parser takes a
    /// token of printable non-space characters, so the only thing refused here is
    /// something that could not be one identifier on one line.
    static func isValidTableName(_ raw: String) -> Bool {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty, s.count <= 64 else { return false }
        return s.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || "_-.".contains($0)) }
    }

    /// Why this routing table isn't one wg-quick would take, or nil.
    static func tableProblem(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty || isValidTable(s) { return nil }
        return "Enter a routing-table name (like main) or a number up to 4294967295 — or choose auto/off above."
    }

    /// wg-quick's `FwMark` grammar: `off`, or an unsigned 32-bit number written in
    /// decimal or as `0x…` hex.
    static func isValidFwMark(_ raw: String) -> Bool {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if s == "off" { return true }
        if s.hasPrefix("0x") {
            guard let n = UInt32(s.dropFirst(2), radix: 16) else { return false }
            return n == n     // any UInt32 is legal
        }
        return UInt32(s) != nil
    }

    /// The endpoint's host half (for serverAddress / probes / the map pin).
    var endpointHost: String {
        let s = endpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return "" }
        if s.hasPrefix("[") {   // [v6]:port
            return String(s.dropFirst().prefix { $0 != "]" })
        }
        guard let colon = s.lastIndex(of: ":"), !s[s.index(after: colon)...].contains(":") else {
            // No port, or a bare v6 literal — return as typed.
            return s
        }
        return String(s[..<colon])
    }

    /// Why this endpoint can't be used, in the user's language — nil when it's
    /// fine. Mirrors wgResolveEndpoint() in the Go shim; both sides must agree
    /// or the editor accepts something the engine rejects.
    static func endpointProblem(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty { return "Enter the server's address as host:port (like vpn.example.com:51820)." }
        // The endpoint is persisted in providerConfiguration (and becomes the
        // shown server address), so anything credential-shaped typed here would
        // be stored in the clear — and WireGuard has no username or password to
        // carry anyway: the keys ARE the sign-in. Same rule, same reason, as
        // ProxyTunnelConfig.upstreamProblem and the Tailscale control URL.
        if s.contains("@") {
            return "The endpoint is just the server's address and port — no username or password."
        }
        let hostPart: Substring
        let portPart: Substring
        if s.hasPrefix("[") {   // [v6]:port
            guard let close = s.firstIndex(of: "]"), s.index(after: close) < s.endIndex,
                  s[s.index(after: close)] == ":" else {
                return "An IPv6 endpoint is written [address]:port."
            }
            hostPart = s[s.index(after: s.startIndex)..<close]
            portPart = s[s.index(close, offsetBy: 2)...]
        } else {
            guard let colon = s.lastIndex(of: ":"), !s[s.index(after: colon)...].contains(":") else {
                return "The endpoint is missing its port (like vpn.example.com:51820)."
            }
            hostPart = s[..<colon]
            portPart = s[s.index(after: colon)...]
            // A bare v6 literal parses as host="2001:db8:" port="1" — catch it.
            if hostPart.contains(":") { return "An IPv6 endpoint is written [address]:port." }
        }
        if hostPart.isEmpty { return "The endpoint is missing a host name." }
        guard let port = Int(portPart), (1...65535).contains(port) else {
            return "\(portPart) isn't a valid port."
        }
        return nil
    }

    /// Why a CIDR (an allowed network) can't be used — nil when it's fine. Same
    /// rules as the Go side (parseRoutes): a real CIDR, in range, no host bits.
    /// Self-contained (not delegating to TailscaleConfig's twin) because this
    /// must be callable from the nonisolated settings builder and connect gate.
    static func routeProblem(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return "Enter a network like 10.0.0.0/24 (or 0.0.0.0/0 for everything)." }
        let parts = s.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, let prefix = Int(parts[1]) else {
            return "\(s) is missing the /length (for example 0.0.0.0/0 or 10.0.0.0/24)."
        }
        let address = String(parts[0])
        let isV6 = address.contains(":")
        let maxPrefix = isV6 ? 128 : 32
        guard prefix >= 0, prefix <= maxPrefix else {
            return "\(s) has a length outside 0\u{2013}\(maxPrefix)."
        }
        var bytes = [UInt8](repeating: 0, count: 16)
        let ok = address.withCString { inet_pton(isV6 ? AF_INET6 : AF_INET, $0, &bytes) == 1 }
        guard ok else { return "\(address) isn't a valid address." }
        // Host bits set would be silently rejected by the engine — say so here.
        let byteCount = isV6 ? 16 : 4
        for i in 0..<byteCount {
            let bitsBefore = i * 8
            if prefix >= bitsBefore + 8 { continue }
            let keep = max(0, min(8, prefix - bitsBefore))
            let mask: UInt8 = keep == 0 ? 0 : UInt8(truncatingIfNeeded: 0xFF << (8 - keep))
            if bytes[i] & ~mask != 0 {
                return "\(s) isn't the start of a network — check the /length."
            }
        }
        return nil
    }

    /// First problem across a route list, or nil.
    static func routesProblem(_ list: [String]) -> String? {
        for r in list {
            if let p = routeProblem(r) { return p }
        }
        return nil
    }

    /// Why this device's own tunnel address can't be used — nil when it's fine.
    ///
    /// DELIBERATELY NOT `routeProblem`: an INTERFACE address legitimately carries
    /// host bits — `10.0.0.2/24` is exactly what a provider hands you, and the
    /// prefix there describes the on-link network, not a route. Running the
    /// route check over this row would reject a perfectly correct config, which
    /// is the other half of the rule (never refuse what the engine accepts).
    /// So: a real address, and a prefix in range when one is written at all.
    static func interfaceAddressProblem(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return "Enter this device's tunnel address, like 10.0.0.2/32." }
        let parts = s.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let address = String(parts[0])
        let isV6 = address.contains(":")
        var bytes = [UInt8](repeating: 0, count: 16)
        let ok = address.withCString { inet_pton(isV6 ? AF_INET6 : AF_INET, $0, &bytes) == 1 }
        guard ok else { return "\(address) isn't a valid address." }
        // A bare address is fine — wg-quick and the settings builder both give
        // it a host prefix. Only a prefix that IS written gets range-checked.
        if parts.count == 2 {
            let maxPrefix = isV6 ? 128 : 32
            guard let prefix = Int(parts[1]), prefix >= 0, prefix <= maxPrefix else {
                return "\(s) has a length outside 0\u{2013}\(maxPrefix)."
            }
        }
        return nil
    }

    /// First problem across the interface-address list, or nil.
    static func addressesProblem(_ list: [String]) -> String? {
        for a in list {
            if let p = interfaceAddressProblem(a) { return p }
        }
        return nil
    }

    /// Why a base64 key can't be used — nil when it decodes to exactly 32 bytes
    /// (and nil for an empty string: "not set" is a different question, asked by
    /// whoever needs the key). An empty-handed 43-character paste — a key copied
    /// without its trailing "=" — is THE commonest real-world WireGuard mistake,
    /// and today it reaches the engine and fails the handshake with nothing for
    /// the user to look at.
    static func keyProblem(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return nil }
        guard let data = Data(base64Encoded: s) else {
            return "That isn't a valid key \u{2014} a WireGuard key is 44 characters of base64, ending in \u{201C}=\u{201D}."
        }
        guard data.count == Self.keyByteCount else {
            return "A WireGuard key is exactly \(Self.keyByteCount) bytes \u{2014} 44 characters of base64, ending in \u{201C}=\u{201D}. This one decodes to \(data.count) byte\(data.count == 1 ? "" : "s"); check the whole key was copied."
        }
        return nil
    }

    /// Why the whole config can't connect (the connect-flow gate), or nil.
    /// Deliberately does NOT check the private key: that lives in the keychain,
    /// not in this (redacted) value — the connect flow checks it separately.
    ///
    /// DERIVED from `connectFault` so that the sentence the connect path refuses with
    /// and the row the editor reddens can never name different fields. See
    /// `Shared/SettingFault.swift`.
    var connectProblem: String? { connectFault?.sentence }

    /// The same gate, WITH the field to blame — what the editor's red required-field
    /// marking is driven from (`SettingNeeds`). The order is the order a person can
    /// act on: identify the peer, reach it, address yourself, then choose what to send.
    var connectFault: SettingFault? {
        if peerPublicKey.trimmingCharacters(in: .whitespaces).isEmpty {
            return SettingFault("wg.public-key", "Enter the server peer's public key.")
        }
        // A truncated key is accepted by every layer until the handshake, where
        // it fails silently — so it's refused here, with the endpoint.
        if let p = Self.keyProblem(peerPublicKey) { return SettingFault("wg.public-key", p) }
        // `endpointProblem` answers for the EMPTY field too ("Enter the server's
        // address as host:port…"), which is what makes the one field a WireGuard VPN
        // cannot work without turn red before anything has been typed.
        if let p = Self.endpointProblem(endpoint) { return SettingFault("wg.endpoint", p) }
        if addresses.isEmpty {
            return SettingFault("wg.address",
                                "Add this device's tunnel address (like 10.0.0.2/32) \u{2014} it's in the config your provider gave you.")
        }
        if let p = Self.addressesProblem(addresses) { return SettingFault("wg.address", p) }
        if allowedIPs.isEmpty {
            return SettingFault("wg.allowed-ips",
                                "Add at least one allowed network (0.0.0.0/0, ::/0 sends everything).")
        }
        if let p = Self.routesProblem(allowedIPs) { return SettingFault("wg.allowed-ips", p) }
        if let p = DNSSearchDomains.problem(list: searchDomains) {
            return SettingFault("wg.search-domains", p)
        }
        // Only when one is actually present in this (usually redacted) copy —
        // the connect flow validates what the user typed separately.
        if let p = Self.keyProblem(presharedKey) { return SettingFault("wg.preshared-key", p) }
        return nil
    }

    /// DNS servers no Allowed IPs prefix covers — the classic split-tunnel
    /// footgun, and NON-blocking (the config is legal and everything else works).
    ///
    /// `WireGuardNetworkSettings` does install a /32 (/128) route for each
    /// advertised resolver, so the query DOES reach the utun. What stops it is
    /// the layer after: wireguard-go routes outbound packets by the peer's
    /// `allowed_ip` set (see `renderWGUAPI` in the Go shim), and a destination
    /// no peer claims has nowhere to go, so the packet is dropped. The tunnel
    /// connects, carries its networks fine, and every name lookup times out.
    ///
    /// A full tunnel covers everything, so there is nothing to report then.
    nonisolated static func dnsOutsideAllowedIPs(dns: [String], allowedIPs: [String]) -> [String] {
        let prefixes = allowedIPs
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        guard !prefixes.isEmpty else { return [] }
        // A default route in either family covers that family entirely.
        let coversV4 = prefixes.contains("0.0.0.0/0")
        let coversV6 = prefixes.contains("::/0")
        return dns.compactMap { raw in
            let server = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !server.isEmpty else { return nil }
            // A wg-quick `DNS =` line legitimately carries SEARCH DOMAINS beside
            // the resolvers ("DNS = 10.0.0.53, corp.example.com"). A domain is
            // not an address, has no prefix to be covered by, and used to be
            // reported here as uncovered — advising the user to "add
            // corp.example.com/32 to Allowed IPs", which is not a thing.
            guard isIPLiteral(server) else { return nil }
            if server.contains(":") ? coversV6 : coversV4 { return nil }
            // No prefix of the same family overlaps this address ⇒ uncovered.
            // A bare address parses as a host prefix, so `overlaps` compares it
            // against each allowed network at that network's own length.
            return prefixes.contains { RoutePrefixMath.overlaps(server, $0) } ? nil : server
        }
    }

    /// Whether this is a bare IPv4/IPv6 address literal (as opposed to a search
    /// domain, which a wg-quick `DNS =` line may also carry).
    nonisolated static func isIPLiteral(_ raw: String) -> Bool {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return false }
        var bytes = [UInt8](repeating: 0, count: 16)
        return s.withCString { inet_pton(s.contains(":") ? AF_INET6 : AF_INET, $0, &bytes) == 1 }
    }

    /// The caveat text for one uncovered resolver.
    nonisolated static func dnsCoverageWarning(_ server: String) -> String {
        "\(server) isn't inside any of the Allowed IPs above, so this peer won't carry lookups to it and DNS will simply stop. Add \(server)/\(server.contains(":") ? "128" : "32") to Allowed IPs, or use a resolver inside a network that is listed."
    }
}

// MARK: - Start payload (the WGStart contract)

/// Exactly the JSON `WGStart` parses. Field names are load-bearing — they are
/// checked against the Go side by TestWGStartConfigKeys over there and
/// WireGuardConfigTests over here.
nonisolated struct WireGuardStartConfig: Codable, Sendable, Equatable {
    /// Session-only. Reaches this struct from startTunnel options, is handed
    /// straight to the engine, and is never persisted or logged.
    var privateKey: String
    var peerPublicKey: String
    /// Session-only, same as the private key. Empty ⇒ none.
    var presharedKey: String
    var endpoint: String
    var allowedIPs: [String]
    var persistentKeepalive: Int
    var listenPort: Int
    var mtu: Int

    /// The wg-quick default: 1500 minus WireGuard's worst-case (IPv6)
    /// encapsulation overhead.
    static let defaultMTU = 1420

    init(config: WireGuardConfig, privateKey: String, presharedKey: String) {
        self.privateKey = privateKey
        peerPublicKey = config.peerPublicKey.trimmingCharacters(in: .whitespaces)
        self.presharedKey = presharedKey
        endpoint = config.endpoint.trimmingCharacters(in: .whitespaces)
        allowedIPs = config.allowedIPs
        persistentKeepalive = config.persistentKeepalive ?? 0
        listenPort = config.listenPort ?? 0
        mtu = (config.mtu ?? 0) > 0 ? config.mtu! : WireGuardStartConfig.defaultMTU
    }

    func jsonString() -> String {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        guard let d = try? enc.encode(self), let s = String(data: d, encoding: .utf8) else { return "{}" }
        return s
    }

    /// Same JSON with the keys replaced — the only form that may be logged.
    /// The peer PUBLIC key stays (public by construction, and the useful
    /// diagnostic when a config points at the wrong server).
    func redactedJSONString() -> String {
        var copy = self
        copy.privateKey = privateKey.isEmpty ? "" : "<redacted>"
        copy.presharedKey = presharedKey.isEmpty ? "" : "<redacted>"
        return copy.jsonString()
    }
}

// MARK: - Engine → app status (the WGStatus payload)

/// The WGStatus payload. A strict whitelist on the Go side — never carries key
/// material.
nonisolated struct WireGuardEngineStatus: Codable, Sendable, Equatable {
    var state: String = "stopped"
    var endpoint: String = ""
    var listenPort: Int = 0
    var rxBytes: Int64 = 0
    var txBytes: Int64 = 0
    /// Unix seconds of the last completed Noise handshake; 0 = never. THE
    /// WireGuard health signal: the protocol is silent, so a stale handshake
    /// (>~3 min with keepalive on) is what "down" looks like.
    var lastHandshake: Int64 = 0
    var packetsDropped: Int64 = 0

    var isRunning: Bool { state == "running" }
    var lastHandshakeDate: Date? {
        lastHandshake > 0 ? Date(timeIntervalSince1970: TimeInterval(lastHandshake)) : nil
    }

    init() {}

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        state = (try? c.decodeIfPresent(String.self, forKey: .state)) ?? "stopped"
        endpoint = (try? c.decodeIfPresent(String.self, forKey: .endpoint)) ?? ""
        listenPort = (try? c.decodeIfPresent(Int.self, forKey: .listenPort)) ?? 0
        rxBytes = (try? c.decodeIfPresent(Int64.self, forKey: .rxBytes)) ?? 0
        txBytes = (try? c.decodeIfPresent(Int64.self, forKey: .txBytes)) ?? 0
        lastHandshake = (try? c.decodeIfPresent(Int64.self, forKey: .lastHandshake)) ?? 0
        packetsDropped = (try? c.decodeIfPresent(Int64.self, forKey: .packetsDropped)) ?? 0
    }

    static func decode(json: String) -> WireGuardEngineStatus? {
        guard let d = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(WireGuardEngineStatus.self, from: d)
    }
}

@MainActor
@Observable
final class WireGuardStore {
    private(set) var configs: [WireGuardConfig] = []
    private static let key = "wireguard.v1"

    init() { load() }

    /// Save a config. Secrets never reach UserDefaults on ANY save path: the
    /// private key and preshared key (if set) move into the keychain under
    /// this profile's "wg.<id>" identity, and only a redacted copy is persisted.
    /// Callers that need the real values back (export, doctor/probe) use
    /// `WireGuardConfig.withSecretsFromKeychain()`.
    func save(_ raw: WireGuardConfig) {
        // Normalize on the way in (every save path does) so a stored value can
        // never be one the editor's own ranges would refuse.
        let c = raw.normalized()
        if !c.privateKey.isEmpty || !c.presharedKey.isEmpty {
            try? KeychainCredentialStore.saveCredentials(
                profile: c.keychainProfile,
                .init(username: c.name, password: c.privateKey,
                      proxyPassword: c.presharedKey.isEmpty ? nil : c.presharedKey))
        }
        var stored = c
        stored.privateKey = ""
        stored.presharedKey = ""
        if let i = configs.firstIndex(where: { $0.id == stored.id }) { configs[i] = stored } else { configs.append(stored) }
        persist()
    }
    func remove(_ id: String) {
        configs.removeAll { $0.id == id }
        KeychainCredentialStore.deleteCredentials(profile: "wg.\(id)")
        persist()
    }

    /// Drop a config from the store WITHOUT touching its keychain item — the
    /// migration path (VPNController.migrateLegacyWireGuardStore) moves the
    /// config into a real packet-tunnel profile that keeps the same id, so the
    /// "wg.<id>" keys must survive the handoff.
    func forget(_ id: String) {
        configs.removeAll { $0.id == id }
        persist()
    }

    private func load() {
        guard let d = UserDefaults.standard.data(forKey: Self.key),
              let list = try? JSONDecoder().decode([WireGuardConfig].self, from: d) else { return }
        configs = list
    }
    private func persist() {
        if let d = try? JSONEncoder().encode(configs) { UserDefaults.standard.set(d, forKey: Self.key) }
    }
}
