// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OVPNInline.swift
//  The syntax of an .ovpn's inline blocks, and the CLASSIFICATION of which of
//  them are secret.
//
//  Two types, deliberately together:
//
//   • `OVPNInline` reads and rewrites `<tag>…</tag>` regions. It moved here from
//     `SimpleVPN/Import/CertificateImport.swift` for one reason: the packet-tunnel
//     extension has to put the secret blocks BACK into the configuration it hands
//     the engine, and a second copy of this CRLF-sensitive parsing is exactly how
//     the two halves drift.
//   • `OVPNSecretMaterial` says which blocks are secret and splits them out. See
//     its own header for the per-tag decision and why each way round.
//

import Foundation
import CryptoKit

// MARK: - Slots

/// The four places a profile embeds crypto material.
nonisolated enum CertSlot: String, CaseIterable, Identifiable, Sendable {
    case ca, cert, key, tlsKey
    var id: String { rawValue }

    var title: String {
        switch self {
        case .ca: return "Certificate Authority"
        case .cert: return "Client Certificate"
        case .key: return "Private Key"
        case .tlsKey: return "TLS Key"
        }
    }
}

// MARK: - Profile inline blocks

/// Read/rewrite the inline blocks of an .ovpn. Setting a block also removes the
/// matching file-reference directive ("ca ca.crt") — after embedding, the file
/// is self-contained.
nonisolated enum OVPNInline {

    static func tags(for slot: CertSlot, in ovpn: String) -> [String] {
        switch slot {
        case .ca: return ["ca"]
        case .cert: return ["cert"]
        case .key: return ["key"]
        case .tlsKey: return ["tls-crypt", "tls-auth"]
        }
    }

    /// The content of the first present tag for the slot (nil = nothing embedded).
    static func block(for slot: CertSlot, in ovpn: String) -> (tag: String, content: String)? {
        for tag in tags(for: slot, in: ovpn) {
            if let c = block(tag, in: ovpn) { return (tag, c) }
        }
        return nil
    }

    static func block(_ tag: String, in ovpn: String) -> String? {
        guard let open = ovpn.range(of: "<\(tag)>"),
              let close = ovpn.range(of: "</\(tag)>", range: open.upperBound..<ovpn.endIndex) else { return nil }
        return String(ovpn[open.upperBound..<close.lowerBound])
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Replace/insert (content != nil) or remove (content == nil) a block, and
    /// drop any "tag <file>" reference lines for it.
    static func setBlock(_ tag: String, content: String?, in ovpn: String) -> String {
        var lines = ovpn.components(separatedBy: "\n")

        // Trim with .whitespacesAndNewlines throughout: a CRLF profile leaves a
        // trailing "\r" on every line, and .whitespaces does NOT strip it — so
        // "<ca>\r" != "<ca>" and the old region would never be found, leaving a
        // duplicate block on export (breaks the round-trip contract).
        func norm(_ s: String) -> String { s.trimmingCharacters(in: .whitespacesAndNewlines) }

        // Remove an existing <tag>…</tag> region.
        if let open = lines.firstIndex(where: { norm($0) == "<\(tag)>" }),
           let close = lines[open...].firstIndex(where: { norm($0) == "</\(tag)>" }) {
            lines.removeSubrange(open...close)
        }
        // Remove file-reference directives ("ca ca.crt", "tls-auth ta.key 1"…).
        lines.removeAll { line in
            let t = norm(line)
            return t == tag || t.hasPrefix("\(tag) ")
        }

        if let content {
            while lines.last?.isEmpty == true { lines.removeLast() }
            lines.append("<\(tag)>")
            lines.append(content.trimmingCharacters(in: .whitespacesAndNewlines))
            lines.append("</\(tag)>")
        }
        return lines.joined(separator: "\n")
    }

    /// Set (value != nil) or remove (nil) a simple single-line directive
    /// ("key value"), replacing any existing occurrence. CRLF-safe. Used by the
    /// Connection Doctor to apply fixes like `mssfix 1360`, `keepalive 10 60`,
    /// `reneg-sec 0` that aren't ClientAPI overrides.
    static func setDirective(_ key: String, _ value: String?, in ovpn: String) -> String {
        var lines = ovpn.components(separatedBy: "\n")
        lines.removeAll { line in
            let t = line.trimmingCharacters(in: .whitespacesAndNewlines)
            return t == key || t.hasPrefix("\(key) ")
        }
        if let value {
            while lines.last?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == true { lines.removeLast() }
            lines.append(value.isEmpty ? key : "\(key) \(value)")
        }
        return lines.joined(separator: "\n")
    }

    /// The value of a simple directive ("key value" → "value"), or nil. Bare
    /// flags return "". CRLF-safe.
    static func directiveValue(_ key: String, in ovpn: String) -> String? {
        for line in ovpn.components(separatedBy: "\n") {
            let t = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if t == key { return "" }
            if t.hasPrefix("\(key) ") { return String(t.dropFirst(key.count + 1)).trimmingCharacters(in: .whitespaces) }
        }
        return nil
    }

    /// Set (direction != nil) or remove (nil) the standalone key-direction
    /// directive. CRLF-safe. Appended after any tls-auth block if newly added.
    static func setKeyDirection(_ direction: String?, in ovpn: String) -> String {
        var lines = ovpn.components(separatedBy: "\n")
        lines.removeAll { $0.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("key-direction") }
        if let direction {
            while lines.last?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == true { lines.removeLast() }
            lines.append("key-direction \(direction)")
        }
        return lines.joined(separator: "\n")
    }

    /// tls-crypt vs tls-auth: what the profile already uses (directive or block).
    static func tlsKeyMode(in ovpn: String) -> String? {
        for tag in ["tls-crypt", "tls-auth"] {
            if block(tag, in: ovpn) != nil { return tag }
            if ovpn.components(separatedBy: "\n").contains(where: {
                let t = $0.trimmingCharacters(in: .whitespacesAndNewlines)
                return t == tag || t.hasPrefix("\(tag) ")
            }) { return tag }
        }
        return nil
    }

    /// The profile's key-direction (from "key-direction" or a tls-auth direction arg).
    static func keyDirection(in ovpn: String) -> String? {
        for line in ovpn.components(separatedBy: "\n") {
            let parts = line.trimmingCharacters(in: .whitespaces)
                .split(separator: " ", omittingEmptySubsequences: true)
            if parts.count >= 2, parts[0] == "key-direction" { return String(parts[1]) }
            if parts.count >= 3, parts[0] == "tls-auth" { return String(parts[2]) }
        }
        return nil
    }
}

// MARK: - Which inline blocks are secret

/// Splits the SECRET inline blocks out of an .ovpn so the stored profile carries
/// none of them, and puts them back for the engine at connect time.
///
/// WHY THIS EXISTS. `providerConfiguration["ovpn"]` is the raw configuration
/// text, and an `.ovpn` may inline its client private key. Storing it there put a
/// private key in the VPN preferences, and `Export .ovpn…` wrote it to whatever
/// file the user chose, in the clear. `WireGuardConfig.redactedForStorage()`
/// already establishes the pattern for exactly this problem in this codebase;
/// OpenVPN was the outlier.
///
/// THE DECISION, PER BLOCK. Getting this wrong in the *other* direction — moving
/// a public certificate into the keychain — makes certificate handling worse and
/// buys nothing, so each tag was decided on its own:
///
/// | Block | Secret | Why |
/// |---|---|---|
/// | `<key>` | **yes** | The client private key. Whoever holds it IS the client. |
/// | `<tls-auth>` | **yes** | A shared symmetric HMAC key over the control channel. |
/// | `<tls-crypt>` | **yes** | A shared symmetric key that *encrypts* the control channel. |
/// | `<tls-crypt-v2>` | **yes** | A per-client symmetric key plus the wrapped server key. |
/// | `<secret>` | **yes** | Static-key mode's shared key — it protects the whole data channel. |
/// | `<pkcs12>` | **yes** | A PKCS#12 bundle *contains* the private key. |
/// | `<auth-user-pass>` | **yes** | An inline username and password. |
/// | `<http-proxy-user-pass>` | **yes** | An inline proxy username and password. |
/// | `<ca>` | no | A public CA certificate — **and integrity-critical**, so it has to stay in the configuration where a review or a diff can see it. |
/// | `<cert>` | no | A public client certificate. Carries no secret, and the Certificates tab needs it to check that the key matches. |
/// | `<extra-certs>` | no | More public certificates in the chain. |
/// | `<crl-verify>` | no | A public revocation list. |
/// | `<dh>` | no | Public Diffie–Hellman parameters. |
///
/// None of this weakens certificate *verification*: `<ca>` and `<cert>` are
/// untouched and the engine sees a byte-identical configuration at connect.
///
/// WHERE THE MATERIAL GOES. `KeychainCredentialStore.saveOVPNInlineSecrets`,
/// keyed by profile id, app-only. It reaches the engine the way every other
/// per-profile secret already does — `startTunnel(options:)` — because the
/// extension runs as root in the system context and cannot read the user's
/// keychain. openvpn3 takes the configuration as a *string*, so the blocks are
/// spliced back in there (`merge`) and never persisted.
nonisolated enum OVPNSecretMaterial {

    /// Inline tags whose content is a secret. Order is fixed so `merge` produces
    /// the same text every time — `hasPendingSettings` compares two of these
    /// strings and a shuffled order would read as an unsaved change.
    static let secretTags = ["key", "tls-auth", "tls-crypt", "tls-crypt-v2",
                             "secret", "pkcs12", "auth-user-pass", "http-proxy-user-pass"]

    /// Inline tags that are PUBLIC and must stay in the stored configuration.
    /// Listed rather than implied so the choice is visible, and asserted by test
    /// against `secretTags` so a tag can never be in both.
    static let publicTags = ["ca", "cert", "extra-certs", "crl-verify", "dh"]

    /// The line left where a secret block was. Both halves matter: it is readable
    /// by whoever inspects the stored configuration, and it has a stable prefix so
    /// `merge`/`exportText` can find it again. Never seen by the user in the
    /// editor — `VPNController.ovpnText(id:)` hands back the reassembled text.
    ///
    /// It names the tag in QUOTES rather than in angle brackets on purpose: a
    /// stored profile or an exported file must not contain the literal string
    /// `<key>` anywhere, so that "does this text mention a key block at all" is a
    /// question a plain grep — and the test that greps — can answer.
    static let markerPrefix = "# SimpleVPN: this VPN's \""
    static let markerSuffix = "\" block is kept in your keychain, not in this file."

    static func marker(for tag: String) -> String { "\(markerPrefix)\(tag)\(markerSuffix)" }

    /// What to CALL a block when talking to the user. ONTOLOGY house terms — the
    /// OpenVPN tag is the vendor's word and stays in quotes where it appears.
    static func humanName(for tag: String) -> String {
        switch tag {
        case "key", "pkcs12": return "private key"
        case "tls-auth", "tls-crypt", "tls-crypt-v2": return "TLS key"
        case "secret": return "shared key"
        case "auth-user-pass": return "saved password"
        case "http-proxy-user-pass": return "proxy password"
        default: return tag
        }
    }

    struct Split: Equatable, Sendable {
        /// The configuration with every secret block replaced by a marker line.
        var config: String
        /// tag → block content, in the order the tags are declared above.
        var secrets: [String: String]
    }

    private static func norm(_ s: String) -> String {
        s.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Lift every secret block out. Idempotent: splitting an already-split
    /// configuration finds nothing and returns it unchanged.
    static func split(_ ovpn: String) -> Split {
        var lines = ovpn.components(separatedBy: "\n")
        var secrets: [String: String] = [:]
        for tag in secretTags {
            var replacedOnce = false
            while let open = lines.firstIndex(where: { norm($0) == "<\(tag)>" }),
                  let close = lines[open...].firstIndex(where: { norm($0) == "</\(tag)>" }) {
                let body = norm(lines[(open + 1)..<close].joined(separator: "\n"))
                // First occurrence wins, which is what openvpn3 does with a
                // duplicated block too. A later duplicate is dropped outright
                // rather than left behind as a second copy of the secret.
                if secrets[tag] == nil, !body.isEmpty { secrets[tag] = body }
                lines.replaceSubrange(open...close, with: replacedOnce ? [] : [marker(for: tag)])
                replacedOnce = true
            }
        }
        return Split(config: lines.joined(separator: "\n"), secrets: secrets)
    }

    /// Drop the marker lines, so they never accumulate across a
    /// split → merge → split cycle.
    static func stripMarkers(_ ovpn: String) -> String {
        var lines = ovpn.components(separatedBy: "\n")
        lines.removeAll { norm($0).hasPrefix(markerPrefix) }
        return lines.joined(separator: "\n")
    }

    /// Which tags a stored configuration says it is missing.
    static func markedTags(in ovpn: String) -> Set<String> {
        var out: Set<String> = []
        for line in ovpn.components(separatedBy: "\n") {
            let t = norm(line)
            guard t.hasPrefix(markerPrefix), t.hasSuffix(markerSuffix) else { continue }
            let tag = String(t.dropFirst(markerPrefix.count).dropLast(markerSuffix.count))
            if secretTags.contains(tag) { out.insert(tag) }
        }
        return out
    }

    /// Put the secret blocks back — the configuration the ENGINE gets, and the one
    /// the editor shows.
    ///
    /// Each block goes back WHERE ITS MARKER IS, not on the end. Appending would
    /// also produce a valid configuration (no OpenVPN parser cares where a block
    /// sits), but it would mean `split` then `merge` never gives the original text
    /// back — and the Configuration tab shows that text, so the first save of any
    /// profile would visibly shuffle its own blocks to the bottom. A block the
    /// keychain holds but the configuration never marked is appended, so nothing is
    /// silently dropped.
    static func merge(_ config: String, secrets: [String: String]) -> String {
        var placed: Set<String> = []
        var out: [String] = []
        out.reserveCapacity(config.count / 40 + secrets.count * 3)
        for line in config.components(separatedBy: "\n") {
            let t = norm(line)
            guard t.hasPrefix(markerPrefix), t.hasSuffix(markerSuffix) else {
                out.append(line); continue
            }
            // A marker is ours, never part of a configuration: it goes whether or
            // not there is anything to put in its place.
            let tag = String(t.dropFirst(markerPrefix.count).dropLast(markerSuffix.count))
            guard secretTags.contains(tag), !placed.contains(tag),
                  let body = secrets[tag], !body.isEmpty else { continue }
            out.append("<\(tag)>")
            out.append(norm(body))
            out.append("</\(tag)>")
            placed.insert(tag)
        }
        var result = out.joined(separator: "\n")
        for tag in secretTags where !placed.contains(tag) {
            guard let body = secrets[tag], !body.isEmpty else { continue }
            result = OVPNInline.setBlock(tag, content: body, in: result)
        }
        return result
    }

    /// A stable, SECRET-FREE identity for a configuration, for the import
    /// duplicate check.
    ///
    /// Import detects duplicates by hashing the profile text, and stripping the
    /// key changes that hash — so re-importing the same `.ovpn` after a strip
    /// would read as a brand-new VPN. Hashing the *stripped* text alone would go
    /// wrong the other way: two profiles differing only in their client key would
    /// collide, which is a real shape (two people, one gateway). So each secret
    /// block contributes a DIGEST of its content instead of the content: stable
    /// across the strip, still discriminating, and safe to log.
    static func canonicalIdentityText(_ ovpn: String, secrets: [String: String] = [:]) -> String {
        let s = split(ovpn)
        var digested: [String] = []
        for tag in secretTags {
            // What is in the text wins over what was passed: it is what the
            // engine has actually been using.
            guard let body = s.secrets[tag] ?? secrets[tag], !body.isEmpty else { continue }
            let hex = SHA256.hash(data: Data(body.utf8)).map { String(format: "%02x", $0) }.joined()
            digested.append("# simplevpn-secret \(tag) \(hex)")
        }
        let body = stripMarkers(s.config)
        guard !digested.isEmpty else { return body }
        return body + "\n" + digested.joined(separator: "\n")
    }

    /// The text `Export .ovpn…` writes.
    ///
    /// It omits the secret blocks and says so in the file. That is the default
    /// and there is no opt-out, for three reasons: an exported file leaves every
    /// protection the app has (mail, a shared folder, a repository, a backup) and
    /// cannot be recalled; a per-export consent dialog is a thing people click
    /// through, and once clicked the file exists; and the material is recoverable
    /// — it is still in the keychain, and whoever issued the VPN can reissue it.
    /// Tunnelblick made the same call ("Saved usernames and passwords are not
    /// exported"); Viscosity's plaintext `.visc` tarball is the other road.
    ///
    /// Safe for an un-migrated profile too: it splits its input first, so a
    /// profile whose migration could not be verified still exports without its
    /// key.
    static func exportText(_ ovpn: String) -> String {
        let s = split(ovpn)
        let omitted = Set(s.secrets.keys).union(markedTags(in: ovpn))
        let body = stripMarkers(s.config)
        guard !omitted.isEmpty else { return body }
        // Tag names in quotes, never in angle brackets: an exported file must not
        // contain the literal `<key>` anywhere, so that a grep for it is a real
        // check rather than a check the note itself defeats.
        let quoted = secretTags.filter { omitted.contains($0) }.map { "\"\($0)\"" }
        return """
        # ----------------------------------------------------------------------
        # Exported by SimpleVPN.
        #
        # Left out on purpose, because they are secrets: the
        # \(quoted.joined(separator: ", ")) block\(quoted.count == 1 ? "" : "s").
        # SimpleVPN keeps them in your keychain and never writes them to a file.
        #
        # To use this configuration in another client, paste the matching block
        # back in by hand, or ask whoever set up this VPN for the file again.
        # ----------------------------------------------------------------------

        """ + body
    }

    /// An English list of DEDUPLICATED house terms for a set of tags, in
    /// `secretTags` order: two TLS-key tags are one thing to a person, and the order
    /// is the declared one so the same set always reads the same way.
    static func humanNames<S: Sequence>(for tags: S) -> [String] where S.Element == String {
        let present = Set(tags)
        var names: [String] = []
        for tag in secretTags where present.contains(tag) {
            let name = humanName(for: tag)
            if !names.contains(name) { names.append(name) }
        }
        return names
    }

    static func humanNameList<S: Sequence>(for tags: S) -> String where S.Element == String {
        let names = humanNames(for: tags)
        switch names.count {
        case 0: return ""
        case 1: return names[0]
        case 2: return "\(names[0]) and \(names[1])"
        default: return names.dropLast().joined(separator: ", ") + " and " + names[names.count - 1]
        }
    }

    /// The sentence the app says after an export that left something out.
    /// Empty when nothing was omitted.
    static func exportOmissionNotice(_ ovpn: String) -> String {
        let omitted = Set(split(ovpn).secrets.keys).union(markedTags(in: ovpn))
        guard !omitted.isEmpty else { return "" }
        return "Exported without this VPN's \(humanNameList(for: omitted)) — those stay in your keychain. "
            + "The file says what to add back."
    }

    /// What the VPN list says about a MANAGED profile whose inline secret blocks were
    /// left where they are, because policy forbids rewriting the stored
    /// configuration (`VPNController.migrateInlineOVPNSecrets`, and
    /// `Docs/SecretsAndSync.md` §2 for the decision).
    ///
    /// It differs from the failure copy in the one way that matters: it does not
    /// offer the user a fix, because they do not have one. Naming the party who does
    /// is the honest ending, and the house rule for any blocked state is to say what
    /// would change it.
    static func managedInlineSecretNotice<S: Sequence>(_ tags: S) -> String where S.Element == String {
        let names = humanNames(for: tags)
        guard !names.isEmpty else { return "" }
        let list = humanNameList(for: tags)
        let isAre = names.count == 1 ? "is" : "are"
        let it = names.count == 1 ? "it" : "them"
        return "This VPN's \(list) \(isAre) stored with its configuration rather than in your "
            + "keychain, because your organization has locked this VPN's settings and SimpleVPN "
            + "will not rewrite them. Nothing is broken and the VPN works normally. Whoever "
            + "manages this Mac can change it — by sending a configuration that keeps the \(list) "
            + "out, or by unlocking settings so SimpleVPN can move \(it)."
    }
}
