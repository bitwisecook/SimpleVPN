// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConfigurationKinship.swift
//  "IS THIS THE SAME VPN, SOMEWHERE ELSE?" — asked once, answered once, and used by
//  both the drop-a-file path and the provider-list path.
//
//  WHERE THE ANSWER CAME FROM. Docs/ServiceBundles.md records the measurement that
//  makes this idea sound rather than hopeful: IPVanish's 3,576 `.ovpn` files were
//  downloaded, normalised by replacing the hostname with a placeholder, and hashed —
//  and ALL 3,576 PRODUCED THE SAME SHA-256. Nord's ~7,000 are the same once IPv4
//  literals and `*.nordvpn.com` are normalised too. That normalisation IS the
//  "everything else matches" test the user described, and it is lifted here rather
//  than reinvented, because a second definition of "the same configuration" is a
//  second answer to a question that must have one.
//
//  THE PART THAT MUST NOT BE GOT WRONG: "EVERYTHING ELSE" IS NOT ONE CATEGORY.
//  Three, and they are treated differently because they carry completely different
//  consequences:
//
//   1. WHERE IT CONNECTS — `remote` / `Endpoint`, and for WireGuard the peer public
//      key that travels with the address. This is THE POINT: these are the
//      differences that mean "the same VPN, elsewhere", and merging them is the
//      feature. The key rides with the address (`VPNEndpoint.peerPublicKey`), because
//      a WireGuard address without its key is a tunnel to nothing.
//
//   2. WHO YOU ARE — a username, an `auth-user-pass` block. Free to differ, and
//      merging the endpoint is still right. But the stored sign-in is NEVER
//      overwritten: something that works must not be replaced by a file, silently or
//      otherwise. The difference is reported and the user decides.
//
//   3. WHO YOU TRUST — the `<ca>`, `verify-x509-name`, `remote-cert-tls`, the cipher,
//      a pinned certificate or host key, the port. **THESE ARE NOT "EVERYTHING
//      ELSE".** A file with a different CA is not the same VPN with another endpoint;
//      it is A DIFFERENT TRUST ANCHOR WEARING A FAMILIAR NAME, and merging it would
//      be the most damaging thing this feature could do — it would take a VPN the
//      user trusts and quietly repoint its trust at somebody else's authority, with
//      the user's own name still on it. So: refuse by default, show what differs, and
//      offer to import it as a separate VPN instead.
//
//  AND WHEN IT DOES NOT MATCH, FAIL USEFULLY. A drop that only says "no" wastes the
//  gesture — the answer is always either "merged" or "here is how to keep it anyway".
//
//  PURE. No files, no controller, no view: it compares two configuration texts.
//

import Foundation

nonisolated enum ConfigurationKinship {

    // MARK: - What the comparison found

    /// The verdict on one dropped file against one existing VPN.
    enum Verdict: Sendable, Equatable {
        /// Same configuration, different place. Merge these as new endpoints.
        ///
        /// `credentialsDiffer` is carried rather than blocking: the endpoints still
        /// merge, and the user is told their saved sign-in was left alone.
        case sameVPNElsewhere(endpoints: [VPNEndpoint], credentialsDiffer: Bool)
        /// Same place, nothing new. Saying so beats silently adding a duplicate row.
        case alreadyHaveIt
        /// Something security-determining differs. NOT merged, and this is what.
        case trustDiffers([String])
        /// Not the same VPN at all. Offer to import it as its own.
        case differentVPN(String)
    }

    // MARK: - The three categories, as field sets

    /// Category 3. A difference in ANY of these refuses the merge.
    ///
    /// The list is deliberately over-inclusive: a directive that turns out not to
    /// matter costs one "import as a separate VPN", while a directive wrongly left
    /// out costs a silently retargeted trust anchor. Those are not comparable
    /// mistakes, so the doubt goes the safe way.
    static let trustDirectives: Set<String> = [
        // Who signed the server's certificate, and whether it is checked at all.
        "ca", "capath", "verify-x509-name", "tls-verify", "remote-cert-tls",
        "remote-cert-eku", "remote-cert-ku", "verify-hash", "peer-fingerprint",
        "x509-username-field", "crl-verify", "ns-cert-type",
        // The control channel's own protection.
        "tls-auth", "tls-crypt", "tls-crypt-v2", "key-direction", "tls-cipher",
        "tls-ciphersuites", "tls-version-min", "tls-version-max",
        // What the data channel is encrypted and authenticated with.
        "cipher", "data-ciphers", "data-ciphers-fallback", "auth", "ncp-ciphers",
        // The transport itself. A UDP profile and a TCP one are not the same VPN
        // reachable in two places; they negotiate differently.
        "proto", "port", "port-share",
    ]

    /// Category 2. Different values here are fine and never overwrite what is stored.
    static let credentialDirectives: Set<String> = [
        "auth-user-pass", "auth-nocache", "askpass", "static-challenge",
        "cert", "key", "pkcs12", "auth-token",
    ]

    /// Category 1. The lines that say WHERE, and therefore the only ones a merge is
    /// allowed to be about.
    static let endpointDirectives: Set<String> = ["remote", "remote-random", "float"]

    // MARK: - Comparing two OpenVPN configurations

    /// Compare a dropped `.ovpn` against the one a VPN already holds.
    ///
    /// `existingEndpoints` is passed so "you already have this server" can be
    /// answered against what the user actually sees, rather than against the file
    /// alone — a profile whose list has been filled from a provider already has
    /// hundreds of remotes the `.ovpn` never mentioned.
    static func compare(dropped: String, against existing: String,
                        existingEndpoints: [VPNEndpoint]) -> Verdict {
        // NORMALISED FIRST, and this step is the measurement rather than a
        // convenience. IPVanish's template carries `verify-x509-name <server> name`,
        // so the name check LEGITIMATELY differs between two of their files — it
        // names the server, and the server is the thing that is allowed to differ.
        // Comparing raw text would call every one of their 3,576 files a different
        // trust anchor, which is the whole feature refusing itself.
        //
        // What the substitution does NOT excuse is a `verify-x509-name` naming a
        // host the file does not dial: the placeholder only replaces THIS file's own
        // remotes, so a name check pointing anywhere else survives as a difference
        // and refuses. That is the property worth having, and it is why the
        // substitution is per-file rather than a blanket "ignore this directive".
        let a = directives(in: normalised(existing))
        let b = directives(in: normalised(dropped))

        // CATEGORY 3 FIRST, ALWAYS. Nothing else is worth computing if the trust
        // anchor differs, and asking in the other order risks a code path that
        // merges before it checks.
        let trust = trustDifferences(a, b)
        guard trust.isEmpty else { return .trustDiffers(trust) }

        // Inline blocks are the other half of category 3 — a `<ca>` is not a
        // directive with a value, it is a block, and comparing only the directive
        // names would miss a wholly different certificate.
        let blockDifferences = inlineBlockDifferences(existing: existing, dropped: dropped)
        guard blockDifferences.isEmpty else { return .trustDiffers(blockDifferences) }

        // What is left over, once where-it-connects and who-you-are are set aside,
        // has to be identical — that is the IPVanish measurement made into a rule.
        if let difference = structuralDifference(a, b) {
            return .differentVPN(difference)
        }

        let incoming = EndpointScanner.endpoints(in: dropped).map(VPNEndpoint.init)
        let known = Set(existingEndpoints.map(\.id))
        let fresh = incoming.filter { !known.contains($0.id) }
        guard !fresh.isEmpty else { return .alreadyHaveIt }
        return .sameVPNElsewhere(endpoints: fresh.map { e in
            var e = e
            // The user did not type this, and it did not come from a provider's
            // published list either — it came from a file they dropped, which is the
            // same provenance as any other import: theirs.
            e.userAdded = true
            return e
        }, credentialsDiffer: differs(a, b, in: credentialDirectives))
    }

    // MARK: - Comparing two WireGuard configurations

    /// The WireGuard counterpart, and it has one extra rule that OpenVPN does not
    /// need: THE PEER PUBLIC KEY TRAVELS WITH THE ADDRESS.
    ///
    /// A second `.conf` from the same provider is the same tunnel — same private key,
    /// same tunnel address, same allowed networks — reaching a DIFFERENT relay with a
    /// DIFFERENT peer key. So the key is category 1 here, not category 3: it is part
    /// of "where", and it is merged onto the endpoint row rather than over the
    /// profile's own peer key.
    ///
    /// Everything about the INTERFACE is still category 3 in spirit: a file with
    /// different allowed networks or a different tunnel address is a different tunnel
    /// wearing a familiar name, and it does not merge.
    static func compare(droppedWireGuard dropped: WireGuardConfig,
                        against existing: WireGuardConfig,
                        existingEndpoints: [VPNEndpoint]) -> Verdict {
        var differences: [String] = []
        // The tunnel's own identity. Different addresses mean a different tunnel,
        // full stop — the provider issued them against a different key registration.
        if dropped.addresses != existing.addresses, !dropped.addresses.isEmpty {
            differences.append("the tunnel address this device uses "
                + "(\(existing.addresses.joined(separator: ", ")) here, "
                + "\(dropped.addresses.joined(separator: ", ")) in the file)")
        }
        if dropped.allowedIPs != existing.allowedIPs, !dropped.allowedIPs.isEmpty {
            differences.append("which networks go through the tunnel")
        }
        // A pre-shared key is an extra symmetric secret on the peer. Present in one
        // and not the other is a different trust arrangement, and we compare only
        // presence because the value is redacted in the stored copy.
        if dropped.presharedKey.isEmpty != existing.presharedKey.isEmpty {
            differences.append("whether a pre-shared key is used")
        }
        guard differences.isEmpty else { return .trustDiffers(differences) }

        let host = dropped.endpointHost
        guard !host.isEmpty else {
            return .differentVPN("the file names no server to connect to.")
        }
        let port = WireGuardEndpointSelection.currentPort(dropped)
        let row = VPNEndpoint(host: host, port: port, userAdded: true,
                              peerPublicKey: VPNEndpoint.canonicalPeerKey(dropped.peerPublicKey))
        guard !existingEndpoints.contains(where: { $0.id == row.id }) else { return .alreadyHaveIt }
        // The private key differing is a CREDENTIAL difference, not a trust one: it
        // is this device's own identity, and the stored one is never overwritten.
        let credentialsDiffer = !dropped.privateKey.isEmpty
            && !existing.privateKey.isEmpty
            && dropped.privateKey != existing.privateKey
        return .sameVPNElsewhere(endpoints: [row], credentialsDiffer: credentialsDiffer)
    }

    // MARK: - Normalisation

    /// The placeholders the substitution leaves behind. Visible in the difference
    /// sentences, and deliberately unmistakable for anything a config could contain.
    static let serverPlaceholder = "{{server}}"
    static let addressPlaceholder = "{{address}}"

    /// An `.ovpn` with its OWN server names and addresses replaced by placeholders.
    ///
    /// THIS IS THE MEASUREMENT FROM Docs/ServiceBundles.md §2, in code: replacing the
    /// hostname made all 3,576 IPVanish files hash identically, and normalising the
    /// IPv4 literals as well made Nord's do the same. Everything the comparison
    /// concludes rests on it.
    ///
    /// It substitutes only what THIS file dials — the hosts and literals on its own
    /// `remote` lines. So `verify-x509-name <its own server> name` collapses to the
    /// placeholder and matches, while a `verify-x509-name` naming some other host
    /// does not and is reported as a trust difference. The narrowness is the point:
    /// a blanket "ignore the name check" would be the same code with none of the
    /// safety.
    /// WHOLE TOKENS, NOT SUBSTRINGS, and this is not a detail — it is a bug this
    /// function had until a test caught it. A plain text replacement of the host
    /// `a.ipvanish.com` also rewrites the CA filename `ca.ipvanish.com.crt` into
    /// `c{{server}}.crt`, so two files that differ only in their server stop
    /// comparing equal AND the certificate path silently becomes part of what varies.
    /// Splitting on whitespace first means a host only ever matches where a host can
    /// actually appear.
    static func normalised(_ ovpn: String) -> String {
        let hosts = Set(EndpointScanner.endpoints(in: ovpn).map(\.host).filter { !$0.isEmpty })
        guard !hosts.isEmpty else { return ovpn }
        var lines: [String] = []
        for rawLine in ovpn.split(separator: "\n", omittingEmptySubsequences: false) {
            // Preserve the original spacing between tokens by rebuilding from the
            // same separator the split used; configuration files are space-separated
            // and nothing here needs to round-trip tabs.
            let rebuilt = rawLine
                .split(separator: " ", omittingEmptySubsequences: false)
                .map { token in replacingHost(in: String(token), hosts: hosts) }
                .joined(separator: " ")
            lines.append(rebuilt)
        }
        return lines.joined(separator: "\n")
    }

    /// One token with a host in it replaced by its placeholder.
    ///
    /// Three shapes, because these are the three a real configuration uses: the bare
    /// host (`remote vpn.example.com 1194`), the `CN=` form Nord's name check uses,
    /// and `host:port`. Anything else is left exactly as it is — an unrecognised
    /// shape must stay a difference rather than be normalised away on a guess.
    private static func replacingHost(in token: String, hosts: Set<String>) -> String {
        func placeholder(_ host: String) -> String {
            host.allSatisfy { $0.isNumber || $0 == "." || $0 == ":" }
                ? addressPlaceholder : serverPlaceholder
        }
        if hosts.contains(token) { return placeholder(token) }
        for prefix in ["CN=", "name="] where token.hasPrefix(prefix) {
            let rest = String(token.dropFirst(prefix.count))
            if hosts.contains(rest) { return prefix + placeholder(rest) }
        }
        if let colon = token.lastIndex(of: ":") {
            let head = String(token[..<colon])
            if hosts.contains(head) { return placeholder(head) + token[colon...] }
        }
        return token
    }

    /// Every directive in an `.ovpn`, as name → the values it was given, with inline
    /// blocks and comments left out.
    ///
    /// Values are kept in order and NOT sorted: `data-ciphers AES-256-GCM:AES-128-GCM`
    /// and its reverse are different preferences, and treating them as the same would
    /// be the kind of "close enough" this file exists to refuse.
    static func directives(in ovpn: String) -> [String: [String]] {
        var out: [String: [String]] = [:]
        var insideBlock = false
        for rawLine in ovpn.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("</") { insideBlock = false; continue }
            if line.hasPrefix("<") { insideBlock = true; continue }
            if insideBlock || line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") {
                continue
            }
            let parts = line.split(separator: " ", omittingEmptySubsequences: true)
            guard let name = parts.first.map(String.init) else { continue }
            out[name, default: []].append(parts.dropFirst().joined(separator: " "))
        }
        return out
    }

    /// The inline blocks (`<ca>`, `<tls-auth>`, …) as name → SHA-256 of their
    /// contents, whitespace-collapsed.
    ///
    /// HASHED RATHER THAN COMPARED AS TEXT, for the reason the IPVanish measurement
    /// used the same trick: two copies of one certificate can differ in line endings
    /// and trailing newlines without being different certificates, and a byte
    /// comparison would call every re-download a new trust anchor.
    static func inlineBlocks(in ovpn: String) -> [String: String] {
        var out: [String: String] = [:]
        var current: String?
        var body: [String] = []
        for rawLine in ovpn.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("</"), let name = current {
                out[name] = SHA256Hex.of(Data(body.joined(separator: "\n").utf8))
                current = nil
                body = []
                continue
            }
            if line.hasPrefix("<"), !line.hasPrefix("</") {
                current = String(line.dropFirst().dropLast())
                body = []
                continue
            }
            if current != nil, !line.isEmpty { body.append(line) }
        }
        return out
    }

    // MARK: - The three comparisons

    /// Category 3, as sentences a person can read. Named individually because
    /// "these differ" is the kind of message that gets clicked through, and a
    /// different CA deserves different words from a different port.
    static func trustDifferences(_ a: [String: [String]], _ b: [String: [String]]) -> [String] {
        var out: [String] = []
        for name in trustDirectives.sorted() {
            let here = a[name] ?? []
            let there = b[name] ?? []
            guard here != there else { continue }
            out.append(sentence(directive: name, here: here, there: there))
        }
        return out
    }

    /// The inline half of category 3.
    static func inlineBlockDifferences(existing: String, dropped: String) -> [String] {
        let a = inlineBlocks(in: existing)
        let b = inlineBlocks(in: dropped)
        var out: [String] = []
        for name in Set(a.keys).union(b.keys).sorted() {
            // A credential block differing is category 2, not category 3: it is who
            // YOU are, not who you trust.
            guard !credentialDirectives.contains(name) else { continue }
            guard a[name] != b[name] else { continue }
            out.append(name == "ca"
                ? "the certificate authority the server is checked against \u{2014} which means the "
                    + "file trusts a different signer, not the same VPN in another place"
                : "the \u{201C}\(name)\u{201D} block")
        }
        return out
    }

    /// Category 1 and 2 set aside, is anything left that differs? Nil means "the same
    /// configuration", which is the IPVanish measurement made into a rule.
    static func structuralDifference(_ a: [String: [String]], _ b: [String: [String]]) -> String? {
        let ignored = endpointDirectives.union(credentialDirectives).union(trustDirectives)
        for name in Set(a.keys).union(b.keys).sorted() where !ignored.contains(name) {
            let here = a[name] ?? []
            let there = b[name] ?? []
            guard here != there else { continue }
            return "it sets \u{201C}\(name)\u{201D} differently, so it is not the same "
                + "configuration reaching another server."
        }
        return nil
    }

    static func differs(_ a: [String: [String]], _ b: [String: [String]],
                        in names: Set<String>) -> Bool {
        names.contains { (a[$0] ?? []) != (b[$0] ?? []) }
    }

    /// One trust difference, in words. `port` and `proto` get their values quoted
    /// because they are short and the actual numbers are what a person recognises;
    /// a certificate does not, because nobody reads one at a glance.
    private static func sentence(directive: String, here: [String], there: [String]) -> String {
        switch directive {
        case "port", "proto":
            return "the \(directive) it connects on (\(display(here)) here, \(display(there)) in the file)"
        case "cipher", "data-ciphers", "auth":
            return "how the traffic is encrypted (\u{201C}\(directive)\u{201D})"
        case "ca", "capath", "verify-x509-name", "remote-cert-tls", "peer-fingerprint":
            return "how the server\u{2019}s identity is checked (\u{201C}\(directive)\u{201D}) \u{2014} "
                + "which is the setting that decides who this VPN trusts"
        default:
            return "\u{201C}\(directive)\u{201D}"
        }
    }

    private static func display(_ values: [String]) -> String {
        values.isEmpty ? "not set" : values.joined(separator: ", ")
    }
}
