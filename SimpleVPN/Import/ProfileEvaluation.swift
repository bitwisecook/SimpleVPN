// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProfileEvaluation.swift
//  Swift-side result of evaluating an OpenVPN profile with the real engine parser
//  (OpenVPNClientHelper::eval_config via OVPNProfileEvaluator), plus a few facts the
//  evaluator doesn't surface that we scan from the text. Drives all profile-adaptive
//  UI: placeholders, conditional rows, server pickers, import validation.
//

import Foundation
import CryptoKit

/// One user-selectable server advertised by the profile (Access Server `serverList`).
struct ProfileServerEntry: Equatable, Sendable {
    var server: String
    var friendlyName: String
}

struct ProfileEvaluation: Equatable, Sendable {
    // Parse outcome
    var error = false
    var message = ""

    // Identity
    var profileName = ""
    var friendlyName = ""

    // Authentication shape
    var autologin = false                    // no credentials required
    var externalPki = false
    var privateKeyPasswordRequired = false
    var allowPasswordSave = true
    var userlockedUsername = ""
    var staticChallenge = ""
    var staticChallengeEcho = false

    // First `remote` — used as placeholder/default display for the override fields.
    var remoteHost = ""
    var remotePort = ""
    var remoteProto = ""

    var serverList: [ProfileServerEntry] = []

    // Facts the evaluator doesn't expose, scanned from the profile text.
    var requestsCompression = false          // comp-lzo / compress directive present
    var usesTLSAuth = false                  // tls-auth / tls-crypt present (key direction applies)
    var hasClientCert = false                // client cert/key or pkcs12 present
    /// `pkcs11-*` directives found in the profile, in the order they appear.
    ///
    /// This is a HARD INCOMPATIBILITY, detected here so it can be explained rather
    /// than discovered. SimpleVPN carries OpenVPN on the openvpn3 core, which does
    /// not implement OpenVPN 2.x's `pkcs11-*` family at all — and openvpn3 does not
    /// merely ignore an option it doesn't know: `ClientOptions::handle_unused_options`
    /// puts anything untouched into its "UNKNOWN/UNSUPPORTED OPTIONS" bucket and
    /// THROWS (`Error::UNUSED_OPTIONS`, fatal). So a profile with `pkcs11-providers`
    /// in it doesn't sign in with a token: it fails to load, complaining about an
    /// option, and the reason is nowhere near the smartcard the user is holding.
    var pkcs11Directives: [String] = []
    var usesPKCS11: Bool { !pkcs11Directives.isEmpty }

    /// The one thing to say about a `pkcs11-*` profile, or nil. Names the directive
    /// found, why it can't work here, and the two routes that do.
    var pkcs11Advice: String? {
        guard let first = pkcs11Directives.first else { return nil }
        return "This configuration uses \u{201C}\(first)\u{201D} to sign in with a smartcard or security key. SimpleVPN's OpenVPN engine (the OpenVPN 3 core) has no smartcard support and refuses to load a profile containing it \u{2014} remove the pkcs11 lines to import the rest. For hardware-backed certificate sign-in, SimpleVPN supports PKCS#11 on the SSL VPN kinds (AnyConnect, GlobalProtect, FortiGate\u{2026}); ask your administrator whether the gateway offers one of those."
    }

    /// Placeholder-friendly accessors (empty string → nil).
    var remoteHostOrNil: String? { remoteHost.isEmpty ? nil : remoteHost }
    var remotePortOrNil: Int? { Int(remotePort) }
    var remoteProtoDisplay: String? {
        guard !remoteProto.isEmpty else { return nil }
        return remoteProto.lowercased().hasPrefix("tcp") ? "TCP"
             : remoteProto.lowercased().hasPrefix("udp") ? "UDP" : remoteProto
    }
}

extension ProfileEvaluation {
    /// Scan for facts eval_config doesn't report: compression request, extra
    /// HMAC key (tls-auth/tls-crypt), client certificate. Lines are trimmed with
    /// .whitespacesAndNewlines so CRLF profiles scan identically to LF ones.
    static func textFacts(in ovpn: String)
        -> (compression: Bool, tlsAuth: Bool, clientCert: Bool, pkcs11: [String]) {
        var compression = false, tlsAuth = false, clientCert = false
        var pkcs11: [String] = []
        for rawLine in ovpn.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.hasPrefix("#") || line.hasPrefix(";") { continue }
            // The whole `pkcs11-*` family: providers, id, id-management, pin-cache,
            // protected-authentication-path, cert-private, private-mode.
            if line.hasPrefix("pkcs11-") {
                let directive = line.split(separator: " ", maxSplits: 1)
                    .first.map(String.init) ?? line
                if !pkcs11.contains(directive) { pkcs11.append(directive) }
            }
            if line == "comp-lzo" || line.hasPrefix("comp-lzo ")
                || line == "compress" || line.hasPrefix("compress ") {
                compression = true
            }
            if line.hasPrefix("<tls-auth>") || line.hasPrefix("<tls-crypt>")
                || line.hasPrefix("tls-auth ") || line.hasPrefix("tls-crypt ") {
                tlsAuth = true
            }
            if line.hasPrefix("<cert>") || line.hasPrefix("<key>") || line.hasPrefix("<pkcs12>")
                || line.hasPrefix("cert ") || line.hasPrefix("key ") || line.hasPrefix("pkcs12 ") {
                clientCert = true
            }
        }
        return (compression, tlsAuth, clientCert, pkcs11)
    }

    static func requestsCompression(in ovpn: String) -> Bool {
        textFacts(in: ovpn).compression
    }

    /// The `pkcs11-*` directives in a profile — the import path's own check, which
    /// runs before the engine parser can throw its opaque "unsupported options".
    static func pkcs11Directives(in ovpn: String) -> [String] {
        textFacts(in: ovpn).pkcs11
    }

    /// Stable content key for memoization/duplicate detection: SHA-256 of the
    /// whitespace-trimmed profile text.
    static func contentHash(of ovpn: String) -> String {
        let trimmed = ovpn.trimmingCharacters(in: .whitespacesAndNewlines)
        let digest = SHA256.hash(data: Data(trimmed.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Map the ObjC++ evaluator result (real engine parser) into the value type.
    init(bridging r: OVPNEvalResult, ovpnText: String) {
        self.init()
        error = r.error
        message = r.message
        profileName = r.profileName
        friendlyName = r.friendlyName
        autologin = r.autologin
        externalPki = r.externalPki
        privateKeyPasswordRequired = r.privateKeyPasswordRequired
        allowPasswordSave = r.allowPasswordSave
        userlockedUsername = r.userlockedUsername
        staticChallenge = r.staticChallenge
        staticChallengeEcho = r.staticChallengeEcho
        remoteHost = r.remoteHost
        remotePort = r.remotePort
        remoteProto = r.remoteProto
        serverList = zip(r.serverList, r.serverFriendlyNames).map {
            ProfileServerEntry(server: $0, friendlyName: $1)
        }
        let facts = Self.textFacts(in: ovpnText)
        requestsCompression = facts.compression
        usesTLSAuth = facts.tlsAuth
        hasClientCert = facts.clientCert
        pkcs11Directives = facts.pkcs11
    }
}

/// Evaluates profiles with the real engine parser, memoized by content hash.
/// The cache is in-memory only — an engine upgrade (new parser behavior)
/// transparently re-evaluates on next launch. Eval is ~ms, but views ask often.
@Observable
final class ProfileEvaluator {

    @ObservationIgnored private var cache: [String: ProfileEvaluation] = [:]

    func evaluation(for ovpnText: String) -> ProfileEvaluation {
        let key = ProfileEvaluation.contentHash(of: ovpnText)
        if let hit = cache[key] { return hit }
        let result = ProfileEvaluation(bridging: OVPNProfileEvaluator.evaluate(ovpnText),
                                       ovpnText: ovpnText)
        // Unbounded growth is fine at "number of profiles the user edits per
        // launch" scale, but cap it anyway.
        if cache.count > 64 { cache.removeAll() }
        cache[key] = result
        return result
    }
}
