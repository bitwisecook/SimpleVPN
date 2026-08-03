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
    static func textFacts(in ovpn: String) -> (compression: Bool, tlsAuth: Bool, clientCert: Bool) {
        var compression = false, tlsAuth = false, clientCert = false
        for rawLine in ovpn.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.hasPrefix("#") || line.hasPrefix(";") { continue }
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
        return (compression, tlsAuth, clientCert)
    }

    static func requestsCompression(in ovpn: String) -> Bool {
        textFacts(in: ovpn).compression
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
