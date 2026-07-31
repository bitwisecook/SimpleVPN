// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHProbeSession.swift
//  The SSH half of the staged probe: one libssh2 session, driven a rung at a
//  time so each rung can be reported separately (key exchange, host key,
//  offered sign-in methods, the key itself) instead of collapsing into one
//  "the SSH handshake failed".
//
//  Two things this does that the tunnel engine deliberately does NOT:
//    • it checks the host key WITHOUT the accept-new side effect. A probe that
//      quietly recorded an unknown key would destroy the evidence the next real
//      connection depends on — and would turn the one check that catches
//      interception into a rubber stamp.
//    • it stops before any password. Offering a key is fine (a key is reusable
//      material and proves nothing is spent); a password attempt counts against
//      the server's sign-in limits, so it lives behind the account boundary.
//
//  libssh2 is single-threaded per session, so every call is funnelled onto one
//  serial queue — the same rule SSHTunnelEngine follows.
//

import Foundation

/// The read-only known_hosts answer, mirrored into Swift so the classification
/// below can be tested without libssh2 (or a server) anywhere in sight.
nonisolated enum SSHKnownHostResult: Sendable, Equatable {
    case match
    case mismatch
    case notFound
    case unavailable
}

nonisolated enum SSHHostKeyVerdict: Sendable, Equatable {
    /// On record and unchanged.
    case trusted
    /// On record and DIFFERENT. Always a hard stop, whatever the strictness —
    /// a changed host key is the signature of interception, and no setting
    /// should be able to wave it through.
    case changed
    /// Not on record, and this VPN is willing to meet new servers.
    case unknownAcceptable
    /// Not on record, and this VPN is set to refuse servers it doesn't know.
    case unknownRefused
    case unavailable

    var isFailure: Bool { self == .changed || self == .unknownRefused }
    var isSecurityFinding: Bool { self == .changed }
    var failure: ProbeFailure? {
        switch self {
        case .changed: .hostKeyChanged
        case .unknownRefused: .hostKeyUnknown
        default: nil
        }
    }
}

nonisolated enum SSHHostKeyPolicy {
    /// `strict` is OpenSSH's StrictHostKeyChecking: "yes" | "accept-new" | "no".
    static func classify(_ result: SSHKnownHostResult, strict: String, pinned: Bool) -> SSHHostKeyVerdict {
        switch result {
        case .match: return .trusted
        case .mismatch: return .changed
        case .notFound:
            // A pin that didn't match reports as .mismatch, so reaching here with
            // a pin set means there was nothing to compare against at all.
            if pinned { return .unknownRefused }
            return strict.lowercased() == "yes" ? .unknownRefused : .unknownAcceptable
        case .unavailable: return .unavailable
        }
    }
}

/// Whether a private key file needs a password before it can be used at all.
nonisolated enum SSHPrivateKeyFile {

    enum Protection: Sendable, Equatable { case open, passphraseProtected, unreadable }

    static func protection(ofFileAt path: String,
                           read: (String) -> String? = { try? String(contentsOfFile: $0, encoding: .utf8) }) -> Protection {
        let expanded = (path as NSString).expandingTildeInPath
        guard let text = read(expanded) else { return .unreadable }
        return protection(ofPEM: text)
    }

    /// Pure: the three markers that mean "encrypted" across the formats a Mac
    /// actually meets — PKCS#8, legacy OpenSSL, and OpenSSH's own format (where
    /// the cipher name follows the magic and is "none" for an unprotected key).
    static func protection(ofPEM text: String) -> Protection {
        guard text.contains("PRIVATE KEY") else { return .unreadable }
        if text.contains("ENCRYPTED PRIVATE KEY") { return .passphraseProtected }
        if text.contains("Proc-Type: 4,ENCRYPTED") { return .passphraseProtected }
        if text.contains("OPENSSH PRIVATE KEY") {
            // The base64 body starts "b3BlbnNzaC1rZXktdjEA" then the cipher name.
            // "none" encodes as "AAAABG5vbmU" within the first line or two.
            let body = text.replacingOccurrences(of: "\n", with: "")
            return body.contains("AAAABG5vbmU") ? .open : .passphraseProtected
        }
        return .open
    }
}

/// A libssh2 failure carried as a value. libssh2's own strings are terse and
/// occasionally quote the server, so they only ever reach a step's evidence,
/// where the redactor sees them first.
nonisolated struct SSHProbeFailure: Error, Sendable, Equatable {
    var message: String
}

// MARK: - The live session

/// Owns one libssh2 session for the duration of a probe. `@unchecked Sendable`
/// because every touch of the underlying session happens on `queue`.
nonisolated final class SSHProbeSession: @unchecked Sendable {

    private let queue = DispatchQueue(label: "com.bragi0.SimpleVPN.probe.ssh")
    private var session: SSHSession?

    struct Handshake: Sendable {
        var fingerprint: String?
        var keyType: String?
        var keyLength: Int
        var methods: [String: String]
    }

    private func on<T: Sendable>(_ work: @escaping @Sendable (SSHSession?) -> T) async -> T {
        await withCheckedContinuation { cont in
            queue.async { cont.resume(returning: work(self.session)) }
        }
    }

    /// TCP connect + key exchange. Returns the negotiated facts, or the reason.
    func connect(host: String, port: Int, timeout: Int = 10) async -> Result<Handshake, SSHProbeFailure> {
        await withCheckedContinuation { cont in
            queue.async {
                let s = SSHSession()
                do {
                    try s.connect(toHost: host, port: Int32(port), timeout: Int32(timeout))
                } catch {
                    cont.resume(returning: .failure(SSHProbeFailure(message: error.localizedDescription)))
                    return
                }
                self.session = s
                cont.resume(returning: .success(Handshake(
                    fingerprint: s.hostKeyFingerprintSHA256,
                    keyType: s.hostKeyType,
                    keyLength: s.hostKeyLength,
                    methods: s.negotiatedMethods)))
            }
        }
    }

    func checkHostKey(knownHostsPath: String?, pin: String?) async -> SSHKnownHostResult {
        await on { session in
            guard let session else { return .unavailable }
            switch session.checkHostKey(withKnownHosts: knownHostsPath, pin: pin) {
            case .match: return .match
            case .mismatch: return .mismatch
            case .notFound: return .notFound
            case .unavailable: return .unavailable
            @unknown default: return .unavailable
            }
        }
    }

    func authMethods(user: String) async -> Result<[String], SSHProbeFailure> {
        await on { session in
            guard let session else { return .failure(SSHProbeFailure(message: "The connection was lost.")) }
            do {
                let methods = try session.authMethods(forUser: user)
                return .success(methods)
            } catch {
                return .failure(SSHProbeFailure(message: error.localizedDescription))
            }
        }
    }

    /// Offer the configured key. Reusable material, no account state — see the
    /// file note for why this is on the automatic side of the boundary.
    func tryPublicKey(user: String, keyPath: String, passphrase: String?) async -> Result<Void, SSHProbeFailure> {
        await on { session in
            guard let session else { return .failure(SSHProbeFailure(message: "The connection was lost.")) }
            do {
                try session.authKey(forUser: user, privateKeyPath: keyPath, passphrase: passphrase)
                return .success(())
            } catch {
                return .failure(SSHProbeFailure(message: error.localizedDescription))
            }
        }
    }

    /// Submit a password. ONLY ever reached from an explicitly opted-in run —
    /// this is the step that counts against the server's sign-in limits, which
    /// is exactly why the ladder holds it back by default. No channel is opened
    /// afterwards, and the session is dropped immediately, so nothing is left
    /// running on the far end.
    func tryPassword(user: String, password: String) async -> Result<Void, SSHProbeFailure> {
        await on { session in
            guard let session else { return .failure(SSHProbeFailure(message: "The connection was lost.")) }
            do {
                try session.authPassword(forUser: user, password: password)
                return .success(())
            } catch {
                return .failure(SSHProbeFailure(message: error.localizedDescription))
            }
        }
    }

    func disconnect() {
        queue.async {
            self.session?.disconnect()
            self.session = nil
        }
    }
}
