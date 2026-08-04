// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHHostKeyDecision.swift
//  Who decides whether to trust an SSH server's host key, and how — as a PURE
//  function, so the one security decision in this feature is unit-tested rather
//  than inferred from the shape of a call site.
//
//  THE SPLIT, and it is not an implementation detail:
//
//    THE EXTENSION IS PIN-ONLY. ALWAYS. It never prompts (it has no UI and no
//    user session), never trusts on first use, and never reads or writes
//    known_hosts — it CANNOT: it runs as root in the system context under a
//    sandbox, where ~/.ssh does not exist and a file it created would belong to
//    root anyway. The bridge already points libssh's KNOWNHOSTS and
//    GLOBAL_KNOWNHOSTS at /dev/null for exactly this reason. So the extension is
//    handed ONE fingerprint and refuses anything else, and it checks that BEFORE
//    authenticating — a host key verified after auth is a host key verified after
//    the password has already been given to whoever answered.
//
//    THE APP RESOLVES TRUST. It has the user, the keychain, ~/.ssh/known_hosts
//    and the ability to put a sheet on screen. It runs the ladder below, arrives
//    at a fingerprint, and passes that fingerprint to the extension. First
//    connect to an unknown host is a SHEET the user answers, logged at .notice —
//    trust on first use is a decision someone makes, never something that
//    happens.
//
//  Everything here is deliberately free of libssh, Foundation-only, and has no
//  side effects: `decide` returns what to DO, and the caller does it.
//

import Foundation

/// What consulting known_hosts said about the key a server presented. Mirrors
/// `SSHHostKeyStatus` in SSHBridge.h so this file needs no bridge import.
nonisolated enum SSHKnownHostsAnswer: Sendable, Equatable {
    case match
    case mismatch
    case notFound
    case unavailable
}

/// The app's decision about one server's host key.
nonisolated enum SSHHostKeyDecision: Sendable, Equatable {

    /// Trusted, with the fingerprint to hand the extension.
    case trusted(pin: String)

    /// Ask the user, then (if they agree) record the key and connect with it.
    /// `fingerprint` is what the sheet must show; `keyType` gives it context.
    case askUser(fingerprint: String, keyType: String)

    /// Refused, with the reason to show. NOT a prompt: a changed key and a
    /// strict-policy miss are both hard stops.
    case refused(reason: String)

    /// Whether this decision may proceed to open a session without asking first.
    var pin: String? {
        if case .trusted(let pin) = self { return pin }
        return nil
    }

    /// Decide, from the policy and what the server actually presented.
    ///
    /// - Parameters:
    ///   - policy: what the user asked for.
    ///   - configuredPin: the fingerprint saved on the profile (may be empty).
    ///   - presentedFingerprint: the SHA-256 hex the server just presented. Empty
    ///     means the probe could not get one, which is never a reason to proceed.
    ///   - keyType: "ssh-ed25519", "ecdsa-sha2-nistp256"… for the sheet.
    ///   - knownHosts: what ~/.ssh/known_hosts says about it.
    static func decide(policy: SSHNetworkTunnelConfig.HostKeyPolicy,
                       configuredPin: String,
                       presentedFingerprint: String,
                       keyType: String,
                       knownHosts: SSHKnownHostsAnswer) -> SSHHostKeyDecision {

        let presented = normalize(presentedFingerprint)
        let configured = normalize(configuredPin)

        // A pin, whenever there is one, decides on its own and decides FIRST —
        // ahead of known_hosts, so a stale or attacker-appended known_hosts entry
        // cannot override an explicit pin.
        if policy == .pinned || !configured.isEmpty {
            guard !configured.isEmpty else {
                return .refused(reason:
                    "This tunnel is set to accept only a pinned host key, but no fingerprint is saved for it. "
                    + "Paste the server's SHA-256 fingerprint in the tunnel's Security settings.")
            }
            guard configured.count == 64 else {
                // A truncated pin must NEVER match. The bridge compares for exact
                // equality precisely so it can't, and this says why rather than
                // failing mysteriously at connect.
                return .refused(reason:
                    "The saved host-key fingerprint is only \(configured.count) of 64 characters. "
                    + "A partial fingerprint can't be checked, so SimpleVPN won't connect with it.")
            }
            guard !presented.isEmpty else {
                return .refused(reason: "The SSH server didn't present a host key to check.")
            }
            guard presented == configured else {
                return .refused(reason:
                    "The SSH server's host key doesn't match the pinned fingerprint. "
                    + "It offered \(keyTypeLabel(keyType)) SHA256:\(presented).")
            }
            return .trusted(pin: configured)
        }

        // No pin: consult known_hosts.
        switch knownHosts {
        case .match:
            guard !presented.isEmpty else {
                return .refused(reason: "The SSH server didn't present a host key to check.")
            }
            return .trusted(pin: presented)

        case .mismatch:
            // Always refused, at every policy. This is the signature of an
            // interception, and "the user chose to be relaxed" is not consent to
            // a key changing underneath them.
            return .refused(reason:
                "The SSH server's host key has CHANGED since last time — refusing to connect. "
                + "It now offers \(keyTypeLabel(keyType)) SHA256:\(presented). "
                + "If the server was genuinely rebuilt, remove its line from ~/.ssh/known_hosts first.")

        case .notFound:
            switch policy {
            case .knownHostsOnly:
                return .refused(reason:
                    "The SSH server isn't in your known_hosts, and this tunnel is set to accept only known hosts. "
                    + "It offered \(keyTypeLabel(keyType)) SHA256:\(presented).")
            case .trustOnFirstUse:
                guard !presented.isEmpty else {
                    return .refused(reason: "The SSH server didn't present a host key to check.")
                }
                return .askUser(fingerprint: presented, keyType: keyTypeLabel(keyType))
            case .pinned:
                // Unreachable — handled above — but stated rather than defaulted.
                return .refused(reason:
                    "This tunnel is set to accept only a pinned host key, and none is saved.")
            }

        case .unavailable:
            return .refused(reason:
                "SimpleVPN couldn't check the SSH server's identity, so it won't hand over your sign-in.")
        }
    }

    /// Bare lowercase hex, no "SHA256:" prefix and no colons — the form the
    /// bridge compares. Anything that isn't 64 hex characters comes back as it
    /// was so the caller can report the real length.
    static func normalize(_ raw: String) -> String {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        // Strip a leading ALGORITHM TAG ("SHA256:…", "pin-sha256:…").
        //
        // The tag is identified by what precedes the colon being non-hexadecimal,
        // NOT by the colon's position. A positional rule ("a colon in the first
        // twenty characters is a separator") gets a colon-separated fingerprint
        // wrong the moment it is short — and "quietly returned two characters
        // instead of the fingerprint" is the shape of a comparison that then
        // never matches, with nothing to see.
        if let colon = s.firstIndex(of: ":") {
            let head = s[s.startIndex..<colon]
            if !head.isEmpty, !head.allSatisfy(\.isHexDigit) {
                s = String(s[s.index(after: colon)...])
            }
        }
        s = s.replacingOccurrences(of: ":", with: "").lowercased()
        return s
    }

    private static func keyTypeLabel(_ raw: String) -> String {
        raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "a key" : raw
    }
}
