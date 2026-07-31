// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProbeCertificates.swift
//  "Would this certificate actually be accepted?" — asked of the profile's own
//  client certificate before a connection is attempted, and of the VPN's
//  certificate once one has been captured.
//
//  Split deliberately in two:
//    • `CertificateVerdict.classify` is pure arithmetic over facts (dates, three
//      booleans). It is where the precedence lives — expired beats untrusted
//      beats name-mismatch, because that is the order a person should fix them
//      in — and it is testable with no certificate at all.
//    • `ProbeCertificateInspector` is the Security.framework half that turns a
//      PEM or a live chain INTO those facts.
//
//  Nothing here renders a key. Evidence is limited to distinguished names,
//  dates, key sizes and fingerprints — public facts printed on the certificate
//  itself.
//

import Foundation
import Security
import CryptoKit

// MARK: - Facts

nonisolated struct CertificateFacts: Sendable, Equatable {
    var commonName = ""
    var organisation = ""
    var issuerCommonName = ""
    var subjectAlternativeNames: [String] = []
    var notBefore: Date?
    var notAfter: Date?
    var keyAlgorithm: String?
    var keyBits: Int?
    var sha256Fingerprint = ""
    var isSelfSigned = false

    var displayName: String {
        if !commonName.isEmpty { return commonName }
        if !organisation.isEmpty { return organisation }
        return "certificate"
    }

    /// Every name the certificate claims to be, for hostname matching.
    var names: [String] {
        var out = subjectAlternativeNames
        if !commonName.isEmpty { out.append(commonName) }
        return out
    }

    /// The lines the details disclosure shows. Public facts only.
    func evidence(role: String) -> [String] {
        var lines = ["\(role): \(displayName)"]
        if !issuerCommonName.isEmpty { lines.append("Issued by: \(issuerCommonName)") }
        if let notBefore { lines.append("Valid from: \(Self.format(notBefore))") }
        if let notAfter { lines.append("Valid until: \(Self.format(notAfter))") }
        if let keyAlgorithm, let keyBits { lines.append("Key: \(keyAlgorithm) \(keyBits)-bit") }
        if !subjectAlternativeNames.isEmpty {
            lines.append("Covers: \(subjectAlternativeNames.prefix(8).joined(separator: ", "))")
        }
        if !sha256Fingerprint.isEmpty { lines.append("SHA-256: \(sha256Fingerprint)") }
        return lines
    }

    static func format(_ date: Date) -> String {
        date.formatted(date: .abbreviated, time: .omitted)
    }
}

// MARK: - Verdict

nonisolated enum CertificateVerdict: Sendable, Equatable {
    case ok(daysRemaining: Int?)
    case missing
    case unreadable
    case expired(on: Date?)
    case notYetValid(from: Date?)
    /// The certificate and the private key in the same profile aren't a pair.
    case keyMismatch
    /// The private key can't be read without its password, so nothing could be
    /// checked about it. Not a failure of the certificate.
    case keyLocked
    /// Didn't chain to the authority we were told to trust.
    case chainUntrusted
    /// Valid and trusted, but not for this address.
    case hostnameMismatch(expected: String)
    /// Doesn't match the fingerprint this profile pins.
    case pinMismatch

    var isFailure: Bool {
        switch self {
        case .ok, .keyLocked: false
        default: true
        }
    }

    /// The advice this verdict maps to. One place, so the UI and the tests
    /// agree about what a given verdict means.
    var failure: ProbeFailure? {
        switch self {
        case .ok, .keyLocked: nil
        case .missing, .unreadable: .clientCertificateUntrusted
        case .expired: .clientCertificateExpired
        case .notYetValid: .clientCertificateNotYetValid
        case .keyMismatch: .clientKeyMismatch
        case .chainUntrusted: .clientCertificateUntrusted
        case .hostnameMismatch: .serverCertificateNameMismatch
        case .pinMismatch: .serverCertificatePinMismatch
        }
    }

    /// …and the same for a certificate presented BY the VPN, where the same
    /// shapes need different advice.
    var serverFailure: ProbeFailure? {
        switch self {
        case .ok, .keyLocked: nil
        case .expired: .serverCertificateExpired
        case .notYetValid: .serverCertificateExpired
        case .hostnameMismatch: .serverCertificateNameMismatch
        case .pinMismatch: .serverCertificatePinMismatch
        default: .serverCertificateUntrusted
        }
    }

    /// The pure core: given the facts, what's wrong with this certificate?
    /// Precedence is the order a person can act on: a certificate that expired
    /// is worth saying so even if it also fails to chain, because renewing it
    /// is the single step that fixes both.
    ///
    /// `nil` for a check means "not asked" and never produces a verdict.
    static func classify(notBefore: Date?, notAfter: Date?, now: Date = .now,
                         keyMatchesCertificate: Bool? = nil,
                         privateKeyLocked: Bool = false,
                         chainsToTrustedAnchor: Bool? = nil,
                         hostnameMatches: Bool? = nil,
                         expectedHostname: String = "",
                         pinMatches: Bool? = nil) -> CertificateVerdict {
        if pinMatches == false { return .pinMismatch }
        if let notAfter, notAfter < now { return .expired(on: notAfter) }
        if let notBefore, notBefore > now { return .notYetValid(from: notBefore) }
        if keyMatchesCertificate == false { return .keyMismatch }
        if chainsToTrustedAnchor == false { return .chainUntrusted }
        if hostnameMatches == false { return .hostnameMismatch(expected: expectedHostname) }
        if privateKeyLocked { return .keyLocked }
        let days = notAfter.map { Int($0.timeIntervalSince(now) / 86_400) }
        return .ok(daysRemaining: days)
    }
}

// MARK: - Hostname matching

nonisolated enum CertificateHostname {

    /// RFC 6125 name matching, pared to what a VPN endpoint needs: exact match,
    /// case-insensitive, plus a single leading `*` that covers ONE label and
    /// never the top two of a name.
    static func matches(host: String, names: [String]) -> Bool {
        let target = normalise(host)
        guard !target.isEmpty else { return false }
        return names.contains { matchesOne(host: target, name: normalise($0)) }
    }

    static func matchesOne(host: String, name: String) -> Bool {
        guard !name.isEmpty else { return false }
        if name == host { return true }
        guard name.hasPrefix("*.") else { return false }
        let suffix = String(name.dropFirst(1))          // ".example.org"
        // The wildcard covers exactly one label, so what remains after stripping
        // the suffix must contain no dot of its own.
        guard host.hasSuffix(suffix) else { return false }
        let label = String(host.dropLast(suffix.count))
        guard !label.isEmpty, !label.contains(".") else { return false }
        // "*.org" would cover the whole registry; require at least two more labels.
        return suffix.dropFirst().contains(".")
    }

    static func normalise(_ s: String) -> String {
        var t = s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        // SANs arrive as "DNS Name: vpn.example.org" from Security.framework in
        // some shapes, and with a trailing dot from others.
        if let colon = t.lastIndex(of: ":"), t.hasPrefix("dns") {
            t = String(t[t.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
        }
        while t.hasSuffix(".") { t.removeLast() }
        return t
    }
}

// MARK: - Reading real certificates

nonisolated enum ProbeCertificateInspector {

    static func facts(pem: String) -> CertificateFacts? {
        guard let cert = CertificateImport.certificates(inPEM: pem).first else { return nil }
        return facts(certificate: cert)
    }

    static func facts(certificate: SecCertificate) -> CertificateFacts {
        let summary = CertificateSummary(certificate: certificate)
        var f = CertificateFacts()
        f.commonName = summary.commonName
        f.organisation = summary.organisation
        f.issuerCommonName = summary.issuerCommonName
        f.subjectAlternativeNames = summary.sans
        f.notBefore = summary.notBefore
        f.notAfter = summary.notAfter
        f.keyAlgorithm = summary.keyAlgorithm
        f.keyBits = summary.keyBits
        f.sha256Fingerprint = summary.sha256Fingerprint
        f.isSelfSigned = summary.isSelfSigned
        return f
    }

    static func sha256(of certificate: SecCertificate) -> String {
        let der = SecCertificateCopyData(certificate) as Data
        return SHA256.hash(data: der).map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    /// Does `pem`'s leaf chain to one of the anchors in `caPEM`? Evaluated with
    /// SecTrust against those anchors ONLY (`anchorCertificatesOnly`), because
    /// the question is "does the profile's own authority vouch for this", not
    /// "does anyone on the internet".
    ///
    /// Returns nil when the question can't be asked (no CA in the profile, or
    /// nothing parseable) — the caller reports that honestly rather than
    /// guessing a pass or a fail.
    static func chains(leafPEM: String, toAnchorsPEM caPEM: String?,
                       now: Date = .now) -> Bool? {
        guard let caPEM, !caPEM.isEmpty else { return nil }
        let chain = CertificateImport.certificates(inPEM: leafPEM)
        let anchors = CertificateImport.certificates(inPEM: caPEM)
        guard !chain.isEmpty, !anchors.isEmpty else { return nil }
        return chains(chain: chain, anchors: anchors, now: now)
    }

    static func chains(chain: [SecCertificate], anchors: [SecCertificate],
                       now: Date = .now) -> Bool? {
        var trust: SecTrust?
        // A basic X.509 policy: dates and signatures, no hostname. Hostname is
        // checked separately so the two produce distinct, actionable verdicts.
        let policy = SecPolicyCreateBasicX509()
        guard SecTrustCreateWithCertificates(chain as CFArray, policy, &trust) == errSecSuccess,
              let trust else { return nil }
        SecTrustSetAnchorCertificates(trust, anchors as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)
        // Evaluate at the given instant so an expired-certificate verdict comes
        // from our own date check, not from SecTrust folding it into "invalid".
        SecTrustSetVerifyDate(trust, now as CFDate)
        var error: CFError?
        let ok = SecTrustEvaluateWithError(trust, &error)
        return ok
    }

    /// Does the private key in the profile belong to its certificate? nil when
    /// the key is encrypted (nothing can be said) or absent.
    static func keyMatchesCertificate(keyPEM: String?, certificatePEM: String?) -> (matches: Bool?, locked: Bool) {
        guard let keyPEM, !keyPEM.isEmpty else { return (nil, false) }
        let summary = PrivateKeySummary(pem: keyPEM, certificatePEM: certificatePEM)
        return (summary.matchesCertificate, summary.encrypted)
    }
}
