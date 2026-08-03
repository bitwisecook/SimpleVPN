// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CertificateImport.swift
//  Certificate/key handling for the VPN editor's Certificates tab: sniff any
//  common format (PEM, DER, PKCS#12, OpenVPN static key) by content — never by
//  file extension — convert to PEM, and embed into the profile's inline blocks
//  (<ca>/<cert>/<key>/<tls-auth>/<tls-crypt>). The raw .ovpn stays the source
//  of truth; this file only reads and rewrites it.
//  Also parses certificates/keys into the human-readable summaries the cards
//  display (CN, SANs, issuer, expiry, key type, fingerprints, key↔cert match).
//

import Foundation
import Security
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

// MARK: - Content sniffing

/// What a dropped/browsed file turned out to contain.
nonisolated enum SniffedPayload {
    case certificates(pem: String, count: Int)      // one or more PEM certificates
    case privateKey(pem: String, encrypted: Bool)
    case pkcs12(Data)                               // needs a password to open
    case staticKey(text: String)                    // OpenVPN static key V1
    case unknown
}

nonisolated enum CertificateImport {

    /// Identify file contents. PEM markers first, then DER/PKCS#12 by parsing.
    static func sniff(_ data: Data) -> SniffedPayload {
        if let text = String(data: data, encoding: .utf8) {
            if text.contains("-----BEGIN OpenVPN Static key V1-----") {
                return .staticKey(text: normalizedPEM(text))
            }
            let certs = pemBlocks(in: text, label: "CERTIFICATE")
            if !certs.isEmpty {
                return .certificates(pem: certs.joined(separator: "\n"), count: certs.count)
            }
            if let key = firstPEMPrivateKey(in: text) {
                return .privateKey(pem: key.pem, encrypted: key.encrypted)
            }
        }
        // Binary: a lone DER certificate?
        if let cert = SecCertificateCreateWithData(nil, data as CFData) {
            let der = SecCertificateCopyData(cert) as Data
            return .certificates(pem: pemWrap(der: der, label: "CERTIFICATE"), count: 1)
        }
        // PKCS#12? Probing with a wrong password distinguishes "is a p12" from junk:
        // a p12 fails with errSecAuthFailed/errSecPkcs12VerifyFailure, junk with decode.
        var items: CFArray?
        let probe = SecPKCS12Import(data as CFData,
                                    [kSecImportExportPassphrase as String: "\u{1}probe\u{1}"] as CFDictionary,
                                    &items)
        if probe == errSecAuthFailed || probe == errSecPkcs12VerifyFailure || probe == errSecSuccess {
            return .pkcs12(data)
        }
        return .unknown
    }

    /// Which slot a payload naturally belongs to (nil = ambiguous/none).
    static func naturalSlot(for payload: SniffedPayload) -> CertSlot? {
        switch payload {
        case .certificates: return nil            // could be CA or client cert — caller decides
        case .privateKey: return .key
        case .staticKey: return .tlsKey
        case .pkcs12: return nil                   // fills several slots after extraction
        case .unknown: return nil
        }
    }

    /// Whether a payload is acceptable in a slot (drives the wrong-slot offer).
    static func payload(_ payload: SniffedPayload, fits slot: CertSlot) -> Bool {
        switch (payload, slot) {
        case (.certificates, .ca), (.certificates, .cert): return true
        case (.privateKey, .key): return true
        case (.staticKey, .tlsKey): return true
        case (.pkcs12, _): return true             // extraction routes the pieces
        default: return false
        }
    }

    // MARK: PKCS#12

    struct PKCS12Contents {
        var certificatePEM: String?    // the identity's leaf certificate
        var chainPEM: String?          // any additional chain certificates
        var keyPEM: String?            // unencrypted PEM of the private key
    }

    enum PKCS12Error: LocalizedError {
        case wrongPassword
        case unreadable
        case keyNotExportable

        var errorDescription: String? {
            switch self {
            case .wrongPassword: return "The password doesn't match this file."
            case .unreadable: return "This PKCS#12 file can't be read."
            case .keyNotExportable: return "The private key in this file doesn't allow export."
            }
        }
    }

    /// Open a .p12/.pfx and convert its pieces to PEM.
    static func extractPKCS12(_ data: Data, password: String) throws -> PKCS12Contents {
        var rawItems: CFArray?
        let status = SecPKCS12Import(data as CFData,
                                     [kSecImportExportPassphrase as String: password] as CFDictionary,
                                     &rawItems)
        switch status {
        case errSecSuccess: break
        case errSecAuthFailed, errSecPkcs12VerifyFailure: throw PKCS12Error.wrongPassword
        default: throw PKCS12Error.unreadable
        }
        guard let items = rawItems as? [[String: Any]], let first = items.first else {
            throw PKCS12Error.unreadable
        }

        var out = PKCS12Contents()

        if let identity = first[kSecImportItemIdentity as String] {
            let secIdentity = identity as! SecIdentity
            var certRef: SecCertificate?
            if SecIdentityCopyCertificate(secIdentity, &certRef) == errSecSuccess, let cert = certRef {
                out.certificatePEM = pemWrap(der: SecCertificateCopyData(cert) as Data, label: "CERTIFICATE")
            }
            var keyRef: SecKey?
            if SecIdentityCopyPrivateKey(secIdentity, &keyRef) == errSecSuccess, let key = keyRef {
                guard let pem = keyPEM(from: key) else {
                    purgeImportedIdentity(secIdentity)
                    throw PKCS12Error.keyNotExportable
                }
                out.keyPEM = pem
            }
            // SecPKCS12Import silently adds the identity (cert + private key) to
            // the user's login keychain. We only wanted its PEM — leaving it
            // there pollutes the keychain with a credential the user never chose
            // to store. Remove it now that we've extracted what we need.
            purgeImportedIdentity(secIdentity)
        }

        // Chain certificates beyond the identity's leaf → CA material.
        if let chain = first[kSecImportItemCertChain as String] as? [SecCertificate], chain.count > 1 {
            let extras = chain.dropFirst().map {
                pemWrap(der: SecCertificateCopyData($0) as Data, label: "CERTIFICATE")
            }
            out.chainPEM = extras.joined(separator: "\n")
        }
        return out
    }

    /// Remove an identity SecPKCS12Import added to the login keychain — both the
    /// certificate and (via the identity) its private key. Best-effort.
    private static func purgeImportedIdentity(_ identity: SecIdentity) {
        var certRef: SecCertificate?
        if SecIdentityCopyCertificate(identity, &certRef) == errSecSuccess, let cert = certRef {
            SecItemDelete([kSecClass as String: kSecClassCertificate,
                           kSecValueRef as String: cert] as CFDictionary)
        }
        var keyRef: SecKey?
        if SecIdentityCopyPrivateKey(identity, &keyRef) == errSecSuccess, let key = keyRef {
            SecItemDelete([kSecClass as String: kSecClassKey,
                           kSecValueRef as String: key] as CFDictionary)
        }
        SecItemDelete([kSecClass as String: kSecClassIdentity,
                       kSecValueRef as String: identity] as CFDictionary)
    }

    /// Export a SecKey as unencrypted PEM (SecItemExport, OpenSSL format + armour).
    static func keyPEM(from key: SecKey) -> String? {
        var exported: CFData?
        let status = SecItemExport(key, .formatOpenSSL, .pemArmour, nil, &exported)
        guard status == errSecSuccess, let data = exported as Data?,
              let pem = String(data: data, encoding: .utf8) else { return nil }
        return normalizedPEM(pem)
    }

    // MARK: PEM plumbing

    static func pemWrap(der: Data, label: String) -> String {
        // The END marker MUST start its own line — OpenSSL/OpenVPN PEM readers
        // reject "…base64-----END…" even though lenient parsers accept it.
        var b64 = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        while b64.hasSuffix("\n") { b64.removeLast() }
        return "-----BEGIN \(label)-----\n\(b64)\n-----END \(label)-----"
    }

    /// All "-----BEGIN <label>----- … -----END <label>-----" blocks in a text.
    static func pemBlocks(in text: String, label: String) -> [String] {
        var blocks: [String] = []
        var remainder = Substring(text)
        let begin = "-----BEGIN \(label)-----"
        let end = "-----END \(label)-----"
        while let b = remainder.range(of: begin), let e = remainder.range(of: end, range: b.upperBound..<remainder.endIndex) {
            blocks.append(String(remainder[b.lowerBound..<e.upperBound]))
            remainder = remainder[e.upperBound...]
        }
        return blocks
    }

    private static func firstPEMPrivateKey(in text: String) -> (pem: String, encrypted: Bool)? {
        for label in ["ENCRYPTED PRIVATE KEY", "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"] {
            if let block = pemBlocks(in: text, label: label).first {
                // Legacy OpenSSL encryption marks the *inside* of the block.
                let encrypted = label.hasPrefix("ENCRYPTED") || block.contains("Proc-Type: 4,ENCRYPTED")
                return (block, encrypted)
            }
        }
        return nil
    }

    private static func normalizedPEM(_ text: String) -> String {
        text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// SecCertificate objects for every PEM certificate in a string.
    static func certificates(inPEM pem: String) -> [SecCertificate] {
        pemBlocks(in: pem, label: "CERTIFICATE").compactMap { block in
            let base64 = block
                .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
                .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
                .replacingOccurrences(of: "\n", with: "")
                .replacingOccurrences(of: "\r", with: "")
            guard let der = Data(base64Encoded: base64) else { return nil }
            return SecCertificateCreateWithData(nil, der as CFData)
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

// MARK: - Summaries for the cards

nonisolated struct CertificateSummary: Identifiable, Equatable {
    var id: String { sha256Fingerprint }

    var commonName = ""
    var organisation = ""
    var issuerCommonName = ""
    var issuerOrganisation = ""
    var sans: [String] = []
    var notBefore: Date?
    var notAfter: Date?
    var keyAlgorithm: String?
    var keyBits: Int?
    var isSelfSigned = false
    var serialHex = ""
    var sha256Fingerprint = ""

    enum ExpiryState: Equatable {
        case ok(Date?)
        case expiringSoon(days: Int)
        case expired
    }

    var expiryState: ExpiryState {
        guard let notAfter else { return .ok(nil) }
        let now = Date()
        if notAfter < now { return .expired }
        let days = Int(notAfter.timeIntervalSince(now) / 86_400)
        return days < 30 ? .expiringSoon(days: days) : .ok(notAfter)
    }

    var displayName: String {
        if !commonName.isEmpty { return commonName }
        if !organisation.isEmpty { return organisation }
        return "Certificate"
    }

    init(certificate: SecCertificate) {
        let der = SecCertificateCopyData(certificate) as Data
        sha256Fingerprint = SHA256.hash(data: der)
            .map { String(format: "%02X", $0) }.joined(separator: ":")
        if let serial = SecCertificateCopySerialNumberData(certificate, nil) as Data? {
            serialHex = serial.map { String(format: "%02X", $0) }.joined(separator: ":")
        }

        // Structured fields via SecCertificateCopyValues.
        let wanted = [kSecOIDX509V1SubjectName, kSecOIDX509V1IssuerName,
                      kSecOIDX509V1ValidityNotBefore, kSecOIDX509V1ValidityNotAfter,
                      kSecOIDSubjectAltName] as CFArray
        let values = SecCertificateCopyValues(certificate, wanted, nil) as? [CFString: [CFString: Any]] ?? [:]

        if let subject = Self.nameComponents(values[kSecOIDX509V1SubjectName]) {
            commonName = subject["2.5.4.3"] ?? ""
            organisation = subject["2.5.4.10"] ?? ""
        }
        if commonName.isEmpty,
           let summary = SecCertificateCopySubjectSummary(certificate) as String? {
            commonName = summary
        }
        if let issuer = Self.nameComponents(values[kSecOIDX509V1IssuerName]) {
            issuerCommonName = issuer["2.5.4.3"] ?? ""
            issuerOrganisation = issuer["2.5.4.10"] ?? ""
        }
        notBefore = Self.date(values[kSecOIDX509V1ValidityNotBefore])
        notAfter = Self.date(values[kSecOIDX509V1ValidityNotAfter])
        sans = Self.subjectAltNames(values[kSecOIDSubjectAltName])

        if let key = SecCertificateCopyKey(certificate),
           let attrs = SecKeyCopyAttributes(key) as? [CFString: Any] {
            keyBits = attrs[kSecAttrKeySizeInBits] as? Int
            if let type = attrs[kSecAttrKeyType] as? String {
                switch type as CFString {
                case kSecAttrKeyTypeRSA: keyAlgorithm = "RSA"
                case kSecAttrKeyTypeECSECPrimeRandom: keyAlgorithm = "EC"
                default: keyAlgorithm = nil
                }
            }
        }

        // Self-signed: normalized subject == normalized issuer.
        if let subj = SecCertificateCopyNormalizedSubjectSequence(certificate) as Data?,
           let iss = SecCertificateCopyNormalizedIssuerSequence(certificate) as Data? {
            isSelfSigned = subj == iss
        }
    }

    /// Flatten a SecCertificateCopyValues name section into OID → value.
    private static func nameComponents(_ section: [CFString: Any]?) -> [String: String]? {
        guard let entries = section?[kSecPropertyKeyValue] as? [[CFString: Any]] else { return nil }
        var out: [String: String] = [:]
        for entry in entries {
            if let oid = entry[kSecPropertyKeyLabel] as? String,
               let value = entry[kSecPropertyKeyValue] as? String {
                out[oid] = value    // last of repeated OIDs wins — fine for display
            }
        }
        return out
    }

    private static func date(_ section: [CFString: Any]?) -> Date? {
        guard let number = section?[kSecPropertyKeyValue] as? NSNumber else { return nil }
        return Date(timeIntervalSinceReferenceDate: number.doubleValue)
    }

    private static func subjectAltNames(_ section: [CFString: Any]?) -> [String] {
        guard let entries = section?[kSecPropertyKeyValue] as? [[CFString: Any]] else { return [] }
        return entries.compactMap { entry in
            guard let value = entry[kSecPropertyKeyValue] as? String else { return nil }
            return value
        }
    }
}

nonisolated struct PrivateKeySummary: Equatable {
    var algorithm: String?
    var bits: Int?
    var encrypted = false
    /// nil = couldn't check (encrypted key or no certificate).
    var matchesCertificate: Bool?

    init(pem: String, certificatePEM: String?) {
        encrypted = pem.contains("ENCRYPTED PRIVATE KEY") || pem.contains("Proc-Type: 4,ENCRYPTED")
        guard !encrypted, let key = Self.importKey(pem) else { return }

        if let attrs = SecKeyCopyAttributes(key) as? [CFString: Any] {
            bits = attrs[kSecAttrKeySizeInBits] as? Int
            if let type = attrs[kSecAttrKeyType] as? String {
                switch type as CFString {
                case kSecAttrKeyTypeRSA: algorithm = "RSA"
                case kSecAttrKeyTypeECSECPrimeRandom: algorithm = "EC"
                default: algorithm = nil
                }
            }
        }

        if let certPEM = certificatePEM,
           let cert = CertificateImport.certificates(inPEM: certPEM).first,
           let certKey = SecCertificateCopyKey(cert),
           let ours = SecKeyCopyPublicKey(key) {
            let a = SecKeyCopyExternalRepresentation(ours, nil) as Data?
            let b = SecKeyCopyExternalRepresentation(certKey, nil) as Data?
            if let a, let b { matchesCertificate = (a == b) }
        }
    }

    private static func importKey(_ pem: String) -> SecKey? {
        var format = SecExternalFormat.formatOpenSSL
        var itemType = SecExternalItemType.itemTypePrivateKey
        var items: CFArray?
        var params = SecItemImportExportKeyParameters()
        params.version = UInt32(SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION)
        let status = SecItemImport(Data(pem.utf8) as CFData, nil, &format, &itemType,
                                   [], &params, nil, &items)
        guard status == errSecSuccess,
              let list = items as? [AnyObject],
              let first = list.first else { return nil }
        return (first as! SecKey)
    }
}

nonisolated struct TLSKeySummary: Equatable {
    var mode: String        // "tls-crypt" | "tls-auth"
    var direction: String?  // key-direction, tls-auth only

    var displayMode: String {
        mode == "tls-crypt" ? "TLS-Crypt (encrypts the handshake)" : "TLS-Auth (signs the handshake)"
    }
}
