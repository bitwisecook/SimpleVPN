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

// MARK: - Content sniffing
//
// `CertSlot` and `OVPNInline` used to live here. They are now in
// `Shared/OVPNInline.swift` so the packet-tunnel extension can re-insert the
// secret blocks it is handed at connect time without a second copy of this
// CRLF-sensitive parsing.

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
