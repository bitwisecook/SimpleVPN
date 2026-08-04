// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OpenConnectAuthWire.swift
//  The conversational JSON-lines protocol between the app and the bundled
//  `ocauth-helper` (libopenconnect sign-in in user context). One JSON object per
//  line, both directions, over the helper's stdin/stdout:
//
//    app → helper   {"start":{"server":…,"protocol":…,"params":{…}}}
//                   {"answers":{"<field id>":"<value>",…}}
//                   {"accept":true|false}
//                   {"cancel":true}
//
//    helper → app   {"form":{"authID":…,"fields":[{id,label,type,secret,options?}…]}}
//                   {"open-url":"https://…"}
//                   {"progress":{"level":1,"message":…}}
//                   {"cert":{"fingerprint":…,"details":…,"reason":…}}
//                   {"done":{"cookie":…,"servercert":…,"connect-url":…,"resolve":{host,ip}}}
//                   {"error":{"kind":…,"message":…}}
//
//  This file is compiled into BOTH the app target and OCAuthHelper (the
//  ControlSurface.swift pattern) so the two sides can never disagree about the
//  wire format; OpenConnectAuthTests pins the round-trips. UI-free, C-free.
//  Everything is `nonisolated`: the app target defaults to MainActor isolation
//  and these types travel between the helper conversation task and callers.
//

import Foundation

// MARK: - app → helper

/// The opening request: which gateway to sign in to, and everything
/// libopenconnect needs at auth time. Secrets in here (key password, proxy
/// URL credentials) ride the helper's private stdin pipe — never argv.
nonisolated struct OCAuthStart: Codable, Equatable, Sendable {
    var server: String
    /// openconnect `--protocol` token (VPNKind.openconnectProtocol).
    var vpnProtocol: String
    var params = OCAuthParams()

    init(server: String, vpnProtocol: String, params: OCAuthParams = OCAuthParams()) {
        self.server = server
        self.vpnProtocol = vpnProtocol
        self.params = params
    }

    private enum CodingKeys: String, CodingKey {
        case server, vpnProtocol = "protocol", params
    }
}

/// Auth-time knobs, all optional (absent = library default). Mirrors the flags
/// the retired `openconnect --external-browser` invocation carried.
nonisolated struct OCAuthParams: Codable, Equatable, Sendable {
    var username: String?
    var realm: String?            // --authgroup
    var usergroup: String?        // --usergroup (URL path)
    var servercert: String?       // pinned cert (accept only this when trust fails)
    var cafile: String?           // --cafile
    var useragent: String?        // --useragent
    var reportedOS: String?       // --os
    var versionString: String?    // --version-string
    var localHostname: String?    // --local-hostname
    var proxy: String?            // --proxy (URL; may embed credentials — stdin only)
    var certFile: String?         // --certificate (client cert for cert+SSO gateways)
    var keyFile: String?          // --sslkey
    var keyPassword: String?      // encrypted key / PKCS#12 passphrase

    private enum CodingKeys: String, CodingKey {
        case username, realm, usergroup, servercert, cafile, useragent
        case reportedOS = "reported-os"
        case versionString = "version-string"
        case localHostname = "local-hostname"
        case proxy
        case certFile = "cert"
        case keyFile = "key"
        case keyPassword = "key-password"
    }
}

/// Every message the app can send. Exactly one key per line.
nonisolated enum OCAuthClientMessage: Equatable, Sendable {
    case start(OCAuthStart)
    case answers([String: String])
    case accept(Bool)
    case cancel
}

extension OCAuthClientMessage: nonisolated Codable {
    private enum CodingKeys: String, CodingKey { case start, answers, accept, cancel }

    nonisolated init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        if let s = try c.decodeIfPresent(OCAuthStart.self, forKey: .start) { self = .start(s); return }
        if let a = try c.decodeIfPresent([String: String].self, forKey: .answers) { self = .answers(a); return }
        if let ok = try c.decodeIfPresent(Bool.self, forKey: .accept) { self = .accept(ok); return }
        if try c.decodeIfPresent(Bool.self, forKey: .cancel) == true { self = .cancel; return }
        throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath,
            debugDescription: "no recognised client-message key"))
    }

    nonisolated func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .start(let s): try c.encode(s, forKey: .start)
        case .answers(let a): try c.encode(a, forKey: .answers)
        case .accept(let ok): try c.encode(ok, forKey: .accept)
        case .cancel: try c.encode(true, forKey: .cancel)
        }
    }
}

// MARK: - helper → app

/// One field of a gateway sign-in form. `id` is openconnect's field name (what
/// an answer must be keyed by); `secret` marks values that must never be
/// echoed or logged.
nonisolated struct OCAuthFormField: Codable, Equatable, Sendable {
    /// Wire values for `type` (string, not enum, so an older app tolerates a
    /// newer helper's field kinds — it can still show the label and refuse).
    nonisolated enum Kind {
        static let text = "text"
        static let password = "password"
        static let select = "select"
        static let token = "token"       // OTP / verification-code entry
        static let ssoUser = "sso-user"  // username field of an SSO form
    }
    nonisolated struct Option: Codable, Equatable, Sendable {
        var value: String   // choice name (what an answer carries)
        var label: String
    }
    var id: String
    var label: String
    var type: String
    var secret: Bool
    var options: [Option]?
}

/// A sign-in form the gateway raised, needing `{"answers":…}` (or `{"cancel":true}`).
nonisolated struct OCAuthFormSpec: Codable, Equatable, Sendable {
    var authID: String?
    var banner: String?
    var message: String?
    var error: String?    // the gateway's own complaint about the previous attempt
    var fields: [OCAuthFormField] = []
}

/// A server certificate that FAILED system-trust verification and matched no
/// pin. Needs `{"accept":…}` — and the app must never answer true on its own.
nonisolated struct OCAuthCert: Codable, Equatable, Sendable {
    var fingerprint: String   // openconnect peer-cert hash ("pin-sha256:…")
    var details: String       // human-readable certificate summary
    var reason: String?       // why verification failed
}

/// Successful sign-in: everything the tunnel connection needs, per
/// libopenconnect's documented auth→connect handoff (cookie + exact cert +
/// connect URL + resolved address).
nonisolated struct OCAuthDone: Codable, Equatable, Sendable {
    nonisolated struct Resolve: Codable, Equatable, Sendable {
        var host: String   // DNS name (SNI / Host header)
        var ip: String     // the exact address authenticated to (defeats round-robin DNS)
    }
    var cookie: String
    var servercert: String    // peer-cert hash — connect must see this exact cert
    var connectURL: String    // full URL incl. port + path (Pulse et al vary the path)
    var resolve: Resolve?

    private enum CodingKeys: String, CodingKey {
        case cookie, servercert, connectURL = "connect-url", resolve
    }

    init(cookie: String, servercert: String, connectURL: String, resolve: Resolve? = nil) {
        self.cookie = cookie
        self.servercert = servercert
        self.connectURL = connectURL
        self.resolve = resolve
    }
}

/// Every event the helper can emit. Exactly one key per line.
nonisolated enum OCAuthEvent: Equatable, Sendable {
    case form(OCAuthFormSpec)
    case openURL(String)
    case progress(level: Int, message: String)
    case cert(OCAuthCert)
    case done(OCAuthDone)
    case error(kind: String, message: String)
}

extension OCAuthEvent: nonisolated Codable {
    private enum CodingKeys: String, CodingKey {
        case form
        case openURL = "open-url"
        case progress, cert, done, error
    }
    private nonisolated struct Progress: Codable { var level: Int; var message: String }
    private nonisolated struct Failure: Codable { var kind: String; var message: String }

    nonisolated init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        if let f = try c.decodeIfPresent(OCAuthFormSpec.self, forKey: .form) { self = .form(f); return }
        if let u = try c.decodeIfPresent(String.self, forKey: .openURL) { self = .openURL(u); return }
        if let p = try c.decodeIfPresent(Progress.self, forKey: .progress) {
            self = .progress(level: p.level, message: p.message); return
        }
        if let cert = try c.decodeIfPresent(OCAuthCert.self, forKey: .cert) { self = .cert(cert); return }
        if let d = try c.decodeIfPresent(OCAuthDone.self, forKey: .done) { self = .done(d); return }
        if let e = try c.decodeIfPresent(Failure.self, forKey: .error) {
            self = .error(kind: e.kind, message: e.message); return
        }
        throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath,
            debugDescription: "no recognised event key"))
    }

    nonisolated func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .form(let f): try c.encode(f, forKey: .form)
        case .openURL(let u): try c.encode(u, forKey: .openURL)
        case .progress(let level, let message):
            try c.encode(Progress(level: level, message: message), forKey: .progress)
        case .cert(let cert): try c.encode(cert, forKey: .cert)
        case .done(let d): try c.encode(d, forKey: .done)
        case .error(let kind, let message):
            try c.encode(Failure(kind: kind, message: message), forKey: .error)
        }
    }
}

/// Error kinds on the wire — shared vocabulary, not an enum, so version skew
/// degrades to a generic message instead of a decode failure.
nonisolated enum OCAuthErrorKind {
    static let badRequest = "badRequest"     // malformed start / server URL
    static let cancelled = "cancelled"       // the app answered {"cancel":true}
    static let certRefused = "certRefused"   // the app answered {"accept":false}
    static let authFailed = "authFailed"     // gateway refused the sign-in
}

// MARK: - Line framing

/// One JSON object per `\n`-terminated line. JSONEncoder never emits raw
/// newlines (they're escaped inside strings), so encode-then-append is safe.
nonisolated enum OCAuthJSON {
    static func encodeLine<T: Encodable>(_ value: T) throws -> Data {
        var data = try JSONEncoder().encode(value)
        data.append(0x0A)
        return data
    }
    static func decode<T: Decodable>(_ type: T.Type, from line: Data) throws -> T {
        try JSONDecoder().decode(type, from: line)
    }
}

// MARK: - Stored-credential autofill (pure, testable)

/// Answers a gateway form from what the profile already knows — the "stored
/// credentials answer silently where they match" half of the SSO flow. Fields
/// it cannot answer are returned so the caller can say exactly what was asked.
nonisolated enum OCAuthFormAutofill {
    nonisolated struct Result: Equatable, Sendable {
        var answers: [String: String] = [:]
        var unanswered: [OCAuthFormField] = []
    }

    static func fill(_ form: OCAuthFormSpec, username: String?, password: String?) -> Result {
        var result = Result()
        for field in form.fields {
            switch field.type {
            case OCAuthFormField.Kind.text, OCAuthFormField.Kind.ssoUser:
                if let username, !username.isEmpty { result.answers[field.id] = username }
                else { result.unanswered.append(field) }
            case OCAuthFormField.Kind.password, OCAuthFormField.Kind.token:
                if let password, !password.isEmpty { result.answers[field.id] = password }
                else { result.unanswered.append(field) }
            case OCAuthFormField.Kind.select:
                // A one-choice select answers itself; a real choice (the helper
                // already applied the configured realm to the auth group) is a
                // decision this code must not guess at.
                if let only = field.options?.first, field.options?.count == 1 {
                    result.answers[field.id] = only.value
                } else {
                    result.unanswered.append(field)
                }
            default:
                result.unanswered.append(field)
            }
        }
        return result
    }
}
