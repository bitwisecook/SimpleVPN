// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ControlSurface.swift
//  The control plane's public vocabulary: commands, queries, replies and events as
//  PURE DATA. Every interface — the app's own UI, the `simplevpn` CLI (over the
//  control socket), App Intents, and later the Tcl control-plane hooks — speaks
//  exactly these types, and every mutation lands in ControlPlaneDispatcher, so all
//  surfaces share one backend, one policy gate and one liveness stream by
//  construction.
//
//  WIRE FORMAT is hand-written (not synthesized) because it is a public contract:
//  flat JSON objects with a discriminator — {"cmd":"connect","profile":"x"},
//  {"query":"profiles"}, {"event":"status","profile":"x","status":"connected"} —
//  chosen so the same stable names can become the Tcl command vocabulary later
//  (CTL::connect, the CTL_COMMAND event's [CTL::cmd] property, …). Add fields
//  leniently, never rename: an old CLI must keep working against a newer app.
//
//  This file is deliberately dependency-light (Foundation only, no NE/AppKit):
//  the CLI target compiles it directly.
//

import Foundation

// MARK: - Commands (mutations)

/// One requested mutation. Commands are data so guards can inspect/veto/rewrite
/// them (MDM today, Tcl `CTL_*` handlers later) before anything executes.
nonisolated enum ControlCommand: Sendable, Equatable {
    /// Connect using the profile's configured credential source (stored/managed —
    /// nothing typed). The dispatcher's readiness gate turns "needs typing" into
    /// a `.notReady` reply rather than a half-started attempt.
    case connect(profile: String)
    case disconnect(profile: String)
    case pause(profile: String)
    case resume(profile: String)
    /// Which VPN owns the default route; nil ⇒ Direct (no VPN owns it).
    case setDefaultGateway(profile: String?)

    /// The profile a command targets (all current commands target one).
    var profileID: String? {
        switch self {
        case .connect(let p), .disconnect(let p), .pause(let p), .resume(let p): p
        case .setDefaultGateway(let p): p
        }
    }

    /// Stable wire/Tcl name.
    var name: String {
        switch self {
        case .connect: "connect"
        case .disconnect: "disconnect"
        case .pause: "pause"
        case .resume: "resume"
        case .setDefaultGateway: "set-gateway"
        }
    }
}

extension ControlCommand: nonisolated Codable {
    private enum Keys: String, CodingKey { case cmd, profile }

    nonisolated init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        let name = try c.decode(String.self, forKey: .cmd)
        func profile() throws -> String { try c.decode(String.self, forKey: .profile) }
        switch name {
        case "connect": self = .connect(profile: try profile())
        case "disconnect": self = .disconnect(profile: try profile())
        case "pause": self = .pause(profile: try profile())
        case "resume": self = .resume(profile: try profile())
        case "set-gateway": self = .setDefaultGateway(profile: try c.decodeIfPresent(String.self, forKey: .profile))
        default:
            throw DecodingError.dataCorruptedError(forKey: .cmd, in: c,
                debugDescription: "unknown command \"\(name)\"")
        }
    }

    nonisolated func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Keys.self)
        try c.encode(name, forKey: .cmd)
        try c.encodeIfPresent(profileID, forKey: .profile)
    }
}

// MARK: - Queries (reads)

nonisolated enum ControlQuery: Sendable, Equatable {
    case profiles
    case status(profile: String)
    case gateway
    case version

    var name: String {
        switch self {
        case .profiles: "profiles"
        case .status: "status"
        case .gateway: "gateway"
        case .version: "version"
        }
    }
}

extension ControlQuery: nonisolated Codable {
    private enum Keys: String, CodingKey { case query, profile }

    nonisolated init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        let name = try c.decode(String.self, forKey: .query)
        switch name {
        case "profiles": self = .profiles
        case "status": self = .status(profile: try c.decode(String.self, forKey: .profile))
        case "gateway": self = .gateway
        case "version": self = .version
        default:
            throw DecodingError.dataCorruptedError(forKey: .query, in: c,
                debugDescription: "unknown query \"\(name)\"")
        }
    }

    nonisolated func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Keys.self)
        try c.encode(name, forKey: .query)
        if case .status(let p) = self { try c.encode(p, forKey: .profile) }
    }
}

// MARK: - Replies

/// One profile as the control surface tells it — strings only, so the CLI and
/// scripts never need app types. `status`/`readiness` use the stable wire words
/// (see `ControlStatusWord` / `ControlReadinessWord`).
nonisolated struct ControlProfileSummary: Sendable, Equatable, Codable, Identifiable {
    var id: String
    var name: String
    var kind: String          // "openvpn" | "tailscale" | … (VPNKind rawValue)
    var status: String        // ControlStatusWord
    var readiness: String     // ControlReadinessWord
    var server: String
    var gatewayOwner: Bool
}

/// Stable wire words for connection status. The app's NEVPNStatus maps onto
/// these; interfaces must never see a raw NE integer.
nonisolated enum ControlStatusWord {
    static let invalid = "invalid"
    static let disconnected = "disconnected"
    static let connecting = "connecting"
    static let connected = "connected"
    static let reasserting = "reconnecting"
    static let disconnecting = "disconnecting"
}

nonisolated enum ControlReadinessWord {
    static let ready = "ready"
    static let needsSignIn = "needs-sign-in"
    static let needsCode = "needs-code"
    static let blocked = "blocked"
}

/// The dispatcher's answer. The failure cases are distinct on purpose — the CLI
/// exits differently for "policy said no" vs "you need to open the app and type".
nonisolated enum ControlReply: Sendable, Equatable {
    case ok
    case profiles([ControlProfileSummary])
    case status(ControlProfileSummary)
    case gateway(owner: String?)
    case version(String)
    /// A guard vetoed the command (MDM now, Tcl later). Nothing executed.
    case denied(String)
    /// The command needs something only the app's UI can collect (credentials,
    /// a one-time code). Nothing executed.
    case notReady(String)
    /// The command ran and failed, or the request was malformed.
    case failed(String)
}

extension ControlReply: nonisolated Codable {
    private enum Keys: String, CodingKey {
        case ok, profiles, status, gateway, version, denied, notReady = "not-ready", error
    }

    nonisolated init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        if let why = try c.decodeIfPresent(String.self, forKey: .denied) { self = .denied(why); return }
        if let why = try c.decodeIfPresent(String.self, forKey: .notReady) { self = .notReady(why); return }
        if let why = try c.decodeIfPresent(String.self, forKey: .error) { self = .failed(why); return }
        if let list = try c.decodeIfPresent([ControlProfileSummary].self, forKey: .profiles) { self = .profiles(list); return }
        if let one = try c.decodeIfPresent(ControlProfileSummary.self, forKey: .status) { self = .status(one); return }
        if let v = try c.decodeIfPresent(String.self, forKey: .version) { self = .version(v); return }
        if c.contains(.gateway) { self = .gateway(owner: try c.decodeIfPresent(String.self, forKey: .gateway)); return }
        self = .ok
    }

    nonisolated func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Keys.self)
        switch self {
        case .ok:
            try c.encode(true, forKey: .ok)
        case .profiles(let list):
            try c.encode(true, forKey: .ok); try c.encode(list, forKey: .profiles)
        case .status(let one):
            try c.encode(true, forKey: .ok); try c.encode(one, forKey: .status)
        case .gateway(let owner):
            try c.encode(true, forKey: .ok)
            // Encode an explicit null so `contains(.gateway)` round-trips "Direct".
            try c.encode(owner, forKey: .gateway)
        case .version(let v):
            try c.encode(true, forKey: .ok); try c.encode(v, forKey: .version)
        case .denied(let why):
            try c.encode(false, forKey: .ok); try c.encode(why, forKey: .denied)
        case .notReady(let why):
            try c.encode(false, forKey: .ok); try c.encode(why, forKey: .notReady)
        case .failed(let why):
            try c.encode(false, forKey: .ok); try c.encode(why, forKey: .error)
        }
    }
}

// MARK: - Events (liveness)

/// What changed, pushed to every subscriber — the UI's observation, the CLI's
/// `watch`, an intent's completion and (later) Tcl `CTL_*` handlers all see the
/// SAME stream, in the same order.
nonisolated enum ControlEvent: Sendable, Equatable {
    case statusChanged(profile: String, status: String)   // ControlStatusWord
    case gatewayChanged(owner: String?)                    // nil ⇒ Direct
    case profilesChanged                                   // added/removed/renamed
    /// A guard rejected a command — surfaced so a watching admin/script SEES
    /// denials, not just successes.
    case commandDenied(cmd: String, profile: String?, reason: String)
}

extension ControlEvent: nonisolated Codable {
    private enum Keys: String, CodingKey { case event, profile, status, owner, cmd, reason }

    nonisolated init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        switch try c.decode(String.self, forKey: .event) {
        case "status":
            self = .statusChanged(profile: try c.decode(String.self, forKey: .profile),
                                  status: try c.decode(String.self, forKey: .status))
        case "gateway":
            self = .gatewayChanged(owner: try c.decodeIfPresent(String.self, forKey: .owner))
        case "profiles":
            self = .profilesChanged
        case "denied":
            self = .commandDenied(cmd: try c.decode(String.self, forKey: .cmd),
                                  profile: try c.decodeIfPresent(String.self, forKey: .profile),
                                  reason: try c.decode(String.self, forKey: .reason))
        case let other:
            throw DecodingError.dataCorruptedError(forKey: .event, in: c,
                debugDescription: "unknown event \"\(other)\"")
        }
    }

    nonisolated func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Keys.self)
        switch self {
        case .statusChanged(let profile, let status):
            try c.encode("status", forKey: .event)
            try c.encode(profile, forKey: .profile)
            try c.encode(status, forKey: .status)
        case .gatewayChanged(let owner):
            try c.encode("gateway", forKey: .event)
            try c.encode(owner, forKey: .owner)   // explicit null = Direct
        case .profilesChanged:
            try c.encode("profiles", forKey: .event)
        case .commandDenied(let cmd, let profile, let reason):
            try c.encode("denied", forKey: .event)
            try c.encode(cmd, forKey: .cmd)
            try c.encodeIfPresent(profile, forKey: .profile)
            try c.encode(reason, forKey: .reason)
        }
    }
}

// MARK: - Guards (the hook chain)

/// A guard's verdict on a command about to execute.
nonisolated enum ControlDecision: Sendable, Equatable {
    case allow
    case deny(String)
}

// MARK: - Wire envelope (the socket protocol)

/// One JSON line from a client: a request id plus either a command, a query, or
/// a watch subscription. Replies echo the id; watch pushes bare event objects.
nonisolated struct ControlRequestEnvelope: Sendable, Codable {
    var id: Int
    var command: ControlCommand?
    var query: ControlQuery?
    var watch: Bool?

    private enum Keys: String, CodingKey { case id, cmd, query, watch }

    init(id: Int, command: ControlCommand? = nil, query: ControlQuery? = nil, watch: Bool? = nil) {
        self.id = id
        self.command = command
        self.query = query
        self.watch = watch
    }

    nonisolated init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        id = try c.decode(Int.self, forKey: .id)
        watch = try c.decodeIfPresent(Bool.self, forKey: .watch)
        // The command/query discriminators live in the SAME flat object.
        command = c.contains(.cmd) ? try ControlCommand(from: decoder) : nil
        query = c.contains(.query) ? try ControlQuery(from: decoder) : nil
    }

    nonisolated func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Keys.self)
        try c.encode(id, forKey: .id)
        try c.encodeIfPresent(watch, forKey: .watch)
        try command?.encode(to: encoder)
        try query?.encode(to: encoder)
    }
}

/// One JSON line back: the echoed id plus the reply's fields, flat.
nonisolated struct ControlReplyEnvelope: Sendable, Codable {
    var id: Int
    var reply: ControlReply

    private enum Keys: String, CodingKey { case id }

    init(id: Int, reply: ControlReply) {
        self.id = id
        self.reply = reply
    }

    nonisolated init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        id = try c.decode(Int.self, forKey: .id)
        reply = try ControlReply(from: decoder)
    }

    nonisolated func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Keys.self)
        try c.encode(id, forKey: .id)
        try reply.encode(to: encoder)
    }
}

// MARK: - Socket location

nonisolated enum ControlSocket {
    /// The control socket's fixed home. Same-user only (0600, in the user's own
    /// Application Support); the app creates it, the CLI dials it.
    static func path() -> String {
        let base = FileManager.default.urls(for: .applicationSupportDirectory,
                                            in: .userDomainMask).first!
        return base.appendingPathComponent("SimpleVPN/control.sock").path
    }
}
