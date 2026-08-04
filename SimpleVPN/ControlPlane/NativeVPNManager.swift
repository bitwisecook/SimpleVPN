// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  NativeVPNManager.swift
//  The protocols macOS carries itself, via NEVPNManager (the "personal VPN"):
//  IKEv2 and IPsec (IKEv1/Cisco). The OS does the tunnelling — no engine, no
//  system extension. Two facts shape this:
//   • NEVPNManager.shared() is a SINGLETON — macOS lets an app manage exactly
//     one personal-VPN configuration at a time. We store the fields for several
//     and push the selected one into that single slot on connect.
//   • It needs the Personal VPN capability (com.apple.developer.networking.vpn.api)
//     on the signing profile. Until that's provisioned, saveToPreferences fails
//     with a clear entitlement error, surfaced verbatim.
//  L2TP/IPsec has no third-party NEVPNManager API on macOS, so it's offered as a
//  downloadable .mobileconfig the user installs (see NativeVPNConfig.mobileconfig).
//

import Foundation
@preconcurrency import NetworkExtension
import Observation
import os

struct NativeVPNConfig: Codable, Sendable, Equatable, Identifiable {
    var id = UUID().uuidString
    var name = "New Native VPN"
    var kind: VPNKind = .ikev2      // .ikev2 | .ipsec | .l2tp
    var server = ""
    var remoteID = ""               // IKEv2 remote identifier (server cert CN / FQDN)
    var username = ""
    // Auth: username/password (EAP) is the default; a shared secret (PSK) is
    // common for IPsec/L2TP and available for IKEv2.
    var usesSharedSecret = false
    var groupOrRealm = ""           // IPsec group name / local identifier
    var onDemand = false

    // Comprehensive IKEv2 knobs (empty/nil = use the OS default). Crypto choices
    // map to NEVPNIKEv2* enums; "" means "let macOS negotiate its default".
    var ikeEncryption = ""          // "" | aes128 | aes256 | aes128gcm | aes256gcm | 3des | chacha20poly1305
    var ikeIntegrity = ""           // "" | sha256 | sha384 | sha512 | sha160 | sha96
    var ikeDHGroup = ""             // "" | 14 | 15 | 16 | 19 | 20 | 21 | 31 | 2
    var ikeLifetimeMinutes: Int? = nil
    var deadPeerDetection = ""      // "" | none | low | medium | high
    var disableMOBIKE = false
    var enablePFS = false
    var disconnectOnSleep = false
    var includeAllNetworks = false  // send *all* traffic (incl. local) into the tunnel
    var excludeLocalNetworks = true // keep LAN reachable when includeAllNetworks is on
}

/// Where a native VPN's secrets live, and what saving one must do to each
/// keychain row. Expressed as a PLAN rather than inline `if !secret.isEmpty`
/// writes so the rule that clearing a field really removes the stored secret —
/// instead of leaving the old one in the keychain and still authenticating at
/// the next Connect — is one rule, in one place, and directly testable.
nonisolated enum NativeVPNSecrets {

    /// What a save does to one row.
    enum Action: Equatable, Sendable {
        case write(String)
        case delete
    }

    /// The two rows a native config can own: the base secret (the IKEv2
    /// password or PSK, or the IPsec XAuth password) and the IPsec group PSK.
    struct Plan: Equatable, Sendable {
        var base: Action
        var groupPSK: Action
    }

    /// Credential-row ids (the persistent-reference accounts `connect()` writes
    /// share the base names — see `apply`).
    static func baseProfile(_ id: String) -> String { "native.\(id)" }
    static func groupPSKProfile(_ id: String) -> String { "native.\(id).secret" }

    /// An empty field means "no such secret" — hence `.delete`, never "leave
    /// whatever was there". Only IPsec has a group PSK, so switching a VPN away
    /// from IPsec removes it too.
    static func plan(kind: VPNKind, secret: String, sharedSecret: String) -> Plan {
        Plan(base: secret.isEmpty ? .delete : .write(secret),
             groupPSK: kind == .ipsec && !sharedSecret.isEmpty ? .write(sharedSecret) : .delete)
    }

    /// Perform a plan. A delete removes BOTH the credential row and the
    /// persistent-reference copy `connect()` made from it — leaving either
    /// behind is a stale-secret leak (the rule `NativeVPNManager.remove(_:)`
    /// already follows).
    @MainActor static func apply(_ plan: Plan, id: String, username: String) {
        switch plan.base {
        case .write(let secret):
            try? KeychainCredentialStore.saveCredentials(
                profile: baseProfile(id), .init(username: username, password: secret))
        case .delete:
            KeychainCredentialStore.deleteCredentials(profile: baseProfile(id))
            KeychainCredentialStore.deleteNativeSecret(account: "native.\(id)")
        }
        switch plan.groupPSK {
        case .write(let psk):
            try? KeychainCredentialStore.saveCredentials(
                profile: groupPSKProfile(id), .init(username: "", password: psk))
        case .delete:
            KeychainCredentialStore.deleteCredentials(profile: groupPSKProfile(id))
            KeychainCredentialStore.deleteNativeSecret(account: "native.\(id).psk")
        }
    }
}

@MainActor
@Observable
final class NativeVPNManager {
    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "native")

    private(set) var status: NEVPNStatus = .invalid
    private(set) var activeConfigID: String?
    private(set) var lastError: String?
    /// Set when saveToPreferences fails for the missing Personal VPN capability.
    private(set) var needsEntitlement = false

    private var store: [NativeVPNConfig] = []
    private static let key = "nativeVPNs.v1"
    private var observer: NSObjectProtocol?

    var configs: [NativeVPNConfig] { store }

    init() {
        load()
        // Scope to the shared personal-VPN connection so we don't churn on every
        // unrelated OpenVPN packet-tunnel transition.
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: NEVPNManager.shared().connection, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated {
                    guard let self else { return }
                    let s = NEVPNManager.shared().connection.status
                    self.status = s
                    // The tunnel can drop OS-side (sleep, server, auth) without a
                    // call to disconnect(); clear the active id so the UI doesn't
                    // keep showing the config as connected.
                    if s == .disconnected || s == .invalid { self.activeConfigID = nil }
                }
            }
        Task { await refreshStatus() }
    }

    // MARK: CRUD (local field store; the OS holds only the connected one)

    func save(_ c: NativeVPNConfig) {
        if let i = store.firstIndex(where: { $0.id == c.id }) { store[i] = c } else { store.append(c) }
        persist()
    }
    func remove(_ id: String) {
        store.removeAll { $0.id == id }
        // Both the persistent-reference copies (nativeService, keyed by the
        // accounts connect() writes) and the credsService copy NativeVPNView.save()
        // writes need clearing — leaving either behind is a stale-secret leak.
        KeychainCredentialStore.deleteNativeSecret(account: "native.\(id)")
        KeychainCredentialStore.deleteNativeSecret(account: "native.\(id).psk")
        KeychainCredentialStore.deleteCredentials(profile: "native.\(id)")
        KeychainCredentialStore.deleteCredentials(profile: "native.\(id).secret")
        // The Custom Routing proxy sign-in and the filter's fallback blob are keyed by
        // the profile id too — same stale-secret rule.
        KeychainCredentialStore.deleteCustomRoutingProxyAuth(profile: id)
        CustomRoutingFallbackStore().clear(id)
        persist()
    }

    // MARK: Connect

    func refreshStatus() async {
        let mgr = NEVPNManager.shared()
        try? await mgr.loadFromPreferences()
        status = mgr.connection.status
    }

    /// Push this config into the single personal-VPN slot and start it.
    /// `secret` is the IKEv2 password/PSK, or the IPsec XAuth password.
    /// `sharedSecret` is the IPsec group PSK (ignored for IKEv2, which only
    /// ever needs one secret at a time).
    /// `proxy` is the user's Custom Routing proxy realized as `NEProxySettings`
    /// (see `ProxyCustomization.nativeApplyRequest`) — for these kinds the APP is
    /// the proxy applier, at connect, through the VPN configuration itself; any
    /// sign-in rides `NEProxyServer.username`/`password` in memory (the OS stores
    /// the saved configuration, never our keychain rows). No default: every caller
    /// must decide, so a new call site can't silently drop the user's proxy.
    func connect(_ c: NativeVPNConfig, secret: String, sharedSecret: String = "",
                 proxy: NEProxySettings?) async {
        lastError = nil; needsEntitlement = false
        guard c.kind != .l2tp else {
            lastError = "L2TP can't be configured programmatically on macOS. Use “Export Configuration Profile” and install it."
            return
        }
        let mgr = NEVPNManager.shared()
        try? await mgr.loadFromPreferences()

        // Distinct keychain accounts per secret — IPsec needs the group PSK
        // and the XAuth password to coexist, so they can no longer share one
        // persistent reference (that was bug: both ended up pointing at
        // whichever value happened to come in last).
        let baseAccount = "native.\(c.id)"
        let pskAccount = "native.\(c.id).psk"

        do {
            let proto: NEVPNProtocol
            switch c.kind {
            case .ikev2:
                let p = NEVPNProtocolIKEv2()
                p.serverAddress = c.server
                p.remoteIdentifier = c.remoteID.isEmpty ? c.server : c.remoteID
                p.localIdentifier = c.username
                // A reference is only written for a secret that EXISTS: storing
                // the empty string would hand the OS a valid-looking reference
                // to nothing (and some concentrators reject the empty attempt
                // rather than falling through to a prompt).
                if c.usesSharedSecret {
                    p.authenticationMethod = .sharedSecret
                    if !secret.isEmpty {
                        p.sharedSecretReference = try KeychainCredentialStore.persistentReference(forSecret: secret, account: baseAccount)
                    } else {
                        KeychainCredentialStore.deleteNativeSecret(account: baseAccount)
                    }
                } else {
                    p.authenticationMethod = .none
                    p.useExtendedAuthentication = true      // EAP username/password
                    p.username = c.username
                    if !secret.isEmpty {
                        p.passwordReference = try KeychainCredentialStore.persistentReference(forSecret: secret, account: baseAccount)
                    } else {
                        KeychainCredentialStore.deleteNativeSecret(account: baseAccount)
                    }
                }
                applyIKEv2Options(c, to: p)
                proto = p
            case .ipsec:
                let p = NEVPNProtocolIPSec()
                p.serverAddress = c.server
                p.username = c.username
                // XAuth is OPTIONAL here (the group PSK alone is sometimes the
                // whole sign-in): claim extended authentication only when there
                // is actually a username or password to send.
                p.useExtendedAuthentication = !c.username.isEmpty || !secret.isEmpty
                p.localIdentifier = c.groupOrRealm.isEmpty ? nil : c.groupOrRealm
                // Certificate/identity authentication isn't wired up (no
                // identity picker or import path exists) — the only mode that
                // actually works, and the one the UI now forces, is a shared
                // secret optionally paired with XAuth username/password (the
                // Cisco-style combo CiscoImport produces from .pcf files).
                p.authenticationMethod = .sharedSecret
                if !sharedSecret.isEmpty {
                    p.sharedSecretReference = try KeychainCredentialStore.persistentReference(forSecret: sharedSecret, account: pskAccount)
                } else {
                    KeychainCredentialStore.deleteNativeSecret(account: pskAccount)
                }
                // An empty XAuth password must leave passwordReference NIL — a
                // reference to "" is an empty XAuth attempt, which some
                // concentrators refuse outright.
                if !secret.isEmpty {
                    p.passwordReference = try KeychainCredentialStore.persistentReference(forSecret: secret, account: baseAccount)
                } else {
                    KeychainCredentialStore.deleteNativeSecret(account: baseAccount)
                }
                applyCommonOptions(c, to: p)
                proto = p
            default:
                return
            }

            // The one native proxy hook: macOS applies these settings itself while the
            // tunnel is up (we then only OBSERVE them via SCDynamicStore — the Proxy
            // mediator's `.limited` bucket).
            proto.proxySettings = proxy

            mgr.protocolConfiguration = proto
            mgr.localizedDescription = c.name
            mgr.isEnabled = true
            mgr.isOnDemandEnabled = c.onDemand
            // isOnDemandEnabled alone does nothing without at least one rule;
            // a bare Connect rule is the sensible default (reconnect whenever
            // something opens a network connection), matching what the
            // "Connect on demand" toggle implies to a user.
            mgr.onDemandRules = c.onDemand ? [NEOnDemandRuleConnect()] : []

            try await mgr.saveToPreferences()
            try await mgr.loadFromPreferences()
            try mgr.connection.startVPNTunnel()
            activeConfigID = c.id
        } catch {
            let ns = error as NSError
            Self.log.error("native connect failed: \(ns.localizedDescription, privacy: .public) domain=\(ns.domain, privacy: .public) code=\(ns.code)")
            if ns.domain == NEVPNErrorDomain, let code = NEVPNError.Code(rawValue: ns.code) {
                switch code {
                case .configurationReadWriteFailed:
                    // macOS gives this same code both for a missing Personal
                    // VPN entitlement AND for the user declining the "Add VPN
                    // Configurations" prompt — there's no distinct code for
                    // either, only the wording differs. Route on that wording
                    // rather than lumping both under "not provisioned".
                    let desc = ns.localizedDescription.localizedLowercase
                    let underlying = ((ns.userInfo[NSUnderlyingErrorKey] as? NSError)?.localizedDescription ?? "").localizedLowercase
                    if desc.contains("denied") || desc.contains("cancel") || underlying.contains("denied") || underlying.contains("cancel") {
                        lastError = "You declined the “Add VPN Configurations” prompt. Native VPN needs that approval — try Connect again and allow it."
                    } else {
                        needsEntitlement = true
                        lastError = "This build isn't provisioned for the native personal VPN yet (Personal VPN capability). \(ns.localizedDescription)"
                    }
                default:
                    // configurationInvalid / configurationDisabled / connectionFailed /
                    // configurationStale / configurationUnknown all mean something
                    // else entirely — show what actually happened.
                    lastError = ns.localizedDescription
                }
            } else if ns.localizedDescription.localizedCaseInsensitiveContains("entitlement") {
                needsEntitlement = true
                lastError = "This build isn't provisioned for the native personal VPN yet (Personal VPN capability). \(ns.localizedDescription)"
            } else {
                lastError = ns.localizedDescription
            }
        }
    }

    /// Options that live on NEVPNProtocol itself, not the IKEv2 subclass —
    /// apply to every native kind so Routing-section toggles (Send All
    /// Traffic, Allow Local Network, Disconnect on Sleep) actually do
    /// something for IPsec, not just IKEv2.
    private func applyCommonOptions(_ c: NativeVPNConfig, to p: NEVPNProtocol) {
        p.disconnectOnSleep = c.disconnectOnSleep
        if #available(macOS 15.0, *) {
            p.includeAllNetworks = c.includeAllNetworks
            p.excludeLocalNetworks = c.excludeLocalNetworks
        }
    }

    /// Map the comprehensive IKEv2 fields onto the protocol object; each blank
    /// value leaves the OS default in place.
    private func applyIKEv2Options(_ c: NativeVPNConfig, to p: NEVPNProtocolIKEv2) {
        applyCommonOptions(c, to: p)
        switch c.deadPeerDetection {
        case "none": p.deadPeerDetectionRate = .none
        case "low": p.deadPeerDetectionRate = .low
        case "high": p.deadPeerDetectionRate = .high
        case "medium": p.deadPeerDetectionRate = .medium
        default: p.deadPeerDetectionRate = .medium
        }
        p.disableMOBIKE = c.disableMOBIKE
        for sa in [p.ikeSecurityAssociationParameters, p.childSecurityAssociationParameters] {
            // The 128-bit cases are deprecated by Apple (macOS 14) with no
            // replacement — the advice is "use 256-bit". They stay because a
            // concentrator that only proposes AES-128 is otherwise unreachable,
            // and dropping the case would fail the connection silently. Reached
            // via rawValue (AES128 = 3, AES128GCM = 5 per <NEVPNProtocolIKEv2.h>)
            // so the deliberate use doesn't raise a deprecation warning every build.
            switch c.ikeEncryption {
            case "aes128": sa.encryptionAlgorithm = NEVPNIKEv2EncryptionAlgorithm(rawValue: 3)!
            case "aes256": sa.encryptionAlgorithm = .algorithmAES256
            case "aes128gcm": sa.encryptionAlgorithm = NEVPNIKEv2EncryptionAlgorithm(rawValue: 5)!
            case "aes256gcm": sa.encryptionAlgorithm = .algorithmAES256GCM
            case "chacha20poly1305": if #available(macOS 14.0, *) { sa.encryptionAlgorithm = .algorithmChaCha20Poly1305 }
            default: break   // 3DES etc. are unavailable on macOS — OS default stands
            }
            switch c.ikeIntegrity {
            case "sha256": sa.integrityAlgorithm = .SHA256
            case "sha384": sa.integrityAlgorithm = .SHA384
            case "sha512": sa.integrityAlgorithm = .SHA512
            default: break   // SHA-1 variants are unavailable on macOS
            }
            if let m = c.ikeLifetimeMinutes { sa.lifetimeMinutes = Int32(m) }
        }
        // The DH group picker always sets the IKE SA's group (or leaves the OS
        // default on "Automatic"). The child SA's diffieHellmanGroup is what
        // actually turns Perfect Forward Secrecy on for CREATE_CHILD_SA
        // rekeys — Apple's API has no separate "enable PFS" bit, so the
        // enablePFS toggle is wired to *whether* the child SA gets a group at
        // all, using the same group as the picker (falling back to the
        // widely-supported Group 14 if the picker is left on Automatic).
        func dhGroup(_ v: String) -> NEVPNIKEv2DiffieHellmanGroup? {
            switch v {
            case "14": return .group14
            case "15": return .group15
            case "16": return .group16
            case "19": return .group19
            case "20": return .group20
            case "21": return .group21
            case "31": return .group31
            default: return nil
            }
        }
        if let g = dhGroup(c.ikeDHGroup) { p.ikeSecurityAssociationParameters.diffieHellmanGroup = g }
        if c.enablePFS {
            p.childSecurityAssociationParameters.diffieHellmanGroup = dhGroup(c.ikeDHGroup) ?? .group14
        }
    }

    func disconnect() {
        NEVPNManager.shared().connection.stopVPNTunnel()
        activeConfigID = nil
    }

    private func load() {
        guard let d = UserDefaults.standard.data(forKey: Self.key),
              let list = try? JSONDecoder().decode([NativeVPNConfig].self, from: d) else { return }
        store = list
    }
    private func persist() {
        if let d = try? JSONEncoder().encode(store) { UserDefaults.standard.set(d, forKey: Self.key) }
    }
}
