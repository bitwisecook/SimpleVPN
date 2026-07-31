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
        KeychainCredentialStore.deleteNativeSecret(account: "native.\(id)")
        persist()
    }

    // MARK: Connect

    func refreshStatus() async {
        let mgr = NEVPNManager.shared()
        try? await mgr.loadFromPreferences()
        status = mgr.connection.status
    }

    /// Push this config into the single personal-VPN slot and start it. `secret`
    /// is the password or shared secret depending on the config's auth mode.
    func connect(_ c: NativeVPNConfig, secret: String) async {
        lastError = nil; needsEntitlement = false
        guard c.kind != .l2tp else {
            lastError = "L2TP can't be configured programmatically on macOS. Use “Export Configuration Profile” and install it."
            return
        }
        let mgr = NEVPNManager.shared()
        try? await mgr.loadFromPreferences()

        let account = "native.\(c.id)"
        let secretRef = KeychainCredentialStore.persistentReference(forSecret: secret, account: account)

        let proto: NEVPNProtocol
        switch c.kind {
        case .ikev2:
            let p = NEVPNProtocolIKEv2()
            p.serverAddress = c.server
            p.remoteIdentifier = c.remoteID.isEmpty ? c.server : c.remoteID
            p.localIdentifier = c.username
            if c.usesSharedSecret {
                p.authenticationMethod = .sharedSecret
                p.sharedSecretReference = secretRef
            } else {
                p.authenticationMethod = .none
                p.useExtendedAuthentication = true      // EAP username/password
                p.username = c.username
                p.passwordReference = secretRef
            }
            applyIKEv2Options(c, to: p)
            proto = p
        case .ipsec:
            let p = NEVPNProtocolIPSec()
            p.serverAddress = c.server
            p.username = c.username
            p.passwordReference = secretRef
            p.useExtendedAuthentication = true
            p.localIdentifier = c.groupOrRealm.isEmpty ? nil : c.groupOrRealm
            // IPsec group auth commonly rides a shared secret alongside XAuth.
            p.authenticationMethod = c.usesSharedSecret ? .sharedSecret : .certificate
            if c.usesSharedSecret { p.sharedSecretReference = secretRef }
            proto = p
        default:
            return
        }

        mgr.protocolConfiguration = proto
        mgr.localizedDescription = c.name
        mgr.isEnabled = true
        mgr.isOnDemandEnabled = c.onDemand

        do {
            try await mgr.saveToPreferences()
            try await mgr.loadFromPreferences()
            try mgr.connection.startVPNTunnel()
            activeConfigID = c.id
        } catch {
            let ns = error as NSError
            // NEVPNError / missing entitlement surfaces here.
            if ns.domain == NEVPNErrorDomain || ns.localizedDescription.localizedCaseInsensitiveContains("entitlement") {
                needsEntitlement = true
                lastError = "This build isn't provisioned for the native personal VPN yet (Personal VPN capability). \(ns.localizedDescription)"
            } else {
                lastError = ns.localizedDescription
            }
            Self.log.error("native connect failed: \(ns.localizedDescription, privacy: .public)")
        }
    }

    /// Map the comprehensive IKEv2 fields onto the protocol object; each blank
    /// value leaves the OS default in place.
    private func applyIKEv2Options(_ c: NativeVPNConfig, to p: NEVPNProtocolIKEv2) {
        switch c.deadPeerDetection {
        case "none": p.deadPeerDetectionRate = .none
        case "low": p.deadPeerDetectionRate = .low
        case "high": p.deadPeerDetectionRate = .high
        case "medium": p.deadPeerDetectionRate = .medium
        default: p.deadPeerDetectionRate = .medium
        }
        p.disableMOBIKE = c.disableMOBIKE
        p.disconnectOnSleep = c.disconnectOnSleep
        if #available(macOS 15.0, *) {
            p.includeAllNetworks = c.includeAllNetworks
            p.excludeLocalNetworks = c.excludeLocalNetworks
        }
        for sa in [p.ikeSecurityAssociationParameters, p.childSecurityAssociationParameters] {
            // The 128-bit cases are deprecated by Apple (macOS 14) with no
            // replacement — the advice is "use 256-bit". They stay because a
            // concentrator that only proposes AES-128 is otherwise unreachable,
            // and dropping the case would fail the connection silently.
            switch c.ikeEncryption {
            case "aes128": sa.encryptionAlgorithm = .algorithmAES128
            case "aes256": sa.encryptionAlgorithm = .algorithmAES256
            case "aes128gcm": sa.encryptionAlgorithm = .algorithmAES128GCM
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
            switch c.ikeDHGroup {
            case "14": sa.diffieHellmanGroup = .group14
            case "15": sa.diffieHellmanGroup = .group15
            case "16": sa.diffieHellmanGroup = .group16
            case "19": sa.diffieHellmanGroup = .group19
            case "20": sa.diffieHellmanGroup = .group20
            case "21": sa.diffieHellmanGroup = .group21
            case "31": sa.diffieHellmanGroup = .group31
            default: break
            }
            if let m = c.ikeLifetimeMinutes { sa.lifetimeMinutes = Int32(m) }
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
