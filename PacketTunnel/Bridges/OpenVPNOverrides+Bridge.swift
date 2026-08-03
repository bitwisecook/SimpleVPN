// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OpenVPNOverrides+Bridge.swift
//  Extension-side mapping from the shared OpenVPNOverrides model onto the ObjC
//  OVPNClientSettings the bridge consumes. nil fields stay nil — the bridge
//  assigns only non-nil values, preserving the engine's compiled-in defaults.
//

import Foundation

extension OpenVPNOverrides {

    /// Build the bridge settings object; nil when there is nothing to override
    /// and no secrets to carry.
    func bridgeSettings(proxyPassword: String? = nil,
                        privateKeyPassword: String? = nil) -> OVPNClientSettings? {
        guard !isEmpty || proxyPassword != nil || privateKeyPassword != nil else { return nil }

        let s = OVPNClientSettings()
        s.serverOverride = server
        s.portOverride = port.map(String.init)
        s.protoOverride = proto?.rawValue
        s.protoVersionOverride = ipVersion.map { NSNumber(value: $0.rawValue) }
        s.connTimeout = connTimeout.map { NSNumber(value: $0) }
        s.tunPersist = tunPersist.map { NSNumber(value: $0) }
        s.retryOnAuthFailed = retryOnAuthFailed.map { NSNumber(value: $0) }
        s.autologinSessions = autologinSessions.map { NSNumber(value: $0) }
        s.allowLocalLanAccess = allowLocalLanAccess.map { NSNumber(value: $0) }
        s.allowUnusedAddrFamilies = allowUnusedAddrFamilies?.rawValue
        s.googleDnsFallback = googleDnsFallback.map { NSNumber(value: $0) }
        s.tlsVersionMinOverride = tlsVersionMin?.rawValue
        s.tlsCertProfileOverride = tlsCertProfile?.rawValue
        s.compressionMode = compression?.rawValue
        s.enableLegacyAlgorithms = enableLegacyAlgorithms.map { NSNumber(value: $0) }
        s.enableNonPreferredDCAlgorithms = enableNonPreferredDCAlgorithms.map { NSNumber(value: $0) }
        s.tlsCipherList = tlsCipherList
        s.tlsCiphersuitesList = tlsCiphersuitesList
        s.disableClientCert = disableClientCert.map { NSNumber(value: $0) }
        s.defaultKeyDirection = defaultKeyDirection.map { NSNumber(value: $0) }
        s.proxyHost = proxyHost
        s.proxyPort = proxyPort.map(String.init)
        s.proxyUsername = proxyUsername
        s.proxyAllowCleartextAuth = proxyAllowCleartextAuth.map { NSNumber(value: $0) }
        s.sslDebugLevel = sslDebugLevel.map { NSNumber(value: $0) }
        s.synchronousDnsLookup = synchronousDnsLookup.map { NSNumber(value: $0) }
        s.proxyPassword = proxyPassword
        s.privateKeyPassword = privateKeyPassword
        return s
    }

}
