// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
@preconcurrency import NetworkExtension

nonisolated enum NativeProxyCredentials {
    static func requiresBroker(_ settings: NEProxySettings?) -> Bool {
        [settings?.httpServer,settings?.httpsServer].compactMap { $0 }.contains {
            $0.authenticationRequired || !($0.password ?? "").isEmpty
        }
    }
    static func hasStoredSecret(_ settings: NEProxySettings?) -> Bool {
        [settings?.httpServer,settings?.httpsServer].compactMap { $0 }.contains { !($0.password ?? "").isEmpty }
    }
    static func redacted(_ settings: NEProxySettings) -> NEProxySettings {
        let copy=settings.copy() as! NEProxySettings
        func server(_ original: NEProxyServer?) -> NEProxyServer? {
            guard let original else { return nil }
            let copy=original.copy() as! NEProxyServer
            copy.username=nil; copy.password=nil; return copy
        }
        copy.httpServer=server(settings.httpServer); copy.httpsServer=server(settings.httpsServer)
        return copy
    }
    static let unsupported = "Authenticated proxies cannot be saved with a native VPN without storing the password in its OS configuration. Use a packet tunnel or remove proxy authentication. Your saved password stays in your Keychain."
}
