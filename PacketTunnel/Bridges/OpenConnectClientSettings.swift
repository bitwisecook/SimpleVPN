// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation

extension OCClientSettings {
    static func make(configuration conf: [String: Any]?, options: [String: Any]?, fallbackServer: String, protocol ocProto: String) -> OCClientSettings {
        let s = OCClientSettings()
        s.server = (conf?["server"] as? String) ?? fallbackServer
        s.protocol = ocProto
        s.username = (options?["username"] as? String) ?? ""
        s.password = options?["password"] as? String
        s.oneTimeCode = options?["oneTimeCode"] as? String
        s.realm = conf?["realm"] as? String
        s.serverCertSHA256 = conf?["serverCert"] as? String
        s.externalBrowser = conf?["samlBrowser"] as? String
        // Every key below is written by `SubprocessTunnelManager.inProcessConfiguration`
        // and each one used to be a REFUSAL: a profile that set any of them ran as an
        // `openconnect` subprocess under `ocproxy -D <port>` instead — a SOCKS port
        // with no interface, no routes and no DNS. Absent ⇒ the engine's default.
        s.caFile = conf?["caFile"] as? String
        s.urlPath = conf?["urlPath"] as? String
        s.reportedOS = conf?["reportedOS"] as? String
        s.versionString = conf?["versionString"] as? String
        s.localName = conf?["localName"] as? String
        s.clientCertFile = conf?["clientCert"] as? String
        s.clientKeyFile = conf?["clientKey"] as? String
        s.proxy = conf?["proxy"] as? String
        s.proxyUsername = conf?["proxyUsername"] as? String
        s.compression = conf?["compression"] as? String
        s.pfs = (conf?["pfs"] as? NSNumber)?.boolValue ?? false
        s.disableIPv6 = (conf?["disableIPv6"] as? NSNumber)?.boolValue ?? false
        s.disableDTLS = (conf?["disableDTLS"] as? NSNumber)?.boolValue ?? false
        s.mtu = (conf?["mtu"] as? NSNumber)?.int32Value ?? 0
        s.dpd = (conf?["dpd"] as? NSNumber)?.int32Value ?? 0
        s.reconnectTimeout = conf?["reconnectTimeout"] as? NSNumber
        // The two secrets among them ride startTunnel options, never
        // providerConfiguration — the same invariant as `password` above, because
        // providerConfiguration persists in NE preferences and options do not.
        s.privateKeyPassword = options?["privateKeyPassword"] as? String
        s.proxyPassword = options?["proxyPassword"] as? String
        // A user agent the gateway may be admitting by name. "SimpleVPN" stays the
        // default, and is NOT a value the user chose — so it must not look like one.
        s.userAgent = (conf?["userAgent"] as? String) ?? "SimpleVPN"
        // SSO cookie handoff (ocauth-helper → app → here, all in memory): the
        // sign-in already happened in user context; connect to the exact URL it
        // authenticated against, accepting only the certificate it saw.
        if let cookie = options?["cookie"] as? String, !cookie.isEmpty {
            s.cookie = cookie
            s.resolveHost = options?["resolveHost"] as? String
            s.resolveIP = options?["resolveIP"] as? String
            if let cert = options?["servercert"] as? String, !cert.isEmpty { s.serverCertSHA256 = cert }
            if let url = options?["connectURL"] as? String, !url.isEmpty { s.server = url }
        }

        s.authFieldAnswer = { [weak s] authID, name, label, kind in
            guard let s else { return nil }
            let field = OCAuthFormField(id: name, label: label, type: kind, secret: kind == OCAuthFormField.Kind.password)
            let form = OCAuthFormSpec(authID: authID, fields: [field])
            return OCAuthFormAutofill.fill(form, username: s.username, password: s.password,
                                           realm: s.realm, vpnProtocol: ocProto).answers[name]
        }
        return s
    }
}
