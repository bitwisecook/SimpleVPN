// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  InProcessOpenConnectCoverageTests.swift
//  THE OTHER HALF OF EVERY GATE THAT WAS REMOVED.
//
//  `inProcessOpenConnectSupports` used to refuse eleven groups of settings, and eight
//  of them were not statements about libopenconnect at all: they were settings nobody
//  had plumbed through to the engine. The cost was invisible and total — a config that
//  merely named a CA file was sent to the `openconnect` subprocess under
//  `ocproxy -D <port>`, which is a SOCKS listener on the loopback with no interface,
//  no routes and no DNS. So "supported" quietly meant "your routing settings do
//  nothing".
//
//  The rule that replaced it: a gate may only be deleted once the setting is GENUINELY
//  CARRIED. This file is how that is held. Every setting whose gate went away must be
//  present in the payload the app hands the extension — `inProcessConfiguration` for
//  the non-secret half (providerConfiguration, which persists) and `inProcessSecrets`
//  for the secret half (startTunnel options, in memory only). Dropping one silently
//  would connect with weaker or simply broken settings than the profile asks for,
//  which is worse than falling back to the tool.
//
//  What this can and cannot prove, stated plainly because the boundary matters: it
//  proves the value leaves the app on the right key. The last hop —
//  `PacketTunnelProvider.startOpenConnect` reading that key into `OCClientSettings`,
//  and `OpenConnectBridge.runSession` making the `openconnect_set_*` call — is
//  Objective-C inside the system extension and is not reachable from a unit test.
//  Nor can any of it prove the GATEWAY honours the setting. Both need a real server.
//

import Foundation
import Testing
@testable import SimpleVPN

@MainActor
struct InProcessOpenConnectCoverageTests {

    private func config(_ mutate: (inout SubprocessTunnelConfig) -> Void = { _ in })
        -> SubprocessTunnelConfig {
        var c = SubprocessTunnelConfig()
        c.kind = .ciscoAnyConnect
        c.server = "vpn.example.com"
        c.username = "alex"
        mutate(&c)
        return c
    }

    private func conf(_ mutate: (inout SubprocessTunnelConfig) -> Void) -> [String: Any] {
        SubprocessTunnelManager.inProcessConfiguration(config(mutate))
    }

    /// One case per removed gate. The assertion is deliberately on the VALUE and not
    /// merely on the key's presence: a mapping that carried the key with an empty
    /// string would pass a presence check and still drop the setting.
    @Test func everySettingWhoseGateWasRemovedReachesThePayload() {
        // --cafile. Tilde-expanded, because the extension has a different home
        // directory (it is root, in the system context) and "~" there is not the
        // user's "~" — an unexpanded path would silently fail to open.
        let ca = conf { $0.caFile = "~/vpn-ca.pem" }
        #expect((ca["caFile"] as? String)?.hasSuffix("/vpn-ca.pem") == true)
        #expect((ca["caFile"] as? String)?.hasPrefix("~") == false, "the extension's ~ is not the user's")

        // --usergroup, which openconnect spells as the URL path.
        #expect(conf { $0.usergroup = "gateway" }["urlPath"] as? String == "gateway")

        // --os / --version-string / --local-hostname / --useragent: what this client
        // claims to be. Four settings answering one question, all four dropped before.
        #expect(conf { $0.spoofOS = "win" }["reportedOS"] as? String == "win")
        #expect(conf { $0.versionString = "4.10.05085" }["versionString"] as? String == "4.10.05085")
        #expect(conf { $0.localHostname = "mac-01" }["localName"] as? String == "mac-01")
        #expect(conf { $0.userAgent = "AnyConnect/4.10" }["userAgent"] as? String == "AnyConnect/4.10")

        // --compression / --pfs / --disable-ipv6 / --no-dtls.
        #expect(conf { $0.ocCompression = "stateless" }["compression"] as? String == "stateless")
        #expect(conf { $0.enablePFS = true }["pfs"] as? Bool == true)
        #expect(conf { $0.disableIPv6 = true }["disableIPv6"] as? Bool == true)
        #expect(conf { $0.disableDTLS = true }["disableDTLS"] as? Bool == true)

        // --mtu / --force-dpd / --reconnect-timeout.
        #expect(conf { $0.ocMTU = 1300 }["mtu"] as? Int == 1300)
        #expect(conf { $0.forceDPD = 30 }["dpd"] as? Int == 30)
        #expect(conf { $0.reconnectTimeout = 60 }["reconnectTimeout"] as? Int == 60)

        // …and 0 is a LEGAL reconnect timeout ("give up immediately"), not "unset".
        // The bridge takes it as an NSNumber for exactly this reason; carrying it as
        // an `int` with 0 meaning absent would turn "give up at once" into "retry for
        // five minutes", which is the quiet-substitution bug in miniature.
        #expect(conf { $0.reconnectTimeout = 0 }["reconnectTimeout"] as? Int == 0)
    }

    /// The explicit port. There is no port setter in libopenconnect: it is part of the
    /// address `openconnect_parse_url` is given. So the gate could only be closed by
    /// folding the port into the server string, and that is what must be asserted —
    /// a `port` key would look right and do nothing.
    @Test func anExplicitPortTravelsInsideTheServerAddress() {
        #expect(conf { $0.port = 8443 }["server"] as? String == "vpn.example.com:8443")
        #expect(conf { _ in }["server"] as? String == "vpn.example.com")
    }

    /// Client-certificate sign-in: the most expensive of the old refusals, because a
    /// certificate profile could not have a system tunnel at all.
    ///
    /// Gated on the PICKER's choice, exactly as the argv builder is. A stale path left
    /// behind by an earlier configuration must not turn a password tunnel into
    /// certificate authentication — that bug has been fixed once already on the
    /// subprocess side and re-introducing it here would be the same bug in a new place.
    @Test func aClientCertificateIsCarriedOnlyWhenItIsTheChosenMethod() {
        let chosen = conf {
            $0.authMode = "certificate"
            $0.clientCertFile = "~/client.pem"
            $0.clientKeyFile = "~/client.key"
        }
        #expect((chosen["clientCert"] as? String)?.hasSuffix("/client.pem") == true)
        #expect((chosen["clientKey"] as? String)?.hasSuffix("/client.key") == true)

        let stale = conf {
            $0.authMode = "password"
            $0.clientCertFile = "~/stale.pem"
            $0.clientKeyFile = "~/stale.key"
        }
        #expect(stale["clientCert"] == nil, "a password tunnel must not present a certificate")
        #expect(stale["clientKey"] == nil)
    }

    /// The gateway proxy. Two things are being asserted at once and both matter:
    ///
    ///  * a MANUAL proxy is carried (its gate is gone), and
    ///  * `.systemDefault` — the default mode — is resolved IN THE APP. The in-process
    ///    path used to ignore it entirely: libopenconnect reads no system proxy
    ///    configuration of its own, and the extension is root in the system context
    ///    where SystemConfiguration answers differently. So the app's own default
    ///    proxy mode was being silently dropped by the path we are now making the
    ///    default for everyone.
    ///
    /// The resolved value depends on this Mac, so what is asserted is the SHAPE: a
    /// manual URL arrives verbatim, and `.none` never produces a proxy.
    @Test func theGatewayProxyIsCarriedAndNeverCarriesItsPassword() {
        let manual = conf {
            $0.proxyMode = .manual
            $0.proxyURL = "http://proxy.example.com:8080"
            $0.proxyUsername = "alex"
        }
        #expect(manual["proxy"] as? String == "http://proxy.example.com:8080")
        #expect(manual["proxyUsername"] as? String == "alex")
        // THE PASSWORD IS NOT HERE. providerConfiguration persists in NE preferences;
        // credentials ride startTunnel options in memory. The URL is composed with its
        // userinfo only at the last moment, inside the bridge — which is also why the
        // in-process path needs no equivalent of the subprocess's explicit
        // "include the proxy password in process arguments" opt-in: there is no argv.
        for value in manual.values.compactMap({ $0 as? String }) {
            #expect(!value.contains(":@"), "no credentials in a persisted configuration")
        }

        #expect(conf { $0.proxyMode = .none }["proxy"] == nil)
        #expect(conf { $0.proxyMode = .none }["proxyUsername"] == nil)
    }

    /// A setting that is not set must be ABSENT rather than empty. The bridge reads
    /// "absent ⇒ the engine's own default", so an empty string arriving as a value
    /// would mean calling `openconnect_set_*` with "" — which is not the same thing,
    /// and for `SSH_OPTIONS_IDENTITY_AGENT` on the other engine is a documented
    /// outright rejection.
    @Test func unsetSettingsAreAbsentNotEmpty() {
        let bare = conf { _ in }
        for key in ["caFile", "urlPath", "reportedOS", "versionString", "localName",
                    "userAgent", "clientCert", "clientKey", "compression",
                    "pfs", "disableIPv6", "disableDTLS", "mtu", "dpd",
                    "reconnectTimeout", "realm", "serverCert", "samlBrowser"] {
            #expect(bare[key] == nil, "\(key) should be absent when nothing set it")
        }
        // Whitespace is not a value either — one representation of "not set".
        #expect(conf { $0.localHostname = "   " }["localName"] == nil)
    }

    /// The profile and protocol the extension dispatches on. `vpnType` is the kind's
    /// raw value and `PacketTunnelProvider` maps it through
    /// `VPNKind.openconnectProtocol`, which is non-nil for all seven — the reason
    /// there is no per-kind allow-list anywhere in this feature.
    @Test func everySSLVPNKindIsDispatchableFromThePayload() {
        for kind in VPNKind.allCases where kind.isSSLVPN {
            let c = conf { $0.kind = kind }
            #expect(c["vpnType"] as? String == kind.rawValue)
            #expect(VPNKind(rawValue: (c["vpnType"] as? String) ?? "")?.openconnectProtocol != nil,
                    "\(kind.rawValue) must resolve to an openconnect protocol token")
        }
    }

    /// The secrets go on the OTHER channel, and only when their method is chosen.
    /// This asserts the split rather than the values — there is no keychain item in a
    /// unit test, so the meaningful assertion is that nothing secret appears in the
    /// persisted half no matter how the profile is configured.
    @Test func secretsNeverAppearInThePersistedConfiguration() {
        let everything = config {
            $0.authMode = "certificate"
            $0.clientCertFile = "~/client.pem"
            $0.clientKeyFile = "~/client.key"
            $0.proxyMode = .manual
            $0.proxyURL = "http://proxy.example.com:8080"
            $0.proxyUsername = "alex"
            $0.caFile = "~/ca.pem"
        }
        let persisted = SubprocessTunnelManager.inProcessConfiguration(everything)
        for key in ["password", "privateKeyPassword", "proxyPassword", "keyPassword", "pin"] {
            #expect(persisted[key] == nil, "\(key) must never be in providerConfiguration")
        }
        // The secret channel is keyed the same way the OpenVPN path already keys it,
        // so the provider reads one vocabulary rather than two.
        let secrets = SubprocessTunnelManager.inProcessSecrets(everything)
        for key in secrets.keys {
            #expect(["privateKeyPassword", "proxyPassword"].contains(key),
                    "unexpected secret key \(key)")
        }
    }

    // MARK: "Allow local network access" — the same seam, and the same fail-closed rule

    /// SECURITY-DETERMINING, so both directions are asserted. `be5045d` wired the
    /// carve-out to WireGuard, the Proxy Tunnel and the SSH Network Tunnel; `51a067a`
    /// made the SSL VPNs whole-Mac by default, and the setting did not exist for them —
    /// so "allow local network access" had no effect on the kinds most people run.
    ///
    /// The TOGGLE rides `providerConfiguration` (it persists, and it is not a secret);
    /// the PREFIXES ride `startTunnel(options:)`, because which networks this Mac is on
    /// is a fact about right now. Absence of the key means OFF in the extension exactly
    /// as `nil` means off here — the fail-closed direction, where traffic stays inside.
    @Test func theLocalNetworkCarveOutTravelsAsAToggleAndDefaultsOff() {
        // OFF by default, and "nobody ever chose" is off — not "on because the field is
        // absent from an older config".
        #expect(SubprocessTunnelConfig().allowLocalNetworkAccess == nil)
        #expect(!SubprocessTunnelConfig().allowsLocalNetworkAccess)
        #expect(conf { _ in }["localLan"] == nil, "an unset carve-out must not appear at all")
        #expect(conf { $0.allowLocalNetworkAccess = true }["localLan"] as? Bool == true)
        // Explicitly-off is also absent: one representation of "no carve-out".
        #expect(conf { $0.allowLocalNetworkAccess = false }["localLan"] == nil)
        // The setting is addressable, documented and declared off (the CLI/MDM/manual
        // contract), and named EXACTLY as the other three kinds name it.
        let spec = OpenConnectSettings.catalog["oc.local-lan"]
        #expect(spec.group == .traffic)
        #expect(!spec.isChanged(false))
        #expect(spec.isChanged(true))
        for other in [WireGuardSettings.catalog["wg.local-lan"],
                      ProxyTunnelSettings.catalog["px.local-lan"],
                      SSHNetSettings.catalog["sshnet.local-lan"]] {
            #expect(spec.name == other.name, "one concept, one name")
            #expect(spec.summary == other.summary, "one concept, one summary")
        }
    }

    /// A CONFIG SAVED BEFORE THE FIELD EXISTED MUST STILL DECODE. `SubprocessTunnelConfig`
    /// has a synthesized `Codable`, and a synthesized decoder does NOT fall back to a
    /// property's default for a missing key — so a non-Optional `Bool` here would have
    /// made every stored SSL VPN undecodable, which is why the field is `Bool?`
    /// (the `proxyPasswordInArgv` precedent).
    @Test func aConfigWithoutTheCarveOutKeyStillDecodes() throws {
        // Built by ENCODING a real config and then removing the one key, so the fixture
        // cannot rot as other fields are added — which is exactly what a hand-written
        // JSON literal would do here.
        var carved = config { $0.allowLocalNetworkAccess = true }
        carved.tokenMode = "totp"
        carved.authMode = "token"
        var object = try #require(try JSONSerialization.jsonObject(
            with: try JSONEncoder().encode(carved)) as? [String: Any])
        #expect(object["allowLocalNetworkAccess"] != nil, "an explicit choice must be written")
        object["allowLocalNetworkAccess"] = nil
        let older = try JSONSerialization.data(withJSONObject: object)

        let decoded = try JSONDecoder().decode(SubprocessTunnelConfig.self, from: older)
        #expect(decoded.allowLocalNetworkAccess == nil)
        #expect(!decoded.allowsLocalNetworkAccess, "an older config must not gain a carve-out")

        // …and the two fields the smartcard / token removal left behind as MARKERS
        // survive every path a save or a load goes through: a stored profile still says
        // what it is, and is refused with an explanation rather than converted.
        #expect(decoded.authMode == "token")
        #expect(decoded.tokenMode == "totp")
        #expect(decoded.normalized().authMode == "token", "normalized() must not convert it")
        #expect(decoded.normalized().tokenMode == "totp")
        #expect(SubprocessTunnelStore.migrated([decoded]).list[0].authMode == "token",
                "load-time migration must not convert it")
    }

    /// THE WIDTH RULE, at the point the extension applies it. Every prefix the app
    /// offers is re-validated by `RoutingRule.routeDest` — the same validator a divert
    /// rule passes — so a `/0` arriving from anywhere can never be installed as a
    /// "local network" and become a whole-tunnel bypass. A carve-out wider than the
    /// truth sends traffic outside the tunnel that the user believes is inside it.
    @Test func aLocalNetworkPrefixIsRevalidatedAndAZeroPrefixIsRefused() {
        for good in LocalNetworkCarveOut.prefixes(of: [.init(name: "en0", subnets: ["192.168.1.34/24"])]) {
            #expect(RoutingRule(destination: good).routeDest != nil, "\(good) should survive")
        }
        for bypass in ["0.0.0.0/0", "::/0", "not-an-address/24", "192.168.1.0/33"] {
            #expect(RoutingRule(destination: bypass).routeDest == nil,
                    "\(bypass) must never become an excluded route")
        }
    }
}
