// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHNetworkTunnelTests.swift
//  The SSH Network Tunnel's contracts. A live SSH handshake is not possible in a
//  unit test (and would be a network dependency if it were), so correctness here
//  rests on the pieces that CAN be pinned:
//
//    • the start payload's key parity with the Go engine's startConfig struct —
//      a rename on either side is a tunnel that connects and carries nothing;
//    • the connect gates, so an unusable config is refused at the editor rather
//      than at the engine;
//    • the network settings, above all that the SSH SERVER'S OWN ADDRESS is
//      excluded — that one is not cosmetic: it is the tunnel's own carrier, and
//      routing it into the utun hangs the session with no error anywhere;
//    • every branch of the host-key decision, including the truncated pin, which
//      is the one place a "close enough" comparison would be a security hole.
//

import Testing
import Foundation
import NetworkExtension
@testable import SimpleVPN

@Suite struct SSHNetworkTunnelConfigTests {

    private func usable() -> SSHNetworkTunnelConfig {
        var c = SSHNetworkTunnelConfig()
        c.server = "gateway.example.com"
        c.username = "alice"
        c.pinnedHostKeySHA256 = String(repeating: "ab", count: 32)
        return c
    }

    // MARK: Start payload ↔ Go contract

    @Test func startPayloadCarriesExactlyTheKeysTheEngineParses() throws {
        var c = usable()
        c.mtu = 1400
        c.useFarSideResolver = true
        c.farSideResolver = "127.0.0.1:53"
        let start = SSHNetworkTunnelStartConfig(config: c, password: "pw",
                                                privateKeyPEM: "KEY", certificatePEM: "CERT",
                                                expectedHostKeySHA256: c.normalizedPin)
        let json = start.engineJSONString()
        let obj = try #require(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])

        // Exactly the fields Vendor/proxy-engine/src/engine.go's startConfig has.
        #expect(Set(obj.keys) == ["upstream", "username", "password", "mtu",
                                  "dnsSentinel", "dnsUpstream"])
        #expect(obj["upstream"] as? String == "ssh://alice@gateway.example.com:22")
        #expect(obj["mtu"] as? Int == 1400)
        #expect(obj["dnsSentinel"] as? String == SSHNetworkTunnelConfig.farSideResolverSentinel)
        #expect(obj["dnsUpstream"] as? String == "127.0.0.1:53")
        // NO CREDENTIAL crosses into Go. The engine has no use for one on this
        // path — Swift owns the session — so a password here would be a secret
        // handed to a component that cannot need it.
        #expect(obj["password"] as? String == "")
        for secret in ["pw", "KEY", "CERT"] {
            #expect(!json.contains(secret), "the engine payload leaked \(secret)")
        }
    }

    @Test func startPayloadOmitsTheSentinelWhenFarSideDNSIsOff() throws {
        let start = SSHNetworkTunnelStartConfig(config: usable(), password: "",
                                                privateKeyPEM: "", certificatePEM: "",
                                                expectedHostKeySHA256: "")
        let obj = try #require(try JSONSerialization.jsonObject(
            with: Data(start.engineJSONString().utf8)) as? [String: Any])
        #expect(obj["dnsSentinel"] == nil)
        #expect(obj["dnsUpstream"] == nil)
    }

    @Test func upstreamURLUsesTheEffectivePortAndBracketsIPv6() {
        var c = usable()
        #expect(c.upstreamURL == "ssh://alice@gateway.example.com:22")
        c.port = 2222
        #expect(c.upstreamURL == "ssh://alice@gateway.example.com:2222")
        c.server = "2001:db8::1"
        #expect(c.upstreamURL == "ssh://alice@[2001:db8::1]:2222")
        c.username = ""
        #expect(c.upstreamURL == "ssh://[2001:db8::1]:2222")
    }

    @Test func redactedDescriptionShowsThePinAndHidesEverythingElse() {
        var c = usable()
        c.useFarSideResolver = true
        let start = SSHNetworkTunnelStartConfig(config: c, password: "hunter2",
                                                privateKeyPEM: "-----BEGIN OPENSSH PRIVATE KEY-----",
                                                certificatePEM: "ssh-ed25519-cert-v01 AAAA",
                                                expectedHostKeySHA256: c.normalizedPin)
        let line = start.redactedDescription()
        for secret in ["hunter2", "BEGIN OPENSSH", "AAAA"] {
            #expect(!line.contains(secret), "the loggable form leaked \(secret)")
        }
        // The pin is a public key's HASH, not a secret, and it is the single most
        // useful thing in a failed-connect log.
        #expect(line.contains(c.normalizedPin))
    }

    /// PIN-ONLY is enforced at the payload, not merely intended: the extension
    /// cannot prompt and cannot read known_hosts, so an empty pin has to be a
    /// refusal rather than "check something else".
    @Test func startPayloadRefusesItselfWithoutAPin() {
        let c = usable()
        let noPin = SSHNetworkTunnelStartConfig(config: c, password: "pw",
                                                privateKeyPEM: "", certificatePEM: "",
                                                expectedHostKeySHA256: "")
        #expect(noPin.problem != nil)
        #expect(noPin.problem?.contains("host key") == true)

        let withPin = SSHNetworkTunnelStartConfig(config: c, password: "pw",
                                                  privateKeyPEM: "", certificatePEM: "",
                                                  expectedHostKeySHA256: c.normalizedPin)
        #expect(withPin.problem == nil)
    }

    // MARK: connectProblem gates

    @Test func connectProblemRefusesEveryUnusableConfig() {
        #expect(SSHNetworkTunnelConfig().connectProblem != nil)          // no server

        var noUser = usable(); noUser.username = ""
        #expect(noUser.connectProblem != nil)

        var url = usable(); url.server = "ssh://gateway.example.com"
        #expect(url.connectProblem?.contains("ssh://") == true)

        var at = usable(); at.server = "alice@gateway.example.com"
        #expect(at.connectProblem?.contains("Username") == true)

        var badPort = usable(); badPort.port = 70000
        #expect(badPort.connectProblem != nil)

        var split = usable(); split.includeDefaultRoute = false
        #expect(split.connectProblem != nil)                             // no routes
        split.includedRoutes = ["10.0.0.0/8"]
        #expect(split.connectProblem == nil)

        var hostBits = usable(); hostBits.includeDefaultRoute = false
        hostBits.includedRoutes = ["10.0.0.5/8"]
        #expect(hostBits.connectProblem?.contains("10.0.0.0/8") == true)

        var dns = usable(); dns.dnsServers = ["1.1.1.1/32"]
        #expect(dns.connectProblem != nil)                               // a prefix isn't a resolver

        var farSide = usable(); farSide.useFarSideResolver = true
        farSide.farSideResolver = "http://resolver"
        #expect(farSide.connectProblem != nil)
        farSide.farSideResolver = "127.0.0.1:53"
        #expect(farSide.connectProblem == nil)

        // Pinned policy with no pin can NEVER connect — the extension accepts
        // nothing else — so it is refused here rather than at the engine.
        var pinned = usable(); pinned.hostKeyPolicy = .pinned; pinned.pinnedHostKeySHA256 = ""
        #expect(pinned.connectProblem != nil)
        // …and a truncated one is refused too, with the length in the message.
        pinned.pinnedHostKeySHA256 = String(repeating: "ab", count: 8)
        #expect(pinned.connectProblem?.contains("64") == true)
    }

    @Test func farSideResolverAcceptsTheShapesTheServerCouldUse() {
        for good in ["127.0.0.1", "127.0.0.1:53", "resolver.internal", "resolver.internal:5353",
                     "::1", "[::1]:53", "10.0.0.53:53"] {
            #expect(SSHNetworkTunnelConfig.farSideResolverProblem(good) == nil,
                    "\(good) should be accepted")
        }
        for bad in ["", "https://resolver", "127.0.0.1:0", "127.0.0.1:99999", ":53", "[::1"] {
            #expect(SSHNetworkTunnelConfig.farSideResolverProblem(bad) != nil,
                    "\(bad) should be refused")
        }
    }

    @Test func normalizedPinAcceptsEveryWayAFingerprintIsWritten() {
        let hex = String(repeating: "ab", count: 32)
        var c = usable()
        for spelling in [hex, hex.uppercased(), "SHA256:" + hex, "sha256:" + hex.uppercased()] {
            c.pinnedHostKeySHA256 = spelling
            #expect(c.normalizedPin == hex, "\(spelling) did not normalise")
        }
        // Colon-separated bytes (the `ssh-keygen -E sha256` habit) too.
        c.pinnedHostKeySHA256 = stride(from: 0, to: 64, by: 2)
            .map { hex[hex.index(hex.startIndex, offsetBy: $0)...]
                     .prefix(2) }
            .joined(separator: ":")
        #expect(c.normalizedPin == hex)
        // Anything not exactly 32 bytes is NOT a pin.
        c.pinnedHostKeySHA256 = String(repeating: "ab", count: 31)
        #expect(c.normalizedPin.isEmpty)
    }

    @Test func normalizedPullsEverythingBackIntoRange() {
        var c = usable()
        c.server = "  gateway.example.com  "
        c.port = 99999
        c.mtu = 9000
        c.keepaliveSeconds = -5
        c.farSideResolver = "   "
        c.includedRoutes = ["10.0.0.0/8", "  ", " 192.168.0.0/16 "]
        let n = c.normalized()
        #expect(n.server == "gateway.example.com")
        #expect(n.port == 0)                                             // ⇒ 22
        #expect(n.mtu == SSHNetworkTunnelStartConfig.defaultMTU)
        #expect(n.keepaliveSeconds == 30)
        #expect(n.farSideResolver == SSHNetworkTunnelConfig.defaultFarSideResolver)
        #expect(n.includedRoutes == ["10.0.0.0/8", "192.168.0.0/16"])
    }

    @Test func decodingToleratesAnEmptyOrPartialBlob() {
        #expect(SSHNetworkTunnelConfig.decode(from: nil) == SSHNetworkTunnelConfig())
        let partial = Data(#"{"server":"gw.example","mtu":1300}"#.utf8)
        let c = SSHNetworkTunnelConfig.decode(from: partial)
        #expect(c.server == "gw.example")
        #expect(c.mtu == 1300)
        // Everything absent takes its DOCUMENTED default, never a decode failure —
        // a settings problem must not be able to break connecting.
        #expect(c.includeDefaultRoute)
        #expect(c.keepaliveSeconds == 30)
        #expect(c.hostKeyPolicy == .trustOnFirstUse)
    }

    @Test func theUDPCaveatNamesQUIC() {
        // Not a style check: QUIC is the default for much of the web now, and
        // "some sites are slow" is a much worse way to discover this limit.
        #expect(SSHNetworkTunnelConfig.udpCaveat.contains("QUIC"))
        #expect(SSHNetworkTunnelConfig.unavailableMethodReason.lowercased().contains("agent"))
        #expect(SSHNetworkTunnelConfig.unavailableMethodReason.contains("Kerberos"))
    }
}

// MARK: - Network settings

@Suite struct SSHNetworkTunnelNetworkSettingsTests {

    private func usable() -> SSHNetworkTunnelConfig {
        var c = SSHNetworkTunnelConfig()
        c.server = "203.0.113.9"
        c.username = "alice"
        return c
    }

    /// §7e: the SSH server's address MUST be an excluded route. It is the
    /// tunnel's own carrier — a loop here hangs the session rather than
    /// misrouting one connection.
    @Test func theServerAddressIsExcludedFromTheTunnel() {
        let c = usable()
        let carveOuts = SSHNetworkTunnelNetworkSettings.serverExclusions(host: c.server)
        #expect(carveOuts == ["203.0.113.9/32"])

        let s = SSHNetworkTunnelNetworkSettings.settings(for: c, extraExcludedRoutes: carveOuts)
        let excluded = (s.ipv4Settings?.excludedRoutes ?? []).map(\.destinationAddress)
        #expect(excluded.contains("203.0.113.9"))
        // …and it is still there under a full tunnel, which is exactly when it
        // matters (the utun owns 0.0.0.0/0).
        #expect(s.ipv4Settings?.includedRoutes?.contains { $0.destinationAddress == "0.0.0.0" } == true)
    }

    @Test func serverExclusionsHandleLiteralIPv6AndUnresolvableNames() {
        #expect(SSHNetworkTunnelNetworkSettings.serverExclusions(host: "2001:db8::1")
                == ["2001:db8::1/128"])
        #expect(SSHNetworkTunnelNetworkSettings.serverExclusions(host: "").isEmpty)
    }

    @Test func aSplitTunnelCarriesOnlyItsRoutesPlusResolverHostRoutes() {
        var c = usable()
        c.includeDefaultRoute = false
        c.includedRoutes = ["10.0.0.0/8"]
        c.dnsServers = ["10.1.2.3"]
        let s = SSHNetworkTunnelNetworkSettings.settings(for: c)
        let v4 = (s.ipv4Settings?.includedRoutes ?? []).map(\.destinationAddress)
        #expect(v4.contains("10.0.0.0"))
        // The resolver needs its own /32 or the netstack never sees the queries.
        #expect(v4.contains("10.1.2.3"))
        #expect(!v4.contains("0.0.0.0"))
    }

    @Test func theFarSideSentinelIsAdvertisedAndRoutedInOnASplitTunnel() {
        var c = usable()
        c.includeDefaultRoute = false
        c.includedRoutes = ["10.0.0.0/8"]
        c.useFarSideResolver = true
        let resolvers = SSHNetworkTunnelNetworkSettings.resolvers(for: c)
        // FIRST: a stub resolver tries the list in order, and the sentinel is the
        // resolver the user actually asked for.
        #expect(resolvers.first == SSHNetworkTunnelConfig.farSideResolverSentinel)

        let s = SSHNetworkTunnelNetworkSettings.settings(for: c)
        #expect(s.dnsSettings?.servers.first == SSHNetworkTunnelConfig.farSideResolverSentinel)
        let v4 = (s.ipv4Settings?.includedRoutes ?? []).map(\.destinationAddress)
        #expect(v4.contains(SSHNetworkTunnelConfig.farSideResolverSentinel),
                "the sentinel must reach the utun or the far-side resolver never sees a query")
    }

    @Test func excludingTheSentinelIsWarnedAboutRatherThanSilentlyBroken() {
        var c = usable()
        c.useFarSideResolver = true
        c.excludedRoutes = ["198.18.0.0/15"]
        #expect(c.sentinelReachabilityWarning != nil)
        c.excludedRoutes = ["10.0.0.0/8"]
        #expect(c.sentinelReachabilityWarning == nil)
    }

    /// A DEMOTED tunnel must not keep hijacking every lookup after losing the
    /// gateway arbitration — its own routes still carry their own traffic.
    @Test func demotionDropsTheDefaultRouteAndTheCatchAllResolver() {
        var c = usable()
        c.includedRoutes = ["10.0.0.0/8"]
        c.dnsServers = ["1.1.1.1"]
        let s = SSHNetworkTunnelNetworkSettings.settings(for: c, suppressDefaultRoute: true)
        let v4 = (s.ipv4Settings?.includedRoutes ?? []).map(\.destinationAddress)
        #expect(!v4.contains("0.0.0.0"))
        #expect(v4.contains("10.0.0.0"))
        #expect(s.dnsSettings == nil)
    }

    @Test func aPurelyIPv4ConfigClaimsNoIPv6Default() {
        var c = usable()
        c.includeDefaultRoute = false
        c.includedRoutes = ["10.0.0.0/8"]
        #expect(SSHNetworkTunnelNetworkSettings.settings(for: c).ipv6Settings == nil)
        c.includedRoutes.append("2001:db8::/32")
        #expect(SSHNetworkTunnelNetworkSettings.settings(for: c).ipv6Settings != nil)
    }

    /// The tunnel address is the RFC 2544 benchmarking range, deliberately not the
    /// friendlier-looking RFC 1918 space someone might actually be routing.
    @Test func theTunnelAddressIsNotRealSpaceAnyoneRoutes() {
        #expect(SSHNetworkTunnelNetworkSettings.tunnelIPv4.hasPrefix("198.18."))
        #expect(SSHNetworkTunnelConfig.farSideResolverSentinel.hasPrefix("198.18."))
        #expect(SSHNetworkTunnelNetworkSettings.tunnelIPv4
                != SSHNetworkTunnelConfig.farSideResolverSentinel)
    }

    @Test func theMTUIsNeverReducedForEncapsulation() {
        // NOT a tautology: it is the regression guard for someone "helpfully"
        // subtracting an SSH overhead that does not exist on this path (the
        // netstack terminates the guest's TCP; nothing is wrapped).
        var c = usable()
        c.mtu = 1500
        #expect(SSHNetworkTunnelNetworkSettings.settings(for: c).mtu?.intValue == 1500)
    }
}

// MARK: - The host-key decision

@Suite struct SSHHostKeyDecisionTests {

    private let good = String(repeating: "ab", count: 32)
    private let other = String(repeating: "cd", count: 32)

    @Test func aMatchingPinIsTrustedAndDecidesAheadOfKnownHosts() {
        // Even when known_hosts disagrees: an explicit pin must not be overridable
        // by a file an attacker who reached the home directory could append to.
        for answer: SSHKnownHostsAnswer in [.match, .notFound, .unavailable] {
            let d = SSHHostKeyDecision.decide(policy: .pinned, configuredPin: "SHA256:" + good,
                                              presentedFingerprint: good, keyType: "ssh-ed25519",
                                              knownHosts: answer)
            #expect(d == .trusted(pin: good), "answer \(answer) should not change a pin match")
        }
    }

    @Test func aNonMatchingPinIsRefusedWithWhatWasOffered() {
        let d = SSHHostKeyDecision.decide(policy: .pinned, configuredPin: good,
                                          presentedFingerprint: other, keyType: "ssh-ed25519",
                                          knownHosts: .match)
        guard case .refused(let why) = d else { #expect(Bool(false), "must refuse"); return }
        #expect(why.contains(other), "the refusal must show what the server actually offered")
        #expect(why.contains("ssh-ed25519"))
    }

    /// THE truncated-pin test. A suffix or prefix comparison would let a key that
    /// merely starts the same through, which is no check at all.
    @Test func aTruncatedPinNeverMatches() {
        for shortPin in [String(good.prefix(32)), String(good.prefix(63)), String(good.suffix(32))] {
            let d = SSHHostKeyDecision.decide(policy: .pinned, configuredPin: shortPin,
                                              presentedFingerprint: good, keyType: "ssh-ed25519",
                                              knownHosts: .notFound)
            guard case .refused(let why) = d else {
                #expect(Bool(false), "a \(shortPin.count)-character pin must be refused")
                continue
            }
            #expect(why.contains("64"), "the refusal should say how long a fingerprint is")
        }
    }

    @Test func pinnedPolicyWithNoPinIsRefusedNotRelaxed() {
        let d = SSHHostKeyDecision.decide(policy: .pinned, configuredPin: "",
                                          presentedFingerprint: good, keyType: "ssh-ed25519",
                                          knownHosts: .match)
        guard case .refused(let why) = d else { #expect(Bool(false), "must refuse"); return }
        #expect(why.lowercased().contains("pinned"))
    }

    @Test func aKnownHostsMatchIsTrustedAndYieldsThePresentedKey() {
        let d = SSHHostKeyDecision.decide(policy: .trustOnFirstUse, configuredPin: "",
                                          presentedFingerprint: good, keyType: "ssh-ed25519",
                                          knownHosts: .match)
        #expect(d == .trusted(pin: good))
    }

    /// A CHANGED key is refused at every policy. "The user chose to be relaxed" is
    /// not consent to a key changing underneath them.
    @Test func aChangedKeyIsRefusedAtEveryPolicy() {
        for policy in SSHNetworkTunnelConfig.HostKeyPolicy.allCases {
            let d = SSHHostKeyDecision.decide(policy: policy, configuredPin: "",
                                              presentedFingerprint: other, keyType: "ssh-ed25519",
                                              knownHosts: .mismatch)
            guard case .refused(let why) = d else {
                #expect(Bool(false), "\(policy) must refuse a changed key"); continue
            }
            #expect(why.contains("CHANGED") || why.lowercased().contains("pinned"))
        }
    }

    @Test func anUnknownHostAsksTheUserOnlyUnderTrustOnFirstUse() {
        let ask = SSHHostKeyDecision.decide(policy: .trustOnFirstUse, configuredPin: "",
                                            presentedFingerprint: good, keyType: "ssh-ed25519",
                                            knownHosts: .notFound)
        #expect(ask == .askUser(fingerprint: good, keyType: "ssh-ed25519"))
        // Never a silent trust: `askUser` has no pin, so nothing can connect on it.
        #expect(ask.pin == nil)

        let refuse = SSHHostKeyDecision.decide(policy: .knownHostsOnly, configuredPin: "",
                                               presentedFingerprint: good, keyType: "ssh-ed25519",
                                               knownHosts: .notFound)
        guard case .refused(let why) = refuse else { #expect(Bool(false), "must refuse"); return }
        #expect(why.contains("known_hosts"))
    }

    /// "Couldn't check" is never permission to proceed.
    @Test func anUnavailableAnswerIsRefused() {
        let d = SSHHostKeyDecision.decide(policy: .trustOnFirstUse, configuredPin: "",
                                          presentedFingerprint: good, keyType: "ssh-ed25519",
                                          knownHosts: .unavailable)
        guard case .refused = d else { #expect(Bool(false), "must refuse"); return }
    }

    @Test func aServerThatPresentedNoKeyIsRefused() {
        for answer: SSHKnownHostsAnswer in [.match, .notFound] {
            let d = SSHHostKeyDecision.decide(policy: .trustOnFirstUse, configuredPin: "",
                                              presentedFingerprint: "", keyType: "",
                                              knownHosts: answer)
            guard case .refused = d else {
                #expect(Bool(false), "no key must be refused (answer \(answer))"); continue
            }
        }
    }

    @Test func normalizeStripsPrefixesColonsAndCase() {
        #expect(SSHHostKeyDecision.normalize("SHA256:" + good.uppercased()) == good)
        #expect(SSHHostKeyDecision.normalize("  " + good + "  ") == good)
        #expect(SSHHostKeyDecision.normalize("ab:ab:ab") == "ababab")
    }
}

// MARK: - Kind registration

@Suite struct SSHNetworkTunnelKindTests {

    @Test func theKindIsAPacketTunnelWithItsOwnRawValue() {
        // The raw value is a stored contract (providerConfiguration["vpnType"]).
        #expect(VPNKind.sshNetworkTunnel.rawValue == "sshnet")
        #expect(VPNKind(rawValue: "sshnet") == .sshNetworkTunnel)
        // NOT .subprocess — `transport`'s `default:` would have made it one
        // silently, and every engine-dispatch seam would then look for a CLI.
        #expect(VPNKind.sshNetworkTunnel.transport == .packetTunnel)
        #expect(!VPNKind.sshNetworkTunnel.isSingletonNative)
        #expect(VPNKind.sshNetworkTunnel.openconnectProtocol == nil)
        #expect(!VPNKind.sshNetworkTunnel.isSSLVPN)
    }

    /// The divert-plan declarations, WITH their reasons — both are `default:`ed
    /// switches, so nothing but this test notices a wrong answer.
    @Test func theKindDeclaresItsDivertCapability() {
        #expect(VPNKind.sshNetworkTunnel.canAcceptRoutedInTraffic,
                "we build this kind's tunnel settings, and every destination becomes its own forward")
        #expect(VPNKind.sshNetworkTunnel.routedInUnsupportedReason == nil)
        #expect(VPNKind.sshNetworkTunnel.canDivertOutside,
                "its excluded routes are ours to write — the server's own address is already one")
        #expect(VPNKind.sshNetworkTunnel.divertOutsideUnsupportedReason == nil)
    }

    @Test func itsSettingsSurfaceIsRegisteredAndResolvesByLongestPrefix() {
        #expect(SettingSurface.sshNetworkTunnel.namespace == "sshnet.")
        #expect(SettingSurface.sshNetworkTunnel.kinds == [.sshNetworkTunnel])
        #expect(!SettingSurface.sshNetworkTunnel.settings.isEmpty)
        // "sshnet." also has the "ssh." prefix; the resolver must prefer the
        // longer namespace or every one of these ids opens the SSH editor.
        #expect(SettingSurface.owning("sshnet.server") == .sshNetworkTunnel)
        #expect(SettingSurface.owning("ssh.server") == .ssh)
    }

    @Test func everySpecIsInItsOwnNamespaceWithADefaultAndAGroup() {
        for s in SSHNetSettings.all {
            #expect(s.id.hasPrefix("sshnet."), "\(s.id) is outside the sshnet.* namespace")
            #expect(s.manualAnchor.hasPrefix("sshnet-"))
            #expect(!s.name.isEmpty)
            #expect(!s.summary.isEmpty)
            #expect(s.group != nil, "\(s.id) has no group")
            #expect(s.declaresDefault, "\(s.id) must declare the value it rests at")
        }
        // At least one Traffic spec: SettingNavigationTests resolves every kind's
        // first Traffic setting, and a kind without one has no answer.
        #expect(SSHNetSettings.specs(in: .traffic).count > 0)
    }
}
