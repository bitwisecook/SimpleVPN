// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  WireGuardTests.swift
//  The WireGuard engine cannot be exercised without a live peer, so everything
//  that CAN go silently wrong without one is pinned here: the JSON contract
//  with the Go shim (field names on both sides — the Go twin is
//  TestWGStartConfigKeys in Vendor/tailscale-engine/src/wireguard_test.go),
//  the endpoint/route validation the editor and the engine must agree on, and
//  the config → NEPacketTunnelNetworkSettings mapping — the translation that
//  can produce a tunnel which connects and carries nothing.
//

import Foundation
import NetworkExtension
import Testing
@testable import SimpleVPN

struct WireGuardStartConfigTests {

    // MARK: Start-payload contract (must match Vendor/tailscale-engine/src/wireguard.go)

    @Test func startConfigEncodesExactlyTheKeysTheEngineParses() throws {
        var c = WireGuardConfig()
        c.peerPublicKey = "PUBKEY"
        c.endpoint = "vpn.example.com:51820"
        c.allowedIPs = ["0.0.0.0/0", "::/0"]
        c.persistentKeepalive = 25
        c.mtu = 1400

        let start = WireGuardStartConfig(config: c, privateKey: "PRIV", presharedKey: "PSK")
        let json = start.jsonString()
        let obj = try #require(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])

        // wgStartConfig in wireguard.go: these names are the contract.
        let expected: Set<String> = ["privateKey", "peerPublicKey", "presharedKey", "endpoint",
                                     "allowedIPs", "persistentKeepalive", "listenPort", "mtu"]
        #expect(Set(obj.keys) == expected)
        #expect(obj["privateKey"] as? String == "PRIV")
        #expect(obj["peerPublicKey"] as? String == "PUBKEY")
        #expect(obj["presharedKey"] as? String == "PSK")
        #expect(obj["endpoint"] as? String == "vpn.example.com:51820")
        #expect(obj["allowedIPs"] as? [String] == ["0.0.0.0/0", "::/0"])
        #expect(obj["persistentKeepalive"] as? Int == 25)
        #expect(obj["listenPort"] as? Int == 0)
        #expect(obj["mtu"] as? Int == 1400)
    }

    @Test func startPayloadRedactsTheKeys() {
        var c = WireGuardConfig()
        c.peerPublicKey = "peer-public-ok-to-show"
        c.endpoint = "h:1"
        let start = WireGuardStartConfig(config: c, privateKey: "very-private", presharedKey: "also-secret")
        let redacted = start.redactedJSONString()
        #expect(!redacted.contains("very-private"))
        #expect(!redacted.contains("also-secret"))
        #expect(redacted.contains("<redacted>"))
        // The peer's PUBLIC key stays — public by construction, and the useful
        // diagnostic when a config points at the wrong server.
        #expect(redacted.contains("peer-public-ok-to-show"))
    }

    @Test func mtuFallsBackWhenUnset() {
        var c = WireGuardConfig()
        c.endpoint = "h:1"
        c.mtu = nil
        let start = WireGuardStartConfig(config: c, privateKey: "k", presharedKey: "")
        #expect(start.mtu == WireGuardStartConfig.defaultMTU)
        #expect(WireGuardStartConfig.defaultMTU == 1420)
    }

    // MARK: Validation (mirrors wgResolveEndpoint / parseRoutes in the Go shim)

    @Test func endpointValidationMatchesEngine() {
        #expect(WireGuardConfig.endpointProblem("vpn.example.com:51820") == nil)
        #expect(WireGuardConfig.endpointProblem("192.0.2.1:51820") == nil)
        #expect(WireGuardConfig.endpointProblem("[2001:db8::1]:51820") == nil)
        // Rejections.
        #expect(WireGuardConfig.endpointProblem("") != nil)
        #expect(WireGuardConfig.endpointProblem("no-port-here") != nil)
        #expect(WireGuardConfig.endpointProblem("host:notaport") != nil)
        #expect(WireGuardConfig.endpointProblem("host:99999") != nil)
        #expect(WireGuardConfig.endpointProblem("2001:db8::1") != nil)   // v6 needs brackets
        #expect(WireGuardConfig.endpointProblem(":51820") != nil)        // no host
        // The endpoint is persisted in providerConfiguration in the clear —
        // credential-shaped input is refused rather than stored.
        #expect(WireGuardConfig.endpointProblem("user:secret@vpn.example.com:51820") != nil)
        #expect(WireGuardConfig.endpointProblem("user@vpn.example.com:51820") != nil)
    }

    @Test func routeValidationMatchesEngine() {
        #expect(WireGuardConfig.routeProblem("0.0.0.0/0") == nil)
        #expect(WireGuardConfig.routeProblem("10.44.0.0/16") == nil)
        #expect(WireGuardConfig.routeProblem("::/0") == nil)
        // The engine's parseRoutes rejects host bits — the editor must too.
        #expect(WireGuardConfig.routeProblem("10.0.0.1/8") != nil)
        #expect(WireGuardConfig.routeProblem("banana") != nil)
        #expect(WireGuardConfig.routeProblem("10.0.0.0/33") != nil)
        #expect(WireGuardConfig.routeProblem("10.0.0.0") != nil)
    }

    // MARK: Key validation (the commonest real-world WireGuard failure)

    /// A base64 key of exactly 32 bytes, the only length WireGuard accepts.
    private static func validKey(_ byte: UInt8 = 1) -> String {
        Data(repeating: byte, count: WireGuardConfig.keyByteCount).base64EncodedString()
    }

    @Test func aRealKeyIsAccepted() {
        let key = Self.validKey()
        #expect(key.count == 44)                               // 43 + one "=" of padding
        #expect(WireGuardConfig.keyProblem(key) == nil)
        // Surrounding whitespace from a paste is not the user's mistake.
        #expect(WireGuardConfig.keyProblem("  \(key)\n") == nil)
        // Empty is "not set", a different question — never this one's problem.
        #expect(WireGuardConfig.keyProblem("") == nil)
        #expect(WireGuardConfig.keyProblem("   ") == nil)
    }

    /// THE real-world case: a 43-character paste — the key copied without its
    /// trailing "=". Every layer accepted it until the handshake, which failed
    /// silently.
    @Test func aTruncatedKeyIsRejected() throws {
        let key = Self.validKey()
        let truncated = String(key.dropLast())                 // 43 chars, no padding
        #expect(truncated.count == 43)
        let problem = try #require(WireGuardConfig.keyProblem(truncated))
        #expect(!problem.isEmpty)
        // Wrong length in the other direction too.
        #expect(WireGuardConfig.keyProblem(
            Data(repeating: 2, count: 16).base64EncodedString()) != nil)
        #expect(WireGuardConfig.keyProblem(
            Data(repeating: 2, count: 64).base64EncodedString()) != nil)
        // Not base64 at all.
        #expect(WireGuardConfig.keyProblem("PUB") != nil)
        #expect(WireGuardConfig.keyProblem("not a key at all!!") != nil)
    }

    // MARK: Interface addresses are NOT routes

    /// `10.0.0.2/24` is a perfectly ordinary tunnel address — the prefix
    /// describes the on-link network, not a route — so the host-bit check that
    /// belongs on Allowed IPs must never run here. Refusing what the engine
    /// accepts is the other half of the rule.
    @Test func interfaceAddressesMayCarryHostBits() {
        for good in ["10.0.0.2/32", "10.0.0.2/24", "10.0.0.2", "fd00::2/64", "fd00::2",
                     "192.168.1.55/16", "0.0.0.0/0"] {
            #expect(WireGuardConfig.interfaceAddressProblem(good) == nil, "\(good) should be accepted")
        }
        // The contrast that motivates the separate validator.
        #expect(WireGuardConfig.routeProblem("10.0.0.2/24") != nil)
        #expect(WireGuardConfig.interfaceAddressProblem("10.0.0.2/24") == nil)
    }

    @Test func malformedInterfaceAddressesAreRejected() {
        for bad in ["", "  ", "banana", "10.0.0.2/33", "fd00::2/129", "10.0.0.2/-1",
                    "10.0.0.2/x", "999.1.1.1"] {
            #expect(WireGuardConfig.interfaceAddressProblem(bad) != nil, "\(bad) should be rejected")
        }
        #expect(WireGuardConfig.addressesProblem(["10.0.0.2/32", "banana"]) != nil)
        #expect(WireGuardConfig.addressesProblem(["10.0.0.2/32", "fd00::2/64"]) == nil)
        #expect(WireGuardConfig.addressesProblem([]) == nil)
    }

    // MARK: Ranges (the UI bound and the stored bound are the same constant)

    /// The Go side only rejects `mtu <= 0` (`if mtu <= 0 { 1420 }`), so 1 was
    /// "accepted" and produced a tunnel that dropped every packet. The floor is
    /// IPv4's minimum reassembly buffer — NOT the IPv6 minimum link MTU, because
    /// sub-1280 MTUs are legal WireGuard and common on PPPoE / double-NAT links.
    @Test func rangeBoundariesAreTheEnginesOwn() {
        #expect(WireGuardConfig.mtuRange == 576...1500)
        #expect(!WireGuardConfig.mtuRange.contains(1))
        #expect(!WireGuardConfig.mtuRange.contains(575))
        #expect(WireGuardConfig.mtuRange.contains(576))
        #expect(WireGuardConfig.mtuRange.contains(1200))
        #expect(WireGuardConfig.mtuRange.contains(1280))
        #expect(WireGuardConfig.mtuRange.contains(WireGuardStartConfig.defaultMTU))
        #expect(WireGuardConfig.mtuRange.contains(1500))
        #expect(!WireGuardConfig.mtuRange.contains(1501))

        // 0 = auto, so the port range starts there — unlike a proxy's.
        #expect(WireGuardConfig.listenPortRange == 0...65535)
        #expect(WireGuardConfig.listenPortRange.contains(0))
        #expect(!WireGuardConfig.listenPortRange.contains(65536))
        #expect(!WireGuardConfig.listenPortRange.contains(-1))

        // uint16 seconds on the wire; 0 = off, 25 typical behind NAT.
        #expect(WireGuardConfig.keepaliveRange == 0...65535)
        #expect(WireGuardConfig.keepaliveRange.contains(0))
        #expect(WireGuardConfig.keepaliveRange.contains(25))
        #expect(!WireGuardConfig.keepaliveRange.contains(65536))

        // Legal WireGuard, but a caveat's worth of trouble on this Mac.
        #expect(WireGuardConfig.privilegedPortRange.contains(1))
        #expect(WireGuardConfig.privilegedPortRange.contains(1023))
        #expect(!WireGuardConfig.privilegedPortRange.contains(1024))
        #expect(!WireGuardConfig.privilegedPortRange.contains(51820))
    }

    @Test func normalizedTrimsAndDropsOutOfRangeNumbers() {
        var c = WireGuardConfig()
        c.name = "  Home  "
        c.endpoint = " vpn.example.com:51820\n"
        c.peerPublicKey = " \(Self.validKey()) "
        c.addresses = ["10.0.0.2/32", "", "  "]
        c.allowedIPs = [" 0.0.0.0/0 ", ""]
        c.dns = ["", " 1.1.1.1"]
        c.mtu = 1                      // "accepted" by the engine, drops every packet
        c.listenPort = 70000
        c.persistentKeepalive = 99_999
        let n = c.normalized()
        #expect(n.name == "Home")
        #expect(n.endpoint == "vpn.example.com:51820")
        #expect(n.peerPublicKey == Self.validKey())
        #expect(n.addresses == ["10.0.0.2/32"])
        #expect(n.allowedIPs == ["0.0.0.0/0"])
        #expect(n.dns == ["1.1.1.1"])
        #expect(n.mtu == nil)          // back to "engine default"
        #expect(n.listenPort == nil)
        #expect(n.persistentKeepalive == nil)
        // In-range values survive untouched.
        c.mtu = 1380; c.listenPort = 51820; c.persistentKeepalive = 25
        let ok = c.normalized()
        #expect(ok.mtu == 1380)
        #expect(ok.listenPort == 51820)
        #expect(ok.persistentKeepalive == 25)
    }

    // MARK: Regressions — the save paths that used to destroy data

    /// REGRESSION (data loss). `normalized()` runs on EVERY `setWireGuardConfig`,
    /// and the floor used to be 1280 — so a provider-issued 1200 (PPPoE) or 1240
    /// (double NAT) imported from a `.conf` silently became "engine default 1420"
    /// on the next unrelated save, and a working tunnel started hanging on large
    /// packets. Sub-1280 costs IPv6 and nothing else; it is a caveat, not a
    /// refusal, and the Go side only rejects `mtu <= 0`.
    @Test func aLegalSub1280MTUSurvivesEverySave() {
        for mtu in [576, 1200, 1240, 1279] {
            var c = WireGuardConfig()
            c.mtu = mtu
            #expect(c.normalized().mtu == mtu, "a save threw away a legal MTU of \(mtu)")
            // Saving twice must be as stable as saving once.
            #expect(c.normalized().normalized().mtu == mtu)
            // Non-blocking, and it reaches the engine as typed.
            #expect(WireGuardConfig.mtuProblem(mtu) == nil)
            #expect(WireGuardConfig.mtuBelowIPv6MinimumCaveat(mtu) != nil || mtu >= 1280)
            #expect(WireGuardStartConfig(config: c, privateKey: "", presharedKey: "").mtu == mtu)
        }
        // 1280 and above carries IPv6, so there is nothing to caveat.
        #expect(WireGuardConfig.mtuBelowIPv6MinimumCaveat(1280) == nil)
        #expect(WireGuardConfig.mtuBelowIPv6MinimumCaveat(nil) == nil)
        // Genuinely out of range is BLOCKED (Save says why) rather than rewritten
        // silently — the editor's `saveDisabledReason` asks this.
        #expect(WireGuardConfig.mtuProblem(9000) != nil)
        #expect(WireGuardConfig.mtuProblem(0) != nil)
        #expect(WireGuardConfig.mtuProblem(nil) == nil)
    }

    /// REGRESSION (data loss). An import replaced the draft WHOLESALE, so a `.conf`
    /// with no `PresharedKey` blanked the draft's copy — and `save()` passed the
    /// pre-shared key as a VALUE ("replace") while the private key was passed as
    /// nil ("leave alone"), so the blank was written over the stored key. Both keys
    /// follow the same rule now.
    @Test func importingAConfNeverDestroysAStoredKey() {
        var stored = WireGuardConfig()
        stored.id = "profile-1"
        stored.name = "Work"
        stored.privateKey = Self.validKey()
        stored.presharedKey = Self.validKey()

        // A real provider `.conf`: peer + endpoint, no keys of its own at all.
        let keyless = """
        [Interface]
        Address = 10.7.0.2/32
        DNS = 10.7.0.1
        [Peer]
        PublicKey = \(Self.validKey())
        Endpoint = vpn.example.com:51820
        AllowedIPs = 0.0.0.0/0
        """
        let afterImport = stored.applyingImport(WireGuardConfig.parse(keyless, name: "x"), name: nil)
        #expect(afterImport.id == "profile-1")                  // identity is not imported
        #expect(afterImport.name == "Work")                     // a paste keeps the name
        #expect(afterImport.endpoint == "vpn.example.com:51820") // …but the fields it carries win
        #expect(afterImport.addresses == ["10.7.0.2/32"])
        #expect(afterImport.privateKey == stored.privateKey, "the import destroyed the private key")
        #expect(afterImport.presharedKey == stored.presharedKey, "the import destroyed the pre-shared key")

        // A `.conf` that DOES carry keys replaces them, and a file import renames.
        let withKeys = keyless + "\nPresharedKey = \(Self.validKey(7))"
        let replaced = stored.applyingImport(WireGuardConfig.parse(withKeys, name: "Home"), name: "Home")
        #expect(replaced.name == "Home")
        #expect(replaced.presharedKey == Self.validKey(7))

        // And the save decision: nil = leave alone, "" = remove, value = replace.
        #expect(WireGuardConfig.presharedKeyToSave(draft: "", removing: false) == nil)
        #expect(WireGuardConfig.presharedKeyToSave(draft: "   ", removing: false) == nil)
        #expect(WireGuardConfig.presharedKeyToSave(draft: "", removing: true) == "")
        #expect(WireGuardConfig.presharedKeyToSave(draft: "abc", removing: false) == "abc")
        // An explicit Remove wins — that is the ONE thing that clears a key.
        #expect(WireGuardConfig.presharedKeyToSave(draft: "abc", removing: true) == "")
    }

    /// REGRESSION (data loss). `Table = main` — anything in `rt_tables` — is valid
    /// wg-quick, and was blanked on save, so an exported `.conf` silently lost the
    /// line.
    @Test func aNamedRoutingTableSurvivesTheSave() {
        for name in ["main", "local", "default", "vpn_table", "table-1", "51820"] {
            var c = WireGuardConfig()
            c.table = name
            #expect(WireGuardConfig.isValidTable(name), "\(name) isn't accepted as a Table")
            #expect(WireGuardConfig.tableProblem(name) == nil)
            #expect(c.normalized().table == name, "a save threw away Table = \(name)")
            #expect(c.serialize().contains("Table = \(name)"))
        }
        // Still refused: something that could not be one token on one line.
        for bad in ["main table", "one\ttwo", "nope!", ""] where !bad.isEmpty {
            #expect(!WireGuardConfig.isValidTable(bad), "\(bad) shouldn't be a valid Table")
            #expect(WireGuardConfig.tableProblem(bad) != nil)
        }
        #expect(WireGuardConfig.tableProblem("") == nil)   // not set is not a problem
    }

    /// REGRESSION. A wg-quick `DNS =` line legitimately carries SEARCH DOMAINS
    /// beside the resolvers; they parse as neither prefix nor address, and were
    /// reported as uncovered — telling the user to "add corp.example.com/32 to
    /// Allowed IPs", which is not a thing.
    @Test func dnsCoverageIgnoresSearchDomains() {
        let uncovered = WireGuardConfig.dnsOutsideAllowedIPs(
            dns: ["10.7.0.1", "corp.example.com", "example.com", "fd00::53"],
            allowedIPs: ["192.168.0.0/24"])
        #expect(uncovered == ["10.7.0.1", "fd00::53"])

        // Covered resolvers are still silent, and a full tunnel reports nothing.
        #expect(WireGuardConfig.dnsOutsideAllowedIPs(dns: ["10.7.0.1", "corp.example.com"],
                                                     allowedIPs: ["10.7.0.0/24"]).isEmpty)
        #expect(WireGuardConfig.dnsOutsideAllowedIPs(dns: ["1.1.1.1", "corp.example.com"],
                                                     allowedIPs: ["0.0.0.0/0", "::/0"]).isEmpty)
        #expect(WireGuardConfig.isIPLiteral("10.7.0.1"))
        #expect(WireGuardConfig.isIPLiteral("fd00::53"))
        #expect(!WireGuardConfig.isIPLiteral("corp.example.com"))
    }

    @Test func connectProblemGatesTheEssentials() {
        var c = WireGuardConfig()
        #expect(c.connectProblem != nil)                       // brand new: no peer key
        c.peerPublicKey = "PUB"
        #expect(c.connectProblem != nil)                       // not a 32-byte key
        c.peerPublicKey = Self.validKey()
        #expect(c.connectProblem != nil)                       // no endpoint
        c.endpoint = "vpn.example.com:51820"
        c.addresses = []
        #expect(c.connectProblem != nil)                       // no interface address
        c.addresses = ["10.0.0.2/32"]
        c.allowedIPs = []
        #expect(c.connectProblem != nil)                       // nothing routed
        c.allowedIPs = ["0.0.0.0/0"]
        // The private key is deliberately NOT part of connectProblem — it lives
        // in the keychain, not in this (redacted) value.
        #expect(c.connectProblem == nil)
        // A truncated pre-shared key IS caught when one is present.
        c.presharedKey = String(Self.validKey(2).dropLast())
        #expect(c.connectProblem != nil)
        c.presharedKey = Self.validKey(2)
        #expect(c.connectProblem == nil)
        // An interface address with host bits stays fine (it isn't a route).
        c.presharedKey = ""
        c.addresses = ["10.0.0.2/24"]
        #expect(c.connectProblem == nil)
        c.addresses = ["10.0.0.2/33"]
        #expect(c.connectProblem != nil)
    }

    // MARK: Redaction invariant

    @Test func redactedForStorageStripsKeysAndNothingElse() {
        var c = WireGuardConfig()
        c.privateKey = "PRIV"
        c.presharedKey = "PSK"
        c.peerPublicKey = "PUB"
        c.endpoint = "h:1"
        let stored = c.redactedForStorage()
        #expect(stored.privateKey.isEmpty)
        #expect(stored.presharedKey.isEmpty)
        #expect(stored.peerPublicKey == "PUB")
        #expect(stored.endpoint == "h:1")
        #expect(stored.id == c.id)
    }

    /// The pre-shared key is key material, so the editor treats it exactly like
    /// the private key: write-only, and never in the persisted blob. This pins
    /// the model half of that — the encoded providerConfiguration blob carries
    /// neither secret, whatever the in-memory value holds.
    @Test func neitherKeyReachesThePersistedBlob() throws {
        var c = WireGuardConfig()
        c.privateKey = "PRIVATE-KEY-VALUE"
        c.presharedKey = "PRESHARED-KEY-VALUE"
        c.peerPublicKey = "PUB"
        let blob = try #require(c.redactedForStorage().encodedBlob())
        let json = String(decoding: blob, as: UTF8.self)
        #expect(!json.contains("PRIVATE-KEY-VALUE"))
        #expect(!json.contains("PRESHARED-KEY-VALUE"))
        // …and the export path still gets the real values (that's why the editor
        // loads them from the keychain without ever rendering them).
        #expect(c.serialize().contains("PresharedKey = PRESHARED-KEY-VALUE"))
    }
}

// MARK: - DNS coverage (the split-tunnel footgun)
//
// `WireGuardNetworkSettings` routes each advertised resolver's /32 into the utun,
// so the query gets there — but wireguard-go then has no peer claiming that
// address (its `allowed_ip` set is the Allowed IPs) and drops it. The tunnel
// connects, carries its own networks, and every name lookup times out.

struct WireGuardDNSCoverageTests {

    @Test func aResolverOutsideTheAllowedIPsIsReported() {
        #expect(WireGuardConfig.dnsOutsideAllowedIPs(dns: ["1.1.1.1"],
                                                     allowedIPs: ["10.0.0.0/8"]) == ["1.1.1.1"])
    }

    @Test func aResolverInsideAnAllowedNetworkIsFine() {
        #expect(WireGuardConfig.dnsOutsideAllowedIPs(dns: ["10.0.0.1"],
                                                     allowedIPs: ["10.0.0.0/8"]).isEmpty)
        // Exact host prefixes count as coverage too.
        #expect(WireGuardConfig.dnsOutsideAllowedIPs(dns: ["1.1.1.1"],
                                                     allowedIPs: ["10.0.0.0/8", "1.1.1.1/32"]).isEmpty)
    }

    @Test func aFullTunnelCoversEverythingSoNothingIsReported() {
        #expect(WireGuardConfig.dnsOutsideAllowedIPs(dns: ["1.1.1.1", "2606:4700:4700::1111"],
                                                     allowedIPs: ["0.0.0.0/0", "::/0"]).isEmpty)
        // A v4 default alone does NOT cover a v6 resolver.
        #expect(WireGuardConfig.dnsOutsideAllowedIPs(dns: ["2606:4700:4700::1111"],
                                                     allowedIPs: ["0.0.0.0/0"])
                == ["2606:4700:4700::1111"])
    }

    @Test func familiesDoNotCoverEachOther() {
        #expect(WireGuardConfig.dnsOutsideAllowedIPs(dns: ["fd00:7::1"],
                                                     allowedIPs: ["10.0.0.0/8"]) == ["fd00:7::1"])
        #expect(WireGuardConfig.dnsOutsideAllowedIPs(dns: ["fd00:7::1"],
                                                     allowedIPs: ["fd00:7::/64"]).isEmpty)
    }

    @Test func everyUncoveredResolverIsReportedInOrder() {
        #expect(WireGuardConfig.dnsOutsideAllowedIPs(dns: ["10.0.0.1", "1.1.1.1", "8.8.8.8"],
                                                     allowedIPs: ["10.0.0.0/8"])
                == ["1.1.1.1", "8.8.8.8"])
    }

    /// No Allowed IPs at all is a different, blocking problem (`connectProblem`
    /// refuses it) — this non-blocking check must not pile on.
    @Test func noAllowedIPsReportsNothing() {
        #expect(WireGuardConfig.dnsOutsideAllowedIPs(dns: ["1.1.1.1"], allowedIPs: []).isEmpty)
    }

    @Test func theWarningNamesTheServerAndTheFix() {
        let w = WireGuardConfig.dnsCoverageWarning("1.1.1.1")
        #expect(w.contains("1.1.1.1"))
        #expect(w.contains("1.1.1.1/32"))
        #expect(WireGuardConfig.dnsCoverageWarning("fd00:7::1").contains("fd00:7::1/128"))
    }
}

// MARK: - Config → NEPacketTunnelNetworkSettings

@MainActor
struct WireGuardNetworkSettingsTests {

    private func fullTunnelConfig() -> WireGuardConfig {
        var c = WireGuardConfig()
        c.addresses = ["10.0.0.2/32", "fd00:7::2/128"]
        c.dns = ["10.0.0.1"]
        c.endpoint = "vpn.example.com:51820"
        c.allowedIPs = ["0.0.0.0/0", "::/0"]
        c.mtu = 1420
        return c
    }

    @Test func fullTunnelBuildsDefaultRoutesBothFamilies() throws {
        let s = try #require(WireGuardNetworkSettings.settings(for: fullTunnelConfig(),
                                                               resolvedEndpoint: "192.0.2.7:51820"))
        // The RESOLVED endpoint is the remote address — NE routes the tunnel's
        // own encrypted UDP around the tunnel via this.
        #expect(s.tunnelRemoteAddress == "192.0.2.7")
        #expect(s.ipv4Settings?.addresses == ["10.0.0.2"])
        #expect(s.ipv4Settings?.subnetMasks == ["255.255.255.255"])
        #expect(s.ipv4Settings?.includedRoutes?.contains { $0.destinationAddress == "0.0.0.0" } == true)
        #expect(s.ipv6Settings?.addresses == ["fd00:7::2"])
        #expect(s.ipv6Settings?.includedRoutes?.contains { $0.destinationAddress == "::" } == true)
        // wg-quick DNS semantics: the servers become the catch-all resolver.
        #expect(s.dnsSettings?.servers == ["10.0.0.1"])
        #expect(s.dnsSettings?.matchDomains == [""])
        #expect(s.mtu == 1420)
    }

    @Test func splitTunnelRoutesOnlyAllowedIPsPlusDNS() throws {
        var c = fullTunnelConfig()
        c.allowedIPs = ["10.44.0.0/16"]
        let s = try #require(WireGuardNetworkSettings.settings(for: c,
                                                               resolvedEndpoint: "192.0.2.7:51820"))
        let v4 = s.ipv4Settings?.includedRoutes ?? []
        #expect(!v4.contains { $0.destinationAddress == "0.0.0.0" })
        #expect(v4.contains { $0.destinationAddress == "10.44.0.0" })
        // The advertised resolver must stay reachable on a split tunnel.
        #expect(v4.contains { $0.destinationAddress == "10.0.0.1" && $0.destinationSubnetMask == "255.255.255.255" })
    }

    @Test func demotionStripsDefaultRouteAndCatchAllDNS() throws {
        let s = try #require(WireGuardNetworkSettings.settings(for: fullTunnelConfig(),
                                                               resolvedEndpoint: "192.0.2.7:51820",
                                                               suppressDefaultRoute: true))
        let v4 = s.ipv4Settings?.includedRoutes ?? []
        #expect(!v4.contains { $0.destinationAddress == "0.0.0.0" })
        // A demoted tunnel must not keep hijacking every lookup on the Mac…
        #expect(s.dnsSettings == nil)
        // …but its resolver stays reachable for its own traffic.
        #expect(v4.contains { $0.destinationAddress == "10.0.0.1" })
    }

    @Test func bareAddressesGetTheirPrefix() {
        #expect(WireGuardNetworkSettings.withPrefixLength("10.0.0.2") == "10.0.0.2/32")
        #expect(WireGuardNetworkSettings.withPrefixLength("fd00::2") == "fd00::2/128")
        #expect(WireGuardNetworkSettings.withPrefixLength("10.0.0.0/24") == "10.0.0.0/24")
    }

    @Test func noParseableAddressMeansNoSettings() {
        var c = fullTunnelConfig()
        c.addresses = ["not-an-address"]
        #expect(WireGuardNetworkSettings.settings(for: c, resolvedEndpoint: "192.0.2.7:51820") == nil)
    }

    @Test func remoteAddressParsesResolvedEndpoints() {
        #expect(WireGuardNetworkSettings.remoteAddress(fromResolved: "192.0.2.7:51820",
                                                       fallbackHost: "x") == "192.0.2.7")
        #expect(WireGuardNetworkSettings.remoteAddress(fromResolved: "[2001:db8::1]:51820",
                                                       fallbackHost: "x") == "2001:db8::1")
        #expect(WireGuardNetworkSettings.remoteAddress(fromResolved: "",
                                                       fallbackHost: "vpn.example.com") == "vpn.example.com")
    }
}

// MARK: - Engine status decode (the WGStatus payload)

struct WireGuardEngineStatusTests {

    @Test func decodesTheEnginePayload() throws {
        let json = """
        {"state":"running","endpoint":"192.0.2.7:51820","listenPort":51821,
         "rxBytes":2020,"txBytes":1010,"lastHandshake":1700000000,"packetsDropped":3}
        """
        let s = try #require(WireGuardEngineStatus.decode(json: json))
        #expect(s.isRunning)
        #expect(s.endpoint == "192.0.2.7:51820")
        #expect(s.listenPort == 51821)
        #expect(s.rxBytes == 2020 && s.txBytes == 1010)
        #expect(s.lastHandshakeDate == Date(timeIntervalSince1970: 1_700_000_000))
        #expect(s.packetsDropped == 3)
    }

    @Test func missingFieldsDegradeToDefaults() throws {
        let s = try #require(WireGuardEngineStatus.decode(json: #"{"state":"stopped"}"#))
        #expect(!s.isRunning)
        #expect(s.lastHandshakeDate == nil)
        #expect(s.rxBytes == 0)
    }
}
