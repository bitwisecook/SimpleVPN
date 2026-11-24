// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Testing
@testable import SimpleVPN

@MainActor
struct ProfilePacketPolicyTests {
    private let rule = "# outbound and inbound\non a: ip.packet { count(); }\n"

    @Test func sshPacketCredentialsReadOnlyTheSelectedRegularFile() async throws {
        var cfg = SubprocessTunnelConfig()
        cfg.kind = .ssh; cfg.sshMode = .netTunnel; cfg.server = "192.0.2.4"
        cfg.username = "alice"; cfg.sshAuthMethod = "key"; cfg.sshPinnedHostKey = String(repeating: "a", count: 64)
        cfg.sshTun = .init(addresses: ["10.8.0.27/24"], routes: ["10.22.0.0/16"])
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: dir) }
        let key = dir.appendingPathComponent("fixture-key")
        try Data("fixture SSH identity".utf8).write(to: key)
        cfg.identityFile = key.path
        let payload = try await OpenConnectProfileStore.sshTunCredentials(cfg, password: "")
        #expect(payload == ["key": Data("fixture SSH identity".utf8)])
        cfg.identityFile = dir.path
        await #expect(throws: (any Error).self) { _ = try await OpenConnectProfileStore.sshTunCredentials(cfg, password: "") }
    }

    @Test func standaloneAndComposedSSHTunKeepExactAddressesAndAuthenticatedTransport() throws {
        var cfg = SubprocessTunnelConfig()
        cfg.kind = .ssh; cfg.sshMode = .netTunnel
        cfg.server = "192.0.2.4"; cfg.username = "alice"; cfg.sshAuthMethod = "password"
        cfg.sshPinnedHostKey = String(repeating: "a", count: 64)
        #expect(ProfilePacketPolicy.adapter(for: cfg) == nil)
        cfg.sshTun = .init(addresses: ["10.8.0.27/24"], routes: ["10.22.0.0/16"])
        let tun = try #require(cfg.sshTunConfiguration)
        let stored = try OpenConnectProfileStore.configurationForStart(cfg, previous: nil)
        #expect(Set(stored.keys) == ["profile", "vpnType", "sshTun"])
        #expect(StandalonePacketPolicyConfiguration.adapterID(for: .ssh, configuration: stored) == "ssh-tun")
        #expect(ProfilePacketPolicy.adapter(for: cfg) == "ssh-tun")
        let member = VirtualRoutingConfig.Member(id: cfg.id, sshTun: tun, prefixes: [])
        #expect(VirtualRoutingConfig(version: 9, id: "test", members: [member], policy: .init()).problem == nil)
        #expect(member.transportKind == .ssh && member.transportAdapter == "ssh-tun")
        var snapshot = ConfigSnapshot()
        var profile = ConfigSnapshot.VPN(id: cfg.id, name: "Point to Point", kind: .ssh, server: cfg.server)
        profile.subprocess = cfg
        snapshot.vpns = [profile]
        let doc = ConfigDocument.build(from: snapshot)
        #expect(doc.root[ConfigDocumentKeys.format]?.intValue == ConfigFormat.pointToPointSSH)
        #expect(ConfigImport.plan(root: doc.root, current: .init()).vpns.first?.vpn.subprocess?.sshTun == cfg.sshTun)
        let suite = "SimpleVPNTests.sshTun." + UUID().uuidString
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = SubprocessTunnelStore(loadSaved: false, defaults: defaults)
        #expect(store.save(cfg))
        for key in ["subprocessTunnels.v1", "subprocessTunnels.packetPolicies.v1"] {
            let data = try #require(defaults.data(forKey: key))
            #expect(try JSONDecoder().decode([SubprocessTunnelConfig].self, from: data).isEmpty)
        }
        #expect(SubprocessTunnelStore(defaults: defaults).tunnels.first?.sshTun == cfg.sshTun)
        cfg.useJumpHost = true
        #expect(cfg.sshTunProblem != nil)
        #expect(throws: (any Error).self) { try OpenConnectProfileStore.configurationForStart(cfg, previous: nil) }
    }

    @Test func builtInL2TPRequiresExplicitIPv4AndBothPPPAndIKEIdentities() throws {
        var config = NativeVPNConfig()
        config.kind = .l2tp
        config.server = "192.0.2.1"
        config.username = "ppp-user"
        config.groupOrRealm = "client"
        config.remoteID = "gateway"
        #expect(config.ownedIPsec == nil)
        config.l2tpMSCHAPv2 = true
        let owned = try #require(config.ownedIPsec)
        #expect(owned.adapterID == "l2tp-strongswan")
        #expect(owned.usesL2TP == true && !owned.usesXAuth && owned.usesEAP != true)
        #expect(owned.username == "ppp-user" && owned.localID == "client" && owned.remoteID == "gateway")
        #expect(NativeVPNReadiness.need(for: config, facts: .init(hasSecret: true, hasPPPPassword: true)) == nil)
        #expect(NativeVPNReadiness.need(for: config, facts: .init(hasSecret: true))?.settingID == "native.password")
        var snapshot = ConfigSnapshot()
        var entry = ConfigSnapshot.VPN(id: config.id, name: "Office", kind: .l2tp, server: config.server)
        entry.native = config
        snapshot.vpns = [entry]
        let doc = ConfigDocument.build(from: snapshot)
        #expect(doc.root[ConfigDocumentKeys.format]?.intValue == ConfigFormat.ownedL2TPVersion)
        #expect(ConfigImport.plan(root: doc.root, current: ConfigSnapshot()).vpns.first?.vpn.native?.ownedIPsec?.usesL2TP == true)
        config.server = "gateway.example.test"
        #expect(config.ownedIPsec == nil)
        for input in ["", "é", "bad\n", String(repeating: "x", count: 256)] {
            #expect(!OwnedIPsecConfiguration.validPPPCredential(input))
        }
    }

    @Test func migratedIPsecPreservesExactAuthenticationAndFailsClosed() throws {
        var profile = NativeVPNConfig()
        profile.server = "vpn.example.test"
        profile.usesSharedSecret = true
        profile.username = "workstation"
        let v2 = try #require(profile.ownedIPsec)
        #expect(v2.remoteID == profile.server)
        #expect(v2.localID == "workstation")
        #expect(v2.adapterID == "ikev2-strongswan")
        profile.ikeIntegrity = "sha256"
        #expect(profile.ownedIPsec == nil)
        profile.ikeIntegrity = ""
        profile.kind = .ipsec
        profile.groupOrRealm = "office"
        #expect(profile.ownedIPsec == nil)
        profile.remoteID = "%any"
        #expect(profile.ownedIPsec == nil)
        profile.remoteID = "gateway"
        let v1 = try #require(profile.ownedIPsec)
        #expect(v1.usesXAuth && v1.username == "workstation" && v1.localID == "office")
        profile.xauth = false
        #expect(profile.ownedIPsec?.username == nil)
        let conf: [String: Any] = ["profile":profile.id, "vpnType":OwnedIPsecConfiguration.providerKind,
                                   "ownedIPsec":try JSONEncoder().encode(v1)]
        #expect(OwnedIPsecConfiguration.decode(from: conf) == v1)
        #expect(OwnedIPsecConfiguration.decode(from: conf.merging(["profile":"other"]) { _, next in next }) == nil)
        profile.kind = .ikev2
        profile.usesSharedSecret = false
        #expect(profile.ownedIPsec == nil)
        profile.eapMSCHAPv2 = true
        #expect(profile.ownedIPsec?.usesEAP == true)
        #expect(profile.ownedIPsec?.username == "workstation")
        profile.kind = .l2tp
        #expect(profile.ownedIPsec == nil)
    }

    @Test func nativePolicySurvivesRestartAndIsUnavailableToOlderReaders() throws {
        let suite = "ProtectedNativeTest." + UUID().uuidString
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let manager = NativeVPNManager(defaults: defaults, observeSystem: false)
        var profile = NativeVPNConfig()
        profile.routingEventSource = rule
        manager.save(profile)
        profile.routingEventSource = nil
        manager.save(profile)
        #expect(NativeVPNManager(defaults: defaults, observeSystem: false).configs.first?.routingEventSource == rule)
        let ordinary = try #require(defaults.data(forKey: "nativeVPNs.v1"))
        #expect(try JSONDecoder().decode([NativeVPNConfig].self, from: ordinary).isEmpty)
    }

    @Test func protectedTunnelIsAbsentFromOlderReadersAndSurvivesStaleDraftSaves() throws {
        let suite = "ProfilePacketPolicyTests." + UUID().uuidString
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = SubprocessTunnelStore(defaults: defaults)
        var tunnel = SubprocessTunnelConfig()
        tunnel.kind = .fortinet
        tunnel.name = "Office"
        #expect(store.save(tunnel))
        #expect(store.setPacketPolicy(rule, for: tunnel.id))
        tunnel.name = "Changed in an older window"
        #expect(store.save(tunnel))
        let oldData = try #require(defaults.data(forKey: "subprocessTunnels.v1"))
        #expect(try JSONDecoder().decode([SubprocessTunnelConfig].self, from: oldData).isEmpty)
        let loaded = SubprocessTunnelStore(defaults: defaults)
        #expect(loaded.tunnels.first?.routingEventSource == rule)
        #expect(loaded.tunnels.first?.name == tunnel.name)
        #expect(loaded.setPacketPolicy(nil, for: tunnel.id))
        #expect(SubprocessTunnelStore(defaults: defaults).tunnels.map(\.id) == [tunnel.id])
    }

    @Test func anOpenConnectMirrorHasOneSelectableOwner() {
        var tunnel = SubprocessTunnelConfig()
        tunnel.kind = .fortinet
        let mirror = ConnectListing.Profile(id: tunnel.id, kind: .fortinet)
        #expect(ConnectListing.soleTag(profiles: [mirror], tunnels: [tunnel], native: []) == ConnectListing.tag(forTunnel: tunnel.id))
        #expect(ConnectListing.soleTag(profiles: [mirror], tunnels: [], native: []) == mirror.id)
    }

    @Test func bridgeActivationRequiresTheOwnedPolicyAndNeverStripsAnExistingOne() throws {
        var config = SubprocessTunnelConfig()
        config.kind = .fortinet
        config.server = "vpn.example.test"
        config.proxyMode = .none
        config.routingEventSource = rule
        let mirror = try OpenConnectProfileStore.configurationForStart(config, previous: nil)
        #expect(try StandalonePacketPolicyConfiguration.source(in: mirror) == rule)
        config.routingEventSource = nil
        #expect(throws: (any Error).self) { try OpenConnectProfileStore.configurationForStart(config, previous: mirror) }
        var malformed = mirror
        malformed.removeValue(forKey: StandalonePacketPolicyConfiguration.sourceKey)
        #expect(throws: (any Error).self) { try OpenConnectProfileStore.configurationForStart(config, previous: malformed) }
        let plain = try OpenConnectProfileStore.configurationForStart(config, previous: nil)
        #expect(plain["routingSession"] == nil)
        #expect(plain[StandalonePacketPolicyConfiguration.sourceKey] == nil)
    }

    @Test func protectedSSHRequiresTheActualEmbeddedEngine() {
        var config = SubprocessTunnelConfig()
        config.kind = .ssh
        config.sshMode = .socks
        config.preferInProcess = true
        #expect(ProfilePacketPolicy.adapter(for: config) == "ssh-libssh")
        config.useJumpHost = true
        config.jumpHost = "jump.example.test"
        #expect(ProfilePacketPolicy.adapter(for: config) == "ssh-openssh")
        config.useJumpHost = false
        config.sshMode = .netTunnel
        #expect(ProfilePacketPolicy.adapter(for: config) == nil)
    }

    @Test func managedOpenSSHSelectsOnlyOwnedChannelEventsAndExplicitOptions() {
        var config = SubprocessTunnelConfig()
        config.kind = .ssh
        config.sshMode = .portForward
        config.forwards = ["R [::1]:8080:[::1]:8081"]
        #expect(ProfilePacketPolicy.adapter(for: config) == OpenSSHReverseDelivery.adapter)
        #expect(OpenSSHReverseDelivery.mappings(for: config)?.first?.remote == "[::1]:8080")
        config.sshExtraOptions = ["ForwardAgent yes"]
        #expect(ProfilePacketPolicy.adapter(for: config) == nil)
        config.sshExtraOptions = []
        config.forwards.append("L 9002:localhost:8000")
        #expect(ProfilePacketPolicy.adapter(for: config) == "ssh-openssh")
        config.forwards = ["R 0:localhost:8000"]
        #expect(ProfilePacketPolicy.adapter(for: config) == nil)
    }

    @Test func settingsFileRoundTripsRequiredSourceAndDowngradesAreRejected() {
        var profile = ConfigSnapshot.VPN(id: "sample", name: "Sample", kind: .wireGuard, server: "")
        profile.wireGuard = WireGuardConfig()
        var snapshot = ConfigSnapshot()
        snapshot.vpns = [profile]
        #expect(ConfigDocument.build(from: snapshot).root[ConfigDocumentKeys.format]?.intValue == 1)
        profile.routingEventSource = rule
        snapshot.vpns = [profile]
        for format in [ConfigFileFormat.json, .yaml] {
            let text = ConfigDocument.text(from: snapshot, format: format)
            let plan = ConfigImport.plan(text: text, current: ConfigSnapshot())
            #expect(plan.refusals.isEmpty)
            #expect(plan.formatVersion == 2)
            #expect(plan.vpns.first?.vpn.requiredPacketPolicy == rule)
        }
        var root = ConfigDocument.build(from: snapshot).root
        root.put(ConfigDocumentKeys.format, .int(1))
        #expect(ConfigImport.plan(root: root, current: ConfigSnapshot()).vpns.isEmpty)
    }

    @Test func unsupportedProfilesCannotImportRequiredRules() {
        for kind: VPNKind in [.ikev2, .ipsec, .l2tp, .ssh] {
            var entry = ConfigSnapshot.VPN(id: "sample", name: "VPN", kind: kind, server: "example.test")
            if kind.isSingletonNative {
                var config = NativeVPNConfig()
                config.kind = kind
                entry.native = config
            } else {
                var config = SubprocessTunnelConfig()
                config.kind = kind
                config.preferInProcess = false
                if kind == .ssh { config.sshMode = .netTunnel }
                entry.subprocess = config
            }
            entry.routingEventSource = rule
            var snapshot = ConfigSnapshot()
            snapshot.vpns = [entry]
            let result = ConfigImport.plan(root: ConfigDocument.build(from: snapshot).root, current: ConfigSnapshot())
            #expect(result.vpns.isEmpty)
            #expect(!result.refusals.isEmpty)
        }
    }
}
