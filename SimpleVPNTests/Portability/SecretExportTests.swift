// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Security
import Testing
@testable import SimpleVPN

@MainActor
struct SecretExportTests {
    @Test func protectedProfileAndDeletedProfileSuppressOrdinaryCredentialWrites() throws {
        let vpn = VPNController(), id = UUID().uuidString
        defer { KeychainCredentialStore.deleteCredentials(profile: id) }
        var auth = VPNAuthConfig()
        auth.protectWithBiometrics = true
        vpn.authConfigs[id] = auth
        vpn.transientCreds[id] = .init(username: "alex", password: "fixture")
        #expect(!vpn.canReconnectUnattended(id: id))
        try vpn.saveOrdinarySignIn(id: id, username: "alex", password: "fixture")
        #expect(KeychainCredentialStore.loadCredentials(profile: id) == nil)
        vpn.authConfigs[id] = nil
        vpn.locallyRemovedProfileIDs.insert(id)
        try vpn.saveOrdinarySignIn(id: id, username: "alex", password: "fixture")
        #expect(KeychainCredentialStore.loadCredentials(profile: id) == nil)
    }

    @Test func deletingAProfileErasesImportedRolesAcrossEngines() throws {
        let id = UUID().uuidString, sibling = UUID().uuidString
        let ssh = VPNController.sshNetKeyProfile(id)
        defer {
            ConfigSecretTransfer.deleteAll(id: id)
            ConfigSecretTransfer.deleteAll(id: sibling)
        }
        try KeychainCredentialStore.saveCredentials(profile: ssh, .init(username: "alex", password: "fixture"))
        try KeychainCredentialStore.saveCustomRoutingProxyAuth(profile: id, .init(username: "alex", password: "fixture"))
        try KeychainCredentialStore.saveCredentials(profile: sibling, .init(username: "alex", password: "sibling"))
        ConfigSecretTransfer.deleteAll(id: id)
        #expect(try KeychainCredentialStore.credentialsForExport(profile: ssh) == nil)
        #expect(try KeychainCredentialStore.routingProxyAuthForExport(profile: id) == nil)
        #expect(try KeychainCredentialStore.credentialsForExport(profile: sibling)?.password == "sibling")
    }

    @Test func importRetainsProtectionWhenThePreferenceAndSecretRoleDisagree() throws {
        var values = ConfigMap()
        values.put("username", .string("alex"))
        values.put("password", .string("ordinary fixture"))
        values.put("privateKeyPassword", .string("separate engine fixture"))
        var secrets = ConfigMap()
        secrets.put("credentials", .map(values))
        var entry = ConfigSnapshot.VPN(id: "test", name: "Example", kind: .openVPN, server: "vpn.example")
        entry.ovpn = "client\nremote vpn.example 1194\n"
        var auth = VPNAuthConfig()
        auth.protectWithBiometrics = true
        entry.auth = auth
        func planned(_ input: ConfigSnapshot.VPN) throws -> ConfigSnapshot.VPN {
            var snapshot = ConfigSnapshot()
            snapshot.vpns = [input]
            let text = ConfigDocument.text(from: snapshot, format: .json, secretMode: .include)
            return try #require(ConfigImport.plan(text: text, current: ConfigSnapshot()).vpns.first?.vpn)
        }
        entry.secrets = secrets
        let converted = try planned(entry)
        #expect(converted.secrets["credentials"] == nil)
        #expect(converted.secrets["protected"]?.mapValue?["password"]?.stringValue == "ordinary fixture")
        #expect(converted.secrets["profile-secrets"]?.mapValue?["privateKeyPassword"]?.stringValue == "separate engine fixture")

        entry.auth = nil
        values["privateKeyPassword"] = nil
        values.put("password", .string("protected fixture"))
        secrets.put("protected", .map(values))
        entry.secrets = secrets
        let restored = try planned(entry)
        #expect(restored.auth?.protectWithBiometrics == true)
        #expect(restored.auth?.rememberCredentials == true)
        #expect(restored.secrets["credentials"] == nil)
        #expect(restored.secrets["protected"]?.mapValue?["password"]?.stringValue == "protected fixture")
    }

    @Test func portableSecretsKeepKeyTerminatorsAndWireGuardPeerNames() throws {
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture  \n-----END OPENSSH PRIVATE KEY-----\n"
        let peerName = Data(repeating: 251, count: 32).base64EncodedString()
        let nested = ConfigJSON.value([peerName: key])
        var doc = ConfigMap()
        doc.put("wireguard-peers", nested)
        for back in [try ConfigJSON.decode(ConfigJSON.encode(doc)), try ConfigYAML.decode(ConfigYAML.encode(doc))] {
            #expect(back["wireguard-peers"]?.mapValue?[peerName]?.stringValue == key)
        }
    }

    @Test func placeholdersAndUnrelatedEngineSecretsStayOutsideTheExportSnapshot() async throws {
        let id = UUID().uuidString
        defer { ConfigSecretTransfer.deleteAll(id: id) }
        try KeychainCredentialStore.saveSSHPrivateKey(profile: id, pem: "private fixture")
        try KeychainCredentialStore.saveCredentials(profile: VPNController.tailscaleNodeStateProfile(id),
            .init(username: "state", password: #"{"other":"YQ=="}"#))
        let ssh = try await ConfigSecretTransfer.collect(id: id, kind: .ssh, mode: .include)
        #expect(ssh["tailscale-state"] == nil)
        #expect(ssh["ssh-key"]?.mapValue?["password"]?.stringValue == "private fixture")
        let redacted = try await ConfigSecretTransfer.collect(id: id, kind: .ssh, mode: .placeholders)
        #expect(!ConfigJSON.encode(redacted).contains("private fixture"))
        #expect(throws: (any Error).self) { try ConfigSecretTransfer.validated(ssh, kind: .tailscale) }
    }

    @Test(arguments: [ConfigFileFormat.yaml, .json])
    func externalSignInRetainsPasswordFieldIdentifier(_ format: ConfigFileFormat) throws {
        var entry = ConfigSnapshot.VPN(id: "test", name: "VPN", kind: .openVPN, server: "vpn.example")
        entry.ovpn = "client\nremote vpn.example 1194"
        var source = CredentialSource()
        source.kind = .onePassword
        source.reference = "fixture-item-id"
        source.accountReference = "fixture-account-id"
        source.vault = "fixture-vault-id"
        source.fieldMap = ["password": "fixture-field-id", "otp": "fixture-otp-id"]
        entry.credentialSource = source
        var input = ConfigSnapshot()
        input.vpns = [entry]
        let text = ConfigDocument.text(from: input, format: format)
        let imported = try #require(ConfigImport.plan(text: text, current: ConfigSnapshot()).vpns.first?.vpn)
        #expect(imported.credentialSource == source)
    }

    @Test func exportedProxyAndEndpointAddressesCannotCarryEmbeddedPasswords() throws {
        let embedded = "http://alex:fixture-password@vpn.example"
        var entry = ConfigSnapshot.VPN(id: "test", name: "VPN", kind: .openVPN, server: "vpn.example")
        entry.ovpn = "client\nremote vpn.example 1194"
        var routing = CustomRoutingProfile()
        routing.proxy.mode = .custom
        routing.proxy.manualURL = embedded
        entry.customRouting = routing
        entry.endpoints = .init(endpoints: [.init(host: embedded), .init(host: "safe.example")])
        var input = ConfigSnapshot()
        input.vpns = [entry]
        let text = ConfigDocument.text(from: input, format: .yaml)
        #expect(!text.contains("fixture-password"))
        let plan = ConfigImport.plan(text: text, current: ConfigSnapshot())
        let imported = try #require(plan.vpns.first?.vpn)
        #expect(imported.endpoints?.endpoints.map(\.host) == ["safe.example"])
        #expect(imported.customRouting?.proxy.manualURL == nil)
    }

    private func snapshot() -> ConfigSnapshot {
        var snapshot = ConfigSnapshot()
        var vpn = ConfigSnapshot.VPN(id: "test", name: "SSH", kind: .ssh, server: "example.com")
        var config = SubprocessTunnelConfig()
        config.kind = .ssh
        config.sshAuthMethod = "keychain"
        vpn.subprocess = config
        var key = ConfigMap()
        key.put("username", .string("ssh"))
        key.put("password", .document("-----BEGIN PRIVATE KEY-----\nEXPORT_CANARY\n-----END PRIVATE KEY-----"))
        vpn.secrets.put("ssh-key", .map(key))
        snapshot.vpns = [vpn]
        return snapshot
    }

    @Test(arguments: [ConfigFileFormat.yaml, .json])
    func placeholderExportCannotBecomeAPassword(_ format: ConfigFileFormat) throws {
        let text = ConfigDocument.text(from: snapshot(), format: format, secretMode: .placeholders)
        #expect(!text.contains("EXPORT_CANARY"))
        #expect(text.contains("placeholder"))
        let plan = ConfigImport.plan(text: text, current: ConfigSnapshot())
        #expect(plan.fatal.isEmpty)
        let vpn = try #require(plan.vpns.first?.vpn)
        #expect(vpn.secrets.isEmpty)
        #expect(vpn.subprocess?.sshAuthMethod == "keychain")
    }

    @Test(arguments: [ConfigFileFormat.yaml, .json])
    func optedInSecretsRoundTripWithoutAppearingInTheDiff(_ format: ConfigFileFormat) throws {
        let text = ConfigDocument.text(from: snapshot(), format: format, secretMode: .include)
        #expect(text.contains("CONTAINS SECRETS"))
        #expect(text.contains("EXPORT_CANARY"))
        let plan = ConfigImport.plan(text: text, current: ConfigSnapshot())
        let planned = try #require(plan.vpns.first)
        #expect(planned.vpn.secrets["ssh-key"]?.mapValue?["password"]?.stringValue?.contains("EXPORT_CANARY") == true)
        #expect(!planned.securityNotes.joined().contains("EXPORT_CANARY"))
        #expect(planned.securityNotes.joined().contains("Keychain"))
    }

    @Test func recoveryDefaultOmitsTheSecretSection() {
        let text = ConfigDocument.text(from: snapshot(), format: .yaml)
        #expect(!text.contains("EXPORT_CANARY"))
        #expect(!text.contains("ssh-key:"))
    }

    @Test func unknownAccountsAndMalformedSecretRecordsAreRefused() {
        var credentials = ConfigMap()
        credentials.put("username", .string("ssh"))
        credentials.put("password", .int(123))
        var secrets = ConfigMap()
        secrets.put("ssh-key", .map(credentials))
        #expect(throws: (any Error).self) { try ConfigSecretTransfer.validated(secrets, kind: .ssh) }
        secrets = ConfigMap()
        secrets.put("arbitrary-user-keychain-account", .map(ConfigMap()))
        #expect(throws: (any Error).self) { try ConfigSecretTransfer.validated(secrets, kind: .ssh) }
    }

    @Test func secretExportIsPrivateWhenCreatedAndWhenReplacingAFile() throws {
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: url) }
        try "old".write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
        try ConfigSecretTransfer.write("EXPORT_CANARY", to: url)
        let permissions = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber
        #expect(permissions?.intValue == 0o600)
        #expect(try String(contentsOf: url, encoding: .utf8) == "EXPORT_CANARY")
    }

    @Test func importedKeysAreStoredUnderTheNewProfileIdentity() async throws {
        let originalID = "secret-export-test-\(UUID().uuidString)"
        let importedID = "secret-import-test-\(UUID().uuidString)"
        defer {
            KeychainCredentialStore.deleteCredentials(profile: "tunnel.\(originalID).sshKey")
            KeychainCredentialStore.deleteCredentials(profile: "tunnel.\(importedID).sshKey")
        }
        try KeychainCredentialStore.saveSSHPrivateKey(profile: originalID, pem: "TEST_ONLY_PEM_CANARY")
        var config = SubprocessTunnelConfig()
        config.id = originalID
        config.kind = .ssh
        config.sshAuthMethod = "keychain"
        config.sshAgentSocket = "unused/relative/socket"
        #expect(SubprocessTunnelManager.sshAuthBlockReason(config) == nil)
        let collected = try await ConfigSecretTransfer.collect(id: originalID, kind: .ssh, mode: .include)
        var export = snapshot()
        export.vpns[0].secrets = collected
        #expect(ConfigDocument.text(from: export, format: .yaml, secretMode: .include).contains("TEST_ONLY_PEM_CANARY"))
        #expect(!ConfigDocument.text(from: export, format: .yaml, secretMode: .placeholders).contains("TEST_ONLY_PEM_CANARY"))
        try ConfigSecretTransfer.save(collected, id: importedID, kind: .ssh)
        #expect(KeychainCredentialStore.loadSSHPrivateKey(profile: originalID) == "TEST_ONLY_PEM_CANARY")
        #expect(KeychainCredentialStore.loadSSHPrivateKey(profile: importedID) == "TEST_ONLY_PEM_CANARY")
    }

    @Test func corruptKeychainRecordsStopExportWithoutQuotingTheirContents() throws {
        let account = "malformed-export-test-\(UUID().uuidString)"
        defer { KeychainCredentialStore.deleteCredentials(profile: account) }
        let status = SecItemAdd([kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.bragi0.SimpleVPN.creds", kSecAttrAccount as String: account,
            kSecValueData as String: Data("MALFORMED_CANARY".utf8)] as CFDictionary, nil)
        #expect(status == errSecSuccess)
        do {
            _ = try KeychainCredentialStore.credentialsForExport(profile: account)
            Issue.record("A corrupt credential was accepted for export")
        } catch {
            #expect(!error.localizedDescription.contains("MALFORMED_CANARY"))
        }
    }

    @Test func replacingNativeSecretsPreservesTheirPersistentReference() throws {
        let account = "native-ref-test-\(UUID().uuidString)"
        defer { KeychainCredentialStore.deleteNativeSecret(account: account) }
        let before = try KeychainCredentialStore.persistentReference(forSecret: "TEST_ONLY_FIRST", account: account)
        let after = try KeychainCredentialStore.persistentReference(forSecret: "TEST_ONLY_SECOND", account: account)
        #expect(before == after)
        var value: CFTypeRef?
        let status = SecItemCopyMatching([kSecValuePersistentRef as String: before,
            kSecReturnData as String: true] as CFDictionary, &value)
        #expect(status == errSecSuccess)
        #expect((value as? Data).flatMap { String(data: $0, encoding: .utf8) } == "TEST_ONLY_SECOND")
    }

    @Test func additionalWireGuardPeerKeysAreRedactedAndRestoredByPublicKey() {
        var config = WireGuardConfig()
        config.rawExtraPeers = ["[Peer]", "PublicKey = peer-a", "PresharedKey = EXTRA_CANARY_A",
                                "[Peer]", "PublicKey = peer-b", "PresharedKey = EXTRA_CANARY_B"]
        let secrets = config.extraPeerSecrets
        let stored = config.redactedForStorage()
        #expect(!stored.serialize().contains("EXTRA_CANARY"))
        #expect(!config.exportText(includingSecrets: false).contains("EXTRA_CANARY"))
        #expect(config.exportText(includingSecrets: true).contains("EXTRA_CANARY"))
        #expect(stored.replacingExtraPeerSecrets(secrets, redact: false).extraPeerSecrets == secrets)
        var snapshot = ConfigSnapshot()
        var vpn = ConfigSnapshot.VPN(id: "wg", name: "WG", kind: .wireGuard, server: "")
        vpn.wireGuard = config
        snapshot.vpns = [vpn]
        #expect(!ConfigDocument.text(from: snapshot, format: .yaml).contains("EXTRA_CANARY"))
        #expect(!ConfigDocument.text(from: snapshot, format: .json).contains("EXTRA_CANARY"))
    }

    @Test func keychainAuthenticationUsesOnlyTheStoredKey() throws {
        var config = SSHTunnelEngine.Config(host: "example.com", port: 22, username: "user",
            password: "passphrase", identityFile: "~/.ssh/other", privateKeyPEM: "key", socksPort: 1080,
            authMethod: "keychain")
        #expect(try SSHTunnelEngine.authPlan(config) == [.storedKey])
        config.privateKeyPEM = nil
        #expect(throws: (any Error).self) { try SSHTunnelEngine.authPlan(config) }
    }

    @Test func aStoppedSSHConnectCannotPublishLateState() async throws {
        let engine = SSHTunnelEngine()
        let config = SSHTunnelEngine.Config(host: "127.0.0.1", port: 1, username: "unused",
            password: nil, identityFile: nil, socksPort: 1080, connectTimeout: 1)
        let connecting = Task.detached { try? await engine.startSOCKS(config) }
        engine.stop()
        await connecting.value
        try await Task.sleep(for: .milliseconds(20)) // Drain queued main-thread publications.
        #expect(engine.state == .idle)
    }

    @Test func keychainKeyHasTheSameProbeAvailabilityAsAFileKey() throws {
        var facts = ProbeTargetFacts()
        facts.kind = .ssh
        facts.clientKeyPEM = "PRIVATE_KEY_CANARY"
        let step = try #require(ProbeLadderPlan.steps(for: facts).first { $0.stage == .sshPublicKey })
        #expect(step.preset == nil)
        #expect(!step.requiresAccountCredentials)
    }

    @Test func localForwardDefaultsToLoopbackAndPreservesExplicitIPv6Bind() throws {
        let normal = try #require(SSHTunnelEngine.localForwardParts("8080:internal:80"))
        #expect(normal.3 == "127.0.0.1")
        let ipv6 = try #require(SSHTunnelEngine.localForwardParts("[::1]:8080:[2001:db8::1]:80"))
        #expect(ipv6.0 == 8080)
        #expect(ipv6.1 == "2001:db8::1")
        #expect(ipv6.3 == "::1")
    }

    @Test func parsersHandleCommentsCRLFAndRejectTruncatedXML() throws {
        let hosts = SSHConfigImport.parse("Host lab # comment\n HostName \"vpn.example.com\" # server\n Port 2222 # listener\n IdentityFile \"~/.ssh/a# b\" # key\n")
        let host = try #require(hosts.first)
        #expect(host.alias == "lab")
        #expect(host.effectiveHostName == "vpn.example.com")
        #expect(host.port == 2222)
        #expect(host.identityFiles == ["~/.ssh/a# b"])
        #expect(hosts.count == 1)
        let config = WireGuardConfig.parse("[Interface]\r\nAddress = 10.0.0.2/32 # address\r\nDNS = 1.1.1.1\r\n[Peer]\r\nAllowedIPs = 10.0.0.0/8\r\n", name: "WG")
        #expect(config.addresses == ["10.0.0.2/32"])
        #expect(config.dns == ["1.1.1.1"])
        #expect(config.allowedIPs == ["10.0.0.0/8"])
        let xml = "<AnyConnectProfile><ServerList><HostEntry><HostName>VPN</HostName><HostAddress>vpn.example.com</HostAddress></HostEntry></ServerList>"
        #expect(CiscoImport.parseAnyConnectXML(xml).isEmpty)
    }

    @Test func nativeProfilesDecodeBeforeTheNewIKEOptionsExisted() throws {
        let data = Data(#"{"id":"old","name":"VPN","kind":"ikev2","server":"vpn.example.com","remoteID":"vpn.example.com","username":"user","usesSharedSecret":false,"groupOrRealm":"","onDemand":false}"#.utf8)
        let config = try JSONDecoder().decode(NativeVPNConfig.self, from: data)
        #expect(config.id == "old")
        #expect(config.ikeEncryption.isEmpty)
        #expect(config.excludeLocalNetworks)
    }

    @Test func verificationBypassesWithSSHWhitespaceAreRefused() {
        for option in ["StrictHostKeyChecking = no", "StrictHostKeyChecking\tno", "UserKnownHostsFile /dev/null"] {
            var settings = ConfigMap()
            settings.put("ssh.extra-options", .strings([option]))
            #expect(ConfigImportGuard.refusal(in: settings, ovpn: nil) != nil)
        }
    }

    @Test func untrustedLargeAndNonfiniteNumbersCannotTrapIntegerConversion() {
        for value in [Double.greatestFiniteMagnitude, .infinity, -.infinity, .nan, Double(Int.max), 1.5] {
            #expect(ConfigValue.double(value).intValue == nil)
        }
        #expect(ConfigValue.double(42).intValue == 42)
        #expect(ConfigValue.double(Double(Int.min)).intValue == Int.min)
        #expect(!ConfigImport.plan(text: #"{"format":1e300}"#, current: ConfigSnapshot()).fatal.isEmpty)
    }
}

@MainActor struct TailscaleIdentityExportTests {
    @Test func nodeIdentityUsesTheClosedRoleAndRestoresIntoTheUsersKeychain() async throws {
        let source=UUID().uuidString, destination=UUID().uuidString
        let state="{\"node-key\":\"VEVTVF9OT0RFX0tFWQ==\"}"
        defer {
            KeychainCredentialStore.deleteCredentials(profile:VPNController.tailscaleNodeStateProfile(source))
            KeychainCredentialStore.deleteCredentials(profile:VPNController.tailscaleNodeStateProfile(destination))
        }
        try KeychainCredentialStore.saveCredentials(profile:VPNController.tailscaleNodeStateProfile(source),.init(username:"node-state",password:state))
        let collected=try await ConfigSecretTransfer.collect(id:source,kind:.tailscale,mode:.include)
        #expect(collected["tailscale-state"]?.mapValue?["password"]?.stringValue == state)
        try ConfigSecretTransfer.save(collected,id:destination,kind:.tailscale)
        #expect(try KeychainCredentialStore.credentialsForExport(profile:VPNController.tailscaleNodeStateProfile(destination))?.password == state)
        #expect(!ConfigSecretTransfer.placeholders(collected).jsonRepresentation.description.contains("VEVTVF9OT0RFX0tFWQ"))
    }
    @Test func identityAcknowledgementsAndUnchangedRepliesBelongToTheirEngine() throws {
        let one = TailscaleNodeState(revision: 7, data: "{}", generation: UUID())
        let two = TailscaleNodeState(revision: 7, data: "{}", generation: UUID())
        #expect(one.cursor != two.cursor)
        #expect(one.acknowledgement != two.acknowledgement)
        let request = String(decoding: TailscaleNodeState.request(after: one.cursor), as: UTF8.self)
        #expect(request == "tsstate:since:" + one.cursor.wireValue)
        #expect(TailscaleNodeState.Cursor.parse(Substring(one.cursor.wireValue)) == one.cursor)
        let unchanged = Data(("unchanged:" + one.cursor.wireValue).utf8)
        #expect(TailscaleNodeState.decodeReply(unchanged, after: one.cursor) == .unchanged)
        #expect(TailscaleNodeState.decodeReply(unchanged, after: two.cursor) == nil)
        #expect(TailscaleNodeState.decodeReply(unchanged, after: nil) == nil)
        let replacement = try JSONEncoder().encode(two)
        #expect(TailscaleNodeState.decodeReply(replacement, after: one.cursor) == .snapshot(two))
        #expect(TailscaleNodeState.decodeReply(Data("starting".utf8), after: two.cursor) == .starting)
    }

    @Test func legacyIdentityPollUsesFullSnapshotAndDetectsReusedRevisions() throws {
        let bytes = Data(#"{"data":"{}","revision":2}"#.utf8)
        let old = TailscaleNodeState(revision: 2, data: "{}")
        #expect(TailscaleNodeState.decodeReply(bytes, after: nil) == .snapshot(old))
        #expect(TailscaleNodeState.request(after: old.cursor) == Data("tsstate".utf8))
        #expect(old.acknowledgement == Data("tsstate:ack:2".utf8))
        let replacement = TailscaleNodeState(revision: 2, data: #"{"node":"YQ=="}"#)
        #expect(old.cursor != replacement.cursor)
    }
    @Test func malformedNodeStateCannotBeAccepted() {
        #expect(!TailscaleNodeState(revision:1,data:"{\"node-key\":123}").isValid)
        #expect(!TailscaleNodeState(revision:1,data:"{\"node-key\":\"!invalid!\"}").isValid)
        #expect(TailscaleNodeState(revision:1,data:"{}").isValid)
    }
}
