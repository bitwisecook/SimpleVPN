// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Testing
@testable import SimpleVPN

@MainActor struct ConfigImportTypeTests {
    private func check<T: Codable>(_ template: T, namespace: String) throws {
        let field = try #require(Mirror(reflecting: template).children.first { Swift.type(of: $0.value) == Bool.self || Swift.type(of: $0.value) == Optional<Bool>.self }?.label)
        var settings = ConfigMap()
        settings.put(ConfigFieldNaming.id(field: field, namespace: namespace), .string("false"))
        #expect(throws: (any Error).self) { try ConfigImport.apply(settings, onto: template, namespace: namespace) }
        settings.put(ConfigFieldNaming.id(field: field, namespace: namespace), .bool(false))
        _ = try ConfigImport.apply(settings, onto: template, namespace: namespace)
    }
    @Test func wrongTypedSettingsCannotDefaultSilentlyInAnyEngine() throws {
        try check(WireGuardConfig(), namespace: "wg.")
        try check(TailscaleConfig(), namespace: "ts.")
        try check(ProxyTunnelConfig(), namespace: "px.")
        try check(SSHNetworkTunnelConfig(), namespace: "sshnet.")
        try check(SubprocessTunnelConfig(), namespace: "ssh.")
        try check(NativeVPNConfig(), namespace: "native.")
        try check(OpenVPNOverrides(), namespace: "openvpn.")
    }
    @Test func listElementsAndNumbersKeepTheirTypes() {
        var settings = ConfigMap()
        settings.put(ConfigFieldNaming.id(field: "allowedIPs", namespace: "wg."), .list([.int(7)]))
        #expect(throws: (any Error).self) { try ConfigImport.apply(settings, onto: WireGuardConfig(), namespace: "wg.") }
        settings = ConfigMap(); settings.put("wg.mtu", .bool(true))
        #expect(throws: (any Error).self) { try ConfigImport.apply(settings, onto: WireGuardConfig(), namespace: "wg.") }
    }
    @Test func unsupportedEnumValuesCannotSilentlyChangeAuthentication() throws {
        var settings = ConfigMap()
        settings.put("sshnet.auth-method", .string("imaginary-sign-in"))
        #expect(throws: (any Error).self) { try ConfigImport.apply(settings, onto: SSHNetworkTunnelConfig(), namespace: "sshnet.") }
        settings.put("sshnet.auth-method", .string("agent"))
        #expect(try ConfigImport.apply(settings, onto: SSHNetworkTunnelConfig(), namespace: "sshnet.").authMethod == .agent)
    }
    @Test func malformedStructuralSectionsCannotDefaultSilently() {
        var fields = ConfigMap()
        fields.put("schema", .string("1"))
        #expect(ConfigImport.decode(CustomRoutingProfile.self, from: fields) == nil)
        fields = ConfigMap(); fields.put("allowPause", .string("false"))
        #expect(ConfigImport.decode(VPNUIPrefs.self, from: fields) == nil)
        var endpoint = ConfigMap()
        endpoint.put("host", .string("vpn.example")); endpoint.put("port", .string("443"))
        fields = ConfigMap(); fields.put("endpoints", .list([.map(endpoint)]))
        #expect(ConfigImport.decode(VPNEndpointList.self, from: fields) == nil)
        endpoint.put("port", .int(443))
        fields.put("endpoints", .list([.map(endpoint)]))
        #expect(ConfigImport.decode(VPNEndpointList.self, from: fields)?.endpoints.first?.port == 443)
    }
}
