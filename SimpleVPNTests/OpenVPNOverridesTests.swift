// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OpenVPNOverridesTests.swift
//  Pins the round-trip invariant: nil = "engine default" is never serialized,
//  decoding is lenient across app↔extension version skew, and normalization
//  collapses default-equal values back to nil.
//

import Foundation
import Testing
@testable import SimpleVPN

struct OpenVPNOverridesTests {

    private func roundTrip(_ o: OpenVPNOverrides) throws -> OpenVPNOverrides {
        try JSONDecoder().decode(OpenVPNOverrides.self, from: JSONEncoder().encode(o))
    }

    private func encodedKeys(_ o: OpenVPNOverrides) throws -> Set<String> {
        let obj = try JSONSerialization.jsonObject(with: JSONEncoder().encode(o)) as! [String: Any]
        return Set(obj.keys)
    }

    // MARK: Round-tripping

    @Test func allNilRoundTripsToAllNil() throws {
        let empty = OpenVPNOverrides()
        #expect(try roundTrip(empty) == empty)
        #expect(empty.isEmpty)
        // Only the schema marker is ever written for an untouched model.
        #expect(try encodedKeys(empty) == ["schema"])
    }

    @Test func singleFieldRoundTrips() throws {
        var o = OpenVPNOverrides()
        o.compression = .asym
        let back = try roundTrip(o)
        #expect(back == o)
        #expect(back.compression == .asym)
        #expect(try encodedKeys(o) == ["schema", "compression"])
    }

    @Test func fullyPopulatedRoundTrips() throws {
        var o = OpenVPNOverrides()
        o.server = "vpn.example.org"; o.port = 1194; o.proto = .adaptive
        o.ipVersion = .v6; o.connTimeout = 30
        o.tunPersist = true; o.retryOnAuthFailed = true; o.autologinSessions = false
        o.allowLocalLanAccess = true; o.allowUnusedAddrFamilies = .block; o.googleDnsFallback = true
        o.tlsVersionMin = .tls1_3; o.tlsCertProfile = .preferredDefault; o.compression = .yes
        o.enableLegacyAlgorithms = true; o.enableNonPreferredDCAlgorithms = true
        o.tlsCipherList = "A:B"; o.tlsCiphersuitesList = "C:D"
        o.disableClientCert = true; o.defaultKeyDirection = 1
        o.proxyHost = "proxy.local"; o.proxyPort = 8080; o.proxyUsername = "u"; o.proxyAllowCleartextAuth = true
        o.sslDebugLevel = 3; o.synchronousDnsLookup = true
        #expect(try roundTrip(o) == o)
        #expect(!o.isEmpty)
    }

    @Test func rawValuesMatchEngineTokens() {
        // Bridging is .rawValue — these strings are the ClientAPI::Config contract.
        #expect(OpenVPNOverrides.TransportProto.adaptive.rawValue == "adaptive")
        #expect(OpenVPNOverrides.TLSVersionMin.tls1_2.rawValue == "tls_1_2")
        #expect(OpenVPNOverrides.TLSCertProfile.legacyDefault.rawValue == "legacy-default")
        #expect(OpenVPNOverrides.AddrFamilyPolicy.allow.rawValue == "yes")
        #expect(OpenVPNOverrides.AddrFamilyPolicy.block.rawValue == "no")
        #expect(OpenVPNOverrides.IPVersion.v4.rawValue == 4)
        #expect(OpenVPNOverrides.Compression.asym.rawValue == "asym")
    }

    // MARK: Lenient decoding (version skew)

    @Test func unknownKeysAreIgnored() throws {
        let json = #"{"schema":1,"compression":"asym","someFutureSetting":true}"#
        let o = try JSONDecoder().decode(OpenVPNOverrides.self, from: Data(json.utf8))
        #expect(o.compression == .asym)
    }

    @Test func unknownEnumValueDegradesToNilWithoutNukingSiblings() throws {
        // A newer app wrote "tls_1_4"; this (older) decoder must keep the rest.
        let json = #"{"schema":1,"tlsVersionMin":"tls_1_4","tunPersist":true}"#
        let o = try JSONDecoder().decode(OpenVPNOverrides.self, from: Data(json.utf8))
        #expect(o.tlsVersionMin == nil)
        #expect(o.tunPersist == true)
    }

    @Test func wrongTypeDegradesToNil() throws {
        let json = #"{"schema":1,"port":"not-a-number","proto":"udp"}"#
        let o = try JSONDecoder().decode(OpenVPNOverrides.self, from: Data(json.utf8))
        #expect(o.port == nil)
        #expect(o.proto == .udp)
    }

    @Test func newerSchemaStillDecodes() throws {
        let json = #"{"schema":99,"compression":"no"}"#
        let o = try JSONDecoder().decode(OpenVPNOverrides.self, from: Data(json.utf8))
        #expect(o.schema == 99)
        #expect(o.compression == OpenVPNOverrides.Compression.no)
    }

    @Test func emptyObjectDecodesToEmptyOverrides() throws {
        let o = try JSONDecoder().decode(OpenVPNOverrides.self, from: Data("{}".utf8))
        #expect(o.isEmpty)
    }

    // MARK: providerConfiguration blob helpers (migration path)

    @Test func absentBlobDecodesToEmpty() {
        #expect(OpenVPNOverrides.decode(from: nil).isEmpty)
    }

    @Test func corruptBlobDegradesToEmpty() {
        #expect(OpenVPNOverrides.decode(from: Data("not json".utf8)).isEmpty)
    }

    @Test func emptyOverridesEncodeToNoBlob() {
        #expect(OpenVPNOverrides().encodedBlob() == nil)
    }

    // MARK: Normalization

    @Test func defaultEqualValuesNormalizeToNil() {
        var o = OpenVPNOverrides()
        o.tunPersist = false             // == engine default
        o.autologinSessions = true       // == engine default (the true-by-default one)
        o.connTimeout = 0                // == engine default
        o.sslDebugLevel = 0              // == engine default
        o.defaultKeyDirection = -1       // == engine default
        #expect(o.normalized().isEmpty)
    }

    @Test func nonDefaultValuesSurviveNormalization() {
        var o = OpenVPNOverrides()
        o.tunPersist = true
        o.autologinSessions = false
        let n = o.normalized()
        #expect(n.tunPersist == true)
        #expect(n.autologinSessions == false)
    }

    @Test func nilAutologinSessionsNeverEmitsKey() throws {
        // The engine default is true; an absent key must stay absent so the engine
        // keeps deciding. (apply-only-non-nil on the bridge side is the other half.)
        var o = OpenVPNOverrides()
        o.tunPersist = true
        let keys = try encodedKeys(o)
        #expect(!keys.contains("autologinSessions"))
    }

    @Test func emptyAndPaddedStringsNormalizeToNil() {
        var o = OpenVPNOverrides()
        o.server = "   "
        o.tlsCipherList = ""
        o.proxyHost = "\n"
        #expect(o.normalized().isEmpty)
    }

    @Test func outOfRangeValuesNormalizeToNil() {
        var o = OpenVPNOverrides()
        o.port = 0
        o.proxyPort = 70_000
        o.sslDebugLevel = 42
        o.defaultKeyDirection = 5
        #expect(o.normalized().isEmpty)
    }

    @Test func proxySubSettingsDropWithoutHost() {
        var o = OpenVPNOverrides()
        o.proxyPort = 8080
        o.proxyUsername = "u"
        o.proxyAllowCleartextAuth = true
        #expect(o.normalized().isEmpty)
    }

    @Test func normalizationStampsCurrentSchema() {
        var o = OpenVPNOverrides()
        o.schema = 0
        o.proto = .tcp
        #expect(o.normalized().schema == OpenVPNOverrides.currentSchema)
    }
}
