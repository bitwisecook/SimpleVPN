// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNEndpointsTests.swift
//  Pins the endpoint blob: round-trips through JSON, decodes leniently (older
//  and hand-mangled blobs must not take the whole list with them), stores only
//  what the user authored, and merges annotations onto the .ovpn's own remotes
//  without ever letting the blob become a second copy of the server list.
//

import Foundation
import Testing
@testable import SimpleVPN

struct VPNEndpointsTests {

    // MARK: Round-trip

    @Test func annotationsRoundTripThroughTheBlob() throws {
        let list = VPNEndpointList(endpoints: [
            VPNEndpoint(host: "lon.example.org", port: 1194, proto: "udp",
                        label: "London", country: "GB"),
            VPNEndpoint(host: "extra.example.org", port: 443, proto: "tcp",
                        label: "Hand-added", region: .oceania, userAdded: true),
        ])
        let blob = try #require(list.encodedBlob())
        let back = VPNEndpointList.decode(from: blob)
        #expect(back == list)
        #expect(back.endpoints[0].country == "GB")
        #expect(back.endpoints[1].region == .oceania)
        #expect(back.endpoints[1].userAdded == true)
    }

    @Test func aPlainServerListIsNotStoredAtAll() {
        // Nothing the user said ⇒ no blob, so a re-import keeps picking up the
        // provider's new servers rather than being shadowed by a stale copy.
        let list = VPNEndpointList(endpoints: [
            VPNEndpoint(host: "a.example.org", port: 1194, proto: "udp"),
            VPNEndpoint(host: "b.example.org"),
        ])
        #expect(list.encodedBlob() == nil)
        #expect(VPNEndpointList.decode(from: nil).endpoints.isEmpty)
    }

    @Test func onlyAnnotatedEntriesArePersisted() throws {
        let list = VPNEndpointList(endpoints: [
            VPNEndpoint(host: "plain.example.org"),
            VPNEndpoint(host: "named.example.org", label: "Named"),
        ])
        let back = VPNEndpointList.decode(from: try #require(list.encodedBlob()))
        #expect(back.endpoints.map(\.host) == ["named.example.org"])
    }

    // MARK: Lenient decoding

    @Test func aBlobFromAnotherBuildStillDecodes() throws {
        // Unknown fields, a port written as a string, an unrecognised region,
        // and a missing host: everything decodable survives, the hostless entry
        // is dropped, and nothing throws.
        let json = """
        {"endpoints":[
          {"host":"a.example.org","port":"1194","proto":"TCP-client","label":"A","future":42},
          {"host":"b.example.org","region":"mars"},
          {"port":443,"label":"no host at all"}
        ],"somethingNew":true}
        """
        let list = VPNEndpointList.decode(from: Data(json.utf8))
        #expect(list.endpoints.count == 2)
        #expect(list.endpoints[0].port == 1194)
        #expect(list.endpoints[0].proto == "tcp")       // normalized on the way in
        #expect(list.endpoints[1].region == nil)        // unknown name ⇒ no override
    }

    @Test func garbageDecodesToNothingRatherThanThrowing() {
        #expect(VPNEndpointList.decode(from: Data("not json".utf8)).endpoints.isEmpty)
        #expect(VPNEndpointList.decode(from: Data()).endpoints.isEmpty)
    }

    @Test func idMatchesTheScannedEndpointID() {
        let scanned = Endpoint(host: "a.example.org", port: 1194, proto: "udp")
        #expect(VPNEndpoint(scanned).id == scanned.id)
        #expect(VPNEndpoint(host: "a").id == "a:*:*")
    }

    // MARK: Merge with the profile's own remotes

    @Test func annotationsAttachToScannedRemotes() {
        let scanned = [
            Endpoint(host: "a.example.org", port: 1194, proto: "udp"),
            Endpoint(host: "b.example.org", port: 443, proto: "tcp"),
        ]
        let stored = VPNEndpointList(endpoints: [
            VPNEndpoint(host: "b.example.org", port: 443, proto: "tcp",
                        label: "Backup", country: "SG"),
        ])
        let merged = VPNEndpointList.merged(scanned: scanned, stored: stored)
        #expect(merged.count == 2)
        #expect(merged[0].label == nil)
        #expect(merged[1].label == "Backup")
        #expect(merged[1].country == "SG")
        // Order follows the profile, which is the order OpenVPN would try.
        #expect(merged.map(\.host) == ["a.example.org", "b.example.org"])
    }

    @Test func userAddedEndpointsSurviveAndAnnotationsForGoneServersDoNot() {
        let scanned = [Endpoint(host: "a.example.org", port: 1194, proto: "udp")]
        let stored = VPNEndpointList(endpoints: [
            VPNEndpoint(host: "gone.example.org", label: "Retired"),
            VPNEndpoint(host: "mine.example.org", port: 8443, label: "Mine", userAdded: true),
        ])
        let merged = VPNEndpointList.merged(scanned: scanned, stored: stored)
        #expect(merged.map(\.host) == ["a.example.org", "mine.example.org"])
        #expect(merged[1].userAdded == true)
    }

    @Test func annotationNeverOverridesTheProfilesAddress() {
        // A stored entry only ever describes; host/port/proto stay the .ovpn's.
        let scanned = [Endpoint(host: "a.example.org", port: 1194, proto: "udp")]
        let stored = VPNEndpointList(endpoints: [
            VPNEndpoint(host: "a.example.org", port: 1194, proto: "udp",
                        label: "A", country: "DE", userAdded: true),
        ])
        let merged = VPNEndpointList.merged(scanned: scanned, stored: stored)
        #expect(merged.count == 1)
        #expect(merged[0].port == 1194)
        #expect(merged[0].proto == "udp")
        #expect(merged[0].userAdded == nil)     // it's the profile's, not theirs
        #expect(merged[0].label == "A")
    }

    @Test func duplicateScannedRemotesCollapse() {
        let scanned = [
            Endpoint(host: "a.example.org", port: 1194, proto: "udp"),
            Endpoint(host: "a.example.org", port: 1194, proto: "udp"),
        ]
        #expect(VPNEndpointList.merged(scanned: scanned, stored: VPNEndpointList()).count == 1)
    }

    @Test func displayLabelFallsBackToTheHost() {
        #expect(VPNEndpoint(host: "a.example.org").displayLabel == "a.example.org")
        #expect(VPNEndpoint(host: "a.example.org", label: "  ").displayLabel == "a.example.org")
        #expect(VPNEndpoint(host: "a.example.org", label: "London").displayLabel == "London")
    }
}
