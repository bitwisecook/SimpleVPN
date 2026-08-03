// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  EndpointScannerTests.swift
//  Pins the .ovpn remote-scanning rules: every `remote` found, top-level
//  port/proto defaults applied, comments and inline-block bodies never parsed,
//  duplicates collapsed in first-seen order.
//

import Foundation
import Testing
@testable import SimpleVPN

struct EndpointScannerTests {

    @Test func multipleRemotesParse() {
        let ovpn = """
        client
        remote vpn1.example.org 1194 udp
        remote vpn2.example.org 443 tcp-client
        remote vpn3.example.org
        """
        let endpoints = EndpointScanner.endpoints(in: ovpn)
        #expect(endpoints == [
            Endpoint(host: "vpn1.example.org", port: 1194, proto: "udp"),
            Endpoint(host: "vpn2.example.org", port: 443, proto: "tcp"),
            Endpoint(host: "vpn3.example.org", port: nil, proto: nil),
        ])
    }

    @Test func topLevelPortAndProtoAreDefaults() {
        // Order-independent, exactly like OpenVPN itself.
        let ovpn = """
        remote early.example.org
        port 1197
        proto udp4
        remote late.example.org
        remote explicit.example.org 443 tcp
        """
        let endpoints = EndpointScanner.endpoints(in: ovpn)
        #expect(endpoints == [
            Endpoint(host: "early.example.org", port: 1197, proto: "udp"),
            Endpoint(host: "late.example.org", port: 1197, proto: "udp"),
            Endpoint(host: "explicit.example.org", port: 443, proto: "tcp"),
        ])
    }

    @Test func protoVariantsNormalize() {
        #expect(EndpointScanner.normalizedProto("tcp-client") == "tcp")
        #expect(EndpointScanner.normalizedProto("TCP") == "tcp")
        #expect(EndpointScanner.normalizedProto("udp6") == "udp")
        #expect(EndpointScanner.normalizedProto("weird") == "weird")
    }

    @Test func commentLinesAreSkipped() {
        let ovpn = """
        # remote commented1.example.org 1194 udp
        ; remote commented2.example.org 1194 udp
        remote real.example.org 1194 udp
        """
        let endpoints = EndpointScanner.endpoints(in: ovpn)
        #expect(endpoints == [Endpoint(host: "real.example.org", port: 1194, proto: "udp")])
    }

    @Test func inlineBlockBodiesAreSkipped() {
        // A hostile/degenerate PEM body must never parse as directives.
        let ovpn = """
        remote real.example.org 1194 udp
        <ca>
        remote fake.example.org 9999 tcp
        port 9999
        -----BEGIN CERTIFICATE-----
        AAAA
        -----END CERTIFICATE-----
        </ca>
        <tls-auth>
        remote alsofake.example.org
        </tls-auth>
        remote second.example.org
        """
        let endpoints = EndpointScanner.endpoints(in: ovpn)
        #expect(endpoints == [
            Endpoint(host: "real.example.org", port: 1194, proto: "udp"),
            Endpoint(host: "second.example.org", port: nil, proto: nil),
        ])
    }

    @Test func duplicatesCollapsePreservingOrder() {
        let ovpn = """
        remote a.example.org 1194 udp
        remote b.example.org 1194 udp
        remote a.example.org 1194 udp
        remote a.example.org 443 tcp
        """
        let endpoints = EndpointScanner.endpoints(in: ovpn)
        #expect(endpoints == [
            Endpoint(host: "a.example.org", port: 1194, proto: "udp"),
            Endpoint(host: "b.example.org", port: 1194, proto: "udp"),
            Endpoint(host: "a.example.org", port: 443, proto: "tcp"),
        ])
    }

    @Test func idEncodesHostPortProto() {
        #expect(Endpoint(host: "a", port: 1194, proto: "udp").id == "a:1194:udp")
        #expect(Endpoint(host: "a", port: nil, proto: nil).id == "a:*:*")
    }

    @Test func emptyAndIrrelevantProfilesYieldNothing() {
        #expect(EndpointScanner.endpoints(in: "").isEmpty)
        #expect(EndpointScanner.endpoints(in: "client\ndev tun\nnobind").isEmpty)
    }
}
