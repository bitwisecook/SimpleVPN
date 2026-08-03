// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ControlSurfaceTests.swift
//  The control surface's wire format is a PUBLIC CONTRACT (the CLI speaks it,
//  Tcl will speak it) — these tests pin the exact JSON so a refactor can't
//  silently rename a discriminator, plus the MDM guard's veto semantics.
//

import Foundation
import Testing
@testable import SimpleVPN

@Suite struct ControlWireFormatTests {

    private func json<T: Encodable>(_ value: T) throws -> String {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        return String(decoding: try enc.encode(value), as: UTF8.self)
    }

    @Test func commandWireNamesAreStable() throws {
        #expect(try json(ControlCommand.connect(profile: "x")) == #"{"cmd":"connect","profile":"x"}"#)
        #expect(try json(ControlCommand.disconnect(profile: "x")) == #"{"cmd":"disconnect","profile":"x"}"#)
        #expect(try json(ControlCommand.pause(profile: "x")) == #"{"cmd":"pause","profile":"x"}"#)
        #expect(try json(ControlCommand.resume(profile: "x")) == #"{"cmd":"resume","profile":"x"}"#)
        #expect(try json(ControlCommand.setDefaultGateway(profile: "x")) == #"{"cmd":"set-gateway","profile":"x"}"#)
        #expect(try json(ControlCommand.setDefaultGateway(profile: nil)) == #"{"cmd":"set-gateway"}"#)
    }

    @Test func commandsRoundTrip() throws {
        let all: [ControlCommand] = [.connect(profile: "a"), .disconnect(profile: "b"),
                                     .pause(profile: "c"), .resume(profile: "d"),
                                     .setDefaultGateway(profile: "e"), .setDefaultGateway(profile: nil)]
        for cmd in all {
            let data = try JSONEncoder().encode(cmd)
            #expect(try JSONDecoder().decode(ControlCommand.self, from: data) == cmd)
        }
    }

    @Test func unknownCommandIsRejectedNotMisread() {
        let raw = Data(#"{"cmd":"self-destruct","profile":"x"}"#.utf8)
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(ControlCommand.self, from: raw)
        }
    }

    @Test func queriesRoundTrip() throws {
        let all: [ControlQuery] = [.profiles, .status(profile: "a"), .gateway, .version]
        for q in all {
            let data = try JSONEncoder().encode(q)
            #expect(try JSONDecoder().decode(ControlQuery.self, from: data) == q)
        }
        #expect(try json(ControlQuery.status(profile: "x")) == #"{"profile":"x","query":"status"}"#)
    }

    @Test func repliesRoundTrip() throws {
        let summary = ControlProfileSummary(id: "i", name: "n", kind: "openvpn",
                                            status: "connected", readiness: "ready",
                                            server: "s", gatewayOwner: true)
        let all: [ControlReply] = [.ok, .profiles([summary]), .status(summary),
                                   .gateway(owner: "i"), .gateway(owner: nil),
                                   .version("0.3 (1)"), .denied("no"), .notReady("type it"),
                                   .failed("boom")]
        for reply in all {
            let data = try JSONEncoder().encode(reply)
            #expect(try JSONDecoder().decode(ControlReply.self, from: data) == reply)
        }
        // The Direct gateway must round-trip as an EXPLICIT null, not an absent key.
        #expect(try json(ControlReply.gateway(owner: nil)) == #"{"gateway":null,"ok":true}"#)
    }

    @Test func eventsRoundTrip() throws {
        let all: [ControlEvent] = [.statusChanged(profile: "p", status: "connected"),
                                   .gatewayChanged(owner: "p"), .gatewayChanged(owner: nil),
                                   .profilesChanged,
                                   .commandDenied(cmd: "connect", profile: "p", reason: "why")]
        for event in all {
            let data = try JSONEncoder().encode(event)
            #expect(try JSONDecoder().decode(ControlEvent.self, from: data) == event)
        }
        #expect(try json(ControlEvent.statusChanged(profile: "p", status: "connected"))
                == #"{"event":"status","profile":"p","status":"connected"}"#)
    }

    @Test func envelopeParsesFlatRequests() throws {
        let cmd = try JSONDecoder().decode(ControlRequestEnvelope.self,
                                           from: Data(#"{"id":7,"cmd":"connect","profile":"x"}"#.utf8))
        #expect(cmd.id == 7)
        #expect(cmd.command == .connect(profile: "x"))
        #expect(cmd.query == nil)

        let query = try JSONDecoder().decode(ControlRequestEnvelope.self,
                                             from: Data(#"{"id":8,"query":"profiles"}"#.utf8))
        #expect(query.query == .profiles)

        let watch = try JSONDecoder().decode(ControlRequestEnvelope.self,
                                             from: Data(#"{"id":9,"watch":true}"#.utf8))
        #expect(watch.watch == true)

        let reply = try JSONDecoder().decode(ControlReplyEnvelope.self,
                                             from: Data(#"{"id":7,"ok":false,"denied":"nope"}"#.utf8))
        #expect(reply.id == 7)
        #expect(reply.reply == .denied("nope"))
    }
}

@Suite struct ControlGuardTests {
    /// ForceKeepInsideVPN must veto handing the default route to Direct — through
    /// EVERY interface — while leaving VPN-to-VPN gateway moves and connects alone.
    @Test @MainActor func forceKeepInsideVPNVetoesDirectOnly() {
        let key = "ForceKeepInsideVPN"
        UserDefaults.standard.set(true, forKey: key)
        defer { UserDefaults.standard.removeObject(forKey: key) }

        #expect(ControlPlaneDispatcher.managedPolicyGuard(.setDefaultGateway(profile: nil))
                != ControlDecision.allow)
        #expect(ControlPlaneDispatcher.managedPolicyGuard(.setDefaultGateway(profile: "vpn1")) == .allow)
        #expect(ControlPlaneDispatcher.managedPolicyGuard(.connect(profile: "vpn1")) == .allow)
        #expect(ControlPlaneDispatcher.managedPolicyGuard(.disconnect(profile: "vpn1")) == .allow)
    }

    @Test @MainActor func unmanagedAllowsEverything() {
        UserDefaults.standard.removeObject(forKey: "ForceKeepInsideVPN")
        #expect(ControlPlaneDispatcher.managedPolicyGuard(.setDefaultGateway(profile: nil)) == .allow)
    }
}
