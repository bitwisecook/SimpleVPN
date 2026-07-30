// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  MTUAssessmentTests.swift
//  Pins the honesty rules of the MTU verdict, because every one of them is a rule
//  about NOT claiming something:
//    • a path that doesn't go through the tunnel can never produce a tunnel verdict,
//    • a negotiated TCP MSS below the tunnel MTU is normal and must not read as
//      "tunnel MTU too high" (it is capped by the far end, not by our path),
//    • silence from ICMP is inconclusive, not "no limit found".
//

import Foundation
import Testing
@testable import SimpleVPN

struct MTUAssessmentTests {

    // MARK: Config parsing

    @Test func parsesOpenVPNMTUDirectives() {
        let ovpn = """
        client
        remote vpn.example.org 1194 udp
        mssfix 1400 mtu
        tun-mtu 1500
        fragment 1300
        """
        let d = TunnelMTUContext.openVPNDirectives(in: ovpn)
        #expect(d.mssfix == 1400)      // the trailing `mtu` keyword must not defeat parsing
        #expect(d.tunMTU == 1500)
        #expect(d.fragment == 1300)
    }

    @Test func absentDirectivesStayNil() {
        let d = TunnelMTUContext.openVPNDirectives(in: "client\nremote host 1194 udp\n")
        #expect(d.mssfix == nil && d.tunMTU == nil && d.fragment == nil)
    }

    // MARK: Helpers

    private func tunnel(mtu: Int?, carries: Bool, mssfix: Int? = nil) -> TunnelMTUContext {
        TunnelMTUContext(profileName: "Lab", tunnelMTU: mtu, mssfix: mssfix, carriesTarget: carries)
    }

    private func icmp(pathMTU: Int, fragments: Bool? = true,
                      localLimit: Bool = false) -> NetworkProbes.PathMTUResult {
        var r = NetworkProbes.PathMTUResult(target: "203.0.113.5")
        r.answersICMP = true
        r.payload = pathMTU - NetworkProbes.icmpOverhead
        r.pathMTU = pathMTU
        r.limitedByLocalInterface = localLimit
        r.fragmentsCorrectly = fragments
        r.fragmentTestPayload = fragments == nil ? nil : pathMTU
        return r
    }

    private func transport(_ proto: NetworkProbes.MTUProtocol, mss: Int?,
                           small: Bool?, large: Bool?) -> NetworkProbes.TransportMTUResult {
        var r = NetworkProbes.TransportMTUResult(target: "203.0.113.5", port: 443, proto: proto)
        r.connected = true
        r.mss = mss
        if let small {
            r.smallExchange = NetworkProbes.MTUExchange(requestBytes: 120, responseBytes: small ? 3900 : 0,
                                                        completed: small, elapsedMS: 20)
        }
        if let large {
            r.largeExchange = NetworkProbes.MTUExchange(requestBytes: 3000, responseBytes: large ? 3900 : 0,
                                                        completed: large, elapsedMS: 30)
        }
        return r
    }

    private func verdict(_ proto: NetworkProbes.MTUProtocol,
                         path: NetworkProbes.PathMTUResult? = nil,
                         transport: NetworkProbes.TransportMTUResult? = nil,
                         ctx: TunnelMTUContext) -> MTUAssessment {
        MTUAssessment.make(proto: proto, path: path, transport: transport, context: ctx)
    }

    // MARK: ICMP path sizing

    @Test func filteredICMPIsInconclusive() {
        var r = NetworkProbes.PathMTUResult(target: "203.0.113.5")
        r.answersICMP = false
        let a = verdict(.icmp, path: r, ctx: tunnel(mtu: 1500, carries: true))
        #expect(a.verdict == .inconclusive)
        #expect(a.suggestedMSSFix == nil)
    }

    @Test func ipv6OnlyTargetIsInconclusive() {
        var r = NetworkProbes.PathMTUResult(target: "2001:db8::1")
        r.hasIPv4 = false
        #expect(verdict(.icmp, path: r, ctx: tunnel(mtu: 1500, carries: true)).verdict == .inconclusive)
    }

    @Test func smallerPathThanTunnelIsTunnelTooHigh() {
        let a = verdict(.icmp, path: icmp(pathMTU: 1400), ctx: tunnel(mtu: 1500, carries: true))
        #expect(a.verdict == .tunnelTooHigh)
        #expect(a.suggestedMSSFix == 1400)      // the measured number, not a guess
    }

    @Test func pathEqualToTunnelMatches() {
        let a = verdict(.icmp, path: icmp(pathMTU: 1400, fragments: nil, localLimit: true),
                        ctx: tunnel(mtu: 1400, carries: true))
        #expect(a.verdict == .matches)
        #expect(a.suggestedMSSFix == nil)
    }

    @Test func droppedFragmentsAreABlackhole() {
        let a = verdict(.icmp, path: icmp(pathMTU: 1300, fragments: false),
                        ctx: tunnel(mtu: 1500, carries: true))
        #expect(a.verdict == .blackhole)
    }

    /// The central scoping rule: a measurement of a path that bypasses the tunnel must
    /// never be turned into a verdict about the tunnel, however bad it looks.
    @Test func targetOutsideTheTunnelNeverJudgesTheTunnel() {
        let a = verdict(.icmp, path: icmp(pathMTU: 1300), ctx: tunnel(mtu: 1500, carries: false))
        #expect(a.verdict == .inconclusive)
        #expect(a.suggestedMSSFix == nil)
    }

    @Test func noTunnelIsInconclusiveButStillReportsTheNumber() {
        let a = verdict(.icmp, path: icmp(pathMTU: 1500), ctx: TunnelMTUContext())
        #expect(a.verdict == .inconclusive)
        #expect(a.headline.contains("1500"))
    }

    // MARK: TCP family

    /// TCP_MAXSEG is capped by the peer's advertised MSS (1388 from example.com on a
    /// 1500 path), so MSS + 40 below the tunnel MTU proves nothing bad. Reading it as
    /// "tunnel MTU too high" would fire on almost every healthy connection.
    @Test func lowNegotiatedMSSIsNotATunnelFault() {
        let a = verdict(.tls, transport: transport(.tls, mss: 1388, small: true, large: true),
                        ctx: tunnel(mtu: 1500, carries: true))
        #expect(a.verdict == .matches)
        #expect(a.suggestedMSSFix == nil)
    }

    @Test func segmentsLargerThanTheTunnelAreFlagged() {
        let a = verdict(.tls, transport: transport(.tls, mss: 1500, small: true, large: true),
                        ctx: tunnel(mtu: 1400, carries: true))
        #expect(a.verdict == .tunnelTooHigh)
        #expect(a.suggestedMSSFix == 1400)      // clamp to what the tunnel can carry
    }

    @Test func largeStallWithSmallSuccessIsABlackhole() {
        let a = verdict(.tls, transport: transport(.tls, mss: 1360, small: true, large: false),
                        ctx: tunnel(mtu: 1400, carries: true))
        #expect(a.verdict == .blackhole)
        // No size was measured, only "this size failed" — so no number is offered.
        #expect(a.suggestedMSSFix == nil)
    }

    @Test func silentEndpointIsInconclusive() {
        let a = verdict(.tls, transport: transport(.tls, mss: 1448, small: false, large: nil),
                        ctx: tunnel(mtu: 1500, carries: true))
        #expect(a.verdict == .inconclusive)
    }

    /// Plain TCP exchanges no payload, so a fitting MSS is not evidence of anything
    /// about the tunnel's own limit.
    @Test func plainTCPCannotConfirmTheTunnel() {
        let a = verdict(.tcp, transport: transport(.tcp, mss: 1360, small: nil, large: nil),
                        ctx: tunnel(mtu: 1500, carries: true))
        #expect(a.verdict == .inconclusive)
    }

    @Test func failedConnectIsInconclusive() {
        var r = NetworkProbes.TransportMTUResult(target: "203.0.113.5", port: 4443, proto: .http)
        r.connected = false
        #expect(verdict(.http, transport: r, ctx: tunnel(mtu: 1500, carries: true)).verdict == .inconclusive)
    }

    @Test func missingMSSIsInconclusiveNotZero() {
        let a = verdict(.http, transport: transport(.http, mss: nil, small: true, large: true),
                        ctx: tunnel(mtu: 1500, carries: true))
        #expect(a.verdict == .inconclusive)
    }
}
