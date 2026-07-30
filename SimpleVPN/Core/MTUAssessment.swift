// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  MTUAssessment.swift
//  Turns the raw MTU evidence from NetworkProbes into a verdict about the *tunnel*:
//  does what actually fits down the path agree with the MTU the tunnel claims and
//  with the mssfix/tun-mtu in the profile?
//
//  The whole point of this type is honesty about scope. Three things must line up
//  before a verdict means anything:
//    1. the measured path (ICMP DF sizing, or the negotiated MSS for TCP-family),
//    2. the MTU the running tunnel reports (TunnelStats.mtu),
//    3. the MTU knobs written in the profile.
//  When the target does not route through the tunnel — a LAN host, a Tailscale peer,
//  a split-tunnel exclusion — the measurement is of the underlay and says nothing
//  about the tunnel. That case is reported as inconclusive, not dressed up as a pass.
//

import Foundation

// MARK: - What the tunnel says about itself

struct TunnelMTUContext: Sendable, Equatable {
    var profileName: String?      // nil = no tunnel to compare against
    var tunnelMTU: Int?           // TunnelStats.mtu, as reported by the running tunnel
    var mssfix: Int?              // .ovpn `mssfix`
    var tunMTU: Int?              // .ovpn `tun-mtu`
    var fragment: Int?            // .ovpn `fragment`
    /// The probed target actually egresses through this tunnel (decided from the
    /// routing table, the same way the Path railroad decides it).
    var carriesTarget = false

    var isConnected: Bool { profileName != nil }

    /// OpenVPN MTU knobs from a profile's config text.
    ///
    /// NOTE: `OpenVPNOverrides` deliberately has no MTU fields — it mirrors
    /// ClientAPI::Config, which exposes none — so mssfix/tun-mtu live as directives
    /// in the .ovpn text, which is also where the Connection Doctor writes mssfix.
    /// Other engines keep their MTU in their own models (WireGuard `MTU =`,
    /// openconnect `--mtu`); those are not read here, so a WireGuard profile shows
    /// only the MTU the running tunnel reports.
    static func openVPNDirectives(in config: String) -> (mssfix: Int?, tunMTU: Int?, fragment: Int?) {
        func value(_ key: String) -> Int? {
            guard let raw = OVPNInline.directiveValue(key, in: config) else { return nil }
            // `mssfix 1400 mtu` is legal in OpenVPN 2.5+ — take the leading number.
            return Int(raw.split(separator: " ").first ?? "")
        }
        return (value("mssfix"), value("tun-mtu"), value("fragment"))
    }
}

// MARK: - Verdict

enum MTUVerdict: Sendable {
    case matches            // what fits agrees with what the tunnel claims
    case tunnelTooHigh      // the tunnel is sized larger than the path can carry
    case blackhole          // oversized packets vanish instead of fragmenting or erroring
    case inconclusive       // nothing was proven — say so rather than guess

    var title: String {
        switch self {
        case .matches:       return "Matches the tunnel"
        case .tunnelTooHigh: return "Tunnel MTU too high"
        case .blackhole:     return "PMTU blackhole"
        case .inconclusive:  return "Inconclusive"
        }
    }
    var symbol: String {
        switch self {
        case .matches:       return "checkmark.seal.fill"
        case .tunnelTooHigh: return "exclamationmark.triangle.fill"
        case .blackhole:     return "xmark.octagon.fill"
        case .inconclusive:  return "questionmark.circle"
        }
    }
    /// Coarse severity; the view owns the colour so this file stays UI-free.
    enum Severity: Sendable { case ok, warning, bad, unknown }
    var severity: Severity {
        switch self {
        case .matches: return .ok
        case .tunnelTooHigh: return .warning
        case .blackhole: return .bad
        case .inconclusive: return .unknown
        }
    }
}

struct MTUAssessment: Sendable {
    var verdict: MTUVerdict
    var headline: String
    var details: [String] = []
    /// An exact mssfix to offer when we measured a smaller path than the tunnel uses.
    var suggestedMSSFix: Int?

    static let notRunYet = MTUAssessment(verdict: .inconclusive,
                                         headline: "No MTU test has run for this target yet.")

    // MARK: Build

    static func make(proto: NetworkProbes.MTUProtocol,
                     path: NetworkProbes.PathMTUResult?,
                     transport: NetworkProbes.TransportMTUResult?,
                     context: TunnelMTUContext) -> MTUAssessment {
        proto == .icmp ? fromICMP(path, context) : fromTransport(proto, transport, context)
    }

    // MARK: ICMP — a real path-MTU measurement

    private static func fromICMP(_ path: NetworkProbes.PathMTUResult?,
                                 _ ctx: TunnelMTUContext) -> MTUAssessment {
        guard let path else { return notRunYet }
        guard path.hasIPv4 else {
            return MTUAssessment(
                verdict: .inconclusive,
                headline: "No IPv4 address for this target.",
                details: ["The unprivileged ICMP socket macOS grants an app is IPv4-only (SOCK_DGRAM/IPPROTO_ICMP), and there is no equivalent we can rely on for ICMPv6 without root. Use the TLS or HTTP test for an IPv6-only target."])
        }
        guard path.answersICMP else {
            return MTUAssessment(
                verdict: .inconclusive,
                headline: "\(path.target) doesn't answer ICMP at all.",
                details: ["Even a 56-byte echo got no reply, so \"too big\" and \"filtered\" are indistinguishable — DF sizing can't run. Lots of hosts and cloud front-ends drop ICMP; try the TLS or HTTP test against a port the target does answer on."])
        }
        guard let mtu = path.pathMTU, let payload = path.payload else { return notRunYet }

        var details: [String] = [
            "Largest don't-fragment payload that came back: \(payload) bytes → path MTU \(mtu) bytes (payload + \(NetworkProbes.icmpOverhead) for the IP and ICMP headers)."
        ]
        if path.limitedByLocalInterface {
            details.append("The boundary was our own kernel refusing to send (EMSGSIZE), not silence from the path — so \(mtu) is the outgoing interface's MTU and nothing further along is smaller than that.")
        }
        switch path.fragmentsCorrectly {
        case .some(true):
            if let f = path.fragmentTestPayload {
                details.append("A \(f + NetworkProbes.icmpOverhead)-byte packet did get through once fragmentation was allowed, so the path fragments correctly rather than dropping oversized traffic.")
            }
        case .some(false):
            if let f = path.fragmentTestPayload {
                details.append("A \(f + NetworkProbes.icmpOverhead)-byte packet was dropped even with fragmentation allowed — oversized packets are being discarded, not fragmented.")
            }
        case .none:
            details.append("Nothing needed fragment-testing: the largest size probed fit end to end.")
        }
        details.append(contentsOf: configNotes(ctx, measuredMTU: mtu, isPathMeasurement: true))

        // A path that won't carry fragments is a blackhole regardless of tunnel sizing.
        if path.fragmentsCorrectly == false {
            return MTUAssessment(verdict: .blackhole,
                                 headline: "Packets above \(mtu) bytes disappear — even fragmentable ones.",
                                 details: details,
                                 suggestedMSSFix: ctx.carriesTarget ? mtu : nil)
        }
        return compareICMP(measuredMTU: mtu, ctx: ctx, details: details)
    }

    // MARK: TCP / TLS / HTTP — MSS plus a big-vs-small blackhole test

    private static func fromTransport(_ proto: NetworkProbes.MTUProtocol,
                                      _ t: NetworkProbes.TransportMTUResult?,
                                      _ ctx: TunnelMTUContext) -> MTUAssessment {
        guard let t else { return notRunYet }
        guard t.connected else {
            return MTUAssessment(
                verdict: .inconclusive,
                headline: "Couldn't connect to \(t.target):\(t.port).",
                details: ["Nothing about packet sizes can be measured without a connection. Check the port, or use the ICMP test."])
        }
        guard let mss = t.mss, let implied = t.impliedMTU else {
            return MTUAssessment(
                verdict: .inconclusive,
                headline: "Connected to \(t.target):\(t.port), but the kernel reported no MSS.",
                details: ["TCP_MAXSEG came back empty, so there is no number to report. We will not invent one."])
        }

        var details: [String] = [
            "Negotiated MSS \(mss) bytes → the largest packet this connection will put on the wire is about \(implied) bytes (MSS + 20 IP + 20 TCP).",
            // The two caveats that stop this number being read as a path MTU. Both are
            // observed facts, not theory: Darwin's TCP_MAXSEG is the send MSS, which is
            // the *peer's* advertised MSS clamped by our route MTU, minus the space
            // taken by negotiated options (timestamps cost 12 bytes).
            "This is a negotiated value, not a measurement: it is capped by whatever MSS the far end advertised and reduced by TCP options, so a figure below the tunnel's MTU is completely normal and is NOT evidence that the tunnel is mis-sized.",
            "A bottleneck further along the path only shows up in this number if PMTU discovery is working — which is exactly what fails in a blackhole. That is what the large-versus-small comparison below is for."
        ]

        if proto == .tcp {
            details.append("Plain TCP exchanges no payload, so a large-packet blackhole cannot be tested this way. Run the TLS or HTTP test for that, or ICMP for a real path-MTU measurement.")
            details.append(contentsOf: configNotes(ctx, measuredMTU: implied, isPathMeasurement: false))
            return compareTransport(implied: implied, largeExchangeProven: false,
                                    proto: proto, ctx: ctx, details: details)
        }

        let small = t.smallExchange
        let large = t.largeExchange
        if small?.completed == false {
            details.append(proto == .tls
                ? "The small TLS request itself got no reply, so the large one proves nothing. The endpoint may not speak TLS on port \(t.port), or it may ignore the plain TLS 1.2 ClientHello we send (1.1.1.1:443 does exactly that). Try the ICMP test, or an ordinary HTTPS host."
                : "The small HTTP request itself got no reply, so the large one proves nothing — the endpoint probably doesn't speak HTTP on port \(t.port).")
            return MTUAssessment(verdict: .inconclusive,
                                 headline: "\(proto.label) on \(t.target):\(t.port) didn't answer.",
                                 details: details)
        }
        if let small, small.completed {
            details.append("A \(small.requestBytes)-byte \(proto.label) request was answered (\(small.responseBytes) bytes back) in \(Int(small.elapsedMS)) ms.")
        }
        if let large {
            if large.completed {
                details.append("A \(large.requestBytes)-byte request — which has to cross the wire as full-size segments — was also answered (\(large.responseBytes) bytes back), so the outbound direction carries full-size packets.")
                if large.responseBytes > mss {
                    details.append("The reply was larger than the MSS, so full-size segments got back to us too.")
                } else {
                    details.append("The reply was smaller than the MSS, so the inbound direction is not proven by this test.")
                }
            } else {
                details.append("A \(large.requestBytes)-byte request got no reply at all while the small one did: the classic PMTU-blackhole signature — something on the path drops full-size packets and the ICMP that should say so is being filtered.")
                details.append("This test can't say where the limit is — no size was measured, only \"this size failed\". Run the ICMP test against the same target for the exact number.")
                details.append(contentsOf: configNotes(ctx, measuredMTU: implied, isPathMeasurement: false))
                return MTUAssessment(
                    verdict: .blackhole,
                    headline: "Small \(proto.label) exchange works, a larger-than-MSS one stalls.",
                    details: details)
            }
        }
        details.append(contentsOf: configNotes(ctx, measuredMTU: implied, isPathMeasurement: false))
        return compareTransport(implied: implied, largeExchangeProven: large?.completed == true,
                                proto: proto, ctx: ctx, details: details)
    }

    // MARK: Comparison against the tunnel

    /// ICMP: a genuine end-to-end measurement, so a path smaller than the tunnel's MTU
    /// is a real finding.
    private static func compareICMP(measuredMTU: Int, ctx: TunnelMTUContext,
                                    details: [String]) -> MTUAssessment {
        let label = "Path MTU"
        var details = details
        guard ctx.isConnected, let name = ctx.profileName else {
            return MTUAssessment(verdict: .inconclusive,
                                 headline: "\(label) \(measuredMTU) bytes — no tunnel connected to compare against.",
                                 details: details)
        }
        guard ctx.carriesTarget else {
            details.append("Connect and test a host that actually sits on the far side of \(name) to check the tunnel's own MTU.")
            return MTUAssessment(verdict: .inconclusive,
                                 headline: "\(label) \(measuredMTU) bytes on the underlay — this target doesn't route through \(name).",
                                 details: details)
        }
        guard let tunnelMTU = ctx.tunnelMTU else {
            details.append("\(name) isn't reporting an MTU in its telemetry, so there is nothing to compare \(measuredMTU) against.")
            return MTUAssessment(verdict: .inconclusive,
                                 headline: "\(label) \(measuredMTU) bytes through \(name); the tunnel's MTU is unknown.",
                                 details: details)
        }

        if measuredMTU >= tunnelMTU {
            return MTUAssessment(verdict: .matches,
                                 headline: "\(label) \(measuredMTU) ≥ \(name)'s MTU \(tunnelMTU) — everything the tunnel allows gets through.",
                                 details: details)
        }
        // Measured smaller than the tunnel claims: the tunnel hands the path packets
        // it can't carry, which is exactly what mssfix exists to clamp.
        return MTUAssessment(verdict: .tunnelTooHigh,
                             headline: "Only \(measuredMTU) bytes get through, but \(name) is using an MTU of \(tunnelMTU).",
                             details: details,
                             suggestedMSSFix: measuredMTU)
    }

    /// TCP family: `implied` is what this connection will actually emit, not what the
    /// path can carry. The asymmetry matters — bigger than the tunnel MTU is a real
    /// finding, smaller is just the peer's advertisement and proves nothing.
    private static func compareTransport(implied: Int, largeExchangeProven: Bool,
                                         proto: NetworkProbes.MTUProtocol,
                                         ctx: TunnelMTUContext, details: [String]) -> MTUAssessment {
        var details = details
        guard ctx.isConnected, let name = ctx.profileName else {
            return MTUAssessment(verdict: .inconclusive,
                                 headline: "Segments up to about \(implied) bytes on this connection — no tunnel connected to compare against.",
                                 details: details)
        }
        guard ctx.carriesTarget else {
            details.append("Connect and test a host that actually sits on the far side of \(name) to say anything about the tunnel.")
            return MTUAssessment(verdict: .inconclusive,
                                 headline: "Segments up to about \(implied) bytes, but this target doesn't route through \(name).",
                                 details: details)
        }
        guard let tunnelMTU = ctx.tunnelMTU else {
            details.append("\(name) isn't reporting an MTU in its telemetry, so there is nothing to compare against.")
            return MTUAssessment(verdict: .inconclusive,
                                 headline: "Segments up to about \(implied) bytes through \(name); the tunnel's MTU is unknown.",
                                 details: details)
        }

        if implied > tunnelMTU {
            details.append("Packets that big have to be fragmented or dropped by the tunnel. Clamping with mssfix \(tunnelMTU) makes the two ends negotiate a size that fits.")
            return MTUAssessment(verdict: .tunnelTooHigh,
                                 headline: "This connection negotiated segments of about \(implied) bytes, larger than \(name)'s MTU of \(tunnelMTU).",
                                 details: details,
                                 suggestedMSSFix: tunnelMTU)
        }
        guard largeExchangeProven else {
            details.append("Run the ICMP test against the same target for an actual path-MTU measurement.")
            return MTUAssessment(verdict: .inconclusive,
                                 headline: "Segments of about \(implied) bytes fit \(name)'s MTU of \(tunnelMTU), but nothing here tested the tunnel's own limit.",
                                 details: details)
        }
        return MTUAssessment(verdict: .matches,
                             headline: "Full-size segments (about \(implied) bytes) crossed \(name) intact, within its MTU of \(tunnelMTU).",
                             details: details)
    }

    /// What the profile asks for, and whether the measurement contradicts it.
    /// `measuredMTU` may only be contradicted against when it is a real path
    /// measurement (`isPathMeasurement`) — a negotiated MSS is a lower bound, so
    /// reading a contradiction out of it would be a false accusation.
    private static func configNotes(_ ctx: TunnelMTUContext, measuredMTU: Int,
                                    isPathMeasurement: Bool) -> [String] {
        var out: [String] = []
        if let t = ctx.tunnelMTU, let name = ctx.profileName {
            out.append("\(name) reports a tunnel MTU of \(t).")
        }
        if let mssfix = ctx.mssfix {
            // OpenVPN reads `mssfix n` as the largest *encapsulated* datagram it will
            // produce, so comparing it against a measured path MTU is the right
            // comparison — not against a TCP MSS.
            out.append(isPathMeasurement && ctx.carriesTarget && mssfix > measuredMTU
                       ? "The profile sets mssfix \(mssfix), which is larger than the \(measuredMTU) bytes this path carries — OpenVPN will still emit datagrams that don't fit."
                       : "The profile sets mssfix \(mssfix) (the largest encapsulated datagram OpenVPN will emit).")
        }
        if let tun = ctx.tunMTU {
            if let t = ctx.tunnelMTU, t != tun {
                out.append("The profile sets tun-mtu \(tun) but the running tunnel reports \(t) — the server's pushed value won.")
            } else {
                out.append("The profile sets tun-mtu \(tun).")
            }
        }
        if let f = ctx.fragment {
            out.append("The profile sets fragment \(f), so OpenVPN fragments internally above that size.")
        }
        return out
    }
}
