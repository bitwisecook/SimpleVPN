// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConnectionBanners.swift
//  The main window's small status voices: the green Connected banner and the
//  chip it shrinks into, the captive-portal / unreachable-here / Tailscale
//  sign-in / stuck-connecting / paused banners, and the header's problem pill.
//  Each says ONE thing in plain English; ConnectionDetailView (and its
//  ConnectControl file) decide when each appears.
//

import SwiftUI

/// The state, in words: a green "you are connected" banner above the map, for
/// everyone who doesn't speak dot-and-stop-button. Makes no claims about WHICH
/// traffic is protected — that's the tunnel-mode toggle's story.
struct ConnectedBanner: View {   // was private — internal for the file split
    let vpnName: String
    let server: String
    let uptime: TimeInterval?

    private var detail: String {
        var bits: [String] = []
        if !server.isEmpty { bits.append(server) }
        if let uptime, uptime >= 1 {
            let d = Duration.seconds(Int(uptime))
            bits.append("connected for \(d.formatted(.units(allowed: [.hours, .minutes, .seconds], width: .abbreviated, maximumUnitCount: 2)))")
        }
        return bits.joined(separator: " \u{00B7} ")
    }

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "checkmark.circle.fill").font(.title3).foregroundStyle(.green)
            VStack(alignment: .leading, spacing: 2) {
                Text("Connected to \(vpnName)").font(.callout.weight(.semibold))
                if !detail.isEmpty {
                    Text(detail).font(.callout).foregroundStyle(.secondary)
                        .monospacedDigit()
                }
            }
            Spacer(minLength: 0)
        }
        .padding(12)
        .background(.green.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
        .accessibilityElement(children: .combine)
    }
}

/// What the big ConnectedBanner shrinks INTO after 5s: a compact green
/// "Connected" pill living beside the stop button, so the header still says in
/// words what the dot says in colour.
struct ConnectedChip: View {   // was private — internal for the file split
    var body: some View {
        HStack(spacing: 5) {
            Image(systemName: "checkmark.circle.fill").font(.callout)
            Text("Connected").font(.callout.weight(.medium))
        }
        .foregroundStyle(.green)
        .padding(.horizontal, 12).frame(height: 34)
        .glassEffect(.regular.tint(.green.opacity(0.22)), in: .capsule)
        .accessibilityLabel("Connected")
    }
}

/// A Wi-Fi sign-in page is intercepting this network's traffic — the VPN cannot
/// get through until the user is past it. Indigo (matching the captive-portal
/// dot language everywhere else), with the two actions that actually move things
/// forward: open the page, and re-check after signing in.
struct CaptivePortalBanner: View {   // was private — internal for the file split
    @Bindable var vpn: VPNController
    @Environment(\.openURL) private var openURL
    @State private var checking = false

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "wifi.exclamationmark").font(.title3).foregroundStyle(.indigo)
            VStack(alignment: .leading, spacing: 3) {
                Text("This Wi-Fi wants you to sign in first")
                    .font(.callout.weight(.semibold))
                Text("A sign-in page is answering instead of the internet — hotel or guest Wi-Fi usually does this. Sign in there, then connect. The VPN can't get through until you do.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 6) {
                Button("Open Sign-In Page") {
                    openURL(vpn.captivePortalURL ?? ConnectionDiagnostics.captivePortalProbeURL)
                }
                .buttonStyle(.glassProminent).tint(.indigo)
                Button {
                    checking = true
                    Task { await vpn.recheckCaptivePortal(); checking = false }
                } label: {
                    if checking {
                        HStack(spacing: 5) { DrawnSpinner(); Text("Checking\u{2026}") }
                    } else {
                        Text("Check Again")
                    }
                }
                .buttonStyle(.glass)
                .disabled(checking)
                .help("Re-check whether the sign-in page is still in the way")
            }
        }
        .padding(12)
        .background(.indigo.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
        // `.contain`, not `.combine`: this banner holds TWO buttons, and a banner-wide
        // combine swallows both — the wave-3 bug class in Docs/Accessibility.md rule 4,
        // and here it hid the only way out of a captive portal. The container sentence
        // says everything the two Texts say.
        .accessibilityElement(children: .contain)
        .accessibilityLabel("This Wi-Fi wants you to sign in first. A sign-in page is answering instead of the internet — hotel or guest Wi-Fi usually does this. Sign in there, then connect. The VPN can't get through until you do.")
    }
}

/// Pre-emptive warning: this VPN has already failed to be reachable from the network
/// we're on now, so say so BEFORE the user clicks Connect and waits out the timeout
/// again. Cleared automatically the moment it does connect from here (see
/// NetworkMemory), and dismissable by hand for when the network has been fixed.
struct UnreachableHereBanner: View {   // was private — internal for the file split
    let vpnName: String
    let networkLabel: String
    let forget: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "wifi.exclamationmark").font(.title3).foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 3) {
                Text("\(vpnName) couldn't be reached from this network before")
                    .font(.callout.weight(.semibold))
                // "You can still TRY" — the honest verb. "You can still connect" promised the
                // very outcome this banner exists to warn is unlikely.
                Text("Last time you tried on \(networkLabel), it never answered. You can still try to connect — if it succeeds, this warning clears itself.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Button("Forget", action: forget)
                .buttonStyle(.glass)
                .help("Stop warning about this network")
                .accessibilityLabel("Forget that \(vpnName) couldn\u{2019}t be reached from \(networkLabel)")
        }
        .padding(12)
        .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
        // `.contain`: the Forget button must stay reachable (rule 4).
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(vpnName) couldn\u{2019}t be reached from this network before. Last time you tried on \(networkLabel), it never answered. You can still try to connect — if it succeeds, this warning clears itself.")
    }
}

/// A Tailscale connect waiting on the user's browser sign-in. Orange like the
/// other "waiting on you" states, with the one action that moves it forward:
/// re-open the sign-in page (the engine's login URL stays valid until used).
struct TailscaleSignInBanner: View {   // was private — internal for the file split
    let reopen: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "person.badge.key").font(.title3).foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 3) {
                Text("Sign in in your browser").font(.callout.weight(.semibold))
                Text("A sign-in page opened in your browser. Finish signing in there and this Mac joins the network by itself. Closed the tab? Open it again.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Button("Open Sign-In Page", action: reopen)
                .buttonStyle(.glassProminent).tint(.orange)
        }
        .padding(12)
        .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
        // `.contain`: the sign-in button is the only way forward and must stay
        // reachable — a combine here made this banner a dead end (rule 4).
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Sign in in your browser. A sign-in page opened in your browser. Finish signing in there and this Mac joins the network by itself. Closed the tab? Open it again.")
    }
}

/// A connect attempt that isn't getting anywhere. The usual cause is being on a
/// network that can't reach the gateway at all (wrong Wi-Fi, guest network, captive
/// portal) — and because the engine retries for ever, nothing would otherwise tell
/// the user that. Names the host it's trying and offers the way out.
struct StuckConnectingBanner: View {   // was private — internal for the file split
    let vpnName: String
    let host: String
    let cancel: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "wifi.exclamationmark").font(.title3).foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 3) {
                Text("Still trying to reach \(vpnName)").font(.callout.weight(.semibold))
                Text("No answer from \(host) yet. This usually means the network you're on can't reach it — a different Wi-Fi, a guest network, or a sign-in page in the way.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Button("Cancel", action: cancel).buttonStyle(.glass)
                .accessibilityLabel("Stop trying to reach \(vpnName)")
        }
        .padding(12)
        .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
        // `.contain`: Cancel is the way out of an endless connect and must stay
        // reachable (rule 4).
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Still trying to reach \(vpnName). No answer from \(host) yet. This usually means the network you're on can't reach it — a different Wi-Fi, a guest network, or a sign-in page in the way.")
    }
}

/// This tunnel is about to swallow the network a running virtual machine or
/// container is sitting on, so the guest is about to lose its connection to this
/// Mac. Names the network, names what is on it, and offers the app's ORDINARY
/// kept-direct rule — with the consequence spelled out, because keeping a subnet
/// out of a tunnel is a split-tunnel decision and this feature must never make
/// one quietly. Amber like the other "you should know this before it bites you"
/// banners; the offer itself comes from `VirtualizationBypass`.
struct GuestNetworkCaptureBanner: View {
    let offers: [VirtualizationBypassOffer]
    let keepDirect: () -> Void
    let dismiss: () -> Void

    /// "Apple Containers on bridge100 (192.168.64.0/24)", joined for the rare
    /// machine running two guest networks at once.
    private var what: String {
        offers.map { "\($0.attribution) on \($0.subnet)" }
            .formatted(.list(type: .and))
    }

    private var headline: String {
        offers.count == 1
            ? "This VPN will cut off \(offers[0].attribution)"
            : "This VPN will cut off \(offers.count) guest networks"
    }

    /// One sentence per offer, each already carrying its own consequence — the
    /// wording belongs to `VirtualizationBypassOffer` so the banner, the report and
    /// the manual cannot describe the same trade-off three different ways.
    private var consequences: String {
        offers.map(\.consequence).joined(separator: " ")
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "shippingbox.and.arrow.backward")
                .font(.title3).foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 3) {
                Text(headline).font(.callout.weight(.semibold))
                Text("\(what) is running right now, and this VPN carries the traffic that would reach it. SimpleVPN has changed nothing.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Text(consequences)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 6) {
                Button("Keep It Reachable", action: keepDirect)
                    .buttonStyle(.glassProminent).tint(.orange)
                    .help("Add \(offers.map(\.subnet).formatted(.list(type: .and))) to this VPN's kept-direct routes and reconnect")
                Button("Not Now", action: dismiss)
                    .buttonStyle(.glass)
                    .help("Leave routing alone \u{2014} ask again next time you connect")
            }
        }
        .padding(12)
        .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
        // `.contain`, not `.combine`: this banner HOLDS BUTTONS, and a banner-wide
        // combine swallows them (Docs/Accessibility.md rule 4). The container
        // sentence carries everything the three Texts say, in the same order.
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(headline). \(what) is running right now, and this VPN carries the traffic that would reach it. SimpleVPN has changed nothing. \(consequences)")
    }
}

/// Paused state banner — deliberately loud: paused means traffic is leaving the
/// Mac outside the VPN, and the user must never forget it. (There is only one
/// pause behaviour now; the old calm "blocked" variant is gone with hold mode.)
struct PausedBanner: View {   // was private — internal for the file split
    let resume: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "road.lane.arrowtriangle.2.inward")
                .font(.title3)
                .foregroundStyle(.white)
            VStack(alignment: .leading, spacing: 2) {
                Text("Paused — traffic is NOT going through the VPN")
                    .bold()
                    .foregroundStyle(.white)
                Text("Everything uses your normal connection and is visible to the local network. You're still signed in — resuming won't ask again.")
                    .font(.callout)
                    .foregroundStyle(.white.opacity(0.9))
            }
            Spacer()
            Button("Resume", action: resume)
                .buttonStyle(.borderedProminent)
                .tint(.white)
                .foregroundStyle(.red)
                .accessibilityLabel("Resume — put traffic back through the VPN")
        }
        .padding(12)
        .background(Color.red, in: RoundedRectangle(cornerRadius: 10))
        // `.contain`: this is the app's loudest safety warning AND the only place the
        // Resume button lives. A combine hid the fix inside the warning (rule 4).
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Paused — traffic is NOT going through the VPN. Everything uses your normal connection and is visible to the local network. You're still signed in — resuming won't ask again.")
    }
}

/// The header's problem chip: appears ONLY when something is wrong (a healthy
/// connection shows nothing here). Plain-English text + the shared dot language.
struct ProblemPill: View {   // was private — internal for the file split
    let text: String
    let dot: DotState
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.colorSchemeContrast) private var contrast

    var body: some View {
        HStack(spacing: 5) {
            StatusDot(state: dot, size: 7)
            // Increase Contrast: secondary-on-tinted-glass is the app's worst
            // text contrast — promote to full strength under the accommodation.
            Text(text).font(.callout)
                .foregroundStyle(contrast == .increased ? AnyShapeStyle(.primary) : AnyShapeStyle(.secondary))
        }
        .padding(.horizontal, 10).padding(.vertical, 5)
        .glassEffect(.regular.tint(dot.color.opacity(0.18)), in: .capsule)
        .animation(reduceMotion ? nil : .smooth(duration: 0.4), value: text)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(text)
    }
}
