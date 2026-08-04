// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConnectionDetailView+ConnectControl.swift
//  The detail column's header row and its Liquid-Glass connect lifecycle
//  control — Connect → tinted “Connecting…” pill → the live Pause/Disconnect
//  cluster → back — plus the plain-English problem chip and the missing-input
//  hint/nudge that walk the user to the fields Connect is waiting on. Behaviour
//  only: the stored state (and the two @Namespace wrappers the morphs share)
//  lives in ConnectionDetailView.swift.
//

import SwiftUI

extension ConnectionDetailView {
    /// State-change easing, honouring Reduce Motion (instant when reduced).
    private var stateEase: Animation? { reduceMotion ? nil : .smooth(duration: 0.35) }

    /// Stall/captive-portal/pause aware dot state for this VPN's header badge.
    private var headerDotState: DotState {
        // Tailscale mid sign-in: show the connecting dot, not the link monitor's
        // "tunnel is up" (see `displayStatus`).
        let shown = vpn.displayStatus(for: profile.id)
        if shown != profile.status { return .from(status: shown) }
        if let link { return link.dot(for: profile.id) }
        let stalled = reach?.isStalled(profile.id) == true
        return .from(status: profile.status,
                     stalled: stalled && !isPaused,   // paused stall is expected
                     captive: vpn.captivePortalSuspected && vpn.incidents[profile.id] != nil,
                     paused: isPaused)
    }

    // Connect/disconnect lives here, in the header, local to this VPN — not a global button.
    var header: some View {   // was private — internal for the file split
        HStack(spacing: 14) {
            LogoBadge(id: profile.id, status: profile.status, dotState: headerDotState)
                .scaleEffect(1.6).frame(width: 40, height: 40)
            VStack(alignment: .leading, spacing: 3) {
                Text(profile.name).font(.title2).bold()
                // A healthy connection says nothing here — good news is the dot's
                // job. The line under the name speaks only when something is
                // wrong (plain English), or shows the server while disconnected.
                if UI.isActive(profile.status) && !isPaused {
                    if let problem = connectionProblem {
                        ProblemPill(text: problem.text, dot: problem.dot)
                    }
                } else if !profile.server.isEmpty {
                    Text(profile.server).foregroundStyle(.secondary)
                }
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 4) {
                connectControl
                // Say WHY Connect is dimmed, pointing at the form directly below.
                if let hint = missingInputHint {
                    Text(hint).font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        // Ease the whole header (badge state, reachability pill ⇄ server line) when
        // the connection or pause state flips, so nothing pops.
        .animation(stateEase, value: UI.isActive(profile.status))
        .animation(stateEase, value: isPaused)
    }

    /// The only states worth a label while connected, in plain English. nil when
    /// everything is fine — the pill disappears rather than saying "Reachable".
    private var connectionProblem: (text: String, dot: DotState)? {
        switch link?.state(for: profile.id) {
        case .captivePortal:
            return ("A sign-in page is in the way", .captivePortal)
        case .stalled(let seconds):
            return (seconds == nil ? "Reconnecting…" : "Not responding", .degraded)
        default:
            // Fallback before LinkStateMonitor exists in the environment.
            if case .stalled = reach?.health(for: profile.id) ?? .healthy {
                return ("Not responding", .degraded)
            }
            return nil
        }
    }

    /// Non-nil while the Connect button is waiting on typed input (and is the
    /// thing on screen). "Verification code" is deliberate — it's the word Apple
    /// uses for one-time codes, so non-technical users recognise it.
    private var missingInputHint: String? {
        guard !busy, !canConnect,
              !UI.isActive(profile.status), profile.status != .connecting,
              profile.status != .disconnecting, !vpn.isReconfiguring(profile.id),
              !(ext?.needsApproval == true && ext?.isActivated == false) else { return nil }
        let c = vpn.transientCredentials(for: profile.id)
        if !usesManager, !isProtected,
           c.username.trimmingCharacters(in: .whitespaces).isEmpty || c.password.isEmpty {
            return "Enter your sign-in below first"
        }
        return "Enter your verification code below first"
    }

    // The whole connect lifecycle lives in one Liquid-Glass control that morphs
    // between states — Connect → a tinted "Connecting…" glass pill → the live
    // Pause/Disconnect cluster → "Disconnecting…" → back to Connect — so a state
    // change reads as one continuous transformation, not a hard cut. Transient
    // states are tinted by DotState so colour alone signals what's happening.
    @ViewBuilder private var connectControl: some View {
        GlassEffectContainer(spacing: 8) {
            connectControlContent
        }
        .animation(stateEase, value: profile.status)
        // Tailscale's connecting→connected morph happens when the BACKEND reaches
        // Running, not when NE status changes (it's already .connected), so animate
        // on the display status too.
        .animation(stateEase, value: vpn.displayStatus(for: profile.id))
        .animation(stateEase, value: vpn.isReconfiguring(profile.id))
        .animation(stateEase, value: isPaused)
    }

    @ViewBuilder private var connectControlContent: some View {
        if vpn.isReconfiguring(profile.id) {
            workingPill("Applying…", tint: .orange)
                .transition(.blurReplace)
        } else {
            connectControlForStatus
                .transition(.blurReplace)
        }
    }

    @ViewBuilder private var connectControlForStatus: some View {
        // Display status, so a Tailscale node mid sign-in shows the "Connecting…" pill
        // (with a cancel ✕) rather than the live Disconnect cluster over a node that
        // can't pass traffic yet.
        let shown = vpn.displayStatus(for: profile.id)
        switch shown {
        case .connected, .reasserting:
            HStack(spacing: 8) {
                // The shrunk-down "Connected" chip lands here once the big banner
                // has retired (matchedGeometry morphs one into the other).
                if bannerCollapsed, !isPaused, profile.status == .connected {
                    ConnectedChip()
                        .matchedGeometryEffect(id: "connectedChip", in: connectedBannerNS)
                        .transition(reduceMotion ? AnyTransition.opacity : AnyTransition(.blurReplace))
                }
                if isPaused {
                    Button("Resume") { Task { await vpn.resume(id: profile.id) } }
                        .buttonStyle(.glassProminent).controlSize(.large)
                        .transition(.blurReplace)
                } else if uiPrefs.allowPause {
                    // Opt-in per VPN (Manage VPNs ▸ this VPN): most people never
                    // pause a tunnel, so the default header is just Disconnect.
                    PauseControl(height: 32,
                                 onPause: { Task { await vpn.pause(id: profile.id) } })
                        .transition(.blurReplace)
                }
                trailingStopButton
            }
        case .connecting, .disconnecting:
            HStack(spacing: 8) {
                workingPill(VPNController.statusText(shown),
                            tint: shown == .connecting ? .yellow : .orange)
                // Connecting must always be escapable. OpenVPN retries a gateway it
                // can't reach indefinitely (wrong Wi-Fi, no route to the
                // concentrator), so without this the UI is a dead end. For Tailscale
                // the ✕ cancels the sign-in wait (the NE tunnel is already up).
                if shown == .connecting { trailingStopButton }
            }
        default:   // disconnected / invalid
            connectButton
        }
    }

    /// A tinted Liquid-Glass pill for the transient connecting/applying states, so
    /// the control keeps a glass shape (and colour) across the whole transition
    /// instead of collapsing to bare text.
    /// ONE trailing control across the whole lifecycle: ✕ while connecting, ■ once
    /// up. Same view identity + the same glassEffectID, so the glass shape matches
    /// geometry and the glyph replaces in place — it visibly becomes the stop button
    /// when the connection succeeds, rather than one control vanishing and another
    /// appearing. Both do the same thing (stopVPNTunnel), which is why it's one view.
    private var trailingStopButton: some View {
        let connecting = profile.status == .connecting
        // Red-TINTED, not red: a small bright-red capsule read as an alarm. This is
        // the sidebar circles' language at header scale — a 40pt round glass button
        // (matching the 40pt logo badge across the row), softly red-tinted glass
        // with a red glyph. Filled glyphs both: a bare "xmark" reads as the LETTER
        // x rather than a cancel control.
        let tint: Color = connecting ? UI.cancelRed : .red
        return Button { vpn.disconnect(id: profile.id) } label: {
            Image(systemName: connecting ? "xmark.circle.fill" : "stop.fill")
                .font(.title3)
                .contentTransition(.symbolEffect(.replace))
                .frame(width: 40, height: 40)
                .foregroundStyle(tint)
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .glassEffect(.regular.tint(tint.opacity(0.25)).interactive(), in: Circle())
        .glassEffectID("trailing-stop", in: connectGlass)
        .help(connecting ? "Cancel connecting" : "Disconnect")
        .accessibilityLabel(connecting ? "Cancel connecting" : "Disconnect")
        .accessibilityValue(VPNController.statusText(vpn.displayStatus(for: profile.id)))
    }

    private func workingPill(_ text: String, tint: Color) -> some View {
        HStack(spacing: 7) {
            DrawnSpinner()
            // Never wrap: "Connecting…" broke onto two lines in the middle pane, which
            // made the pill twice as tall as the control beside it.
            // Increase Contrast: full-strength text on the tinted glass.
            Text(text)
                .foregroundStyle(contrast == .increased ? AnyShapeStyle(.primary) : AnyShapeStyle(.secondary))
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
        }
        .padding(.horizontal, 14).padding(.vertical, 8)
        .glassEffect(.regular.tint(tint.opacity(0.22)), in: .capsule)
        // One element, saying the state once — not "In progress, Connecting…".
        .accessibilityElement(children: .combine)
        .accessibilityLabel(text)
    }

    private var connectButton: some View {
        // Resolving credentials can take real time — a password manager may be locked, or
        // waiting on Touch ID — and `.disabled(busy)` alone made the button look broken:
        // greyed out, no motion, no explanation. Show that work is happening instead.
        if busy {
            return AnyView(HStack(spacing: 8) {
                workingPill(credentialKind == .manual ? "Connecting\u{2026}"
                                                     : "Asking \(credentialKind.displayName)\u{2026}",
                            tint: .yellow)
                // Escapable, like every other wait in this app: cancelling kills the
                // credential lookup (the op subprocess included), not just the spinner.
                Button { connectTask?.cancel() } label: {
                    Image(systemName: "xmark.circle.fill")
                }
                .buttonStyle(.glass).controlSize(.large).tint(UI.cancelRed)
                // ESC abandons the wait, matching every sheet in the app.
                .keyboardShortcut(.cancelAction)
                .help("Stop asking for credentials")
                .accessibilityLabel("Cancel credential lookup")
            })
        }
        // When macOS hasn't granted permission yet, "Connect" is a button that cannot
        // work — pressing it can only fail. Say what the next step actually is instead.
        // Wording avoids "system extension" entirely: that's our implementation detail,
        // not something a person wanting their work VPN should have to learn.
        if ext?.needsApproval == true, ext?.isActivated == false {
            return AnyView(
                Button("Allow VPN Access\u{2026}") {
                    Task { await ext?.activate() }
                }
                .buttonStyle(.glassProminent).controlSize(.large)
                .help("macOS needs your permission before SimpleVPN can make VPN connections")
            )
        }
        // NOT `.disabled(!canConnect)`: a dead button teaches nothing. It LOOKS
        // disabled while input is missing, but a click walks the user to the fix —
        // focus lands on the first empty required field and it gets a little shake.
        // Two-phase when an official Tailscale client is already running, both phases
        // yellow: "Connect Anyway" → "I Understand". The first press does NOT connect —
        // it arms, and bumps the warning below (a small double pulse) so the eye lands
        // on WHY before the second press confirms. So a person can't start a
        // conflicting second datapath with one absent-minded click.
        let armed = tailscaleConflict && tailscaleConflictArmed
        let label = armed ? "I Understand" : (tailscaleConflict ? "Connect Anyway" : "Connect")
        return AnyView(
            Button(label) {
                guard canConnect else { nudgeMissingInput(); return }
                if tailscaleConflict && !tailscaleConflictArmed {
                    withAnimation(reduceMotion ? nil : .snappy(duration: 0.2)) {
                        tailscaleConflictArmed = true
                    }
                    conflictNudge += 1   // pulses the warning banner
                    return
                }
                connectTask = Task { await connect() }
            }
                .buttonStyle(.glassProminent).controlSize(.large)
                // Return connects from anywhere in the window that isn't a text
                // field (the fields' own onSubmit already routes to the same
                // attempt) — the visibly prominent button IS the default action.
                .keyboardShortcut(.defaultAction)
                // Yellow whenever the official client is running — the caution
                // colours the whole conflict state, not just the armed press
                // (and not red: it's a warning being overridden, not destruction).
                .tint(tailscaleConflict ? .yellow : (canConnect ? nil : .gray))
                .opacity(canConnect ? 1 : 0.6)
                // The value is the VPN's live state, so a focused Connect button
                // answers "what is this connection doing" without hunting for it.
                .accessibilityValue(VPNController.statusText(vpn.displayStatus(for: profile.id)))
                // VoiceOver can't see the banner pulse, so the hint says what the
                // press will do at each phase — the same information the animation
                // conveys visually.
                .accessibilityHint(canConnect
                                   ? (armed
                                      ? "Connects even though the Tailscale app is running"
                                      : (tailscaleConflict
                                         ? "Not recommended — the Tailscale app is already running. Shows the warning; press again to connect."
                                         : ""))
                                   : (missingInputHint ?? ""))
        )
    }

    /// Draw the eye to what's missing: ring + focus + a soft shake.
    func nudgeMissingInput() {   // was private — internal for the file split
        submitAttempted = true
        focusedField = firstMissingField
        if reduceMotion { return }   // the focus ring + accent ring carry the message
        withAnimation(.easeInOut(duration: 0.4)) { nudgeTick += 1 }
    }
}
