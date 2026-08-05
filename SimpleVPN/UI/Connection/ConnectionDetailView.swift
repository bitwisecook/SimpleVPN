// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConnectionDetailView.swift
//  The main window's middle column: everything about the SELECTED VPN — the
//  credential forms (typed / manager / Touch ID-protected), the Tailscale and
//  proxy-tunnel stand-ins for them, the pre-connect banners and panels, and
//  the connect/load actions. The header row and its Liquid-Glass connect
//  lifecycle control live in ConnectionDetailView+ConnectControl.swift; every
//  piece of stored @State (and both @Namespace wrappers) stays HERE, because
//  Swift extensions cannot hold stored properties.
//

import SwiftUI
import os

// MARK: - Connection detail (connection only)

struct ConnectionDetailView: View {   // was private — internal for the file split
    @Bindable var vpn: VPNController
    let profile: VPNController.Profile
    @Environment(ProfileEvaluator.self) private var evaluator
    @Environment(PublicIPMonitor.self) private var publicIP
    @Environment(ReachabilityMonitor.self) var reach: ReachabilityMonitor?   // was private — internal for the file split
    @Environment(LinkStateMonitor.self) var link: LinkStateMonitor?   // was private — internal for the file split
    @Environment(ExtensionController.self) var ext: ExtensionController?   // was private — internal for the file split
    @Environment(ExtensionDoctor.self) private var extDoctor: ExtensionDoctor?
    @Environment(\.accessibilityReduceMotion) var reduceMotion   // was private — internal for the file split
    @Environment(\.colorSchemeContrast) var contrast   // read by the glass pills (ConnectControl)
    @State var busy = false   // was private — internal for the file split
    /// The in-flight connect, so the busy pill's ✕ can cancel the credential lookup.
    @State var connectTask: Task<Void, Never>?   // was private — internal for the file split
    @State private var loaded = false
    @State var submitAttempted = false   // was private — internal for the file split
    /// Bumped to shake the still-empty required fields (Connect clicked too
    /// early, or the sidebar/menu asked us to show what's missing).
    @State var nudgeTick = 0   // was private — internal for the file split
    /// First-connect hand-holding: true until a successful connect writes a
    /// baseline (persisted — survives restarts until the setup is PROVEN).
    @State private var neverConnected = false
    @State private var setupDismissed = false
    /// The "change how you sign in" popover — the unobtrusive way back for a VPN
    /// that is already set up, so nobody has to go to Manage VPNs to switch.
    @State var showSignInChooser = false   // internal: the manager/typed forms open it
    /// What this Mac can offer, shared app-wide (one set of probes for every
    /// surface).
    @State var sources = SignInSourceAvailability.shared   // internal: read by both forms
    /// The big green "Connected" banner shrinks to a compact chip beside the
    /// stop button 5s after connecting — the reassurance, then out of the way.
    @State var bannerCollapsed = false   // was private — internal for the file split
    @Namespace var connectedBannerNS   // was private — internal for the file split

    /// Shared namespace so the cancel ✕ and the stop ■ are the same glass element
    /// morphing, not two controls swapping.
    @Namespace var connectGlass   // was private — internal for the file split

    /// True once a connect attempt has been grinding long enough that something is
    /// probably wrong (unreachable gateway, wrong network) rather than just slow.
    @State private var connectingTooLong = false
    @State private var netMemory = NetworkMemory.shared

    /// An official Tailscale client is running. Refreshed on appear and whenever an
    /// app launches/quits, so the warning appears/clears live. Only meaningful for a
    /// Tailscale-kind profile (see `tailscaleConflict`).
    @State private var tailscaleClientsRunning = false
    /// Two-phase Connect for the conflict case: the first press ("Connect Anyway")
    /// ARMS this and bumps the warning; only the second ("I Understand") connects.
    @State var tailscaleConflictArmed = false   // was private — internal for the file split
    /// Bumped when the user presses "Connect Anyway", to pulse the warning banner.
    /// A counter, not the armed flag: disarming must not replay the animation.
    @State var conflictNudge = 0   // internal: the connect control triggers it


    enum CredentialField { case username, password, otp }   // was private — internal for the file split
    /// Plain state (not @FocusState): focus is bridged into the AppKit-backed
    /// AutoFillFields, which SwiftUI focus can't reach.
    @State var focusedField: CredentialField?   // was private — internal for the file split

    // MARK: Security key (YubiKey and similar)

    /// The armed-capture state machine for this VPN's verification code. See
    /// Credentials/YubiKeyTouchCapture.swift — the whole reason it exists is that a
    /// security key types into whatever has focus, so arming has to be an explicit
    /// state rather than a field the user aims at.
    @State private var yubiKeyCapture = YubiKeyCapture()
    /// What is plugged in, and whether `ykman` is here. IORegistry reads only — no
    /// Input Monitoring, ever (Credentials/YubiKeyPresence.swift).
    @State private var yubiKeyPresence = SecurityKeyPresence()
    /// The object that swallows the key's own trailing Return. Held (not rebuilt
    /// per frame) because `AutoFillField`'s coordinator consults it by reference.
    @State private var yubiKeyReturnPolicy: YubiKeyFieldReturnPolicy?

    private var yubiKeyConfig: YubiKeyAuthConfig { vpn.authConfig(for: profile.id).yubiKey }

    /// Everything the mutual-exclusion rules turn on, gathered from this VPN.
    private var yubiKeyInputs: YubiKeyConflictInputs {
        var inputs = YubiKeyConflictInputs()
        inputs.config = yubiKeyConfig
        inputs.requiresOTP = requiresOTP
        inputs.staticChallenge = hasStaticChallenge
        inputs.credentialKind = credentialKind
        inputs.sourceSuppliesCode = credentialKind.suppliesOTP
        inputs.keychainSuppliesCode = isProtected && biometricInfo.hasTOTP
        inputs.passwordTemplate = vpn.authConfig(for: profile.id).passwordTemplate
        inputs.managerToolInstalled = yubiKeyPresence.managerToolInstalled
        inputs.typingKeyAttached = yubiKeyPresence.hasTypingKey
        return inputs
    }

    /// The profile declares the server's own code prompt (`static-challenge`), so
    /// the code travels as the engine's challenge response rather than inside the
    /// password — which makes the password template inert.
    private var hasStaticChallenge: Bool {
        vpn.ovpnText(id: profile.id)
            .map { !evaluator.evaluation(for: $0).staticChallenge.isEmpty } ?? false
    }

    /// Will a security key be asked for this VPN's code on the next connect?
    private var yubiKeyActive: Bool { YubiKeyConflicts.isActive(yubiKeyInputs) }

    private var requiresOTP: Bool { vpn.requiresOTP(for: profile.id) }
    private var allowPasswordSave: Bool {
        vpn.ovpnText(id: profile.id).map { evaluator.evaluation(for: $0).allowPasswordSave } ?? true
    }
    /// Autologin profiles sign in with their certificate — no credentials to
    /// collect, so no form, no gating, no first-connect credential coaching.
    private var isAutologin: Bool {
        vpn.ovpnText(id: profile.id).map { evaluator.evaluation(for: $0).autologin } ?? false
    }
    /// A `USERNAME` userlock: the profile fixes the username, so the form shows
    /// it read-only and Connect never waits on it.
    private var lockedUsername: String {
        vpn.ovpnText(id: profile.id).map { evaluator.evaluation(for: $0).userlockedUsername } ?? ""
    }
    var isPaused: Bool { vpn.pausedProfiles.contains(profile.id) }   // was private — internal for the file split
    private var isStalled: Bool { reach?.isStalled(profile.id) == true }
    /// This VPN's opt-in advanced controls (pause button, Connection Manager).
    var uiPrefs: VPNUIPrefs { vpn.uiPrefs(for: profile.id) }   // was private — internal for the file split
    @Environment(TopologyMonitor.self) private var topo: TopologyMonitor?

    /// Snapshot of live telemetry the Connection Manager + Doctor read.
    private var doctorSnapshot: DoctorSnapshot {
        var stalled: Int?
        if case .stalled(let s) = reach?.health(for: profile.id) { stalled = s }
        var snap = DoctorSnapshot()
        snap.status = profile.status
        snap.overrides = vpn.overrides(for: profile.id)
        snap.ovpn = vpn.ovpnText(id: profile.id) ?? ""
        snap.stats = reach?.stats(for: profile.id)
        snap.stalledSeconds = stalled
        snap.topology = topo?.topology ?? NetworkTopology()
        snap.incident = vpn.incidents[profile.id]
        snap.requiresOTP = requiresOTP
        snap.captivePortalSuspected = vpn.captivePortalSuspected && vpn.incidents[profile.id] != nil
        if let probe = vpn.probeResults[profile.id] {
            snap.pathMTU = probe.pathMTU
            // "UDP is blocked" = the VPN uses UDP, its connect failed with a
            // network error, yet plain web (TCP 443) is reachable on this network.
            let networkIncident = snap.incident.map { $0.category == .network || $0.category == .timeout } ?? false
            snap.udpBlockedTCP443Open = (!probeSpeaksTLS && networkIncident && probe.tcp443Reachable == true)
        }
        return snap
    }
    private var doctorFindings: [DoctorFinding] { ConnectionDoctor.findings(for: doctorSnapshot) }
    /// The source that will actually be used — which is not always the one
    /// stored: "type it this time" (the recovery path) and a password app with
    /// nothing linked both come out as manual, so the form on screen is the form
    /// the connect will really use. See `VPNController.effectiveCredentialKind`.
    var credentialKind: CredentialSourceKind { vpn.effectiveCredentialKind(for: profile.id) }   // was private — internal for the file split
    var usesManager: Bool { credentialKind != .manual }   // was private — internal for the file split

    /// First time versus every other time, in one place. Everything it turns on
    /// is a plain fact about this VPN; the decision itself is pure and tested
    /// (SignInFlow.step).
    var signInStep: SignInFlowStep {   // internal: read by the body
        var inputs = SignInFlowInputs()
        inputs.collectsNothing = profile.kind == .tailscale || profile.kind == .proxyTunnel
            || profile.kind == .wireGuard || isAutologin
        let source = vpn.credentialSource(for: profile.id)
        inputs.chosenKind = source.kind
        inputs.chosenSourceAvailable = sources.canServe(source)
            // An in-force "type it this time" has already answered the recovery
            // question — don't keep asking it.
            || vpn.typedSignInOnce.contains(profile.id)
        inputs.hasConnectedBefore = !neverConnected
        inputs.hasStoredSignIn = hasStoredSignIn
        inputs.dismissedForNow = setupDismissed
        return SignInFlow.step(inputs)
    }

    /// Is there already a sign-in for this VPN? Saved credentials, a Touch
    /// ID-protected item, or a password app with something linked — any of them
    /// means the question has been answered once already.
    private var hasStoredSignIn: Bool {
        let source = vpn.credentialSource(for: profile.id)
        if source.kind != .manual {
            return !source.reference.trimmingCharacters(in: .whitespaces).isEmpty
        }
        if BiometricCredentialStore.exists(profile: profile.id) { return true }
        if let saved = KeychainCredentialStore.loadCredentials(profile: profile.id),
           !saved.password.isEmpty { return true }
        return false
    }
    /// A manager source still needs a typed OTP only when the profile requires
    /// one AND the manager can't supply it (Apple Passwords can't; 1Password
    /// and KeePassXC can).
    private var managerNeedsTypedOTP: Bool {
        usesManager && requiresOTP && !credentialKind.suppliesOTP
    }

    // One live credential state shared with the menu bar and edit sheet:
    // typing anywhere shows everywhere. Memory-only until Remember persists it.
    private var username: Binding<String> {
        Binding(get: { vpn.transientCredentials(for: profile.id).username },
                set: { var c = vpn.transientCredentials(for: profile.id); c.username = $0
                       vpn.setTransientCredentials(c, for: profile.id) })
    }
    private var password: Binding<String> {
        Binding(get: { vpn.transientCredentials(for: profile.id).password },
                set: { var c = vpn.transientCredentials(for: profile.id); c.password = $0
                       vpn.setTransientCredentials(c, for: profile.id) })
    }
    private var otp: Binding<String> {
        Binding(get: { vpn.transientCredentials(for: profile.id).otp },
                set: { var c = vpn.transientCredentials(for: profile.id); c.otp = $0
                       vpn.setTransientCredentials(c, for: profile.id) })
    }
    /// Protection can only start once there's a sign-in to protect.
    private var canEnableProtection: Bool {
        let c = vpn.transientCredentials(for: profile.id)
        if !c.username.isEmpty && !c.password.isEmpty { return true }
        if let saved = KeychainCredentialStore.loadCredentials(profile: profile.id),
           !saved.username.isEmpty, !saved.password.isEmpty { return true }
        return vpn.authConfig(for: profile.id).protectWithBiometrics
    }

    /// The Touch ID toggle: flipping it MOVES the secret between stores (see
    /// VPNController.setBiometricProtection), so the write happens on change,
    /// not on some later save.
    private var protectBinding: Binding<Bool> {
        Binding(get: { vpn.authConfig(for: profile.id).protectWithBiometrics },
                set: { on in
                    Task {
                        do { try await vpn.setBiometricProtection(on, for: profile.id) }
                        catch is CancellationError {}
                        catch { vpn.lastError = error.localizedDescription }
                    }
                })
    }

    /// The shared Remember preference (persisted with the profile's auth config).
    private var remember: Binding<Bool> {
        Binding(get: { vpn.authConfig(for: profile.id).rememberCredentials },
                set: { on in
                    var auth = vpn.authConfig(for: profile.id)
                    auth.rememberCredentials = on
                    Task { try? await vpn.setAuthConfig(auth, for: profile.id) }
                    if !on { KeychainCredentialStore.deleteCredentials(profile: profile.id) }
                })
    }

    /// Touch ID-protected saved credentials (manual source only).
    private var biometricInfo: (exists: Bool, hasTOTP: Bool) {
        guard !usesManager, vpn.authConfig(for: profile.id).protectWithBiometrics else { return (false, false) }
        return BiometricCredentialStore.info(profile: profile.id)
    }
    var isProtected: Bool { biometricInfo.exists }   // was private — internal for the file split

    /// Enabled exactly when the shared readiness decision says so — the SAME
    /// source of truth the sidebar play button and menu row read, so the two
    /// controls can never disagree (Tailscale/autologin/proxy included).
    var canConnect: Bool {   // was private — internal for the file split
        vpn.connectReadiness(for: profile.id) == .ready
    }

    /// Warn (and gate Connect behind a second click): this is a Tailscale profile, an
    /// official Tailscale client is already running, and we're not already up. Two
    /// Tailscale datapaths at once conflict — it has panicked the kernel — so we don't
    /// recommend starting ours alongside theirs.
    var tailscaleConflict: Bool {   // was private — internal for the file split
        profile.kind == .tailscale && tailscaleClientsRunning && !UI.isActive(profile.status)
    }

    /// Re-read whether an official Tailscale client is running; drop the two-phase arm
    /// if the conflict has gone away (they quit their app), so a stale red "Connect
    /// anyway" doesn't linger.
    private func refreshTailscaleClients() {
        let running = TailscaleConflict.isOfficialClientRunning
        tailscaleClientsRunning = running
        if !running { tailscaleConflictArmed = false }
    }

    var body: some View {
        // Scroll rather than grow: a long detail (Doctor cards + incident +
        // endpoint + credentials) must stay inside the window, not resize it.
        ScrollView {
            VStack(spacing: 20) {
                header
                // The engine's own doctor outranks per-VPN concerns: when the
                // system extension needs a (consent-gated) repair, nothing
                // below can work until it happens — say so first, quietly.
                if let extDoctor, let surface = extDoctor.surface {
                    ExtensionDoctorCard(doctor: extDoctor, surface: surface)
                }
                // Default-gateway picker (PolicyRouting.md Tier 2) moved OUT of this
                // window — too prominent for non-technical users to find here. It
                // now lives in VPN ▸ Routes, alongside the route graph and the
                // drift/diff indicators it's naturally paired with (see
                // RouteGraphView's compact `gatewayBar`).
                // Sign-in comes FIRST, directly under the Connect row it feeds —
                // username/password/OTP are what the button is waiting for, so they
                // must not sit below the fold behind panels and pickers.
                if !UI.isActive(profile.status), !vpn.isReconfiguring(profile.id) {
                    // A fresh import knows how to REACH the VPN but nothing about
                    // how you SIGN IN (a gresearch.conf import defaults to plain
                    // username/password — wrong for an OTP gateway, and the user
                    // has no way to know that yet). Hold their hand right here
                    // until the first successful connect proves the setup.
                    // Tailscale has nothing to type: it signs itself in with a
                    // setup key or a browser, so neither the credential form nor
                    // the first-connect credential coaching applies.
                    if profile.kind == .tailscale {
                        tailscalePanel
                    } else if profile.kind == .proxyTunnel {
                        proxyTunnelPanel
                    } else if profile.kind == .wireGuard {
                        wireGuardPanel
                    } else if isAutologin {
                        // Autologin: the profile's certificate signs in by
                        // itself, so there is no credential form to show and
                        // no "how do you sign in" questions to ask.
                        Label("This VPN signs in automatically — no username or password needed.",
                              systemImage: "checkmark.seal")
                            .font(.callout).foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    } else {
                        // First time versus every other time is ONE decision
                        // (SignInFlow.step) rather than three views each guessing:
                        // ask only when nothing is set up, never re-ask a VPN
                        // that has connected, and when the chosen password app
                        // has gone away say so HERE instead of letting the
                        // connect discover it.
                        switch signInStep {
                        case .chooseHowToSignIn:
                            FirstConnectSetupCard(vpn: vpn, profile: profile,
                                                  allowsPasswordSave: allowPasswordSave,
                                                  dismissed: $setupDismissed.animation(.snappy(duration: 0.25)))
                                .transition(reduceMotion ? AnyTransition.opacity : AnyTransition(.blurReplace))
                        case .recoverUnavailableSource(let kind):
                            SignInSourceRecoveryNotice(
                                kind: kind,
                                onTypeItOnce: {
                                    vpn.setTypedSignInOnce(true, for: profile.id)
                                    focusedField = firstMissingField
                                },
                                onChange: { showSignInChooser = true })
                                .transition(reduceMotion ? AnyTransition.opacity : AnyTransition(.blurReplace))
                        case .connectStraightThrough, .nothingToCollect:
                            EmptyView()
                        }
                        if usesManager { managerForm } else { credentialForm }
                    }
                    if let incident = vpn.incidents[profile.id] {
                        ConnectionIncidentCard(vpn: vpn, profile: profile, incident: incident,
                                               host: probeHost, port: probePort, speaksTLS: probeSpeaksTLS)
                    }
                }
                // A sign-in page is holding this network's traffic hostage — nothing
                // can connect until the user gets through it, so it outranks the
                // softer "couldn't reach it here before" memory below.
                if !UI.isActive(profile.status), !vpn.isReconfiguring(profile.id),
                   vpn.captivePortalSuspected {
                    CaptivePortalBanner(vpn: vpn)
                        .transition(reduceMotion ? AnyTransition.opacity
                                                 : AnyTransition(.blurReplace))
                }
                // Directly under the Connect row it's warning about — a pre-emptive
                // "this network couldn't reach it last time" is useless below the fold.
                // Hidden once a session is live: the warning is about STARTING one, and
                // success is what clears the memory anyway. Keyed on the warning text so
                // switching networks fades the old one out rather than snapping.
                if !UI.isActive(profile.status), !vpn.isReconfiguring(profile.id),
                   let warning = netMemory.knownUnreachableHere(profile: profile.id) {
                    UnreachableHereBanner(vpnName: profile.name, networkLabel: warning) {
                        netMemory.clear(profile: profile.id)
                    }
                    .transition(reduceMotion ? AnyTransition.opacity
                                             : AnyTransition(.blurReplace))
                    .animation(reduceMotion ? nil : .snappy(duration: 0.3), value: warning)
                }
                // "Nobody has ever proven this VPN type works." Below the urgent
                // banners on purpose — it is a standing fact, not something that
                // just happened — but above the optional panels, because the
                // moment before a connect is when it matters and the moment after
                // is when a report is worth most. Shown whatever the status: a
                // connect that SUCCEEDED against an untested kind is the single
                // most valuable thing anyone can tell us. One line here serves
                // all sixteen kinds; the claim itself lives in the maturity
                // registry and nowhere else.
                if let notice = profile.kind.maturityNotice {
                    MaturityBanner(notice: notice,
                                   request: .init(kind: profile.kind, profileID: profile.id,
                                                  reason: .untestedKind))
                }
                if vpn.hasPendingSettings(id: profile.id) {
                    PendingSettingsNotice(vpn: vpn, profileID: profile.id)
                }
                // Advanced surface, opt-in per VPN (Manage VPNs ▸ this VPN):
                // health checks and connection toggles most people never touch.
                if uiPrefs.showConnectionManager {
                    ConnectionManagerPanel(vpn: vpn, profileID: profile.id, vpnName: profile.name,
                                           snapshot: doctorSnapshot, findings: doctorFindings)
                }
                // Say "connected" in WORDS, not just the dot — a lone red stop
                // button next to a green dot asks the user to know the iconography.
                // Sits above the map; deliberately makes no claims about which
                // traffic is protected (that's the tunnel-mode toggle's story).
                if vpn.displayStatus(for: profile.id) == .connected, !vpn.isReconfiguring(profile.id), !isPaused,
                   !bannerCollapsed {
                    ConnectedBanner(vpnName: profile.name, server: profile.server,
                                    uptime: reach?.stats(for: profile.id)?.uptime)
                        .matchedGeometryEffect(id: "connectedChip", in: connectedBannerNS)
                        .transition(reduceMotion ? AnyTransition.opacity : AnyTransition(.blurReplace))
                }
                // The endpoint picker (and its little map) lives HERE, always — one
                // fixed home below the Connection Manager. It used to appear in the
                // middle column when disconnected and in the inspector when live, which
                // put a second world map under the topology one.
                EndpointSection(vpn: vpn, profile: profile)
                if UI.isActive(profile.status) || vpn.isReconfiguring(profile.id) {
                    Divider()
                    connectedBody
                }
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(minWidth: 440)
        .navigationTitle(profile.name)
        .disabled(busy)
        .task { loadOnce() }
        // Detect a conflicting official Tailscale client with a light 2s poll (cheap:
        // it reads an in-process array). NSWorkspace's launch/quit notifications are
        // unreliable for menu-bar/agent apps like Tailscale, so polling is the honest
        // approach — and it keeps this view pure SwiftUI. A profile switch also
        // re-checks and resets the arm (see below).
        .task {
            while !Task.isCancelled {
                refreshTailscaleClients()
                try? await Task.sleep(for: .seconds(2))
            }
        }
        .onChange(of: profile.id) { _, _ in
            tailscaleConflictArmed = false
            refreshTailscaleClients()
        }
        // NetworkMemory now watches the path itself, so this is only the initial read;
        // switching Wi-Fi updates it without any view having to notice.
        .task(id: profile.id) { await netMemory.refresh() }

        .task(id: UI.isActive(profile.status)) {
            // "Appears from" flips when the tunnel comes up or goes away. Throughput
            // is served by the shared app-wide store, so there's no per-view poller.
            await publicIP.refresh()
        }
        .task(id: isStalled) {
            // A live stall at the ~1400-byte boundary is the MTU-blackhole signal.
            // Size the path once so the Doctor can offer an exact mssfix.
            if isStalled { await vpn.measurePathMTU(host: probeHost, for: profile.id) }
        }
        // "Connecting" that never resolves is the common wrong-network case: say so
        // after a grace period instead of spinning silently for ever.
        .task(id: profile.status) {
            connectingTooLong = false
            guard profile.status == .connecting else { return }
            try? await Task.sleep(for: .seconds(20))
            if !Task.isCancelled, profile.status == .connecting { connectingTooLong = true }
        }
        // The sidebar play button (and menu bar) land here when this VPN still
        // needs typing: focus the first empty field and shake it. `initial` +
        // consume: a nudge that switched the selection lands before this view
        // exists, so check on appearance too — the one-shot claim keeps a later
        // revisit from replaying it.
        .onChange(of: vpn.credentialNudge[profile.id] ?? 0, initial: true) { _, _ in
            if vpn.consumeCredentialNudge(id: profile.id) { nudgeMissingInput() }
        }
        // A different network means the sign-in-page verdict is stale — drop the
        // banner rather than accusing the new Wi-Fi of the old one's portal.
        .onChange(of: netMemory.current?.key) { _, _ in
            vpn.captivePortalSuspected = false
            vpn.captivePortalURL = nil
        }
        // First-success detection for the setup card: the baseline is written a
        // few seconds after .connected, so re-check on status changes too.
        .task(id: profile.id) {
            neverConnected = ConnectionBaselineStore.load(profile: profile.id) == nil
        }
        .onChange(of: profile.status) { _, new in
            if new == .connected { neverConnected = false }
        }
        // The big "Connected" banner shows for 5s on connect, then shrinks to
        // the header chip. Reset the moment the tunnel isn't cleanly connected.
        .task(id: profile.status) {
            guard profile.status == .connected, !isPaused else {
                bannerCollapsed = false
                return
            }
            try? await Task.sleep(for: .seconds(5))
            guard !Task.isCancelled, profile.status == .connected, !isPaused else { return }
            withAnimation(reduceMotion ? nil : .smooth(duration: 0.45)) { bannerCollapsed = true }
        }
    }

    /// Effective probe target with overrides applied (what a connect would use).
    private var probeHost: String {
        let overrides = vpn.overrides(for: profile.id)
        if let s = overrides.server { return s }
        let eval = vpn.ovpnText(id: profile.id).map { evaluator.evaluation(for: $0) }
        return eval?.remoteHostOrNil ?? profile.server
    }
    private var probePort: Int {
        let overrides = vpn.overrides(for: profile.id)
        if let p = overrides.port { return p }
        let eval = vpn.ovpnText(id: profile.id).map { evaluator.evaluation(for: $0) }
        return eval?.remotePortOrNil ?? 1194
    }
    private var probeSpeaksTLS: Bool {
        let overrides = vpn.overrides(for: profile.id)
        if let p = overrides.proto { return p == .tcp }
        let eval = vpn.ovpnText(id: profile.id).map { evaluator.evaluation(for: $0) }
        return eval?.remoteProto.lowercased().hasPrefix("tcp") ?? false
    }

    /// While connected the middle column carries only status banners — the live
    /// graph, map and details live in the inspector (third) column.
    @ViewBuilder private var connectedBody: some View {
        VStack(alignment: .leading, spacing: 16) {
            // A Tailscale connect waiting on the browser sign-in: say so, and
            // keep the URL reachable — a dismissed tab must not be a dead end.
            if profile.status == .connecting, profile.kind == .tailscale,
               vpn.tailscaleSignInURL[profile.id] != nil {
                TailscaleSignInBanner { vpn.openTailscaleSignIn(id: profile.id) }
            }
            if profile.status == .connecting, connectingTooLong,
               vpn.tailscaleSignInURL[profile.id] == nil {   // the sign-in banner already explains the wait
                StuckConnectingBanner(vpnName: profile.name, host: probeHost) {
                    vpn.disconnect(id: profile.id)
                }
            }
            if isPaused {
                PausedBanner { Task { await vpn.resume(id: profile.id) } }
            }
            // No stalled/reconnecting banners here any more: connection state has
            // ONE spot in the window (the header badge + its problem chip). The
            // paused banner stays because it's a safety warning about traffic
            // outside the VPN, not a state duplicate — and pause is opt-in anyway.
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// What stands in for the credential form on a WireGuard VPN: the keys are
    /// the sign-in, so there is nothing to type — only a pointer at the editor
    /// while the config still needs something.
    @ViewBuilder private var wireGuardPanel: some View {
        if let problem = vpn.wireGuardConfig(for: profile.id).connectProblem {
            Label(problem, systemImage: "exclamationmark.triangle")
                .font(.callout).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
        } else if !vpn.wireGuardHasPrivateKey(profile.id) {
            Label("Set this tunnel's private key first — open Manage VPNs and paste it under Set / Replace Key.",
                  systemImage: "key")
                .font(.callout).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
        } else {
            Label("This VPN signs in with its keys — nothing to type.",
                  systemImage: "checkmark.seal")
                .font(.callout).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    /// What stands in for the credential form on a Tailscale/Headscale VPN.
    /// Says what will happen rather than asking for something that doesn't
    /// exist, and points at the one place a setup key can be entered.
    @ViewBuilder private var tailscalePanel: some View {
        let status = vpn.tailscaleStatuses[profile.id]
        let signInURL = vpn.tailscaleSignInURL[profile.id]
        VStack(alignment: .leading, spacing: 8) {
            // Read out here: the keyframe closure below is @Sendable and can't
            // touch the main-actor environment.
            let pulses = !reduceMotion
            if tailscaleConflict {
                // The official Tailscale app is running. Starting ours as well puts two
                // wireguard/gVisor datapaths on the same Mac — they fight over magicsock
                // and the tun injection path, and in the field this has crashed the
                // kernel. Steer hard away from it; Connect is two-phase below.
                Label {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("The official Tailscale app is already running.")
                            .fontWeight(.semibold)
                        Text("Running two Tailscale connections at once can conflict — it has crashed the Mac. We don't recommend starting this one alongside it.")
                            .foregroundStyle(.secondary)
                    }
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.red.opacity(0.10), in: RoundedRectangle(cornerRadius: 10))
                // "Connect Anyway" doesn't connect — it sends the user HERE, so the
                // warning gives a small double bump ("bump-bump") to catch the eye
                // before they confirm with "I Understand". Pure shapes and text, so
                // scaling it is safe (no platform-backed views in a transform).
                // Reduce Motion: no pulse — the button label change carries it.
                .keyframeAnimator(initialValue: 1.0, trigger: conflictNudge) { view, scale in
                    view.scaleEffect(pulses ? scale : 1, anchor: .center)
                } keyframes: { _ in
                    KeyframeTrack(\.self) {
                        SpringKeyframe(1.045, duration: 0.11)
                        SpringKeyframe(1.0, duration: 0.11)
                        SpringKeyframe(1.045, duration: 0.11)
                        SpringKeyframe(1.0, duration: 0.17)
                    }
                }
                .accessibilityAddTraits(.isStaticText)
            }
            if let status, status.backendState.needsUserAction {
                Label(status.backendState == .needsMachineAuth
                      ? "Waiting for someone to approve this Mac on your network."
                      : "Waiting for you to sign in. The sign-in page should have opened in your browser.",
                      systemImage: "person.badge.key")
                    .foregroundStyle(.orange)
                if status.backendState == .needsLogin {
                    // Re-opens the engine's login URL in the default browser —
                    // the way back when the tab was closed. Disabled until the
                    // engine has actually issued one.
                    Button("Open Sign-In Page") { vpn.openTailscaleSignIn(id: profile.id) }
                        .disabled(signInURL == nil)
                }
            } else if let status, status.backendState == .running {
                Label("This Mac is on the network as \(status.selfDNSName.isEmpty ? status.primaryIPv4 : status.selfDNSName).",
                      systemImage: "checkmark.circle")
                    .foregroundStyle(.secondary)
                if status.peerCount > 0 {
                    Text("\(status.peersOnline) of \(status.peerCount) machines online.")
                        .font(.callout).foregroundStyle(.secondary)
                }
            } else {
                Label("This VPN signs itself in — with a setup key, or by opening a sign-in page the first time.",
                      systemImage: "point.3.connected.trianglepath.dotted")
                    .foregroundStyle(.secondary)
            }
        }
        .font(.callout)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// What stands in for the credential form on a Proxy Tunnel. Says what will
    /// happen and points at the editor for the upstream/credentials, rather than
    /// asking for something the connect row doesn't own.
    @ViewBuilder private var proxyTunnelPanel: some View {
        let config = vpn.proxyTunnelConfig(for: profile.id)
        VStack(alignment: .leading, spacing: 8) {
            if let problem = config.connectProblem {
                Label(problem, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            } else {
                Label("Every connection is dialled through \(config.proxyHost.isEmpty ? "the proxy" : config.proxyHost).",
                      systemImage: "arrow.triangle.branch")
                    .foregroundStyle(.secondary)
                if config.requiresAuth {
                    let creds = vpn.proxyTunnelCredentials(for: profile.id)
                    let ok = !creds.username.isEmpty && !creds.password.isEmpty
                    Label(ok ? "Sign-in details are saved."
                             : "This proxy needs a username and password — add them in this VPN's settings.",
                          systemImage: ok ? "checkmark.circle" : "person.badge.key")
                        .foregroundStyle(ok ? Color.secondary : Color.orange)
                }
            }
        }
        .font(.callout)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// Manager-source form: credentials come from 1Password / Apple Passwords /
    /// KeePassXC on connect. Only shows an OTP field when the manager can't
    /// supply one.
    private var managerForm: some View {
        VStack(alignment: .leading, spacing: 12) {
            // A statement, not a question — this VPN's sign-in is already
            // decided. The Change button is the whole "unobtrusive way to change
            // it" requirement: one click, right here, no trip to Manage VPNs.
            SignInSourceSummary(
                option: SignInSourceCatalog.option(
                    for: credentialKind, remembers: true,
                    facts: sources.facts(allowsPasswordSave: allowPasswordSave)),
                footnote: managerFootnote,
                onChange: { showSignInChooser = true })
                .signInChooserPopover(isPresented: $showSignInChooser, vpn: vpn, profile: profile,
                                      allowsPasswordSave: allowPasswordSave, sources: sources)
            if managerNeedsTypedOTP {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 10) {
                    verificationCodeGridRow
                }
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 380)
                securityKeyPrompt
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .onAppear {
            if managerNeedsTypedOTP { focusedField = .otp }
            prepareSecurityKey()
        }
    }

    // MARK: The verification-code row, and the security key behind it

    /// ONE code row, shared by all three credential forms (typed, Touch
    /// ID-protected, and password-app). It used to be copy-pasted three times,
    /// which is how the security key's return policy would have reached two of
    /// them and not the third.
    ///
    /// `returnPolicy` is what stops a security key's own trailing Return from
    /// firing Connect — see UI/Credentials/YubiKeyTouchPrompt.swift. It is nil
    /// unless a key is actually set up for this VPN, so every other VPN's code
    /// field behaves exactly as it always has.
    @ViewBuilder private var verificationCodeGridRow: some View {
        GridRow {
            Text("Code").gridColumnAlignment(.trailing).foregroundStyle(.secondary)
            AutoFillField(kind: .oneTimeCode, placeholder: "Verification code",
                          text: otp, focus: $focusedField, focusValue: .otp,
                          onSubmit: attemptConnect,
                          returnPolicy: yubiKeyActive ? yubiKeyReturnPolicy : nil)
                .requiredEmphasis(missing: otp.wrappedValue.isEmpty, attempted: submitAttempted, nudge: nudgeTick)
        }
    }

    /// "Touch your key now", when this VPN is set up for one. Absent otherwise —
    /// no dormant row, no hint of a feature nobody switched on.
    @ViewBuilder private var securityKeyPrompt: some View {
        if yubiKeyActive {
            YubiKeyTouchPrompt(capture: yubiKeyCapture, config: yubiKeyConfig,
                               presence: yubiKeyPresence, arm: armSecurityKey)
                .frame(maxWidth: 380)
        }
    }

    /// Arm the wait — and, crucially, put the cursor where the code must land.
    /// FOCUS IS THE FEATURE: a key types into whatever has focus, so an armed state
    /// that has not moved focus is a trap rather than a help.
    private func armSecurityKey() {
        yubiKeyCapture.mechanism = yubiKeyConfig.mechanism
        yubiKeyCapture.delivery = yubiKeyConfig.delivery
        // A stale code in the box would be indistinguishable from the fresh one
        // about to arrive, and `observe` matches on the box's whole contents.
        if !yubiKeyConfig.mechanism.capturesInPasswordField {
            otp.wrappedValue = YubiKeyComposition.clearedCodeField()
            focusedField = .otp
        } else {
            focusedField = .password
        }
        yubiKeyCapture.arm(wait: yubiKeyConfig.effectiveWait,
                           passwordSoFar: password.wrappedValue)
        if yubiKeyConfig.mechanism.needsManagerTool {
            Task { await fetchSecurityKeyCode() }
        }
    }

    /// The FETCHED mechanisms (an OATH code, a challenge-response answer): nothing
    /// is typed, so SimpleVPN asks `ykman` and puts the answer in the box itself.
    /// The armed state still exists, because both can need a physical touch.
    private func fetchSecurityKeyCode() async {
        let config = yubiKeyConfig
        do {
            let code: SingleUseCode
            switch config.mechanism {
            case .oathCode:
                code = try await YubiKeyManagerTool().oathCode(
                    account: config.oathAccount, serial: config.normalizedSerial)
            case .challengeResponse:
                // Nothing here has a gateway challenge to answer yet — that
                // arrives from the engine, and wiring it is the engine side's
                // work. Until then this mechanism is configurable and honest
                // about needing a challenge rather than silently doing nothing.
                yubiKeyCapture.cancel()
                vpn.lastError = "Answering a challenge needs the challenge from your VPN\u{2019}s "
                    + "server, which SimpleVPN doesn\u{2019}t have yet for this kind of VPN."
                return
            case .yubicoOTP, .staticPassword:
                return
            }
            // Straight into the box, then straight out of the box object: the
            // field is now the only holder, and it is cleared the moment the code
            // is spent.
            if let value = code.consume() {
                otp.wrappedValue = value
                _ = yubiKeyCapture.observe(fieldText: value)
            }
        } catch is CancellationError {
        } catch {
            yubiKeyCapture.cancel()
            vpn.lastError = error.localizedDescription
        }
    }

    /// Called as each credential form appears: gather what is plugged in, build the
    /// return policy, and — when this VPN asks for it — arm the wait straight away
    /// so the cursor is already in the right box when the user reaches for the key.
    ///
    /// Auto-arming is a SETTING (`yk.arm-automatically`, on by default) rather than
    /// an assumption: an armed field that quietly swallows a Return is exactly the
    /// behaviour some people will want to turn off.
    private func prepareSecurityKey() {
        refreshSecurityKeyPresence()
        guard yubiKeyActive, yubiKeyConfig.armAutomatically,
              yubiKeyCapture.state == .idle else { return }
        armSecurityKey()
    }

    /// Re-read what is plugged in. Cheap (IORegistry plus one file check), so it is
    /// safe on appear and on every window activation.
    private func refreshSecurityKeyPresence() {
        guard yubiKeyConfig.enabled else { return }
        var next = SecurityKeyPresence()
        next.keys = IORegistrySecurityKeyScanner().scan()
        next.managerToolInstalled = YkmanRunner().locate() != nil
        if next != yubiKeyPresence { yubiKeyPresence = next }
        if yubiKeyReturnPolicy == nil {
            yubiKeyReturnPolicy = YubiKeyFieldReturnPolicy(capture: yubiKeyCapture) { _ in
                // A code has landed. Focus moves on to whatever is still empty, so
                // the person who just touched their key is not left with a cursor
                // in a box that is already full.
                focusedField = firstMissingField
            }
        }
        yubiKeyCapture.mechanism = yubiKeyConfig.mechanism
        yubiKeyCapture.delivery = yubiKeyConfig.delivery
    }

    /// The code to send, taking it out of its single-use box on the way.
    ///
    /// THE no-retry guard, at the one point it matters: a second call gets nil,
    /// the box is empty, the field is cleared, and `ConnectReadiness` therefore
    /// reports `.needsCode` — so a retry asks for a fresh touch instead of
    /// replaying a code the gateway has already burned.
    private func typedOTPForConnect() -> String {
        guard yubiKeyActive, yubiKeyCapture.state.hasUnspentCode else {
            return vpn.transientCredentials(for: profile.id).otp
        }
        let taken = yubiKeyCapture.consumeCode() ?? ""
        // Out of the visible box as well. A spent code left on screen is a code
        // someone will believe in.
        if !yubiKeyConfig.mechanism.capturesInPasswordField {
            otp.wrappedValue = YubiKeyComposition.clearedCodeField()
        }
        return taken
    }

    /// What connecting will feel like, per password app — a wrong promise here
    /// ("Touch ID" for an app that shows a different dialog) reads as a bug.
    private var managerFootnote: String {
        switch credentialKind {
        case .onePassword: "1Password will ask for Touch ID when you connect."
        case .keePassXC: "KeePassXC will ask to allow access when you connect (and to unlock first, if the database is locked)."
        case .keeper: "Keeper Commander answers without asking, as long as it is signed in on this Mac."
        case .bitwarden: "Bitwarden answers without asking, as long as its local service (\u{201C}bw serve\u{201D}) is running with your vault unlocked."
        default: "macOS will ask permission to read the saved password the first time."
        }
    }

    // Inline credentials so you can connect straight from here (Remember saves them).
    @ViewBuilder private var credentialForm: some View {
        if isProtected { protectedForm } else { typedCredentialForm }
    }

    /// The steady state of the fingerprint flow: no fields at all, just the
    /// promise of the prompt. The only field that can appear is the code, and
    /// only for an OTP profile with no stored authenticator secret.
    private var protectedForm: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: "touchid")
                    .font(.title2)
                    .foregroundStyle(.pink)
                    .accessibilityHidden(true)   // decorative; the text says "Touch ID"
                VStack(alignment: .leading, spacing: 2) {
                    Text("Sign-in protected by Touch ID").font(.callout.weight(.semibold))
                    Text(requiresOTP && biometricInfo.hasTOTP
                         ? "Connecting asks for your fingerprint, which unlocks the username, password and verification code in one go."
                         : "Connecting asks for your fingerprint to unlock the saved sign-in.")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                Menu {
                    Button("Change How You Sign In\u{2026}") { showSignInChooser = true }
                    Button("Remove Touch ID Protection…") {
                        Task {
                            do { try await vpn.setBiometricProtection(false, for: profile.id) }
                            catch is CancellationError {}
                            catch { vpn.lastError = error.localizedDescription }
                        }
                    }
                } label: {
                    Image(systemName: "ellipsis.circle").frame(width: 28, height: 22).contentShape(Rectangle())
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
                .help("Change how these credentials are stored")
                .accessibilityLabel("Credential protection options")
            }
            .padding(12)
            .background(.pink.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
            .signInChooserPopover(isPresented: $showSignInChooser, vpn: vpn, profile: profile,
                                  allowsPasswordSave: allowPasswordSave, sources: sources)

            if requiresOTP && !biometricInfo.hasTOTP {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 10) {
                    verificationCodeGridRow
                }
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 380)
                securityKeyPrompt
                Text("Add your authenticator's setup key in Manage VPNs and the fingerprint will cover the code too.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        // Same courtesy as the typed form: if a code is needed, the cursor is
        // already in the field that needs it.
        .onAppear { focusedField = firstMissingField; prepareSecurityKey() }
    }

    private var typedCredentialForm: some View {
        VStack(alignment: .leading, spacing: 14) {
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 10) {
                GridRow {
                    Text("Username").gridColumnAlignment(.trailing).foregroundStyle(.secondary)
                    // A userlocked profile fixes the username: prefilled (see
                    // loadOnce) and read-only, matching the editor's behaviour.
                    AutoFillField(kind: .username, placeholder: "Username",
                                  text: username, focus: $focusedField, focusValue: .username,
                                  onSubmit: attemptConnect)
                        .disabled(!lockedUsername.isEmpty)
                        .requiredEmphasis(missing: username.wrappedValue.isEmpty && lockedUsername.isEmpty,
                                          attempted: submitAttempted, nudge: nudgeTick)
                        .help(lockedUsername.isEmpty ? "" : "This VPN's configuration fixes the username.")
                }
                GridRow {
                    Text("Password").gridColumnAlignment(.trailing).foregroundStyle(.secondary)
                    AutoFillField(kind: .password, placeholder: "Password",
                                  text: password, focus: $focusedField, focusValue: .password,
                                  onSubmit: attemptConnect)
                        .requiredEmphasis(missing: password.wrappedValue.isEmpty, attempted: submitAttempted, nudge: nudgeTick)
                }
                if requiresOTP {
                    verificationCodeGridRow
                }
            }
            .textFieldStyle(.roundedBorder)
            .frame(maxWidth: 380)
            securityKeyPrompt

            if allowPasswordSave {
                Toggle("Remember username & password", isOn: remember)
                    .toggleStyle(.checkbox)
                // The fingerprint upgrade: saved credentials move into a Touch
                // ID-gated keychain item; the plain copy is destroyed. Only
                // offered once there's something to protect.
                Toggle("Protect them with Touch ID", isOn: protectBinding)
                    .toggleStyle(.checkbox)
                    .disabled(!canEnableProtection)
                    .help("Connecting will ask for your fingerprint (or Apple Watch, or your password) to unlock the sign-in.")
                if requiresOTP, vpn.authConfig(for: profile.id).protectWithBiometrics {
                    Text("Tip: add your authenticator's setup key in Manage VPNs so the fingerprint covers the verification code too.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            } else {
                Label("This VPN's administrator doesn't allow saving the password.",
                      systemImage: "key.slash")
                    .font(.caption).foregroundStyle(.secondary)
            }

            // WHO holds the secret, in the same words the chooser's keychain row
            // uses — one explanation of the keychain across the whole app.
            Text(requiresOTP
                 ? "A remembered password is kept in the Apple keychain, where macOS protects it. The verification code is used once and never stored."
                 : "A remembered password is kept in the Apple keychain, where macOS protects it \u{2014} SimpleVPN keeps no copy of its own.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            // The quiet way to change your mind, for a VPN that is already set
            // up: the first-run chooser is gone by then, and Manage VPNs is a
            // long way to go to switch to 1Password.
            Button("Change how you sign in\u{2026}") { showSignInChooser = true }
                .buttonStyle(.link)
                .font(.caption)
                .help("Choose a different way to sign in to this VPN \u{2014} type it, save it securely, or use a password app")
                .accessibilityHint("Choose a different way to sign in to this VPN: type it each time, save it securely, or use a password app.")
                .signInChooserPopover(isPresented: $showSignInChooser, vpn: vpn, profile: profile,
                                      allowsPasswordSave: allowPasswordSave, sources: sources)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .onAppear {
            // Cursor lands in the first field that actually needs typing.
            focusedField = firstMissingField
            prepareSecurityKey()
        }
    }

    var firstMissingField: CredentialField? {   // was private — internal for the file split
        // Nothing to type at all for these — a nudge must not focus a field
        // that isn't on screen.
        if profile.kind == .tailscale || profile.kind == .proxyTunnel
            || profile.kind == .wireGuard || isAutologin { return nil }
        // The manager/protected forms render at most an OTP field.
        if usesManager { return managerNeedsTypedOTP ? .otp : nil }
        if isProtected { return (requiresOTP && !biometricInfo.hasTOTP) ? .otp : nil }
        let c = vpn.transientCredentials(for: profile.id)
        return (c.username.isEmpty && lockedUsername.isEmpty) ? .username
             : c.password.isEmpty ? .password
             : requiresOTP ? .otp : nil
    }

    private func attemptConnect() {
        if canConnect {
            // Through connectTask, same as the Connect button: an Enter-initiated
            // connect must be cancellable by the same ✕ a clicked one is.
            connectTask = Task { await connect() }
        } else {
            nudgeMissingInput()
        }
    }

    private func loadOnce() {
        guard !loaded else { return }
        loaded = true
        // Materialize the shared credential state (prefills from the keychain)
        // so every surface sees the same values from here on.
        var creds = vpn.transientCredentials(for: profile.id)
        // A userlocked username always wins — the row is read-only, so a stale
        // saved value could otherwise never be corrected.
        if !lockedUsername.isEmpty { creds.username = lockedUsername }
        vpn.transientCreds[profile.id] = creds
    }

    func connect() async {   // was private — internal for the file split
        busy = true; defer { busy = false }
        submitAttempted = false
        // (allowsPasswordSaveEvaluator is wired once at app launch — see SimpleVPNApp.)
        do {
            try await vpn.connectUsingConfiguredSource(
                id: profile.id,
                // Not the raw field: `typedOTPForConnect` takes the code out of
                // its single-use box, so a retry cannot replay it.
                typedOTP: typedOTPForConnect())
        } catch is CancellationError {
            // The user backed out — that's an outcome, not an error to report.
        } catch {
            // Log AND alert: an alert can be missed/dismissed, and a connect
            // that dies without a trace is undiagnosable from a capture.
            VPNController.log.error("connect failed for \(profile.id, privacy: .public): \(error.localizedDescription, privacy: .public)")
            // report(profile:) — not lastError — so the sheet's Try Again knows
            // which VPN to re-run, and the redactor knows this profile's secrets.
            vpn.report(error, profile: profile.id)
        }
    }
}

/// The "fill in this required field" emphasis: quiet until the user actually
/// tries to connect, then a soft accent ring around each still-empty required
/// field (the closest native idiom — no dedicated Liquid Glass component exists).
/// `nudge` adds the kinetic half: each bump gives every still-empty field a
/// small sideways shake — the "no, over here" gesture for a click on a Connect
/// button that's waiting on input. Reduce Motion suppresses the shake; the ring
/// and focus placement carry the message alone.
private struct RequiredFieldEmphasis: ViewModifier {
    let missing: Bool
    let attempted: Bool
    var nudge: Int = 0
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    private var active: Bool { missing && attempted }

    func body(content: Content) -> some View {
        content
            .overlay(
                RoundedRectangle(cornerRadius: 6)
                    .strokeBorder(Color.accentColor.opacity(active ? 0.8 : 0), lineWidth: 2)
                    .animation(.easeInOut(duration: 0.25), value: active)
            )
            .modifier(ShakeEffect(animatableData: CGFloat((missing && !reduceMotion) ? nudge : 0)))
            .accessibilityValue(active ? "Required" : "")
    }
}

/// Three quick 4pt side-to-side cycles per nudge unit — enough to catch the eye,
/// small enough not to read as an error condition.
private struct ShakeEffect: GeometryEffect {
    var animatableData: CGFloat
    func effectValue(size: CGSize) -> ProjectionTransform {
        ProjectionTransform(CGAffineTransform(
            translationX: 4 * sin(animatableData * .pi * 6), y: 0))
    }
}

private extension View {
    func requiredEmphasis(missing: Bool, attempted: Bool, nudge: Int = 0) -> some View {
        modifier(RequiredFieldEmphasis(missing: missing, attempted: attempted, nudge: nudge))
    }
}
