// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ExtensionDoctor.swift
//  Self-healing for the packet-tunnel system extension. A remedy LADDER where
//  every rung verifies (re-pings) before escalating:
//
//    1. ping      — IPC liveness probe (2 s) against every connected session,
//                   plus the version handshake (running vs bundled).
//    2. resession — reload the NETunnelProviderManagers so the app holds live
//                   provider-message session objects again; ping again. Never
//                   touches the tunnel itself.
//    3. upgrade   — the running/installed extension is older (or newer) than
//                   the app: submit the activation request — the standard
//                   same-team silent upgrade. Restarts the extension process.
//    4. bounce    — same version but a session is wedged: stop + reconnect the
//                   affected tunnel(s); unattended only where the credential
//                   source can serve the whole sign-in without the user.
//    5. restart   — still dead: deactivate → activate the whole engine. Never
//                   automatic — offered as a card on the Doctor surface.
//
//  THE POLICY (binding): never disrupt a live tunnel without informed consent.
//  Rungs 1–2 are non-disruptive and always automatic; rungs 3–5 restart the
//  extension or drop tunnels, so while anything is up they STOP and ask first —
//  one warning naming the affected connections ("your VPN connection will drop
//  and you'll need to sign in again"), Heal Now / Not Now. "Not Now" leaves a
//  quiet card on the Doctor surface, never a nag loop. Silent automatic healing
//  is allowed only when nothing is connected (or the step can't drop anything).
//
//  The DECISION is the pure ladder below (state in → next rung + the
//  disruptive/consent bits), pinned by ExtensionDoctorTests; the @Observable
//  controller under it does the gathering, the consent UX and the remedies.
//

import Foundation
import AppKit
import SwiftUI
import os

// MARK: - The ladder (pure, testable)

/// The facts one check-up gathers. Assembled on the main actor from live
/// sources; the decision below is a pure function of it.
nonisolated struct ExtensionHealthSnapshot: Equatable {
    /// One profile a remedy may have to take down (and put back).
    struct ProfileFacts: Equatable {
        var id: String
        var name: String
        /// Whether a reconnect needs the user (fresh one-time code, unsaved
        /// password) — VPNController.canReconnectUnattended at gather time.
        var canReconnectUnattended: Bool
    }

    /// Everything up or on its way up (connected/connecting/reasserting) —
    /// what a disruptive remedy would drop. The policy gates on THIS, not just
    /// `.connected`: a tunnel mid-handshake is equally the user's to lose.
    var engaged: [ProfileFacts] = []
    /// The connected profiles whose 2 s IPC ping went unanswered. nil ⇒ nothing
    /// was connected, so there was no session to ask — no liveness verdict.
    var deadSessions: [String]?
    /// Version the running extension reported over IPC (nil = no answer).
    var runningVersion: String?
    /// Version systemextensionsd says is installed (nil = none on the system).
    var installedVersion: String?
    /// Version of the .systemextension bundled inside this app.
    var bundledVersion: String = ""

    // What this episode already tried — each rung is attempted once, then the
    // ladder escalates. It can never loop on a remedy that didn't take.
    var sessionRefreshed = false
    var upgradeAttempted = false
    var bounced = false
}

nonisolated enum ExtensionRemedy: Equatable {
    case none                       // healthy (or nothing the doctor can do)
    case reconnectSession           // rung 2: reload managers, re-ping
    case upgradeExtension           // rung 3: activation request (silent same-team upgrade)
    case bounceTunnels([String])    // rung 4: profile ids whose sessions are dead
    case restartEngine              // rung 5: deactivate → activate (Doctor card only)

    var name: String {
        switch self {
        case .none: "none"
        case .reconnectSession: "reconnect-session"
        case .upgradeExtension: "upgrade-extension"
        case .bounceTunnels: "bounce-tunnels"
        case .restartEngine: "restart-engine"
        }
    }
}

/// The ladder's verdict: what to do next, and whether doing it needs the
/// user's blessing first.
nonisolated struct ExtensionDoctorStep: Equatable {
    var remedy: ExtensionRemedy
    /// Could this drop a live tunnel? THE POLICY BIT: a disruptive step never
    /// runs silently while anything is engaged.
    var disruptive: Bool
    /// Names of the connections the remedy would drop — what the warning lists.
    var affectedNames: [String]
    /// Consent is required for anything disruptive that touches live
    /// connections — and for an engine restart ALWAYS, even idle: it re-runs
    /// the approval dance and must never be a surprise.
    var needsConsent: Bool {
        (disruptive && !affectedNames.isEmpty) || remedy == .restartEngine
    }
}

nonisolated enum ExtensionDoctorLadder {

    /// State in → next rung out. Pure; pinned by ExtensionDoctorTests.
    static func nextStep(_ s: ExtensionHealthSnapshot) -> ExtensionDoctorStep {
        let engagedNames = s.engaged.map(\.name)
        let mismatch = versionMismatch(running: s.runningVersion ?? s.installedVersion,
                                       bundled: s.bundledVersion)

        guard let dead = s.deadSessions else {
            // Nothing connected — no session to ping. The one health question
            // left is staleness of the INSTALLED copy; upgrading it is the
            // standard silent same-team replace. Never submit an activation
            // when no extension is installed: that would raise the macOS
            // approval dialog uninvited (the first-connect flow owns that).
            if mismatch, s.installedVersion != nil, !s.upgradeAttempted {
                return .init(remedy: .upgradeExtension,
                             disruptive: !engagedNames.isEmpty,   // a connecting tunnel still counts
                             affectedNames: engagedNames)
            }
            return .init(remedy: .none, disruptive: false, affectedNames: [])
        }

        if dead.isEmpty {
            // Every session answers — the engine is alive. Only staleness can
            // still be wrong.
            if mismatch {
                return s.upgradeAttempted
                    ? .init(remedy: .restartEngine, disruptive: true, affectedNames: engagedNames)
                    : .init(remedy: .upgradeExtension, disruptive: !engagedNames.isEmpty,
                            affectedNames: engagedNames)
            }
            return .init(remedy: .none, disruptive: false, affectedNames: [])
        }

        // A connected session isn't answering. Cheapest theory first: the APP's
        // session objects went stale (every saveToPreferences can replace
        // mgr.connection) — reloading them costs the tunnel nothing.
        if !s.sessionRefreshed {
            return .init(remedy: .reconnectSession, disruptive: false, affectedNames: [])
        }
        // Fresh sessions and still no answer: if the extension is a different
        // build than the app, replace it before bouncing tunnels at it.
        if mismatch, !s.upgradeAttempted {
            return .init(remedy: .upgradeExtension, disruptive: !engagedNames.isEmpty,
                         affectedNames: engagedNames)
        }
        // Same version, wedged: bounce exactly the dead tunnels.
        if !s.bounced {
            let deadNames = s.engaged.filter { dead.contains($0.id) }.map(\.name)
            return .init(remedy: .bounceTunnels(dead), disruptive: true,
                         affectedNames: deadNames.isEmpty ? engagedNames : deadNames)
        }
        return .init(remedy: .restartEngine, disruptive: true, affectedNames: engagedNames)
    }

    /// Version strings compare exactly ("v0.3 (build 12)" — the one format both
    /// the IPC reply and bundledExtensionVersion emit). Mismatch only when BOTH
    /// sides are known: "unknown"/"unavailable"/"?" must never trigger a
    /// disruptive remedy on a guess.
    static func versionMismatch(running: String?, bundled: String) -> Bool {
        guard let running, isKnown(running), isKnown(bundled) else { return false }
        return running != bundled
    }

    private static func isKnown(_ v: String) -> Bool {
        !v.isEmpty && v != "unknown" && v != "unavailable" && !v.contains("?")
    }
}

// MARK: - The controller (gathering, consent UX, remedies)

@MainActor
@Observable
final class ExtensionDoctor {

    static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "extdoctor")

    enum Trigger: String {
        case launch          // app start (.task)
        case connectGate     // the ensureExtensionReady seam, before a connect
        case statsTimeout    // a connected tunnel's stats IPC stopped answering
        case doctorCard      // the user pressed the Doctor card's button
    }

    /// The quiet indicator on the Doctor surface: a postponed heal ("Not Now")
    /// or the ladder's last rung waiting for the user. Never a nag loop — while
    /// this is up, automatic runs keep verifying but never re-alert.
    struct Surface: Equatable {
        enum Kind { case postponed, restartEngine }
        var kind: Kind
        var title: String
        var detail: String
        var actionLabel: String
    }

    private(set) var surface: Surface?

    /// What the control plane tells out-of-process callers (the CLI) while a
    /// consent-gated repair is pending: they cannot grant consent — only the
    /// app's own warning can — so a wire connect gets a clean "not ready".
    var connectBlockedMessage: String? {
        guard surface != nil else { return nil }
        return "SimpleVPN's VPN engine needs a repair that can drop live connections — open SimpleVPN to approve it"
    }

    private let vpn: VPNController
    private let ext: ExtensionController

    /// Single-flight + debounce: one wedge produces one doctor, not a stack
    /// (the stats poll can report the same dead extension once a second).
    @ObservationIgnored private var running = false
    @ObservationIgnored private var lastCompleted: Date?
    private static let debounce: TimeInterval = 20
    private static let pingTimeout: TimeInterval = 2

    /// Per-run memory: which rungs ran, and whether the user already consented
    /// (one warning covers the run — the drop it warned about has happened).
    private struct Episode {
        var sessionRefreshed = false
        var upgradeAttempted = false
        var bounced = false
        var restarted = false
        var consentGranted = false
        /// Set while a postponed heal is already on the Doctor surface:
        /// automatic runs keep verifying but must never re-raise the alert.
        var consentSuppressed = false
    }

    init(vpn: VPNController, ext: ExtensionController) {
        self.vpn = vpn
        self.ext = ext
        // Trigger 3: stats-IPC timeout detection. fetchStats reports a
        // connected tunnel that stopped answering — the classic dead-extension
        // symptom — and the debounce above absorbs the once-a-second repeats.
        vpn.statsTimeoutHook = { [weak self] id in
            Self.log.log("stats IPC timeout for \(id, privacy: .public) — waking the extension doctor")
            Task { [weak self] in await self?.checkUp(trigger: .statsTimeout) }
        }
    }

    /// The Doctor card's button: re-run the ladder as a user action (no
    /// debounce, no suppression) — the consent alert is the actual gate.
    func healFromCard() async {
        await checkUp(trigger: .doctorCard)
    }

    /// One check-up: gather → decide → remedy → re-gather, until healthy or out
    /// of rungs. Every pass re-verifies, so a remedy must PROVE it worked (the
    /// next ping) before the doctor goes quiet.
    func checkUp(trigger: Trigger) async {
        guard !running else { return }   // single-flight
        if trigger != .doctorCard, let last = lastCompleted,
           Date().timeIntervalSince(last) < Self.debounce { return }
        running = true
        defer { running = false; lastCompleted = Date() }

        Self.log.log("check-up begins (trigger: \(trigger.rawValue, privacy: .public))")
        var episode = Episode()
        // "Not Now" must not become a nag: while a heal is already surfaced,
        // automatic runs verify quietly and leave the card as the way back in.
        if trigger != .doctorCard, surface != nil { episode.consentSuppressed = true }

        // Bounded by the ladder's own escalation (each rung runs once).
        for _ in 0..<5 {
            let snap = await gather(episode: episode)
            let step = ExtensionDoctorLadder.nextStep(snap)
            switch step.remedy {
            case .none:
                Self.log.log("check-up ends: healthy (running \(snap.runningVersion ?? snap.installedVersion ?? "n/a", privacy: .public), bundled \(snap.bundledVersion, privacy: .public))")
                if surface != nil, trigger == .doctorCard {
                    ToastCenter.shared.post("The VPN engine is healthy again.",
                                            symbol: "checkmark.seal.fill", tint: .green, seconds: 6)
                }
                surface = nil
                return

            case .reconnectSession:
                Self.log.log("remedy: re-establish NE sessions (non-disruptive)")
                episode.sessionRefreshed = true
                await vpn.loadAll()

            case .upgradeExtension:
                guard consent(step, episode: &episode) else { postpone(step); return }
                Self.log.log("remedy: upgrade extension — engine \(snap.runningVersion ?? snap.installedVersion ?? "unknown", privacy: .public) vs app \(snap.bundledVersion, privacy: .public)")
                episode.upgradeAttempted = true
                await upgradeExtension(engaged: snap.engaged, disruptive: step.disruptive)

            case .bounceTunnels(let ids):
                guard consent(step, episode: &episode) else { postpone(step); return }
                Self.log.log("remedy: bounce wedged tunnel(s) \(ids.joined(separator: ", "), privacy: .public)")
                episode.bounced = true
                await bounce(snap.engaged.filter { ids.contains($0.id) })

            case .restartEngine:
                // The heaviest remedy is NEVER automatic: it runs only off the
                // Doctor card, where the user has just been warned — and once
                // per run, so a restart that didn't take escalates to a person.
                if trigger == .doctorCard, !episode.restarted, consent(step, episode: &episode) {
                    Self.log.log("remedy: restart engine (deactivate → activate)")
                    episode.restarted = true
                    await restartEngine(engaged: snap.engaged)
                } else {
                    offerRestartCard(affecting: step.affectedNames)
                    return
                }
            }
        }
        // Out of rungs without a clean bill — leave the card as the way forward.
        offerRestartCard(affecting: vpn.profiles.filter { vpn.isEngaged(id: $0.id) }.map(\.name))
    }

    // MARK: Gathering (rung 1 is the gather itself)

    private func gather(episode: Episode) async -> ExtensionHealthSnapshot {
        var snap = ExtensionHealthSnapshot()
        snap.bundledVersion = SystemExtensionManager.bundledExtensionVersion
        snap.sessionRefreshed = episode.sessionRefreshed
        snap.upgradeAttempted = episode.upgradeAttempted
        snap.bounced = episode.bounced
        snap.engaged = vpn.profiles.filter { vpn.isEngaged(id: $0.id) }.map {
            .init(id: $0.id, name: $0.name,
                  canReconnectUnattended: vpn.canReconnectUnattended(id: $0.id))
        }
        // Ping: only a CONNECTED profile has a session obliged to answer.
        let connected = vpn.profiles.filter { $0.status == .connected }
        if !connected.isEmpty {
            var dead: [String] = []
            for p in connected {
                if let data = await vpn.sendMessageData("version", to: p.id, timeout: Self.pingTimeout),
                   let v = String(data: data, encoding: .utf8), !v.isEmpty {
                    if snap.runningVersion == nil { snap.runningVersion = v }
                } else {
                    dead.append(p.id)
                }
            }
            snap.deadSessions = dead
        }
        snap.installedVersion = await SystemExtensionManager.installedExtensionVersion()
        return snap
    }

    // MARK: Consent (the policy's teeth)

    private func consent(_ step: ExtensionDoctorStep, episode: inout Episode) -> Bool {
        guard step.needsConsent else { return true }   // silent is allowed here
        if episode.consentGranted { return true }
        guard !episode.consentSuppressed else { return false }
        guard presentConsentAlert(step) else { return false }
        episode.consentGranted = true
        return true
    }

    /// One warning, following the app's alert conventions (see the quit gate in
    /// SimpleVPNApp): what's wrong, what healing costs, the affected connections
    /// BY NAME, and two honest buttons.
    private func presentConsentAlert(_ step: ExtensionDoctorStep) -> Bool {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Heal the VPN engine?"
        var text = explanation(for: step.remedy)
        if step.affectedNames.isEmpty {
            text += "\n\nNothing is connected right now, so no connection will drop."
        } else {
            text += "\n\nYour VPN connection will drop and you\u{2019}ll need to sign in again:\n\n"
                + step.affectedNames.map { "\u{2022}  \($0)" }.joined(separator: "\n")
                + "\n\nSimpleVPN reconnects what it can by itself; anything needing a fresh code will ask you."
        }
        alert.informativeText = text
        alert.addButton(withTitle: "Heal Now")
        alert.addButton(withTitle: "Not Now")
        NSApp.activate()
        return alert.runModal() == .alertFirstButtonReturn
    }

    private func explanation(for remedy: ExtensionRemedy) -> String {
        switch remedy {
        case .upgradeExtension:
            "SimpleVPN\u{2019}s VPN engine is running a different version than the app. Updating it restarts the engine."
        case .bounceTunnels:
            "The VPN engine stopped answering. Reconnecting the affected VPN usually clears it."
        case .restartEngine:
            "The VPN engine isn\u{2019}t responding, and restarting it is the remaining fix."
        case .none, .reconnectSession:
            ""   // never asked — these run silently by design
        }
    }

    /// "Not Now" (or suppressed consent): a quiet card on the Doctor surface,
    /// holding the door open without ever knocking again.
    private func postpone(_ step: ExtensionDoctorStep) {
        Self.log.log("heal awaits consent (\(step.remedy.name, privacy: .public)) — surfaced on the Doctor card")
        let names = step.affectedNames.joined(separator: ", ")
        surface = Surface(
            kind: .postponed,
            title: "The VPN engine still needs healing",
            detail: names.isEmpty
                ? "A repair is waiting. Heal when you\u{2019}re ready."
                : "Healing was postponed. When you heal, \(names) will drop and need signing in again.",
            actionLabel: "Heal Now")
    }

    private func offerRestartCard(affecting names: [String]) {
        Self.log.log("ladder exhausted — offering the engine-restart card")
        surface = Surface(
            kind: .restartEngine,
            title: "Restart the VPN engine",
            detail: names.isEmpty
                ? "The VPN engine isn\u{2019}t responding. Restarting it should fix that."
                : "The VPN engine isn\u{2019}t responding. Restarting it should fix that — \(names.joined(separator: ", ")) will drop and need signing in again.",
            actionLabel: "Restart Engine\u{2026}")
    }

    // MARK: Remedies (rungs 3–5)

    private func upgradeExtension(engaged: [ExtensionHealthSnapshot.ProfileFacts], disruptive: Bool) async {
        // Deterministic order: stop what the replace would kill anyway, swap
        // the extension, then bring back what was actually up.
        let wasConnected = engaged.filter { f in
            vpn.profiles.first { $0.id == f.id }?.status == .connected
        }
        if disruptive { await stop(engaged) }
        await activateBounded()
        try? await Task.sleep(for: .seconds(1))   // let systemextensionsd swap the process in
        if disruptive { await bringBack(wasConnected) }
    }

    private func bounce(_ affected: [ExtensionHealthSnapshot.ProfileFacts]) async {
        await stop(affected)
        await bringBack(affected)
    }

    private func restartEngine(engaged: [ExtensionHealthSnapshot.ProfileFacts]) async {
        let wasConnected = engaged.filter { f in
            vpn.profiles.first { $0.id == f.id }?.status == .connected
        }
        await stop(engaged)
        do {
            try await SystemExtensionManager.deactivate()
            Self.log.log("engine deactivated")
        } catch {
            // Carry on: activation replaces whatever state deactivation left.
            Self.log.error("deactivate failed: \(error.localizedDescription, privacy: .public)")
        }
        await activateBounded()
        try? await Task.sleep(for: .seconds(1))
        await bringBack(wasConnected)
    }

    private func stop(_ profiles: [ExtensionHealthSnapshot.ProfileFacts]) async {
        guard !profiles.isEmpty else { return }
        for f in profiles { vpn.disconnect(id: f.id) }
        for _ in 0..<100 {   // ≤10 s for teardown, same bound as reconnect()
            if !profiles.contains(where: { vpn.isEngaged(id: $0.id) }) { break }
            try? await Task.sleep(for: .milliseconds(100))
        }
    }

    /// Reconnect what consent just dropped: unattended where the credential
    /// source can serve the whole sign-in, the sign-in flow where it can't —
    /// exactly what the warning said would happen.
    private func bringBack(_ profiles: [ExtensionHealthSnapshot.ProfileFacts]) async {
        for f in profiles {
            if f.canReconnectUnattended {
                if await vpn.connectWithSavedCredentials(id: f.id) {
                    watchForReturn(f)
                } else {
                    vpn.nudgeCredentials(id: f.id)
                }
            } else {
                vpn.nudgeCredentials(id: f.id)
                ToastCenter.shared.post("\(f.name) needs you to sign in again.",
                                        symbol: "person.badge.key", seconds: 10)
            }
        }
    }

    /// The promised toast when a healed VPN actually comes back.
    private func watchForReturn(_ f: ExtensionHealthSnapshot.ProfileFacts) {
        Task { [weak self] in
            for _ in 0..<450 {   // ≤45 s — the connect watchdog's own deadline
                guard let self else { return }
                if self.vpn.profiles.first(where: { $0.id == f.id })?.status == .connected {
                    ToastCenter.shared.post("\(f.name) is connected again.",
                                            symbol: "checkmark.circle.fill", tint: .green, seconds: 6)
                    return
                }
                try? await Task.sleep(for: .milliseconds(100))
            }
        }
    }

    /// Activation normally completes silently (same-team upgrade). If macOS
    /// wants approval instead, don't hold the doctor hostage — the wait is
    /// bounded and the existing approval UI (ActivationPrompt banner + toast)
    /// takes over from here. Unstructured on purpose: everything stays on the
    /// main actor (racing the MainActor call in a task group trips the
    /// region-isolation checker), and an abandoned activation simply finishes
    /// in the background and logs.
    private func activateBounded() async {
        let done = CompletionFlag()
        Task { await ext.activate(); done.value = true }   // inherits MainActor
        for _ in 0..<900 where !done.value {   // ≤90 s
            try? await Task.sleep(for: .milliseconds(100))
        }
        if !done.value {
            Self.log.log("activation still pending after 90 s — leaving it to the approval UI")
        }
    }

    /// Main-actor mutable box so the bounded wait above can watch a Task it
    /// deliberately doesn't await.
    private final class CompletionFlag { var value = false }
}
