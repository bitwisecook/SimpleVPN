// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ExtensionDoctorTests.swift
//  Pins the extension doctor's pure ladder — the decision standing between a
//  wedged system extension and a non-technical user's live tunnel:
//    • the escalation order (ping → resession → upgrade → bounce → restart),
//      each rung tried once, never looping;
//    • THE POLICY: any remedy that could drop an engaged tunnel is marked
//      disruptive and demands consent — verified by sweeping every snapshot
//      shape, not just the happy paths — while the two quiet rungs never are;
//    • version comparison never calls "mismatch" on an unknown ("?", empty,
//      "unavailable") — a disruptive remedy must not run on a guess;
//    • the doctor stays silent when no extension is installed at all (the
//      first-connect flow owns the approval dialog, not the doctor).
//

import Foundation
import Testing
@testable import SimpleVPN

struct ExtensionDoctorTests {

    private let bundled = "v0.3 (build 7)"
    private let older = "v0.2 (build 6)"

    private func facts(_ id: String, name: String? = nil,
                       unattended: Bool = true) -> ExtensionHealthSnapshot.ProfileFacts {
        .init(id: id, name: name ?? id.uppercased(), canReconnectUnattended: unattended)
    }

    private func snapshot(engaged: [ExtensionHealthSnapshot.ProfileFacts] = [],
                          dead: [String]? = nil,
                          running: String? = nil,
                          installed: String? = nil,
                          refreshed: Bool = false,
                          upgraded: Bool = false,
                          bounced: Bool = false) -> ExtensionHealthSnapshot {
        var s = ExtensionHealthSnapshot()
        s.engaged = engaged
        s.deadSessions = dead
        s.runningVersion = running
        s.installedVersion = installed
        s.bundledVersion = bundled
        s.sessionRefreshed = refreshed
        s.upgradeAttempted = upgraded
        s.bounced = bounced
        return s
    }

    // MARK: - Healthy / idle

    @Test func healthyPingWithMatchingVersionDoesNothing() {
        let step = ExtensionDoctorLadder.nextStep(
            snapshot(engaged: [facts("a")], dead: [], running: bundled, installed: bundled))
        #expect(step.remedy == .none)
        #expect(!step.disruptive)
        #expect(!step.needsConsent)
    }

    @Test func idleWithNothingInstalledStaysQuiet() {
        // No extension on the system: activation is the first-connect flow's
        // moment (it raises the macOS approval dialog) — never the doctor's.
        let step = ExtensionDoctorLadder.nextStep(snapshot())
        #expect(step.remedy == .none)
    }

    @Test func idleStaleInstalledUpgradesSilently() {
        // Nothing connected ⇒ the silent same-team upgrade is allowed to be
        // automatic (the policy's one carve-out).
        let step = ExtensionDoctorLadder.nextStep(snapshot(installed: older))
        #expect(step.remedy == .upgradeExtension)
        #expect(!step.disruptive)
        #expect(!step.needsConsent)
        #expect(step.affectedNames.isEmpty)
    }

    @Test func idleUpgradeIsTriedOnceThenGoesQuiet() {
        let step = ExtensionDoctorLadder.nextStep(snapshot(installed: older, upgraded: true))
        #expect(step.remedy == .none)
    }

    @Test func connectingTunnelGatesTheIdleUpgrade() {
        // "Up" for the policy includes on-the-way-up: a connecting tunnel has
        // no pingable session, but replacing the extension would still kill it.
        let step = ExtensionDoctorLadder.nextStep(
            snapshot(engaged: [facts("a", name: "GR Lab")], installed: older))
        #expect(step.remedy == .upgradeExtension)
        #expect(step.disruptive)
        #expect(step.needsConsent)
        #expect(step.affectedNames == ["GR Lab"])
    }

    // MARK: - The escalation order

    @Test func firstPingFailureReconnectsSessionsSilently() {
        // Cheapest theory first: the app's session objects went stale. That
        // rung never touches the tunnel, so it's automatic even when connected.
        let step = ExtensionDoctorLadder.nextStep(
            snapshot(engaged: [facts("a")], dead: ["a"]))
        #expect(step.remedy == .reconnectSession)
        #expect(!step.disruptive)
        #expect(!step.needsConsent)
    }

    @Test func staleRunningVersionWithLiveTunnelNeedsConsent() {
        let step = ExtensionDoctorLadder.nextStep(
            snapshot(engaged: [facts("a", name: "GR Lab")], dead: [],
                     running: older, installed: older))
        #expect(step.remedy == .upgradeExtension)
        #expect(step.disruptive)
        #expect(step.needsConsent)
        #expect(step.affectedNames == ["GR Lab"])
    }

    @Test func deadAndStaleUpgradesBeforeBouncing() {
        // A wedged session on an old build: replace the build first — bouncing
        // a tunnel at a broken engine would just fail twice.
        let step = ExtensionDoctorLadder.nextStep(
            snapshot(engaged: [facts("a")], dead: ["a"], installed: older, refreshed: true))
        #expect(step.remedy == .upgradeExtension)
        #expect(step.disruptive)
    }

    @Test func refreshedButDeadSameVersionBounces() {
        let step = ExtensionDoctorLadder.nextStep(
            snapshot(engaged: [facts("a", name: "GR Lab")], dead: ["a"],
                     installed: bundled, refreshed: true))
        #expect(step.remedy == .bounceTunnels(["a"]))
        #expect(step.disruptive)
        #expect(step.needsConsent)
        #expect(step.affectedNames == ["GR Lab"])
    }

    @Test func bounceTargetsOnlyTheDeadSessions() {
        // One healthy session proves the engine process is alive — the wedge is
        // per-tunnel, so only the dead one is bounced (and named).
        let step = ExtensionDoctorLadder.nextStep(
            snapshot(engaged: [facts("a", name: "Alive"), facts("b", name: "Wedged")],
                     dead: ["b"], running: bundled, installed: bundled, refreshed: true))
        #expect(step.remedy == .bounceTunnels(["b"]))
        #expect(step.affectedNames == ["Wedged"])
    }

    @Test func everythingTriedLandsOnTheRestartCard() {
        let step = ExtensionDoctorLadder.nextStep(
            snapshot(engaged: [facts("a")], dead: ["a"], installed: bundled,
                     refreshed: true, bounced: true))
        #expect(step.remedy == .restartEngine)
        #expect(step.disruptive)
        #expect(step.needsConsent)
    }

    @Test func mismatchSurvivingAnUpgradeEscalatesToRestart() {
        // The upgrade was submitted and the engine still reports the old build
        // (e.g. the swap needs a reboot) — don't loop the upgrade; escalate.
        let step = ExtensionDoctorLadder.nextStep(
            snapshot(engaged: [facts("a")], dead: [], running: older, upgraded: true))
        #expect(step.remedy == .restartEngine)
        #expect(step.needsConsent)
    }

    @Test func restartNeedsConsentEvenWithNothingConnected() {
        // The last rung re-runs the approval dance — never a surprise, even idle.
        let step = ExtensionDoctorStep(remedy: .restartEngine, disruptive: true, affectedNames: [])
        #expect(step.needsConsent)
    }

    // MARK: - The policy, swept

    /// Every snapshot shape with something engaged: a remedy that could drop a
    /// tunnel (upgrade/bounce/restart) must be disruptive AND consent-gated;
    /// the quiet rungs (none/resession) must never be. This is the binding
    /// "never disrupt a live tunnel without informed consent" rule as a sweep,
    /// so a future ladder edit can't quietly open a silent-disruption path.
    @Test func noDisruptiveRemedyEverRunsSilentlyWhileEngaged() {
        let engaged = [facts("a", name: "GR Lab"), facts("b", name: "Office", unattended: false)]
        let deadOptions: [[String]?] = [nil, [], ["a"], ["a", "b"]]
        let versions: [String?] = [nil, bundled, older, "unknown", "v? (build ?)"]
        let bools = [false, true]
        for dead in deadOptions {
            for running in versions {
                for installed in versions {
                    for refreshed in bools {
                        for upgraded in bools {
                            for bounced in bools {
                                let step = ExtensionDoctorLadder.nextStep(snapshot(
                                    engaged: engaged, dead: dead, running: running,
                                    installed: installed, refreshed: refreshed,
                                    upgraded: upgraded, bounced: bounced))
                                switch step.remedy {
                                case .none, .reconnectSession:
                                    #expect(!step.disruptive)
                                    #expect(!step.needsConsent)
                                case .upgradeExtension, .bounceTunnels, .restartEngine:
                                    #expect(step.disruptive)
                                    #expect(step.needsConsent)
                                    #expect(!step.affectedNames.isEmpty)
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: - Version comparison

    @Test func equalVersionsAreNotAMismatch() {
        #expect(!ExtensionDoctorLadder.versionMismatch(running: bundled, bundled: bundled))
    }

    @Test func differentKnownVersionsAreAMismatch() {
        #expect(ExtensionDoctorLadder.versionMismatch(running: older, bundled: bundled))
    }

    @Test func unknownsNeverTriggerAMismatch() {
        // A disruptive remedy must never run on a guess.
        #expect(!ExtensionDoctorLadder.versionMismatch(running: nil, bundled: bundled))
        #expect(!ExtensionDoctorLadder.versionMismatch(running: "", bundled: bundled))
        #expect(!ExtensionDoctorLadder.versionMismatch(running: "unknown", bundled: bundled))
        #expect(!ExtensionDoctorLadder.versionMismatch(running: "unavailable", bundled: bundled))
        #expect(!ExtensionDoctorLadder.versionMismatch(running: "v? (build ?)", bundled: bundled))
        #expect(!ExtensionDoctorLadder.versionMismatch(running: older, bundled: "unknown"))
        #expect(!ExtensionDoctorLadder.versionMismatch(running: older, bundled: ""))
    }
}
