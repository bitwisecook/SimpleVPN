// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DiagnosticReportAssembler.swift
//  Builds the payload, and hosts the dialog.
//
//  NOTHING HERE MEASURES ANYTHING. Every fact is read from whoever already owns
//  it: `ProbeLadderStore` for what the probe ladder found, `VPNController` for
//  status and the last failure-time probe, `SignInSourceAvailability` for the
//  vendor states and the tool-discovery map, `ManagedPolicy` for what an
//  administrator decided. Re-probing would report a DIFFERENT connection attempt
//  from the one being complained about — and on a Mac that has since moved
//  networks, a different network too.
//
//  The one exception, stated plainly because it is the sort of thing that gets
//  missed in review: `DiagnosticReportLog.collect` runs `/usr/bin/log show` for
//  our own subsystem. That reads a log; it sends no traffic and touches no server.
//

import SwiftUI
import AppKit

// MARK: - What the assembler is allowed to read

/// The live objects a report can be built from. All optional: the report degrades
/// to `not recorded — <reason>` rather than lying, and rather than refusing to
/// open at all.
@MainActor
struct DiagnosticReportContext {
    var vpn: VPNController?
    var tunnels: SubprocessTunnelStore?
    var reachability: ReachabilityMonitor?
    var linkState: LinkStateMonitor?
    var availability: SignInSourceAvailability = .shared
    var settings: SignInSourceSettingsStore = .shared

    /// How mature a VPN kind is — "tested", "untested", "partly verified".
    ///
    /// A CLOSURE, and deliberately so: the maturity registry belongs to the
    /// "Untested" banner, not to the report, and this file must not become a
    /// second place that decides which kinds are tested. Left unset, the report
    /// says the maturity was not recorded, which is honest and harmless.
    ///
    /// ONE-LINE WIRING: `context.maturity = { VPNMaturity.state(for: $0).title }`.
    var maturity: @MainActor (VPNKind) -> String? = { _ in nil }
}

// MARK: - Assembly

@MainActor
enum DiagnosticReportAssembler {

    /// Build the payload. `async` only because reading the log is.
    static func assemble(_ request: DiagnosticReportRequest,
                         context: DiagnosticReportContext,
                         answers: DiagnosticReportAnswers) async -> DiagnosticReportPayload {
        let scrubber = SecretScrubber(policy: .report,
                                     literalSecrets: literalSecrets(context: context))
        let facts = context.availability.facts

        var sections: [DiagnosticReportSection] = [
            whatHappened(request, answers: answers),
            appAndSystem(request, context: context),
            DiagnosticReportSection(
                id: .passwordManagers,
                fields: DiagnosticReportInventory.passwordManagerFields(facts: facts),
                emptyNote: context.settings.discoveryEnabled
                    ? "No password manager SimpleVPN knows about was found on this Mac."
                    : "SimpleVPN isn\u{2019}t looking for password managers on this Mac (that setting is off)."),
            toolsAndAPIs(context: context, facts: facts),
            activeAndReachable(request, context: context),
            DiagnosticReportSection(
                id: .switchedOff,
                fields: DiagnosticReportInventory.switchedOffFields(
                    settings: context.settings, facts: facts)),
        ]

        let log = await DiagnosticReportLog.collect(scrubber: scrubber)
        sections.append(logSection(log))

        return DiagnosticReportPayload(request: request, sections: sections, scrubber: scrubber)
    }

    /// Replace only the section that depends on what the user typed.
    ///
    /// The dialog calls this on every keystroke. Re-assembling would mean reading
    /// the system log again to reflect a typed character — the facts have not
    /// changed, and the dialog would stutter.
    static func rebuildWhatHappened(_ request: DiagnosticReportRequest,
                                    answers: DiagnosticReportAnswers,
                                    in payload: DiagnosticReportPayload) -> [DiagnosticReportSection] {
        payload.sections.map { section in
            section.id == .whatHappened ? whatHappened(request, answers: answers) : section
        }
    }

    // MARK: The user's own words

    private static func whatHappened(_ request: DiagnosticReportRequest,
                                     answers: DiagnosticReportAnswers) -> DiagnosticReportSection {
        var fields: [DiagnosticReportField] = []
        let doing = answers.whatYouWereDoing.trimmingCharacters(in: .whitespacesAndNewlines)
        let wrong = answers.whatWentWrong.trimmingCharacters(in: .whitespacesAndNewlines)
        fields.append(DiagnosticReportField(
            label: "What you were doing",
            value: doing.isEmpty ? .absent(reason: "left blank") : .userText(doing)))
        fields.append(DiagnosticReportField(
            label: "What went wrong",
            value: wrong.isEmpty ? .absent(reason: "left blank") : .userText(wrong)))
        fields.append(DiagnosticReportField(label: "Why SimpleVPN asked",
                                            value: .state(request.reason.rawValue)))
        return DiagnosticReportSection(id: .whatHappened, fields: fields)
    }

    // MARK: Versions, and how mature this kind is

    private static func appAndSystem(_ request: DiagnosticReportRequest,
                                     context: DiagnosticReportContext) -> DiagnosticReportSection {
        var fields: [DiagnosticReportField] = [
            DiagnosticReportField(label: "SimpleVPN", value: .version(UI.appVersion)),
            DiagnosticReportField(
                label: "System extension",
                value: context.vpn.map { ReportValue.version($0.extensionVersion) }
                    ?? .absent(reason: "the report was opened without the VPN controller attached")),
            DiagnosticReportField(label: "macOS",
                                  value: .version(ProcessInfo.processInfo.operatingSystemVersionString)),
            DiagnosticReportField(label: "Architecture", value: .state(IssueReport.architecture)),
        ]
        if let kind = request.kind {
            fields.append(DiagnosticReportField(label: "VPN type", value: .state(kind.displayName)))
            fields.append(DiagnosticReportField(
                label: "How well tested this type is",
                value: context.maturity(kind).map { ReportValue.state($0) }
                    ?? .absent(reason: "this build doesn\u{2019}t record a maturity for each VPN type")))
        }
        // A COUNT per type, never a name or an address — the same promise the
        // About window's report already makes.
        if let vpn = context.vpn {
            var counts: [VPNKind: Int] = [:]
            for profile in vpn.profiles { counts[profile.kind, default: 0] += 1 }
            for tunnel in context.tunnels?.tunnels ?? [] { counts[tunnel.kind, default: 0] += 1 }
            let summary = counts.isEmpty
                ? "none configured"
                : counts.sorted { $0.key.displayName < $1.key.displayName }
                    .map { "\($0.key.displayName) \u{00D7}\($0.value)" }
                    .joined(separator: ", ")
            fields.append(DiagnosticReportField(label: "VPN types configured", value: .words(summary)))
        }
        return DiagnosticReportSection(id: .appAndSystem, fields: fields)
    }

    // MARK: Tools, vendors, modules, keys

    private static func toolsAndAPIs(context: DiagnosticReportContext,
                                    facts: SignInSourceFacts) -> DiagnosticReportSection {
        var fields = DiagnosticReportInventory.vendorStateFields(facts: facts)
        fields += DiagnosticReportInventory.toolFields(
            discoveries: context.settings.discoveryEnabled ? context.availability.discoveries : [:])
        fields += DiagnosticReportInventory.pkcs11Fields()
        fields += DiagnosticReportInventory.securityKeyFields()
        return DiagnosticReportSection(id: .toolsAndAPIs, fields: fields)
    }

    // MARK: What was already measured

    /// Reuses the probe ladder, the last failure-time probe, the passive link
    /// health and what this network is remembered for. Runs no probe.
    private static func activeAndReachable(_ request: DiagnosticReportRequest,
                                          context: DiagnosticReportContext) -> DiagnosticReportSection {
        var fields: [DiagnosticReportField] = []

        guard let profileID = request.profileID, !profileID.isEmpty else {
            return DiagnosticReportSection(
                id: .activeAndReachable, fields: [],
                emptyNote: "This report isn\u{2019}t about one particular VPN, so there is nothing measured to include.")
        }

        if let vpn = context.vpn, let profile = vpn.profiles.first(where: { $0.id == profileID }) {
            fields.append(DiagnosticReportField(
                label: "Connection status when the report was made",
                value: .state(VPNController.statusText(profile.status))))
        }
        if let linkState = context.linkState {
            fields.append(DiagnosticReportField(label: "Link state",
                                                value: .state(String(describing: linkState.state(for: profileID)))))
        }
        if let health = context.reachability?.health(for: profileID) {
            fields.append(DiagnosticReportField(label: "Passive link health",
                                                value: .state(String(describing: health)),
                                                detail: [.words("judged from byte counters \u{2014} no probe traffic")]))
        }

        // The probe ladder, exactly as it was recorded. Every step's evidence has
        // already been through `ProbeEvidence.sanitise`; it goes through the
        // report scrubber again on the way out.
        if let ladder = ProbeLadderStore.shared.ladder(for: profileID) {
            fields.append(DiagnosticReportField(
                label: "Probe ladder",
                value: .words(ladder.summary),
                detail: [
                    .state("VPN type: \(ladder.kind.displayName)"),
                    .moment(ladder.startedAt),
                    ladder.elapsed.map { ReportValue.seconds($0) } ?? .absent(reason: "it didn\u{2019}t finish"),
                ]))
            for step in ladder.steps where step.status != .pending {
                var detail: [ReportValue] = [.words(step.detail)]
                detail += step.evidence.map { ReportValue.words($0) }
                if let remedy = step.remedy { detail.append(.words("suggested fix: \(remedy.title)")) }
                if step.securityFinding { detail.append(.words("flagged as a security finding")) }
                fields.append(DiagnosticReportField(label: "Probe: \(step.title)",
                                                    value: .state(step.status.rawValue),
                                                    detail: detail))
            }
        } else {
            fields.append(DiagnosticReportField(
                label: "Probe ladder",
                value: .absent(reason: "it hasn\u{2019}t been run for this VPN in this session, and SimpleVPN won\u{2019}t run it just to make a report")))
        }

        // The failure-time active probe, if one was taken. Dropped by its owner
        // whenever the Mac changes network, so its presence already means "this
        // was measured here".
        if let probe = context.vpn?.probeResults[profileID] {
            var detail: [ReportValue] = [
                .words("server reachable over TCP: " + boolWords(probe.tcpReachable)),
                .words("TCP 443 reachable: " + boolWords(probe.tcp443Reachable)),
                .flag(probe.dnsFailed),
            ]
            if let rtt = probe.rttMilliseconds { detail.append(.count(rtt)) }
            if let mtu = probe.pathMTU { detail.append(.words("path MTU: \(mtu)")) }
            if probe.captivePortal { detail.append(.words("a captive portal was in the way")) }
            detail += probe.baselineNotes.map { ReportValue.words($0) }
            fields.append(DiagnosticReportField(label: "Last failure-time probe",
                                                value: .words("recorded"), detail: detail))
        }

        if let remembered = NetworkMemory.shared.knownUnreachableHere(profile: profileID) {
            fields.append(DiagnosticReportField(
                label: "Remembered about this network",
                value: .words(remembered)))
        }
        if let baseline = ConnectionBaselineStore.load(profile: profileID) {
            fields.append(DiagnosticReportField(
                label: "Last time it worked",
                value: .moment(baseline.date)))
        }

        return DiagnosticReportSection(id: .activeAndReachable, fields: fields)
    }

    private static func boolWords(_ value: Bool?) -> String {
        guard let value else { return "not measured" }
        return value ? "yes" : "no"
    }

    // MARK: Log events

    private static func logSection(_ admitted: DiagnosticReportLog.Admitted) -> DiagnosticReportSection {
        var fields = admitted.fields
        if let failure = admitted.failure {
            fields.append(DiagnosticReportField(label: "Reading the log",
                                                value: .words(failure)))
        }
        if admitted.unrecognised > 0 {
            fields.append(DiagnosticReportField(
                label: "Left out",
                value: .count(admitted.unrecognised),
                detail: [.words("log events of SimpleVPN\u{2019}s own that are not one of the recognised kinds. Only known event types are included, so these are counted rather than quoted.")]))
        }
        if admitted.outsideAllowedCategories > 0 {
            fields.append(DiagnosticReportField(
                label: "Left out (other areas of the app)",
                value: .count(admitted.outsideAllowedCategories)))
        }
        return DiagnosticReportSection(
            id: .logEvents, fields: fields,
            emptyNote: "No log events of a recognised kind in the last twenty minutes.")
    }

    // MARK: Literals worth removing

    /// Values that identify this Mac or its owner. Handed to the scrubber so that
    /// if one turns up inside something the user typed, or inside a captured
    /// fragment of a log event, it is gone.
    private static func literalSecrets(context: DiagnosticReportContext) -> [String] {
        var out = SecretScrubber.machineIdentifiers()
        for profile in context.vpn?.profiles ?? [] {
            out.append(profile.name)
            out.append(profile.server)
        }
        for tunnel in context.tunnels?.tunnels ?? [] {
            out.append(tunnel.username)
        }
        return out.filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
    }
}

// MARK: - Hosting the dialog

/// The one live implementation of `DiagnosticReportPresenting`.
///
/// It hosts its own window rather than being a sheet on somebody else's, for a
/// practical reason: the request can arrive from an editor, from a connect-time
/// banner, from a list badge or from the Help menu, and a report that is a sheet
/// on whichever window happened to ask cannot be left open while the user goes
/// to look at the thing they are reporting.
@MainActor
final class DiagnosticReportCoordinator: NSObject, DiagnosticReportPresenting, NSWindowDelegate {

    static let shared = DiagnosticReportCoordinator()

    /// What the assembler may read. Set by `hostsDiagnosticReports()`, or
    /// directly by a caller that has the objects to hand.
    var context = DiagnosticReportContext()

    private var window: NSWindow?
    private var model: DiagnosticReportModel?

    func presentReport(_ request: DiagnosticReportRequest) {
        if let window {
            // Already open: re-aim it rather than stacking a second copy.
            window.makeKeyAndOrderFront(nil)
            model?.restart(with: request)
            return
        }
        let model = DiagnosticReportModel(request: request, context: context)
        self.model = model
        let hosting = NSHostingController(rootView: DiagnosticReportView(model: model))
        let window = ReportWindow(contentViewController: hosting)
        window.title = "Report a Problem"
        window.setContentSize(NSSize(width: 640, height: 720))
        window.isReleasedWhenClosed = false
        window.delegate = self
        window.center()
        window.makeKeyAndOrderFront(nil)
        self.window = window
    }

    /// Whether the dialog is on screen. Used by the smoke test, and by anything
    /// that wants to avoid offering a second copy.
    var isPresented: Bool { window != nil }

    func close() { window?.close() }

    /// The red button and `close()` both land here, so the references are dropped
    /// exactly once however the window went away.
    func windowWillClose(_ notification: Notification) {
        window = nil
        model = nil
    }

    /// ESC closes the window. An `NSWindow` does not do this for free, and a
    /// modal-feeling dialog that ignores ESC is a keyboard dead end — see
    /// `Docs/Accessibility.md`, "Keyboard driving".
    private final class ReportWindow: NSWindow {
        override func cancelOperation(_ sender: Any?) { close() }
    }
}

/// Wire the coordinator to the live stores. ONE line, applied wherever the
/// environment has them:
///
/// ```swift
/// ContentView().hostsDiagnosticReports()
/// ```
///
/// Without it the dialog still opens and still gathers everything that has a
/// shared owner (the discovery map, the vendor states, the probe ladder, the
/// policies); the handful of facts that need an injected object report themselves
/// as "not recorded", with the reason.
struct DiagnosticReportHost: ViewModifier {
    @Environment(VPNController.self) private var vpn: VPNController?
    @Environment(SubprocessTunnelStore.self) private var tunnels: SubprocessTunnelStore?
    @Environment(ReachabilityMonitor.self) private var reachability: ReachabilityMonitor?
    @Environment(LinkStateMonitor.self) private var linkState: LinkStateMonitor?

    func body(content: Content) -> some View {
        content.onAppear {
            var context = DiagnosticReportCoordinator.shared.context
            context.vpn = vpn
            context.tunnels = tunnels
            context.reachability = reachability
            context.linkState = linkState
            // The maturity registry owns this decision; the assembler only asks.
            // Wired here rather than defaulted inside the assembler so there is
            // still exactly one table deciding what is tested (FeatureMaturity).
            context.maturity = { $0.maturity.badgeText }
            DiagnosticReportCoordinator.shared.context = context
        }
    }
}

extension View {
    func hostsDiagnosticReports() -> some View { modifier(DiagnosticReportHost()) }
}
