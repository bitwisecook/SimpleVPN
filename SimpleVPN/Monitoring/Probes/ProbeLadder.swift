// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProbeLadder.swift
//  The staged, AUTHENTICATED probe: every rung of a VPN handshake as its own
//  step, in the order the real connection performs them, so a person can see
//  exactly how far a connection gets and where it stops.
//
//  This is the model and the run rules only — no sockets, no crypto, no UI.
//  Everything here is pure so the two rules that matter can be tested without a
//  network:
//
//  1. ORDER AND STOP. Steps run in order. A failed step marked `blocking` ends
//     the run: every later step becomes `.skipped` saying it was never reached.
//     A failed step that is NOT blocking is recorded and the run continues —
//     "the VPN didn't answer our signed hello" is a finding, not proof that the
//     next question is unanswerable.
//
//  2. THE ACCOUNT BOUNDARY (non-negotiable). A probe must never burn a one-time
//     code, never risk a lockout, and never leave a session behind. So the
//     ladder is split at the point where a step would submit a username,
//     password or OTP:
//
//       • Everything up to and INCLUDING certificate, private-key, host-key and
//         tls-auth/tls-crypt verification runs automatically. That material is
//         reusable — presenting it again next week costs nothing, consumes
//         nothing, and touches no account state.
//       • Anything that would submit an account credential does NOT run
//         automatically. It appears in the ladder as `.skipped` with a plain
//         reason ("would use your one-time code" / "would count against
//         sign-in attempts") and an opt-in the user clicks deliberately.
//
//     `requiresAccountCredentials` is that boundary, and `ProbeLadderEngine`
//     is the only thing allowed to cross it — on an explicit `includeAccountSteps`.
//
//  Nothing here may ever carry a secret. Evidence strings are technical facts —
//  fingerprints, distinguished names, expiry dates, cipher names, yes/no — and
//  every one of them is pushed through `ProbeEvidence.sanitise` on the way in,
//  in the outcome's initialiser, so there is no path that skips it.
//

import Foundation

// MARK: - Stages

/// Every rung any protocol's ladder can have. A stable identity (it keys the
/// UI's rows and the incident diagram's lookup), not a display string.
nonisolated enum ProbeStage: String, Sendable, CaseIterable, Codable {
    // Shared
    case dnsResolve
    case reachability

    // OpenVPN
    case openVPNReset
    case openVPNStaticKey
    case openVPNClientCertificate
    case openVPNServerCertificate
    case openVPNSignIn

    // SSH
    case sshBanner
    case sshKeyExchange
    case sshHostKey
    case sshAuthMethods
    case sshPublicKey
    case sshPasswordSignIn

    // IKEv2 / IPsec
    case ikeReachability
    case ikeSAInit
    case ikeNATTraversal
    case ikeAuth

    // SSL-VPN (Fortinet / F5 / GlobalProtect / AnyConnect / …)
    case tlsHandshake
    case vendorClassification
    case clientCertificateRequested
    case sslClientCertificate
    case sslSignIn

    // WireGuard
    case wireGuardHandshake

    // Tailscale / Headscale
    case controlPlaneReachability
    case controlPlaneTLS
    case controlPlaneIdentity
}

/// Where a rung sits on the failure diagram's five-hop journey, so the ladder
/// and ConnectionIncidentView never disagree about where something broke.
nonisolated enum ProbeDiagramHop: Sendable, Equatable {
    case network, internet, server, signIn
}

nonisolated extension ProbeStage {
    var diagramHop: ProbeDiagramHop {
        switch self {
        case .dnsResolve: .internet
        case .reachability, .ikeReachability, .ikeNATTraversal, .controlPlaneReachability: .server
        case .openVPNReset, .openVPNStaticKey, .openVPNServerCertificate,
             .sshBanner, .sshKeyExchange, .sshHostKey,
             .ikeSAInit, .ikeAuth,
             .tlsHandshake, .vendorClassification, .clientCertificateRequested,
             .wireGuardHandshake, .controlPlaneTLS, .controlPlaneIdentity: .server
        case .openVPNClientCertificate, .sslClientCertificate,
             .sshAuthMethods, .sshPublicKey,
             .openVPNSignIn, .sslSignIn, .sshPasswordSignIn: .signIn
        }
    }
}

// MARK: - Status

nonisolated enum ProbeStepStatus: String, Sendable, Codable, CaseIterable {
    /// Planned, not started.
    case pending
    /// In flight.
    case running
    /// The step did what it says on the tin.
    case ok
    /// The step ran and did not pass.
    case failed
    /// Deliberately not run: either an earlier step stopped the ladder, or this
    /// one is behind the account boundary and nobody opted in.
    case skipped
    /// Can't apply to this VPN at all (no certificate configured, no static key,
    /// or the platform gives us no honest way to ask).
    case notApplicable

    var isTerminalFailure: Bool { self == .failed }

    /// Glyph + tint language shared with the rest of the app's status dots.
    var symbol: String {
        switch self {
        case .pending: "circle.dotted"
        case .running: "circle.dashed"
        case .ok: "checkmark.circle.fill"
        case .failed: "xmark.circle.fill"
        case .skipped: "minus.circle"
        case .notApplicable: "minus.circle"
        }
    }
}

// MARK: - Evidence redaction

/// Everything technical the ladder shows passes through here. The steps below
/// are written not to produce secrets in the first place; this exists so a
/// future one CAN'T, and so server-supplied text (a banner, a certificate
/// subject, a libssh2 message) can never smuggle one onto the screen.
nonisolated enum ProbeEvidence {

    /// Longest single token we'll show. A base64 blob past this is key material
    /// or a session cookie however it got here, so it never reaches the screen.
    static let maxTokenLength = 96

    static func sanitise(_ raw: String) -> String {
        // UserFacingError.redact already handles key=value secrets, one-time
        // codes, and length. Layer the long-opaque-token rule on top.
        var text = UserFacingError.redact(raw)
        text = collapseLongTokens(text)
        return text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func sanitise(_ lines: [String]) -> [String] {
        lines.map(sanitise).filter { !$0.isEmpty }
    }

    /// Replace any run of base64/hex-ish characters longer than `maxTokenLength`
    /// with a marker. Fingerprints (64 hex chars, or colon-separated) survive;
    /// a PEM body or a session cookie does not.
    static func collapseLongTokens(_ text: String) -> String {
        var out = ""
        var token = ""
        func flush() {
            out += token.count > maxTokenLength ? "\u{2026}(\(token.count) characters withheld)" : token
            token = ""
        }
        for ch in text {
            if ch.isLetter || ch.isNumber || ch == "+" || ch == "/" || ch == "=" || ch == "_" || ch == "-" {
                token.append(ch)
            } else {
                flush()
                out.append(ch)
            }
        }
        flush()
        return out
    }
}

// MARK: - Outcome

/// What running one step produced. Constructed by the executor; the initialiser
/// is the redaction choke point.
nonisolated struct ProbeStepOutcome: Sendable, Equatable {
    var status: ProbeStepStatus
    /// One plain-language sentence: what this step found.
    var detail: String
    /// Technical facts behind it, for the disclosure. Already redacted.
    var evidence: [String]
    /// What to do about it, when it failed and there is something to do.
    var remedy: UserFacingError?
    /// A finding with security weight of its own (a changed host key, a
    /// certificate that doesn't chain) — surfaced prominently, not as a nit.
    var securityFinding: Bool

    init(status: ProbeStepStatus, detail: String, evidence: [String] = [],
         remedy: UserFacingError? = nil, securityFinding: Bool = false) {
        self.status = status
        self.detail = detail
        self.evidence = ProbeEvidence.sanitise(evidence)
        self.remedy = remedy
        self.securityFinding = securityFinding
    }

    static func ok(_ detail: String, evidence: [String] = []) -> ProbeStepOutcome {
        ProbeStepOutcome(status: .ok, detail: detail, evidence: evidence)
    }
    static func failed(_ detail: String, evidence: [String] = [],
                       remedy: UserFacingError? = nil,
                       securityFinding: Bool = false) -> ProbeStepOutcome {
        ProbeStepOutcome(status: .failed, detail: detail, evidence: evidence,
                         remedy: remedy, securityFinding: securityFinding)
    }
    static func notApplicable(_ detail: String, evidence: [String] = []) -> ProbeStepOutcome {
        ProbeStepOutcome(status: .notApplicable, detail: detail, evidence: evidence)
    }
    static func skipped(_ detail: String, evidence: [String] = []) -> ProbeStepOutcome {
        ProbeStepOutcome(status: .skipped, detail: detail, evidence: evidence)
    }
}

// MARK: - Step

nonisolated struct ProbeStep: Identifiable, Sendable, Equatable {
    var stage: ProbeStage
    /// The sentence a non-technical person reads. No jargon, no protocol names
    /// where a plain phrase will do.
    var title: String
    /// Filled in by the run; before that it's the "what this checks" line.
    var detail: String
    var status: ProbeStepStatus = .pending
    var duration: TimeInterval?
    var evidence: [String] = []
    var remedy: UserFacingError?
    var securityFinding = false

    /// A failure here means nothing after it can be judged, so the run stops.
    var blocking = true
    /// This step would submit a username / password / one-time code. See the
    /// account-boundary rule at the top of this file.
    var requiresAccountCredentials = false
    /// Why it isn't run automatically — shown verbatim on the skipped row.
    var accountSkipReason: String?
    /// Decided at planning time, without running anything: "this profile has no
    /// certificate, so there is nothing to check". Never a failure — a step the
    /// plan already knows the answer to cannot be evidence of a fault.
    var preset: ProbeStepOutcome?

    var id: String { stage.rawValue }

    init(_ stage: ProbeStage, title: String, detail: String,
         blocking: Bool = true, requiresAccountCredentials: Bool = false,
         accountSkipReason: String? = nil, preset: ProbeStepOutcome? = nil) {
        self.stage = stage
        self.title = title
        self.detail = detail
        self.blocking = blocking
        self.requiresAccountCredentials = requiresAccountCredentials
        self.accountSkipReason = accountSkipReason
        assert(preset == nil || preset?.status != .failed,
               "a planned outcome may not be a failure — nothing was tested")
        self.preset = preset
    }

    /// Apply an outcome, keeping the planned identity/title intact.
    mutating func apply(_ outcome: ProbeStepOutcome, duration: TimeInterval?) {
        status = outcome.status
        detail = outcome.detail
        evidence = outcome.evidence
        remedy = outcome.remedy
        securityFinding = outcome.securityFinding
        self.duration = duration
    }
}

// MARK: - Ladder

nonisolated struct ProbeLadder: Sendable, Equatable {
    var kind: VPNKind
    var host: String
    var port: Int
    var profileName: String
    var steps: [ProbeStep]
    /// Whether the account-boundary steps were included in this run.
    var includedAccountSteps: Bool = false
    var startedAt: Date = .now
    var finishedAt: Date?

    /// The first step that actually failed — what the summary and the incident
    /// diagram both point at.
    var firstFailure: ProbeStep? { steps.first { $0.status == .failed } }

    /// Steps held back at the account boundary, in ladder order.
    var accountSteps: [ProbeStep] { steps.filter(\.requiresAccountCredentials) }

    /// Is there anything left to offer an opt-in for?
    var hasUntestedSignIn: Bool {
        accountSteps.contains { $0.status == .skipped }
    }

    var securityFindings: [ProbeStep] { steps.filter(\.securityFinding) }

    var isComplete: Bool { finishedAt != nil }

    var elapsed: TimeInterval? {
        finishedAt.map { $0.timeIntervalSince(startedAt) }
    }

    /// One sentence for the top of the card.
    var summary: String {
        if let failure = firstFailure {
            return "\(failure.title) — \(failure.detail)"
        }
        let ran = steps.filter { $0.status == .ok }.count
        if ran == 0 { return "Nothing could be checked for this VPN yet." }
        if hasUntestedSignIn {
            return "Everything that can be checked without signing in passed (\(ran) of \(steps.count) checks). The sign-in itself hasn't been tried."
        }
        return "All \(ran) checks passed."
    }
}

// MARK: - The run

/// Runs a planned ladder. The executor is injected, so the ordering, the
/// stop-at-first-hard-failure rule and the account boundary are all testable
/// with no network at all — which is the point.
nonisolated enum ProbeLadderEngine {

    typealias Executor = @Sendable (ProbeStage) async -> ProbeStepOutcome

    /// Reason text put on a step that never ran because an earlier one stopped
    /// the ladder. Deliberately blame-free: the failing row above carries the
    /// explanation, this one only says it wasn't reached.
    static let notReached = "Not checked \u{2014} the step before this one didn\u{2019}t get through."

    /// Run `plan` in order.
    ///
    /// - `includeAccountSteps`: the opt-in. False (the default everywhere the
    ///   app runs a probe by itself) means steps marked
    ///   `requiresAccountCredentials` are skipped without being executed.
    /// - `progress`: called after each step so the UI can fill in live.
    static func run(plan: [ProbeStep],
                    includeAccountSteps: Bool = false,
                    seed: [ProbeStep]? = nil,
                    clock: @Sendable () -> Date = { Date() },
                    progress: (@Sendable ([ProbeStep]) -> Void)? = nil,
                    execute: Executor) async -> [ProbeStep] {
        var steps = plan
        var stopped = false

        // Incremental re-run: carry forward the leading run of already-SETTLED rungs
        // (passed or not-applicable) from a same-shaped earlier ladder, and only
        // execute from the first UNSETTLED rung onward — the failed handshake step,
        // or the held-back sign-in. A settled step's answer was true of a path that,
        // by the caller's fingerprint check, hasn't changed, so re-running it would
        // only spend time re-confirming it. Any other seed shape is ignored.
        var startIndex = 0
        if let seed, seed.count == steps.count, seed.map(\.stage) == steps.map(\.stage) {
            startIndex = seed.firstIndex { $0.status != .ok && $0.status != .notApplicable }
                ?? seed.count
            for i in 0..<startIndex { steps[i] = seed[i] }
        }

        for index in steps.indices {
            if index < startIndex {
                progress?(steps)        // carried forward; nothing to run
                continue
            }
            if stopped {
                steps[index].apply(.skipped(notReached), duration: nil)
                progress?(steps)
                continue
            }
            if let preset = steps[index].preset {
                // Answered at planning time; running it would only invent work.
                steps[index].apply(preset, duration: nil)
                progress?(steps)
                continue
            }
            if steps[index].requiresAccountCredentials && !includeAccountSteps {
                let reason = steps[index].accountSkipReason ?? Self.defaultAccountSkipReason
                steps[index].apply(.skipped(reason), duration: nil)
                // NOT a stop: the sign-in being untested says nothing about the
                // steps after it, and holding it back is our choice, not a fault.
                progress?(steps)
                continue
            }

            steps[index].status = .running
            progress?(steps)

            let began = clock()
            let outcome = await execute(steps[index].stage)
            let elapsed = clock().timeIntervalSince(began)
            steps[index].apply(outcome, duration: elapsed)

            if outcome.status == .failed && steps[index].blocking { stopped = true }
            progress?(steps)
        }
        return steps
    }

    static let defaultAccountSkipReason =
        "Not tested \u{2014} this would count against your sign-in attempts."
    static let otpAccountSkipReason =
        "Not tested \u{2014} this would use your one-time code."
}
