// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProbeLadderTests.swift
//  The two rules the staged probe must never break — run in order and stop at
//  the first hard failure, and never cross the account boundary without being
//  asked — plus the plan each protocol produces from a profile.
//
//  Everything here runs with a stub executor and hand-built facts: no socket,
//  no keychain, no VPN. That is the point of keeping the rules pure.
//

import Testing
import Foundation
@testable import SimpleVPN

struct ProbeLadderEngineTests {

    /// Records which stages the engine actually asked for — the only way to
    /// prove a step was SKIPPED rather than run-and-reported-as-skipped.
    private final class Recorder: @unchecked Sendable {
        private let lock = NSLock()
        nonisolated(unsafe) private var seen: [ProbeStage] = []
        nonisolated func note(_ stage: ProbeStage) { lock.lock(); seen.append(stage); lock.unlock() }
        nonisolated var stages: [ProbeStage] { lock.lock(); defer { lock.unlock() }; return seen }
    }

    private func plan(_ steps: ProbeStep...) -> [ProbeStep] { steps }

    private func step(_ stage: ProbeStage, blocking: Bool = true,
                      account: Bool = false, preset: ProbeStepOutcome? = nil) -> ProbeStep {
        ProbeStep(stage, title: stage.rawValue, detail: "planned",
                  blocking: blocking, requiresAccountCredentials: account,
                  accountSkipReason: account ? ProbeLadderEngine.otpAccountSkipReason : nil,
                  preset: preset)
    }

    // MARK: Ordering

    @Test func runsEveryStepInPlanOrder() async {
        let recorder = Recorder()
        let steps = await ProbeLadderEngine.run(
            plan: plan(step(.dnsResolve), step(.reachability), step(.openVPNReset))) { stage in
                recorder.note(stage)
                return .ok("fine")
            }
        #expect(recorder.stages == [.dnsResolve, .reachability, .openVPNReset])
        #expect(steps.allSatisfy { $0.status == .ok })
        #expect(steps.map(\.stage) == [.dnsResolve, .reachability, .openVPNReset])
    }

    @Test func recordsHowLongEachStepTook() async {
        let steps = await ProbeLadderEngine.run(plan: plan(step(.dnsResolve))) { _ in .ok("fine") }
        #expect(steps[0].duration != nil)
    }

    // MARK: Stop at the first hard failure

    @Test func blockingFailureSkipsEverythingAfterIt() async {
        let recorder = Recorder()
        let steps = await ProbeLadderEngine.run(
            plan: plan(step(.dnsResolve), step(.reachability), step(.openVPNReset))) { stage in
                recorder.note(stage)
                return stage == .reachability ? .failed("nothing there") : .ok("fine")
            }
        // The third stage must never have been asked for.
        #expect(recorder.stages == [.dnsResolve, .reachability])
        #expect(steps[1].status == .failed)
        #expect(steps[2].status == .skipped)
        #expect(steps[2].detail == ProbeLadderEngine.notReached)
    }

    @Test func nonBlockingFailureLetsTheLadderCarryOn() async {
        let recorder = Recorder()
        let steps = await ProbeLadderEngine.run(
            plan: plan(step(.openVPNReset, blocking: false),
                       step(.openVPNStaticKey, blocking: false),
                       step(.openVPNClientCertificate, blocking: false))) { stage in
                recorder.note(stage)
                return stage == .openVPNStaticKey ? .failed("ignored our signed hello") : .ok("fine")
            }
        #expect(recorder.stages.count == 3)
        #expect(steps[1].status == .failed)
        #expect(steps[2].status == .ok)
    }

    @Test func firstFailureIsTheOneReported() async {
        var ladder = ProbeLadder(kind: .openVPN, host: "vpn.example.org", port: 1194,
                                 profileName: "Work", steps: [])
        ladder.steps = await ProbeLadderEngine.run(
            plan: plan(step(.dnsResolve, blocking: false),
                       step(.reachability, blocking: false),
                       step(.openVPNReset, blocking: false))) { stage in
                stage == .dnsResolve ? .ok("fine") : .failed("broke at \(stage.rawValue)")
            }
        #expect(ladder.firstFailure?.stage == .reachability)
        #expect(ladder.summary.contains("broke at reachability"))
    }

    // MARK: The account boundary

    @Test func accountStepsNeverRunAutomatically() async {
        let recorder = Recorder()
        let steps = await ProbeLadderEngine.run(
            plan: plan(step(.reachability), step(.openVPNSignIn, blocking: false, account: true))) { stage in
                recorder.note(stage)
                return .ok("fine")
            }
        #expect(recorder.stages == [.reachability])          // the sign-in was never attempted
        #expect(steps[1].status == .skipped)
        #expect(steps[1].detail == ProbeLadderEngine.otpAccountSkipReason)
    }

    @Test func skippingASignInDoesNotStopTheLadder() async {
        let recorder = Recorder()
        _ = await ProbeLadderEngine.run(
            plan: plan(step(.openVPNSignIn, blocking: false, account: true),
                       step(.openVPNClientCertificate, blocking: false))) { stage in
                recorder.note(stage)
                return .ok("fine")
            }
        #expect(recorder.stages == [.openVPNClientCertificate])
    }

    @Test func optingInFlipsExactlyTheAccountSteps() async {
        let recorder = Recorder()
        let steps = await ProbeLadderEngine.run(
            plan: plan(step(.reachability), step(.openVPNSignIn, blocking: false, account: true)),
            includeAccountSteps: true) { stage in
                recorder.note(stage)
                return .ok("fine")
            }
        #expect(recorder.stages == [.reachability, .openVPNSignIn])
        #expect(steps.allSatisfy { $0.status == .ok })
    }

    @Test func optingInDoesNotResurrectStepsAnEarlierFailureSkipped() async {
        let steps = await ProbeLadderEngine.run(
            plan: plan(step(.dnsResolve), step(.reachability), step(.openVPNSignIn, account: true)),
            includeAccountSteps: true) { stage in
                stage == .dnsResolve ? .failed("no such name") : .ok("fine")
            }
        #expect(steps[2].status == .skipped)
        #expect(steps[2].detail == ProbeLadderEngine.notReached)
    }

    @Test func untestedSignInIsVisibleOnTheLadder() async {
        var ladder = ProbeLadder(kind: .openVPN, host: "h", port: 1, profileName: "Work", steps: [])
        ladder.steps = await ProbeLadderEngine.run(
            plan: plan(step(.reachability), step(.openVPNSignIn, blocking: false, account: true))) { _ in .ok("fine") }
        #expect(ladder.hasUntestedSignIn)
        #expect(ladder.summary.contains("sign-in"))
    }

    // MARK: Presets

    @Test func presetStepsAreNeverExecuted() async {
        let recorder = Recorder()
        let steps = await ProbeLadderEngine.run(
            plan: plan(step(.openVPNStaticKey,
                            preset: .notApplicable("no shared key in this profile")))) { stage in
                recorder.note(stage)
                return .ok("fine")
            }
        #expect(recorder.stages.isEmpty)
        #expect(steps[0].status == .notApplicable)
        #expect(steps[0].duration == nil)
    }

    @Test func presetStepsDoNotStopTheLadder() async {
        let steps = await ProbeLadderEngine.run(
            plan: plan(step(.openVPNStaticKey, preset: .notApplicable("nothing to do")),
                       step(.openVPNClientCertificate))) { _ in .ok("fine") }
        #expect(steps[1].status == .ok)
    }

    // MARK: Incremental re-run (seed)

    /// A step in a given post-run state, to seed an incremental re-run.
    private func settled(_ stage: ProbeStage, _ status: ProbeStepStatus) -> ProbeStep {
        var s = step(stage)
        s.status = status
        s.detail = "seeded"
        return s
    }

    @Test func aSeedReRunsOnlyFromTheFirstUnsettledStep() async {
        let recorder = Recorder()
        // DNS + reachability passed; the shared-key step failed (the reported bug).
        let seed = [settled(.dnsResolve, .ok), settled(.reachability, .ok),
                    settled(.openVPNStaticKey, .failed)]
        let steps = await ProbeLadderEngine.run(
            plan: plan(step(.dnsResolve), step(.reachability), step(.openVPNStaticKey)),
            seed: seed) { stage in
                recorder.note(stage)
                return .ok("now fine")
            }
        // Only the failed rung is re-run; the passes are carried, not re-executed.
        #expect(recorder.stages == [.openVPNStaticKey])
        #expect(steps[0].status == .ok)
        #expect(steps[0].detail == "seeded", "an untouched pass keeps its earlier result")
        #expect(steps[2].status == .ok)
        #expect(steps[2].detail == "now fine")
    }

    @Test func aSeedTreatsNotApplicableAsSettled() async {
        let recorder = Recorder()
        // ok, not-applicable, then a held-back sign-in (skipped) is the first
        // unsettled rung — so only it re-runs on the opt-in.
        let seed = [settled(.reachability, .ok), settled(.openVPNStaticKey, .notApplicable),
                    settled(.openVPNSignIn, .skipped)]
        _ = await ProbeLadderEngine.run(
            plan: plan(step(.reachability), step(.openVPNStaticKey),
                       step(.openVPNSignIn, blocking: false, account: true)),
            includeAccountSteps: true, seed: seed) { stage in
                recorder.note(stage)
                return .ok("signed in")
            }
        #expect(recorder.stages == [.openVPNSignIn])
    }

    @Test func aSeedOfADifferentShapeIsIgnored() async {
        let recorder = Recorder()
        // Seed for a different plan (fewer/renamed stages) can't be resumed, so the
        // whole ladder runs — the safe answer when the profile changed shape.
        let seed = [settled(.dnsResolve, .ok)]
        let steps = await ProbeLadderEngine.run(
            plan: plan(step(.dnsResolve), step(.reachability)),
            seed: seed) { stage in
                recorder.note(stage)
                return .ok("fine")
            }
        #expect(recorder.stages == [.dnsResolve, .reachability])
        #expect(steps.allSatisfy { $0.status == .ok })
    }
}

// MARK: - Network fingerprint (the re-run decision seam)

struct ProbeNetworkFingerprintTests {

    @Test func sameNetworkAndServerIsUnchanged() {
        let a = ProbeNetworkFingerprint(networkKey: "mac:0:8:a2:e:dc:c7", serverIP: "203.0.113.9")
        let b = ProbeNetworkFingerprint(networkKey: "mac:0:8:a2:e:dc:c7", serverIP: "203.0.113.9")
        #expect(a == b, "unchanged network + server ⇒ an incremental re-run is honest")
    }

    @Test func aMovedNetworkChangesTheFingerprint() {
        let home = ProbeNetworkFingerprint(networkKey: "mac:0:8:a2:e:dc:c7", serverIP: "203.0.113.9")
        let cafe = ProbeNetworkFingerprint(networkKey: "mac:a0:99:9b:18:dc:93", serverIP: "203.0.113.9")
        #expect(home != cafe)
    }

    @Test func theServerResolvingElsewhereChangesTheFingerprint() {
        // Same physical network, but the host now resolves to a different address
        // (round-robin / failover) — the earlier rungs measured a different target,
        // so the whole ladder must run again.
        let before = ProbeNetworkFingerprint(networkKey: "mac:0:8:a2:e:dc:c7", serverIP: "203.0.113.9")
        let after = ProbeNetworkFingerprint(networkKey: "mac:0:8:a2:e:dc:c7", serverIP: "198.51.100.4")
        #expect(before != after)
    }
}

// MARK: - Plans

struct ProbeLadderPlanTests {

    private func openVPNFacts(ovpn: String, requiresOTP: Bool = false) -> ProbeTargetFacts {
        .openVPN(profileID: "p1", name: "Work", host: "vpn.example.org", port: 1194,
                 transport: .udp, ovpn: ovpn, requiresOTP: requiresOTP)
    }

    private static let staticKeyBlock = """
    <tls-crypt>
    -----BEGIN OpenVPN Static key V1-----
    \(String(repeating: "ab", count: 256))
    -----END OpenVPN Static key V1-----
    </tls-crypt>
    """

    @Test func openVPNLadderIsOrderedAndEndsAtTheSignIn() {
        let steps = ProbeLadderPlan.steps(for: openVPNFacts(ovpn: "client\nauth-user-pass\n"))
        #expect(steps.first?.stage == .dnsResolve)
        #expect(steps.map(\.stage).contains(.reachability))
        // Every account step is last, and there is exactly one.
        let accountIndexes = steps.indices.filter { steps[$0].requiresAccountCredentials }
        #expect(accountIndexes == [steps.count - 1])
        #expect(steps.last?.stage == .openVPNSignIn)
    }

    @Test func openVPNWithoutASharedKeyMarksThatStepNotApplicable() {
        let steps = ProbeLadderPlan.steps(for: openVPNFacts(ovpn: "client\n"))
        let key = steps.first { $0.stage == .openVPNStaticKey }
        #expect(key?.preset?.status == .notApplicable)
    }

    @Test func openVPNWithASharedKeyMakesThatStepRunnable() {
        let steps = ProbeLadderPlan.steps(for: openVPNFacts(ovpn: "client\n" + Self.staticKeyBlock))
        let key = steps.first { $0.stage == .openVPNStaticKey }
        #expect(key?.preset == nil)
    }

    @Test func openVPNWithoutACertificateMarksThatStepNotApplicable() {
        let steps = ProbeLadderPlan.steps(for: openVPNFacts(ovpn: "client\n"))
        let cert = steps.first { $0.stage == .openVPNClientCertificate }
        #expect(cert?.preset?.status == .notApplicable)
    }

    @Test func openVPNWithACertificateMakesThatStepRunnable() {
        let ovpn = "client\n<cert>\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n</cert>\n"
        let cert = ProbeLadderPlan.steps(for: openVPNFacts(ovpn: ovpn))
            .first { $0.stage == .openVPNClientCertificate }
        #expect(cert?.preset == nil)
    }

    @Test func openVPNServerCertificateIsHonestlyNotApplicable() {
        let step = ProbeLadderPlan.steps(for: openVPNFacts(ovpn: "client\n"))
            .first { $0.stage == .openVPNServerCertificate }
        #expect(step?.preset?.status == .notApplicable)
        // The reason has to explain itself, not just say "n/a".
        #expect((step?.preset?.detail.count ?? 0) > 40)
    }

    @Test func anOTPProfileSaysItWouldSpendTheCode() {
        let steps = ProbeLadderPlan.steps(for: openVPNFacts(ovpn: "client\nauth-user-pass\n",
                                                            requiresOTP: true))
        #expect(steps.last?.accountSkipReason == ProbeLadderEngine.otpAccountSkipReason)
    }

    @Test func aPasswordOnlyProfileSaysItWouldCountAsAnAttempt() {
        let steps = ProbeLadderPlan.steps(for: openVPNFacts(ovpn: "client\nauth-user-pass\n"))
        #expect(steps.last?.accountSkipReason == ProbeLadderEngine.defaultAccountSkipReason)
    }

    // MARK: WireGuard

    @Test func wireGuardLadderHasNoAccountBoundaryAtAll() {
        var config = WireGuardConfig()
        config.privateKey = "aaa"
        config.peerPublicKey = "bbb"
        config.endpoint = "wg.example.org:51820"
        let steps = ProbeLadderPlan.steps(for: .resolveForTest(wireGuard: config))
        #expect(!steps.contains { $0.requiresAccountCredentials })
        #expect(steps.last?.stage == .wireGuardHandshake)
        #expect(steps.last?.preset == nil)
    }

    @Test func wireGuardWithoutKeysCannotBeHandshaked() {
        var config = WireGuardConfig()
        config.endpoint = "wg.example.org:51820"
        let steps = ProbeLadderPlan.steps(for: .resolveForTest(wireGuard: config))
        #expect(steps.last?.preset?.status == .notApplicable)
    }

    // MARK: SSH

    @Test func sshLadderChecksTheHostKeyBeforeOfferingAnything() {
        var facts = ProbeTargetFacts()
        facts.kind = .ssh
        facts.username = "jim"
        facts.identityFilePath = "~/.ssh/id_ed25519"
        let stages = ProbeLadderPlan.steps(for: facts).map(\.stage)
        let hostKey = stages.firstIndex(of: .sshHostKey)
        let publicKey = stages.firstIndex(of: .sshPublicKey)
        let signIn = stages.firstIndex(of: .sshPasswordSignIn)
        #expect(hostKey != nil && publicKey != nil && signIn != nil)
        #expect(hostKey! < publicKey!)
        #expect(publicKey! < signIn!)
    }

    @Test func sshHostKeyStepStopsTheLadderWhenItFails() {
        var facts = ProbeTargetFacts()
        facts.kind = .ssh
        let step = ProbeLadderPlan.steps(for: facts).first { $0.stage == .sshHostKey }
        #expect(step?.blocking == true)
    }

    @Test func sshWithoutAKeyFileMarksTheKeyStepNotApplicable() {
        var facts = ProbeTargetFacts()
        facts.kind = .ssh
        facts.username = "jim"
        let step = ProbeLadderPlan.steps(for: facts).first { $0.stage == .sshPublicKey }
        #expect(step?.preset?.status == .notApplicable)
    }

    @Test func sshPublicKeyRunsAutomatically() {
        // A key is reusable material: offering it spends nothing, so it must NOT
        // sit behind the account boundary.
        var facts = ProbeTargetFacts()
        facts.kind = .ssh
        facts.identityFilePath = "~/.ssh/id_ed25519"
        let step = ProbeLadderPlan.steps(for: facts).first { $0.stage == .sshPublicKey }
        #expect(step?.requiresAccountCredentials == false)
    }

    // MARK: IPsec

    @Test func ikeLadderStopsHonestlyBeforeAuthentication() {
        var facts = ProbeTargetFacts()
        facts.kind = .ikev2
        let steps = ProbeLadderPlan.steps(for: facts)
        #expect(steps.map(\.stage).contains(.ikeSAInit))
        let auth = steps.first { $0.stage == .ikeAuth }
        #expect(auth?.preset?.status == .notApplicable)
        #expect(auth?.preset?.detail.contains("live session") == true)
    }

    // MARK: SSL-VPN

    @Test func sslVPNLadderAsksWhetherACertificateIsRequired() {
        var facts = ProbeTargetFacts()
        facts.kind = .fortinet
        let stages = ProbeLadderPlan.steps(for: facts).map(\.stage)
        #expect(stages.contains(.clientCertificateRequested))
        #expect(stages.last == .sslSignIn)
    }

    // MARK: Tailscale

    @Test func tailscaleLadderChecksTheControlPlaneOnly() {
        var config = TailscaleConfig()
        config.preset = .headscale
        config.controlURL = "https://headscale.example.org"
        let facts = ProbeTargetFacts.tailscale(config, profileID: "t1", name: "Mesh")
        let stages = ProbeLadderPlan.steps(for: facts).map(\.stage)
        #expect(stages == [.dnsResolve, .controlPlaneReachability, .controlPlaneTLS, .controlPlaneIdentity])
        #expect(facts.host == "headscale.example.org")
    }

    @Test func tailscalePresetFallsBackToTheServiceControlPlane() {
        let facts = ProbeTargetFacts.tailscale(TailscaleConfig(), profileID: "t1", name: "Mesh")
        #expect(facts.controlURL == ProbeTargetFacts.tailscaleDefaultControlURL)
        #expect(facts.host == "controlplane.tailscale.com")
    }

    // MARK: Every plan

    @Test(arguments: VPNKind.allCases)
    func everyKindProducesAnOrderedPlanThatStartsWithTheAddress(kind: VPNKind) {
        var facts = ProbeTargetFacts()
        facts.kind = kind
        facts.host = "vpn.example.org"
        let steps = ProbeLadderPlan.steps(for: facts)
        #expect(!steps.isEmpty)
        #expect(steps.first?.stage == .dnsResolve)
        // Stage ids must be unique — they key the UI's rows.
        #expect(Set(steps.map(\.id)).count == steps.count)
        // Any account step is at the very end.
        if let first = steps.firstIndex(where: { $0.requiresAccountCredentials }) {
            let tail = steps[first...].allSatisfy { $0.requiresAccountCredentials }
            #expect(tail)
        }
    }
}

// MARK: - The ladder as a whole

struct ProbeLadderSummaryTests {

    private func ladder(_ steps: [ProbeStep]) -> ProbeLadder {
        ProbeLadder(kind: .openVPN, host: "vpn.example.org", port: 1194,
                    profileName: "Work", steps: steps, finishedAt: .now)
    }

    private func done(_ stage: ProbeStage, _ status: ProbeStepStatus,
                      account: Bool = false, security: Bool = false) -> ProbeStep {
        var step = ProbeStep(stage, title: stage.rawValue, detail: "did a thing",
                             blocking: false, requiresAccountCredentials: account)
        step.apply(ProbeStepOutcome(status: status, detail: "did a thing",
                                    securityFinding: security), duration: 0.01)
        return step
    }

    @Test func aCleanRunSaysSo() {
        let l = ladder([done(.dnsResolve, .ok), done(.reachability, .ok)])
        #expect(l.firstFailure == nil)
        #expect(l.summary.contains("All 2 checks passed"))
        #expect(!l.hasUntestedSignIn)
    }

    @Test func anUntestedSignInIsNeverCountedAsAPass() {
        let l = ladder([done(.reachability, .ok), done(.openVPNSignIn, .skipped, account: true)])
        #expect(l.hasUntestedSignIn)
        #expect(l.accountSteps.count == 1)
        #expect(!l.summary.contains("All"))
    }

    @Test func securityFindingsAreCollectedSeparately() {
        let l = ladder([done(.reachability, .ok),
                        done(.sshHostKey, .failed, security: true)])
        #expect(l.securityFindings.map(\.stage) == [.sshHostKey])
    }

    @Test func anEmptyLadderDoesNotClaimSuccess() {
        let l = ladder([done(.openVPNStaticKey, .notApplicable)])
        #expect(l.summary.contains("Nothing could be checked"))
    }
}

// MARK: - Sign-in material

struct ProbeSignInMaterialTests {

    @Test func onlySubstantialValuesAreHandedToTheRedactor() {
        // Short strings would turn every occurrence of "ab" in a message into
        // bullets; the redactor's own floor is four characters, and this must
        // agree with it.
        let material = ProbeSignInMaterial(username: "jim", password: "hunter2",
                                           otp: "12", privateKeyPassphrase: "")
        #expect(material.secrets == ["hunter2"])
    }

    @Test func aSignInFailureNeverQuotesThePasswordBack() {
        let material = ProbeSignInMaterial(username: "jim", password: "swordfish",
                                           otp: "", privateKeyPassphrase: "")
        let evidence = ProbeEvidence.sanitise(
            UserFacingError.redact("auth failed for jim with swordfish", secrets: material.secrets))
        #expect(!evidence.contains("swordfish"))
    }
}

// MARK: - Redaction of evidence

struct ProbeEvidenceTests {

    @Test func evidencePassesThroughTheRedactorOnTheWayIn() {
        let outcome = ProbeStepOutcome(status: .ok, detail: "fine",
                                       evidence: ["password=hunter2ZZZ", "otp: 123456"])
        #expect(!outcome.evidence.joined().contains("hunter2ZZZ"))
        #expect(!outcome.evidence.joined().contains("123456"))
    }

    @Test func longOpaqueTokensAreWithheld() {
        let blob = String(repeating: "QUJDREVG", count: 20)      // 160 characters
        let outcome = ProbeStepOutcome(status: .ok, detail: "fine", evidence: ["key: \(blob)"])
        #expect(!outcome.evidence.joined().contains(blob))
        #expect(outcome.evidence.joined().contains("characters withheld"))
    }

    @Test func fingerprintsSurviveRedaction() {
        // 64 hex characters — a SHA-256 fingerprint has to stay readable, it's
        // the whole point of the host-key step.
        let fingerprint = String(repeating: "a1b2c3d4", count: 8)
        let outcome = ProbeStepOutcome(status: .ok, detail: "fine",
                                       evidence: ["Fingerprint (SHA-256): \(fingerprint)"])
        #expect(outcome.evidence.joined().contains(fingerprint))
    }

    @Test func colonSeparatedFingerprintsSurvive() {
        let fingerprint = (0..<32).map { _ in "AB" }.joined(separator: ":")
        let outcome = ProbeStepOutcome(status: .ok, detail: "fine",
                                       evidence: ["SHA-256: \(fingerprint)"])
        #expect(outcome.evidence.joined().contains(fingerprint))
    }

    @Test func emptyEvidenceLinesAreDropped() {
        let outcome = ProbeStepOutcome(status: .ok, detail: "fine", evidence: ["", "  ", "real"])
        #expect(outcome.evidence == ["real"])
    }

    @Test func serverSuppliedTextIsRedactedToo() {
        // A banner is whatever the far end chose to send; it must not be able to
        // carry something secret-shaped onto the screen.
        let outcome = ProbeStepOutcome(status: .ok, detail: "fine",
                                       evidence: ["Greeting: SSH-2.0-Server token=abcd1234"])
        #expect(!outcome.evidence.joined().contains("abcd1234"))
        #expect(outcome.evidence.joined().contains("SSH-2.0-Server"))
    }
}

// MARK: - Failures map to advice

struct ProbeRemedyTests {

    @Test(arguments: ProbeFailure.allCases)
    func everyFailureHasUsableAdvice(failure: ProbeFailure) {
        let error = UserFacingError.probeRemedy(failure, vpnName: "Work")
        #expect(!error.title.isEmpty)
        #expect(!error.explanation.isEmpty)
        #expect(!error.steps.isEmpty)
    }

    @Test func certificateVerdictsMapToTheAdviceThatFixesThem() {
        #expect(CertificateVerdict.expired(on: nil).failure == .clientCertificateExpired)
        #expect(CertificateVerdict.notYetValid(from: nil).failure == .clientCertificateNotYetValid)
        #expect(CertificateVerdict.keyMismatch.failure == .clientKeyMismatch)
        #expect(CertificateVerdict.chainUntrusted.failure == .clientCertificateUntrusted)
        #expect(CertificateVerdict.ok(daysRemaining: 90).failure == nil)
        #expect(CertificateVerdict.keyLocked.failure == nil)
    }

    @Test func theSameShapesGetDifferentAdviceForTheVPNsOwnCertificate() {
        #expect(CertificateVerdict.expired(on: nil).serverFailure == .serverCertificateExpired)
        #expect(CertificateVerdict.hostnameMismatch(expected: "a").serverFailure == .serverCertificateNameMismatch)
        #expect(CertificateVerdict.pinMismatch.serverFailure == .serverCertificatePinMismatch)
        #expect(CertificateVerdict.chainUntrusted.serverFailure == .serverCertificateUntrusted)
    }

    @Test func hostKeyVerdictsMapToTheirAdvice() {
        #expect(SSHHostKeyVerdict.changed.failure == .hostKeyChanged)
        #expect(SSHHostKeyVerdict.unknownRefused.failure == .hostKeyUnknown)
        #expect(SSHHostKeyVerdict.trusted.failure == nil)
        #expect(SSHHostKeyVerdict.unknownAcceptable.failure == nil)
    }

    @Test func aChangedHostKeyIsPresentedAsASecurityFinding() {
        #expect(SSHHostKeyVerdict.changed.isSecurityFinding)
        #expect(!SSHHostKeyVerdict.unknownAcceptable.isSecurityFinding)
        let error = UserFacingError.probeRemedy(.hostKeyChanged, vpnName: "Bastion")
        #expect(error.symbol == "exclamationmark.shield.fill")
        // It must tell the user to stop, not to click through.
        #expect(error.steps.contains { $0.text.lowercased().contains("do not sign in") })
    }

    @Test func adviceNeverLeaksTheDetailItWasGiven() {
        let error = UserFacingError.probeRemedy(.publicKeyRejected, vpnName: "Work",
                                                detail: "passphrase=swordfish99")
        #expect(!error.technicalDetail.contains("swordfish99"))
    }

    // MARK: Diagram

    @Test func everyStageKnowsWhichHopOfTheDiagramItIs() {
        #expect(ProbeStage.dnsResolve.diagramHop == .internet)
        #expect(ProbeStage.reachability.diagramHop == .server)
        #expect(ProbeStage.openVPNStaticKey.diagramHop == .server)
        #expect(ProbeStage.openVPNSignIn.diagramHop == .signIn)
        #expect(ProbeStage.sshPasswordSignIn.diagramHop == .signIn)
        #expect(ProbeStage.wireGuardHandshake.diagramHop == .server)
    }
}

// MARK: - Test conveniences

extension ProbeTargetFacts {
    /// The main-actor `resolve(wireGuard:)` reaches into VPNProbeTarget; this is
    /// the same thing without the actor hop, for the plan tests.
    static func resolveForTest(wireGuard config: WireGuardConfig) -> ProbeTargetFacts {
        let parts = config.endpoint.split(separator: ":")
        let host = parts.first.map(String.init) ?? ""
        let port = parts.count == 2 ? (Int(parts[1]) ?? VPNProbe.wireGuardDefaultPort)
                                    : VPNProbe.wireGuardDefaultPort
        return .wireGuard(config, profileID: config.id, host: host, port: port)
    }
}
