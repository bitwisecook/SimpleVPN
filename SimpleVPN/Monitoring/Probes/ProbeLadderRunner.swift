// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProbeLadderRunner.swift
//  The main-actor side of the staged probe: gathers what a saved VPN actually
//  contains, hands it to the runner as a value, and publishes the ladder as it
//  fills in.
//
//  Two rules this file exists to keep:
//
//  • Nothing is asked for before it is needed. Building facts for a saved VPN
//    reads only material the app already holds (the .ovpn text, the config
//    stores) — it never touches the keychain, never wakes 1Password and never
//    raises a Touch ID prompt. A probe that made the Mac ask for a fingerprint
//    just because a window opened would be intolerable.
//
//  • Account credentials are fetched ONLY for an opted-in sign-in test, through
//    exactly the same providers a connect uses, at the moment the user clicks.
//    That click is a genuine need, so one prompt there is right; anything
//    earlier is not.
//
//  The facts value can hold private key material for the length of a run. It is
//  built at the click, held by the runner, and dropped when the run ends — the
//  same in-memory-only handling the connect path uses.
//

import Foundation
import Observation

/// Ladder results, kept per VPN so the incident card can show the last one
/// without re-running it. In memory only: a probe result is a statement about
/// one network at one moment, and persisting it would let a stale verdict
/// outlive the Wi-Fi it was measured on.
@MainActor
@Observable
final class ProbeLadderStore {
    static let shared = ProbeLadderStore()

    private(set) var ladders: [String: ProbeLadder] = [:]

    func record(_ ladder: ProbeLadder, for profileID: String) {
        guard !profileID.isEmpty else { return }
        ladders[profileID] = ladder
    }
    func ladder(for profileID: String) -> ProbeLadder? { ladders[profileID] }
    func clear(_ profileID: String) { ladders[profileID] = nil }
}

/// The lightweight identity of the network a ladder was run on: the physical
/// network (default interface + its gateway/address, via `NetworkFingerprint`)
/// plus the address the probe would actually dial. It is what decides, on a
/// "Check Again", whether the earlier rungs' results are still true or the whole
/// ladder must climb again — bringing a tunnel up or down does NOT change it (the
/// key is physical-only), but moving networks or the server resolving elsewhere
/// does. Pure and Equatable, so the equality is testable without a network.
nonisolated struct ProbeNetworkFingerprint: Sendable, Equatable {
    /// `NetworkFingerprint.key` — physical interface + gateway MAC / local network.
    var networkKey: String
    /// The first address the host resolves to (or the literal, when it is one).
    var serverIP: String
}

@MainActor
@Observable
final class ProbeLadderRunner {

    /// Which flavour of run last happened, so the card can say whether it re-ran
    /// everything or only the failed / sign-in rung.
    enum RerunMode: Sendable, Equatable { case full, incremental, incrementalSignIn }

    private(set) var ladder: ProbeLadder?
    private(set) var isRunning = false
    /// Set when the opted-in sign-in test couldn't get its credentials.
    private(set) var signInProblem: UserFacingError?

    /// The VPN the current ladder belongs to, so a second click re-runs the
    /// right one and the result is filed under the right profile.
    private(set) var facts: ProbeTargetFacts?

    /// The network the current ladder was measured on — the "did anything move?"
    /// test a re-run consults.
    private(set) var networkContext: ProbeNetworkFingerprint?
    /// How the last re-run went (nil before any re-run). Surfaced in the UI.
    private(set) var lastRerun: RerunMode?

    private var task: Task<Void, Never>?

    func cancel() {
        task?.cancel()
        task = nil
        isRunning = false
    }

    /// A fresh, full run of the automatic part of the ladder: everything up to
    /// the account boundary. The initial entry point (a first "Check Step by
    /// Step" / an auto-run Probe); it captures the network context re-runs compare
    /// against.
    func run(_ facts: ProbeTargetFacts) {
        lastRerun = nil
        // Start the ladder at once — its own DNS rung does the resolving the user
        // is watching. Capture the network context in parallel (it only has to be
        // ready by the NEXT re-run, seconds away), so a slow/broken lookup never
        // delays the first climb.
        start(facts, includeAccountSteps: false, signIn: nil, seed: nil)
        Task { [weak self] in
            let context = await Self.networkFingerprint(for: facts)
            guard let self, !Task.isCancelled else { return }
            if self.facts?.profileID == facts.profileID { self.networkContext = context }
        }
    }

    /// "Check Again": re-run the ladder. If the network hasn't moved, only the
    /// first unsettled rung onward is re-run (the failed handshake step) and the
    /// earlier passes are kept; if it has, the whole ladder runs again. Never
    /// crosses the account boundary — a sign-in is retried only on the opt-in.
    func checkAgain(vpn: VPNController?) {
        guard let facts, let existing = ladder, existing.isComplete else {
            if let facts { run(facts) }
            return
        }
        isRunning = true
        Task { [weak self] in
            guard let self else { return }
            let fresh = await Self.networkFingerprint(for: facts)
            guard !Task.isCancelled else { return }
            let unchanged = self.networkContext.map { $0 == fresh } ?? false
            self.networkContext = fresh
            if unchanged {
                self.lastRerun = .incremental
                self.start(facts, includeAccountSteps: false, signIn: nil, seed: existing)
            } else {
                self.lastRerun = .full
                self.start(facts, includeAccountSteps: false, signIn: nil, seed: nil)
            }
        }
    }

    /// "Test sign-in too" — the deliberate, clicked-on crossing of the account
    /// boundary. Credentials are resolved here, not before. When the network is
    /// unchanged it re-runs ONLY the sign-in rung, keeping the earlier passes.
    func runIncludingSignIn(_ facts: ProbeTargetFacts, vpn: VPNController?) {
        signInProblem = nil
        isRunning = true
        let existing = ladder
        Task { [weak self] in
            guard let self else { return }
            var material = ProbeSignInMaterial(username: "", password: "", otp: "",
                                               privateKeyPassphrase: "")
            if let vpn, !facts.profileID.isEmpty {
                do {
                    material = try await Self.signInMaterial(profileID: facts.profileID, vpn: vpn)
                } catch is CancellationError {
                    self.isRunning = false
                    return                      // the user dismissed the prompt
                } catch {
                    self.signInProblem = UserFacingError.classify(error)
                    self.isRunning = false
                    return
                }
            }
            let fresh = await Self.networkFingerprint(for: facts)
            guard !Task.isCancelled else { return }
            let unchanged = self.networkContext.map { $0 == fresh } ?? false
            self.networkContext = fresh
            let seed = (unchanged && existing?.isComplete == true) ? existing : nil
            self.lastRerun = seed != nil ? .incrementalSignIn : .full
            self.start(facts, includeAccountSteps: true, signIn: material, seed: seed)
        }
    }

    /// The network context (physical fingerprint + resolved server address) for a
    /// set of facts, read off the main actor.
    private static func networkFingerprint(for facts: ProbeTargetFacts) async -> ProbeNetworkFingerprint {
        let key = await NetworkIdentity.current()?.key ?? "net:unknown"
        let host = facts.host.trimmingCharacters(in: .whitespacesAndNewlines)
        let ip: String
        if host.isEmpty {
            ip = ""
        } else if NetworkProbes.isIPv4Literal(host) {
            ip = host
        } else {
            let resolved = await NetworkProbes.resolve(host: host)
            ip = resolved.v4.first ?? resolved.v6.first ?? host
        }
        return ProbeNetworkFingerprint(networkKey: key, serverIP: ip)
    }

    private func start(_ facts: ProbeTargetFacts, includeAccountSteps: Bool,
                       signIn: ProbeSignInMaterial?, seed: ProbeLadder?) {
        cancel()
        self.facts = facts
        // A seed keeps the earlier results on screen while only the tail re-runs,
        // rather than flashing the whole ladder back to "pending".
        ladder = seed ?? ProbeLadderPlan.ladder(for: facts)
        isRunning = true
        let profileID = facts.profileID
        // One weak capture, made here rather than inside the run task, so the
        // live-progress callback doesn't re-capture an already-captured `self`.
        let publish: @Sendable ([ProbeStep]) -> Void = { [weak self] steps in
            Task { @MainActor in
                guard let self, self.isRunning else { return }
                self.ladder?.steps = steps
            }
        }
        task = Task { [weak self] in
            let result = await AuthenticatedProbe.run(
                facts: facts, includeAccountSteps: includeAccountSteps, signIn: signIn,
                seed: seed, progress: publish)
            guard !Task.isCancelled else { return }
            self?.ladder = result
            self?.isRunning = false
            if !profileID.isEmpty { ProbeLadderStore.shared.record(result, for: profileID) }
        }
    }

    /// Resolve the profile's sign-in through its configured source — the same
    /// providers, the same one-prompt behaviour, as a connect.
    private static func signInMaterial(profileID: String, vpn: VPNController) async throws -> ProbeSignInMaterial {
        let auth = vpn.authConfig(for: profileID)
        if let provider = vpn.managerProvider(for: profileID) {
            let raw = try await provider.resolve(profile: profileID, fields: auth.request.fields)
            let typed = vpn.transientCredentials(for: profileID)
            return ProbeSignInMaterial(
                username: raw.username ?? typed.username,
                password: raw.password ?? typed.password,
                otp: (raw.otp?.isEmpty == false ? raw.otp! : typed.otp),
                privateKeyPassphrase: raw.privateKeyPassphrase ?? "")
        }
        let typed = vpn.transientCredentials(for: profileID)
        let saved = vpn.savedCredentials(id: profileID)
        return ProbeSignInMaterial(
            username: typed.username.isEmpty ? (saved?.username ?? "") : typed.username,
            password: typed.password.isEmpty ? (saved?.password ?? "") : typed.password,
            otp: typed.otp, privateKeyPassphrase: "")
    }
}

// MARK: - Gathering facts from the live app

@MainActor
extension ProbeTargetFacts {

    /// Facts for one of the NetworkExtension-carried VPNs (OpenVPN, Tailscale).
    /// Reads only what the app already has in memory.
    static func resolve(profile: VPNController.Profile, vpn: VPNController,
                        evaluator: ProfileEvaluator?) -> ProbeTargetFacts {
        let target = VPNProbeTarget.resolve(profile: profile, vpn: vpn, evaluator: evaluator)
        switch profile.kind {
        case .tailscale:
            var facts = ProbeTargetFacts.tailscale(vpn.tailscaleConfig(for: profile.id),
                                                   profileID: profile.id, name: profile.name)
            if facts.host.isEmpty { facts.host = target.host; facts.port = target.port }
            return facts
        case .openVPN:
            let ovpn = vpn.ovpnText(id: profile.id) ?? ""
            return .openVPN(profileID: profile.id, name: profile.name,
                            host: target.host, port: target.port,
                            transport: VPNProbe.Transport(hint: target.proto),
                            ovpn: ovpn,
                            requiresOTP: vpn.authConfig(for: profile.id).requiresOTP)
        default:
            var facts = ProbeTargetFacts()
            facts.kind = profile.kind
            facts.profileID = profile.id
            facts.profileName = profile.name
            facts.host = target.host
            facts.port = target.port
            facts.transport = VPNProbe.Transport(hint: target.proto)
            facts.requiresOTP = vpn.authConfig(for: profile.id).requiresOTP
            return facts
        }
    }

    /// Facts for an SSH / SSL-VPN tunnel from the subprocess store.
    static func resolve(tunnel: SubprocessTunnelConfig) -> ProbeTargetFacts {
        let split = VPNProbeTarget.splitHostPort(tunnel.server)
        var host = split.host
        // The SSL-VPN kinds store a URL rather than a bare host.
        if let url = URL(string: tunnel.server), let urlHost = url.host(), url.scheme != nil {
            host = urlHost
        }
        let port = tunnel.port ?? split.port
            ?? (tunnel.kind == .ssh ? 22 : (URL(string: tunnel.server)?.port ?? 443))
        return .subprocess(tunnel, host: host, port: port,
                           requiresOTP: !tunnel.tokenMode.isEmpty)
    }

    static func resolve(wireGuard config: WireGuardConfig) -> ProbeTargetFacts {
        let split = VPNProbeTarget.splitHostPort(config.endpoint)
        // WireGuardStore.save() never keeps the private/preshared key in the
        // persisted config (they live in the keychain) — fill them back in
        // here, at the click, so the handshake rung isn't permanently stuck on
        // "missing key" for every editor-saved config.
        return .wireGuard(config.withSecretsFromKeychain(), profileID: config.id,
                          host: split.host,
                          port: split.port ?? VPNProbe.wireGuardDefaultPort)
    }

    static func resolve(native config: NativeVPNConfig) -> ProbeTargetFacts {
        .native(config, host: VPNProbeTarget.splitHostPort(config.server).host)
    }
}
