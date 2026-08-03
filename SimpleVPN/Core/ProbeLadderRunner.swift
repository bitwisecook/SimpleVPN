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

@MainActor
@Observable
final class ProbeLadderRunner {

    private(set) var ladder: ProbeLadder?
    private(set) var isRunning = false
    /// Set when the opted-in sign-in test couldn't get its credentials.
    private(set) var signInProblem: UserFacingError?

    /// The VPN the current ladder belongs to, so a second click re-runs the
    /// right one and the result is filed under the right profile.
    private(set) var facts: ProbeTargetFacts?

    private var task: Task<Void, Never>?

    func cancel() {
        task?.cancel()
        task = nil
        isRunning = false
    }

    /// Run the automatic part of the ladder: everything up to the account
    /// boundary. This is what every entry point calls.
    func run(_ facts: ProbeTargetFacts) {
        start(facts, includeAccountSteps: false, signIn: nil)
    }

    /// "Test sign-in too" — the deliberate, clicked-on crossing of the account
    /// boundary. Credentials are resolved here, not before.
    func runIncludingSignIn(_ facts: ProbeTargetFacts, vpn: VPNController?) {
        signInProblem = nil
        Task { [weak self] in
            guard let self else { return }
            var material = ProbeSignInMaterial(username: "", password: "", otp: "",
                                               privateKeyPassphrase: "")
            if let vpn, !facts.profileID.isEmpty {
                do {
                    material = try await Self.signInMaterial(profileID: facts.profileID, vpn: vpn)
                } catch is CancellationError {
                    return                      // the user dismissed the prompt
                } catch {
                    self.signInProblem = UserFacingError.classify(error)
                    return
                }
            }
            self.start(facts, includeAccountSteps: true, signIn: material)
        }
    }

    private func start(_ facts: ProbeTargetFacts, includeAccountSteps: Bool,
                       signIn: ProbeSignInMaterial?) {
        cancel()
        self.facts = facts
        ladder = ProbeLadderPlan.ladder(for: facts)
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
                progress: publish)
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
