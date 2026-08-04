// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ControlPlaneDispatcher.swift
//  THE single entry for control-plane mutations. Every interface — UI buttons,
//  the `simplevpn` CLI (via ControlServer), App Intents, and later Tcl handlers —
//  submits a ControlCommand here, so all of them get identical treatment:
//
//    normalize (command is data)
//      → guard chain (MDM policy today; Tcl CTL_* handlers attach here later —
//        each guard may veto with a reason, e.g. "no endpoints in China")
//      → readiness gate (the SAME ConnectReadiness the UI's buttons read)
//      → execute (the sole backend: VPNController + the mediators)
//      → broadcast ControlEvent (one liveness stream for every subscriber)
//
//  CONSISTENCY IS STRUCTURAL, not conventional: the dispatcher installs its
//  guard chain INTO VPNController (`controlGuard`), whose lifecycle entries
//  (connect/disconnect/pause/resume/setDefaultGateway) consult it before
//  acting. So the UI's direct `vpn.*` calls are gated exactly like a wire
//  command — a new view (or a forgotten call site) cannot bypass policy.
//  Out-of-process interfaces still come through execute()/query()/subscribe(),
//  which adds the readiness gate and clean denied/notReady replies.
//

import Foundation
import NetworkExtension

@MainActor
@Observable
final class ControlPlaneDispatcher {
    private let vpn: VPNController

    /// The guard chain, run in order on every mutation. Each entry is named so a
    /// denial can say WHO said no. Tcl `CTL_*` handlers attach here later as one
    /// more entry — same seam, same veto shape (see Docs/PolicyEvents.md).
    @ObservationIgnored private var guards: [(name: String, check: (ControlCommand) -> ControlDecision)] = []

    /// Live event subscribers (UI observation aside — views observe the models
    /// directly; this stream is for the CLI's `watch`, intents, and scripts).
    @ObservationIgnored private var subscribers: [UUID: AsyncStream<ControlEvent>.Continuation] = [:]

    /// Extension-doctor seam: non-nil while the engine needs a CONSENT-GATED
    /// repair. Out-of-process callers (the CLI) can never grant that consent —
    /// only the app's own warning can — so a wire connect answers `.notReady`
    /// with this message instead of half-starting against a wedged engine.
    @ObservationIgnored var engineAttention: (() -> String?)?

    init(vpn: VPNController) {
        self.vpn = vpn
        guards.append((name: "mdm", check: Self.managedPolicyGuard))
        // One liveness stream: VPNController reports status flips, the Route
        // mediator reports every default-gateway change (commands AND fallback
        // promotions AND drift re-asserts — the sink is on the published owner,
        // so nothing can change it without every subscriber hearing).
        vpn.controlEventSink = { [weak self] event in self?.broadcast(event) }
        vpn.routes.onOwnerChange = { [weak self] owner in
            self?.broadcast(.gatewayChanged(owner: owner))
        }
        // Structural enforcement: the backend's own lifecycle entries consult
        // this chain, so even direct UI calls can't route around a guard.
        vpn.controlGuard = { [weak self] command in
            guard let self else { return .allow }
            if case .denied(let why) = self.runGuards(command) ?? .ok {
                return .deny(why)
            }
            return .allow
        }
    }

    // MARK: - Commands

    func execute(_ command: ControlCommand) async -> ControlReply {
        if let veto = runGuards(command) { return veto }
        switch command {
        case .connect(let id):
            guard hasProfile(id) else { return .failed("no such VPN: \(id)") }
            if let why = engineAttention?() { return .notReady(why) }
            switch vpn.connectReadiness(for: id) {
            case .ready: break
            case .needsSignIn: return .notReady("this VPN needs a sign-in — open SimpleVPN to enter it")
            case .needsCode: return .notReady("this VPN needs a verification code — open SimpleVPN to enter it")
            case .blocked: return .notReady("this VPN has a configuration problem — open SimpleVPN")
            }
            do {
                try await vpn.connectUsingConfiguredSource(id: id, typedOTP: "")
                return .ok
            } catch is CancellationError {
                return .failed("cancelled")
            } catch {
                return .failed(error.localizedDescription)
            }
        case .disconnect(let id):
            guard hasProfile(id) else { return .failed("no such VPN: \(id)") }
            vpn.disconnect(id: id)
            return .ok
        case .pause(let id):
            guard hasProfile(id) else { return .failed("no such VPN: \(id)") }
            guard vpn.profiles.first(where: { $0.id == id })?.status == .connected else {
                return .failed("only a connected VPN can pause")
            }
            await vpn.pause(id: id)
            return .ok
        case .resume(let id):
            guard hasProfile(id) else { return .failed("no such VPN: \(id)") }
            await vpn.resume(id: id)
            return .ok
        case .setDefaultGateway(let owner):
            if let owner {
                guard hasProfile(owner) else { return .failed("no such VPN: \(owner)") }
                guard vpn.canBeDefaultGateway(owner) else {
                    return .failed("\(displayName(owner)) can't take the default route right now")
                }
            }
            await vpn.setDefaultGateway(to: owner)
            return .ok
        }
    }

    /// Run the guard chain; non-nil = the reply to return (already broadcast).
    private func runGuards(_ command: ControlCommand) -> ControlReply? {
        for entry in guards {
            if case .deny(let why) = entry.check(command) {
                broadcast(.commandDenied(cmd: command.name, profile: command.profileID, reason: why))
                return .denied(why)
            }
        }
        return nil
    }

    // MARK: - Queries

    func query(_ q: ControlQuery) -> ControlReply {
        switch q {
        case .profiles:
            return .profiles(vpn.profiles.map { summary($0) })
        case .status(let id):
            guard let p = vpn.profiles.first(where: { $0.id == id }) else {
                return .failed("no such VPN: \(id)")
            }
            return .status(summary(p))
        case .gateway:
            return .gateway(owner: vpn.routes.effectiveGatewayOwner)
        case .version:
            let info = Bundle.main.infoDictionary
            let short = info?["CFBundleShortVersionString"] as? String ?? "?"
            let build = info?["CFBundleVersion"] as? String ?? "?"
            return .version("\(short) (\(build))")
        }
    }

    /// Resolve a user-typed name/id to a profile id — shared by the CLI and
    /// intents so "connect gr lab" behaves identically everywhere. Exact id,
    /// then exact name (case-insensitive), then unique name prefix.
    func resolveProfile(_ text: String) -> String? {
        let t = text.trimmingCharacters(in: .whitespaces)
        if vpn.profiles.contains(where: { $0.id == t }) { return t }
        let lowered = t.lowercased()
        if let exact = vpn.profiles.first(where: { $0.name.lowercased() == lowered }) { return exact.id }
        let prefixed = vpn.profiles.filter { $0.name.lowercased().hasPrefix(lowered) }
        return prefixed.count == 1 ? prefixed[0].id : nil
    }

    // MARK: - Liveness

    /// Subscribe to the one event stream. Ends automatically when the consumer
    /// goes away (the continuation's termination removes it).
    func subscribe() -> AsyncStream<ControlEvent> {
        let id = UUID()
        return AsyncStream { continuation in
            continuation.onTermination = { [weak self] _ in
                Task { @MainActor [weak self] in self?.subscribers[id] = nil }
            }
            subscribers[id] = continuation
        }
    }

    private func broadcast(_ event: ControlEvent) {
        for continuation in subscribers.values { continuation.yield(event) }
    }

    // MARK: - Guards

    /// MDM enforcement, centrally: what a configuration profile forbids is
    /// forbidden through EVERY interface — no side doors. Internal (not private)
    /// so the tests can drive it directly.
    static func managedPolicyGuard(_ command: ControlCommand) -> ControlDecision {
        switch command {
        case .setDefaultGateway(let owner) where owner == nil && ManagedPolicy.forceKeepInsideVPN:
            return .deny("management policy keeps traffic inside the VPN (ForceKeepInsideVPN)")
        default:
            return .allow
        }
    }

    // MARK: - Helpers

    private func hasProfile(_ id: String) -> Bool {
        vpn.profiles.contains { $0.id == id }
    }

    private func displayName(_ id: String) -> String {
        vpn.profiles.first { $0.id == id }?.name ?? id
    }

    private func summary(_ p: VPNController.Profile) -> ControlProfileSummary {
        ControlProfileSummary(
            id: p.id,
            name: p.name,
            kind: p.kind.rawValue,
            status: VPNController.wireStatus(p.status),
            readiness: Self.wireReadiness(vpn.connectReadiness(for: p.id)),
            server: p.server,
            gatewayOwner: vpn.routes.effectiveGatewayOwner == p.id)
    }

    nonisolated static func wireReadiness(_ r: ConnectReadiness) -> String {
        switch r {
        case .ready: ControlReadinessWord.ready
        case .needsSignIn: ControlReadinessWord.needsSignIn
        case .needsCode: ControlReadinessWord.needsCode
        case .blocked: ControlReadinessWord.blocked
        }
    }
}
