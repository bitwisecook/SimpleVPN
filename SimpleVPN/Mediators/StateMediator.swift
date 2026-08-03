// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  StateMediator.swift
//  The GENERIC five-stage mediator shape (Docs/StateMediators.md), factored so the
//  three system-state mediators — Routes (P1, here), DNS (P2), Proxy (P3) — are the
//  same object graph with different concrete `Intent`/`Plan`/`Realizer` types. Only
//  the Route instance is built now; DNS/Proxy slot in by conforming to these
//  protocols without reshaping anything.
//
//  The five stages, each a protocol below:
//    1. Intent capture   — engines SUBMIT structured intent through ONE hookable
//                          seam (`IntentCapture.submit`/`withdraw`). This is the
//                          scriptable point: tier-3 `ROUTE_ADVERTISED`/`DNS_PUSHED`/
//                          `PROXY_PUSHED` Tcl events attach here later to rewrite
//                          intent before arbitration (see `MediatorIntentHook`).
//    2. Arbiter          — PURE computation of desired state from intents + policy
//                          (`MediatorArbiter`). No I/O; testable in isolation, like
//                          `GatewayPolicy`.
//    3. Realizer         — the SOLE writer: how a plan hits the OS (`MediatorRealizer`).
//                          `MultiTunnelRealizer` now; `PBRRealizer` later (P4) —
//                          same protocol, policy flips the backing.
//    4. Monitor          — observes REAL OS state and calls back on external drift
//                          (`MediatorMonitor`); its `*_CHANGED` callback is the second
//                          Tcl attach point (`MediatorDriftHook`).
//    5. Publisher         — `@Observable` EFFECTIVE (observed) state to the UI, so the
//                          picture reflects reality, never just the stored preference.
//
//  Nothing here is Route-specific. Keep it that way.
//

import Foundation

// MARK: - Stage 1: intent capture

/// A structured, per-engine statement of what an engine WANTS on the host — never a
/// direct write. `RouteIntent` / (later) `DNSIntent` / `ProxyIntent` conform.
protocol MediatorIntent: Sendable, Equatable {
    /// The engine (our profile id) this intent belongs to. One SCOPE = one subject.
    var engine: String { get }
}

/// The single hookable capture point per mediator. An engine submits or withdraws
/// intent here; a tier-3 handler (attached via `MediatorIntentHook`) may rewrite it
/// before it reaches the arbiter. Left deliberately minimal — no Tcl engine now.
protocol IntentCapture {
    associatedtype Intent: MediatorIntent
    /// Record/replace this engine's intent (fires the intent hook, if any).
    func submit(_ intent: Intent, from engine: String)
    /// Drop this engine's intent entirely (it disconnected / withdrew).
    func withdraw(engine: String)
}

/// The tier-3 seam for `*_ADVERTISED`/`*_PUSHED`: a synchronous, pure rewrite of a
/// submitted intent BEFORE arbitration. `nil` (the default) ⇒ intent passes through
/// untouched. No async I/O — this edits config-plane intent in place.
typealias MediatorIntentHook<Intent: MediatorIntent> = @MainActor (inout Intent) -> Void

// MARK: - Stage 2: arbiter (pure)

/// PURE desired-state computation. Given every engine's (already hook-rewritten)
/// intent and a policy, produce one coherent plan under the mediator's invariants
/// (Route: ≤1 default owner; DNS: split-DNS precedence; Proxy: one decision).
protocol MediatorArbiter {
    associatedtype Intent: MediatorIntent
    associatedtype Policy: Sendable
    associatedtype Plan: Sendable & Equatable
    static func plan(intents: [Intent], policy: Policy) -> Plan
}

// MARK: - Stage 3: realizer (sole writer)

/// The one path a plan takes to the OS for a resource. `realize` is handed the
/// previously-realized plan so it can compute the minimal, SAFELY-ORDERED delta
/// (Route: strip-old default before add-new). Backing-agnostic: multi-tunnel now,
/// PBR utun later.
protocol MediatorRealizer {
    associatedtype Plan: Sendable
    /// Drive the OS toward `plan`. `previous` is the last plan this realizer applied
    /// (nil on first run), so it can order/skip steps. Runs on the main actor; the
    /// realizer awaits its own IPC.
    @MainActor func realize(_ plan: Plan, from previous: Plan?) async
}

// MARK: - Stage 4: monitor (external drift)

/// Watches the ACTUAL OS state for the resource and fires when something external
/// changes it (another VPN app, a `route`/`scutil` command, a network change). The
/// callback delivers an observation the mediator diffs against expected.
protocol MediatorMonitor: AnyObject {
    associatedtype Observation: Sendable
    /// Begin watching. `onDrift` is invoked (off the main actor is fine; the mediator
    /// hops to main) whenever the monitor sees a candidate external change.
    func start(onDrift: @escaping @Sendable (Observation) -> Void) throws
    func stop()
}

/// The tier-3 seam for `*_CHANGED`: fired from the monitor after an external change
/// is confirmed drift, so policy can re-assert/alert/adapt. `nil` now.
typealias MediatorDriftHook<Event: Sendable> = @MainActor (Event) -> Void

// MARK: - A published external-change event (shared shape)

/// What a monitor detected, in words + when — published for the UI drift indicator
/// and handed to the `*_CHANGED` hook. Resource-neutral.
nonisolated struct MediatorDriftEvent: Sendable, Equatable, Identifiable {
    let id: UUID
    /// One-line human description ("External change took the default route to en0").
    let summary: String
    /// Whether the mediator re-asserted in response (vs. surfaced only).
    let reasserted: Bool
    let at: Date

    init(summary: String, reasserted: Bool, at: Date = Date()) {
        self.id = UUID()
        self.summary = summary
        self.reasserted = reasserted
        self.at = at
    }
}
