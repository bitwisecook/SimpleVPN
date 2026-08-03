// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNIntents.swift
//  Shortcuts/Siri surface. THIN ADAPTERS over the control plane: every intent
//  submits the same ControlCommand/ControlQuery the UI and the `simplevpn` CLI
//  use, through the same dispatcher — same MDM guard chain, same readiness
//  rules. If Shortcuts can do something the app forbids (or vice versa), that's
//  a control-surface bug, not a feature.
//
//  needsSignIn is surfaced as a RESULT, not a prompt loop: Shortcuts can't type
//  an OTP, so the intent says to open the app rather than half-connecting.
//

import AppIntents

// MARK: - Dependency plumbing

/// The dispatcher, handed to the intents at app startup (AppIntents constructs
/// intent instances itself, so dependencies flow through AppDependencyManager).
enum VPNIntentSupport {
    @MainActor static func register(_ dispatcher: ControlPlaneDispatcher) {
        AppDependencyManager.shared.add(dependency: dispatcher)
    }
}

// MARK: - Entity

/// A VPN as Shortcuts sees it — resolved fresh from the control plane so the
/// picker always matches the sidebar.
struct VPNProfileEntity: AppEntity, Identifiable {
    static let typeDisplayRepresentation = TypeDisplayRepresentation(name: "VPN")
    static let defaultQuery = VPNProfileQuery()

    var id: String
    var name: String
    var kind: String
    var status: String

    var displayRepresentation: DisplayRepresentation {
        DisplayRepresentation(title: "\(name)", subtitle: "\(status)")
    }

    @MainActor static func from(_ summary: ControlProfileSummary) -> VPNProfileEntity {
        VPNProfileEntity(id: summary.id, name: summary.name,
                         kind: summary.kind, status: summary.status)
    }
}

struct VPNProfileQuery: EntityQuery {
    @Dependency private var control: ControlPlaneDispatcher

    @MainActor
    func entities(for identifiers: [String]) async throws -> [VPNProfileEntity] {
        guard case .profiles(let list) = control.query(.profiles) else { return [] }
        return list.filter { identifiers.contains($0.id) }.map(VPNProfileEntity.from)
    }

    @MainActor
    func suggestedEntities() async throws -> [VPNProfileEntity] {
        guard case .profiles(let list) = control.query(.profiles) else { return [] }
        return list.map(VPNProfileEntity.from)
    }
}

// MARK: - Errors

enum VPNIntentError: Error, CustomLocalizedStringResourceConvertible {
    case denied(String)
    case notReady(String)
    case failed(String)

    var localizedStringResource: LocalizedStringResource {
        switch self {
        case .denied(let why): "Not allowed: \(why)"
        case .notReady(let why): "\(why)"
        case .failed(let why): "\(why)"
        }
    }
}

/// Shared reply handling so every intent maps denied/notReady/failed identically.
@MainActor
private func requireOK(_ reply: ControlReply) throws {
    switch reply {
    case .denied(let why): throw VPNIntentError.denied(why)
    case .notReady(let why): throw VPNIntentError.notReady(why)
    case .failed(let why): throw VPNIntentError.failed(why)
    default: break
    }
}

// MARK: - Intents

struct ConnectVPNIntent: AppIntent {
    static let title: LocalizedStringResource = "Connect VPN"
    static let description = IntentDescription(
        "Connects a VPN using its saved sign-in. If the VPN needs something typed, this opens SimpleVPN instead.")

    @Parameter(title: "VPN") var profile: VPNProfileEntity
    @Dependency private var control: ControlPlaneDispatcher

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        try requireOK(await control.execute(.connect(profile: profile.id)))
        return .result(dialog: "Connecting \(profile.name).")
    }
}

struct DisconnectVPNIntent: AppIntent {
    static let title: LocalizedStringResource = "Disconnect VPN"
    static let description = IntentDescription("Disconnects a VPN.")

    @Parameter(title: "VPN") var profile: VPNProfileEntity
    @Dependency private var control: ControlPlaneDispatcher

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        try requireOK(await control.execute(.disconnect(profile: profile.id)))
        return .result(dialog: "Disconnecting \(profile.name).")
    }
}

struct VPNStatusIntent: AppIntent {
    static let title: LocalizedStringResource = "Get VPN Status"
    static let description = IntentDescription(
        "Reports a VPN's connection status (connected, disconnected, connecting…).")

    @Parameter(title: "VPN") var profile: VPNProfileEntity
    @Dependency private var control: ControlPlaneDispatcher

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog & ReturnsValue<String> {
        let reply = control.query(.status(profile: profile.id))
        try requireOK(reply)
        guard case .status(let summary) = reply else {
            throw VPNIntentError.failed("no status for \(profile.name)")
        }
        return .result(value: summary.status, dialog: "\(profile.name) is \(summary.status).")
    }
}

// MARK: - Shortcuts

struct SimpleVPNShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: ConnectVPNIntent(),
                    phrases: ["Connect \(.applicationName)", "Connect a VPN in \(.applicationName)"],
                    shortTitle: "Connect VPN", systemImageName: "lock.shield")
        AppShortcut(intent: DisconnectVPNIntent(),
                    phrases: ["Disconnect \(.applicationName)"],
                    shortTitle: "Disconnect VPN", systemImageName: "lock.open")
        AppShortcut(intent: VPNStatusIntent(),
                    phrases: ["\(.applicationName) status"],
                    shortTitle: "VPN Status", systemImageName: "waveform.path.ecg")
    }
}
