// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Testing

@testable import SimpleVPN

@MainActor
struct MainConnectionEnvironmentTests {
    private static let repoRoot: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()

    private func source(_ path: String) throws -> String {
        try String(contentsOf: Self.repoRoot.appendingPathComponent(path), encoding: .utf8)
    }

    @Test("the main window receives every store and live manager it displays")
    func mainWindowGetsTheConnectionDependencies() throws {
        let app = try source("SimpleVPN/App/SimpleVPNApp.swift")
        let main = try #require(app.components(separatedBy: "Window(\"About SimpleVPN\"").first)
        for dependency in [".environment(tunnels)", ".environment(tunnelManager)", ".environment(nativeVPN)"] {
            #expect(main.contains(dependency), "main window is missing \(dependency)")
        }

        let view = try source("SimpleVPN/UI/Connection/ConnectionView.swift")
        #expect(!view.contains("SubprocessTunnelManager?"))
        #expect(!view.contains("SubprocessTunnelStore?"))
        #expect(!view.contains("NativeVPNManager?"))
    }

    @Test("a missing-auth repair is routed before its settings window is opened")
    func repairRouteIsRegisteredBeforeManageWindowOpens() throws {
        let view = try source("SimpleVPN/UI/Connection/ConnectionView.swift")
        let function = try #require(view.components(separatedBy: "private func revealSetting")
            .dropFirst().first?.components(separatedBy: "\n    }").first)
        let route = try #require(function.range(of: "settingsRouter?.go(to: settingID, profileID: profileID)"))
        let window = try #require(function.range(of: "openWindow(id: \"manage\")"))
        #expect(route.lowerBound < window.lowerBound)
    }

    @Test("the Manage VPNs initial seed cannot replace an explicit repair destination")
    func manageSeedPrefersRoutedVPN() throws {
        let manage = try source("SimpleVPN/UI/Editors/ManageVPNsView.swift")
        let seed = try #require(manage.components(separatedBy: "private func loadInitialState() async {")
            .dropFirst().first?.components(separatedBy: "\n    /// Keeping the selection lookup").first)
        #expect(seed.contains("guard !seeded else { return }"))
        let route = try #require(seed.range(of: "settingsRouter?.route?.profileID"))
        let fallback = try #require(seed.range(of: "vpn.selectedID ?? vpn.profiles.first?.id"))
        #expect(route.lowerBound < fallback.lowerBound)
    }

    @Test("an active transient-password session does not retain a sign-in repair banner")
    func liveTunnelClearsSavedCredentialNeed() throws {
        let connection = try source("SimpleVPN/UI/Connection/ConnectionView.swift")
        #expect(connection.contains("let need = row.isActive ? nil : otherNeeds[row.id]"))
        #expect(connection.contains("guard !tunnelManager.isActive(t.id) else { continue }"))

        let detail = try source("SimpleVPN/UI/Connection/OtherConnectionDetailView.swift")
        #expect(detail.contains("if !isActive {"))
        #expect(detail.contains("The readiness cache is based on saved credentials"))
    }

    @Test("Delete asks before removing the selected managed VPN instead of entering List reordering")
    func managedListHandlesDeleteBeforeReorder() throws {
        let manage = try source("SimpleVPN/UI/Editors/ManageVPNsView.swift")
        #expect(manage.contains(".onDeleteCommand(perform: removeSelection)"))
        let removal = try #require(manage.components(separatedBy: "private func confirmRemoval()")
            .dropFirst().first?.components(separatedBy: "// MARK: Discovery").first)
        let clear = try #require(removal.range(of: "selection = nil"))
        let tunnel = try #require(removal.range(of: "tunnels.remove(id)"))
        #expect(clear.lowerBound < tunnel.lowerBound)
        #expect(manage.contains(".confirmationDialog(\"Remove \\(pendingRemoval?.name ?? \"VPN\")?\""))
    }
}
