// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Testing
@testable import SimpleVPN

/// Guards two boundary races: a stale NetworkExtension preference snapshot must
/// not revive a just-deleted VPN, and an `op://` item reference must reach the
/// 1Password well rather than be mistaken for a configuration-file URL.
@MainActor
struct ProfileRemovalAndDropTests {

    private func source(_ path: String) throws -> String {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        return try String(contentsOf: root.appendingPathComponent(path), encoding: .utf8)
    }

    @Test func removalTombstoneFiltersStalePreferenceSnapshotsBeforeCredentialReads() throws {
        let controller = try source("SimpleVPN/ControlPlane/VPNController.swift")
        let crud = try source("SimpleVPN/ControlPlane/VPNController+CRUD.swift")

        #expect(controller.contains("locallyRemovedProfileIDs: Set<String>"))
        let guardIndex = try #require(controller.range(of: "guard !locallyRemovedProfileIDs.contains(id) else { continue }").map(\.lowerBound))
        let credentialIndex = try #require(controller.range(of: "credentialSources[id] =").map(\.lowerBound))
        #expect(guardIndex < credentialIndex,
                "a profile being removed must be skipped before its credential source is read")
        #expect(crud.contains("locallyRemovedProfileIDs.insert(id)"))
        #expect(controller.contains("func hideProfileWhileRemoving(id: String)"))
        #expect(crud.contains("hideProfileWhileRemoving(id: id)"))
        #expect(crud.contains("locallyRemovedProfileIDs.remove(id)\n            await loadAll()"),
                "only a failed preference removal may clear the tombstone")
    }

    @Test func credentialWellOwnsItsSourceDetectingDestinationWithoutAWindowWideAncestor() throws {
        let ui = try source("SimpleVPN/UI/Editors/ImportUI.swift")
        let firstConnect = try source("SimpleVPN/UI/Connection/FirstConnectSetupCard.swift")
        let connectionView = try source("SimpleVPN/UI/Connection/ConnectionView.swift")
        let endpointSection = try source("SimpleVPN/UI/Connection/EndpointSection.swift")

        #expect(!ui.contains("OVPNDropTarget"))
        #expect(!connectionView.contains(".ovpnDropTarget"),
                "a window-wide destination competes with the credential well before either handler can filter its payload")
        #expect(firstConnect.contains("Release to use this password item"))
        #expect(firstConnect.contains("regardless of which method is selected above"))
        #expect(firstConnect.contains("Browse 1Password"))
        #expect(firstConnect.contains(".onDrop(of: CredentialItemDrop.acceptedContentTypes"))
        #expect(firstConnect.contains("perform: acceptCredentialDrop"),
                "the visible well must directly own the same small handler proven by OnePasswordProbe")
        #expect(firstConnect.contains("CredentialItemDrop.canAccept(providers)"))
        #expect(firstConnect.contains("CredentialItemDrop.source(from: providers)"),
                "the drag payload, not the selected auth button, must choose the provider")
        #expect(firstConnect.contains("updated.kind = .applePasswords"))
        #expect(firstConnect.contains("OnePasswordDropItem.activeDragSnapshot()"))
        let dropModel = try source("SimpleVPN/Credentials/CredentialItemDrop.swift")
        #expect(dropModel.contains(".utf8PlainText, .plainText, .text, .url, .data"),
                "the target must negotiate through the public flavours exported by 1Password and Apple Passwords")
        #expect(!connectionView.contains("MainWindowOnboardingSizer"),
                "a full-window AppKit background prevents nested SwiftUI drop negotiation")
        let globe = try source("SimpleVPN/UI/Map/MetalGlobeView.swift")
        #expect(!endpointSection.contains("usesMetalSurface"))
        #expect(!globe.contains("NSViewRepresentable"))
        #expect(!globe.contains("MTKView"),
                "the textured globe must remain a SwiftUI shader so it cannot block nested external drop targets")
        #expect(globe.contains("ShaderLibrary.globeDay"))
        #expect(globe.contains("ShaderLibrary.globeNightLights"))
    }
}
