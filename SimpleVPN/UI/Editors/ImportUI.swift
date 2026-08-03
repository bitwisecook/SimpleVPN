// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ImportUI.swift
//  Shared UI for the profile-import pipeline: a drop target any window can adopt,
//  and the outcome alert (duplicate → "already imported as…", invalid → reason).
//  All entry points call VPNController.handleImport(of:) so behavior is identical
//  everywhere.
//

import SwiftUI
import UniformTypeIdentifiers

extension VPNController {

    /// Import files and stage the outcome for the alert. New imports are selected;
    /// success needs no dialog.
    func handleImport(of urls: [URL]) {
        Task {
            for url in urls {
                let outcome = await importProfile(from: url)
                switch outcome {
                case .imported(let id, _):
                    // OpenVPN and WireGuard imports land in `profiles`; a Cisco
                    // import (routed to its own store by otherEngineImportHandler)
                    // has no row here to select, so don't clobber whatever
                    // profile was showing.
                    if profiles.contains(where: { $0.id == id }) { selectedID = id }
                case .duplicate, .invalid:
                    // First problem wins in a multi-file drop — don't clobber an
                    // alert the user hasn't acknowledged yet.
                    if importOutcome == nil { importOutcome = outcome }
                }
            }
        }
    }
}

extension View {

    /// Accept .ovpn drops (Finder files) anywhere on this view, with the standard
    /// drop highlight. Dropping is never the only path — every window keeps its
    /// Import button/menu equivalent.
    func ovpnDropTarget(vpn: VPNController) -> some View {
        modifier(OVPNDropTarget(vpn: vpn))
    }

    /// Accept any config-file drop (Finder files) and hand the URLs to `perform`,
    /// which decides the engine per file. Same highlight/label as `ovpnDropTarget`,
    /// but the caller owns routing (used by the multi-engine Manage VPNs window).
    func fileDropTarget(label: String = "Drop to import",
                        perform: @escaping ([URL]) -> Void) -> some View {
        modifier(FileDropTarget(label: label, perform: perform))
    }

    /// Present the shared import-outcome alert (duplicate / unreadable).
    func importOutcomeAlert(vpn: VPNController) -> some View {
        modifier(ImportOutcomeAlert(vpn: vpn))
    }
}

private struct OVPNDropTarget: ViewModifier {
    @Bindable var vpn: VPNController
    @State private var isTargeted = false

    func body(content: Content) -> some View {
        content
            .dropDestination(for: URL.self) { urls, _ in
                // Take anything that plausibly is a profile; the engine parser is
                // the real gate and reports a clear reason for junk.
                let candidates = urls.filter { $0.isFileURL }
                guard !candidates.isEmpty else { return false }
                vpn.handleImport(of: candidates)
                return true
            } isTargeted: { isTargeted = $0 }
            .overlay {
                if isTargeted {
                    RoundedRectangle(cornerRadius: 10)
                        .strokeBorder(.tint, lineWidth: 2.5)
                        .background(.tint.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
                        .overlay {
                            Label("Drop to import", systemImage: "arrow.down.doc")
                                .font(.title3.weight(.medium))
                                .padding(12)
                                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10))
                        }
                        .padding(6)
                        .allowsHitTesting(false)
                }
            }
            .animation(.easeOut(duration: 0.12), value: isTargeted)
    }
}

/// Generic file drop that delegates routing to the caller (multi-engine import).
private struct FileDropTarget: ViewModifier {
    let label: String
    let perform: ([URL]) -> Void
    @State private var isTargeted = false

    func body(content: Content) -> some View {
        content
            .dropDestination(for: URL.self) { urls, _ in
                let candidates = urls.filter { $0.isFileURL }
                guard !candidates.isEmpty else { return false }
                perform(candidates)
                return true
            } isTargeted: { isTargeted = $0 }
            .overlay {
                if isTargeted {
                    RoundedRectangle(cornerRadius: 10)
                        .strokeBorder(.tint, lineWidth: 2.5)
                        .background(.tint.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
                        .overlay {
                            Label(label, systemImage: "arrow.down.doc")
                                .font(.title3.weight(.medium))
                                .padding(12)
                                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10))
                        }
                        .padding(6)
                        .allowsHitTesting(false)
                }
            }
            .animation(.easeOut(duration: 0.12), value: isTargeted)
    }
}

private struct ImportOutcomeAlert: ViewModifier {
    @Bindable var vpn: VPNController
    @Environment(\.openWindow) private var openWindow

    func body(content: Content) -> some View {
        content
            .alert(alertTitle,
                   isPresented: Binding(get: { vpn.importOutcome != nil },
                                        set: { if !$0 { vpn.importOutcome = nil } })) {
                if case .duplicate(let id, _) = vpn.importOutcome {
                    Button("Show") {
                        vpn.selectedID = id
                        openWindow(id: "main")
                    }
                }
                Button("OK", role: .cancel) {}
            } message: {
                Text(alertMessage)
            }
    }

    private var alertTitle: String {
        switch vpn.importOutcome {
        case .duplicate: "Already Imported"
        case .invalid: "Couldn't Import"
        default: ""
        }
    }

    private var alertMessage: String {
        switch vpn.importOutcome {
        case .duplicate(_, let name):
            "This VPN is already imported as \u{201C}\(name)\u{201D}."
        case .invalid(let reason):
            reason
        default: ""
        }
    }
}
