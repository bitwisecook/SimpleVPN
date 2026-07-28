// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ContentView.swift
//  Shared UI helpers/components used across the connection window, the VPN
//  management pane, and Settings.
//

import SwiftUI
import UniformTypeIdentifiers
import NetworkExtension
import CoreGraphics

enum UI {
    static func color(_ s: NEVPNStatus) -> Color {
        switch s {
        case .connected: return .green
        case .connecting, .reasserting: return .yellow
        case .disconnecting: return .orange
        default: return .secondary
        }
    }
    static var ovpnType: UTType { UTType(filenameExtension: "ovpn") ?? .data }
    static var appVersion: String {
        let i = Bundle.main.infoDictionary
        return "v\(i?["CFBundleShortVersionString"] as? String ?? "?") (build \(i?["CFBundleVersion"] as? String ?? "?"))"
    }
    static func isActive(_ s: NEVPNStatus) -> Bool { s == .connected || s == .connecting || s == .reasserting }
    static func parseRemote(_ ovpn: String) -> String? {
        for line in ovpn.split(separator: "\n") {
            let parts = line.split(separator: " ", omittingEmptySubsequences: true)
            if parts.count >= 2, parts[0] == "remote" { return String(parts[1]) }
        }
        return nil
    }
}

/// Sidebar row: logo · name · label pills.
struct VPNRow: View {
    let profile: VPNController.Profile
    let labelDefs: [LabelDef]
    var body: some View {
        HStack(spacing: 8) {
            LogoBadge(id: profile.id, status: profile.status)
            Text(profile.name).lineLimit(1).truncationMode(.tail)
            Spacer(minLength: 6)
            ForEach(labelDefs) { LabelPill(label: $0) }
        }
    }
}

struct LogoBadge: View {
    let id: String
    let status: NEVPNStatus
    var body: some View {
        ZStack(alignment: .bottomTrailing) {
            logo.frame(width: 22, height: 22).clipShape(RoundedRectangle(cornerRadius: 5))
            Circle().fill(UI.color(status)).frame(width: 7, height: 7)
                .overlay(Circle().strokeBorder(.white.opacity(0.9), lineWidth: 1))
        }
    }
    @ViewBuilder private var logo: some View {
        if let cg = LogoStore.load(id) { Image(decorative: cg, scale: 1).resizable().scaledToFill() }
        else { Image(systemName: "globe").foregroundStyle(.secondary) }
    }
}

/// A tappable logo well (click to pick, or drop an image).
struct LogoWell: View {
    let image: CGImage?
    let pick: () -> Void
    let drop: (URL) -> Void
    var body: some View {
        content
            .frame(width: 64, height: 64)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 12))
            .contentShape(Rectangle())
            .onTapGesture(perform: pick)
            .dropDestination(for: URL.self) { urls, _ in if let u = urls.first { drop(u); return true }; return false }
    }
    @ViewBuilder private var content: some View {
        if let image { Image(decorative: image, scale: 1).resizable().scaledToFit() }
        else { Image(systemName: "photo.badge.plus").font(.largeTitle).foregroundStyle(.secondary) }
    }
}

/// Liquid Glass status pill (plain capsule fallback pre-macOS 26).
struct StatusPill: View {
    let status: NEVPNStatus
    var body: some View {
        let content = HStack(spacing: 6) {
            Circle().fill(UI.color(status)).frame(width: 9, height: 9)
            Text(VPNController.statusText(status)).font(.callout)
        }
        .padding(.horizontal, 12).padding(.vertical, 6)

        if #available(macOS 26, *) { content.glassEffect(.regular, in: .capsule) }
        else { content.background(.quaternary, in: .capsule) }
    }
}

/// A toggleable label chip.
struct LabelChip: View {
    let label: LabelDef
    let on: Bool
    let toggle: () -> Void
    var body: some View {
        Button(action: toggle) {
            Text(label.name).font(.caption)
                .padding(.horizontal, 9).padding(.vertical, 3)
                .background(on ? AnyShapeStyle(label.color) : AnyShapeStyle(.clear), in: Capsule())
                .overlay(Capsule().strokeBorder(label.color, lineWidth: on ? 0 : 1))
                .foregroundStyle(on ? AnyShapeStyle(.black.opacity(0.78)) : AnyShapeStyle(.primary))
        }
        .buttonStyle(.plain)
    }
}

/// Minimal text document for exporting an .ovpn.
struct OVPNDocument: FileDocument {
    static var readableContentTypes: [UTType] { [UTType(filenameExtension: "ovpn") ?? .data, .plainText] }
    var text: String
    init(text: String) { self.text = text }
    init(configuration: ReadConfiguration) throws {
        text = String(data: configuration.file.regularFileContents ?? Data(), encoding: .utf8) ?? ""
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: Data(text.utf8))
    }
}
