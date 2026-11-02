// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import SwiftUI

/// A request survives opening the management window and is consumed once there.
@MainActor @Observable
final class VPNCreationRequests {
    private(set) var pending = false
    private(set) var generation = 0

    func request() { pending = true; generation += 1 }
    func take() -> Bool {
        defer { pending = false }
        return pending
    }
}

struct AddVPNButton: View {
    var action: () -> Void

    var body: some View {
        Button("Add VPN", systemImage: "plus", action: action)
            .labelStyle(.iconOnly)
            .buttonStyle(.borderless)
            .frame(width: 32, height: 32)
            .contentShape(Rectangle())
            .help("Set up a new VPN from a file, pasted instructions, or a server address")
            .accessibilityLabel("Add VPN")
            .accessibilityHint("Opens a new VPN in the manager.")
    }
}

struct SidebarActionBar<Content: View>: View {
    @ViewBuilder var content: () -> Content
    var body: some View {
        VStack(spacing: 0) {
            Divider()
            HStack(spacing: 4, content: content)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(.bar)
    }
}
