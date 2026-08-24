// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// ConfigurationDropTarget.swift
// One visible promise for the window-wide configuration drop handler. The empty
// page and every provider setup page use this exact surface, so neither can imply
// a different set of accepted files or drift into a decorative, inert-looking box.

import SwiftUI

struct ConfigurationDropTarget: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.liveVisualPolicy) private var liveVisuals

    let isTargeted: Bool
    /// Most compact onboarding surfaces use the standard 420pt well. A staged
    /// provider page passes nil so its input matches the step card exactly.
    var maximumWidth: CGFloat? = 420
    /// The empty landing page needs to reveal the provider choices below its
    /// import well without asking a first-time person to scroll merely to see
    /// them. Other appearances retain the roomier default treatment.
    var compact = false

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: isTargeted ? "arrow.down.doc.fill" : "arrow.down.doc")
                .font(.system(size: 38))
                .foregroundStyle(isTargeted ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
                .contentTransition(.symbolEffect(.replace))
                .symbolEffect(.wiggle, options: .repeat(.periodic(delay: 5)),
                              isActive: liveVisuals.permitsContinuousAnimation(reduceMotion: reduceMotion) && !isTargeted)
                .accessibilityHidden(true)
            Text("Drag a VPN configuration here")
                .font(.callout.weight(.medium))
            Text("OpenVPN (.ovpn / .conf), WireGuard (.conf), Cisco (.xml / .pcf), or a 1Password item")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(.vertical, compact ? 16 : 24)
        .padding(.horizontal, compact ? 24 : 30)
        .frame(maxWidth: maximumWidth ?? .infinity)
        .contentShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
        .glassEffect(
            .regular.tint(isTargeted ? Color.accentColor.opacity(0.22) : nil).interactive(),
            in: RoundedRectangle(cornerRadius: 20, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .strokeBorder(style: StrokeStyle(lineWidth: isTargeted ? 2 : 1,
                                                 dash: [7, 5]))
                .foregroundStyle(isTargeted ? AnyShapeStyle(.tint) : AnyShapeStyle(.quaternary))
        }
        .animation(.snappy(duration: 0.2), value: isTargeted)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Drop zone for VPN configuration files")
        .accessibilityHint("Use the configuration button to select a file instead.")
    }
}
