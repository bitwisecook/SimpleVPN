// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  PauseControl.swift
//  The single Pause action: the tunnel stays signed in, its routes come out so
//  traffic uses the normal connection, and Resume puts them back. (The old
//  hover-to-split Block/Outside pair is gone — one pause, one meaning.) The
//  PausedBanner stays loud about traffic being outside the VPN, so the control
//  itself can be a calm pause glyph.
//
//  Iconography (kept consistent app-wide): road.lane.arrowtriangle.2.inward =
//  traffic routed AROUND the VPN (a lane-diversion sign), matching the sidebar
//  row + the paused banner. arrow.triangle.branch is reserved elsewhere for
//  "route OVER another VPN" and must NOT be used for pause.
//

import SwiftUI

struct PauseControl: View {
    var height: CGFloat = 32
    let onPause: () -> Void

    var body: some View {
        Button(action: onPause) {
            HStack(spacing: 5) {
                Image(systemName: "pause.fill")
                Text("Pause").font(.callout.weight(.medium))
            }
            .padding(.horizontal, 14)
            .frame(height: height)
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .foregroundStyle(.orange)
        .glassEffect(.regular.tint(.orange.opacity(0.22)).interactive(), in: .capsule)
        .help("Pause — the VPN stays signed in, but traffic uses your normal connection until you resume")
        .accessibilityLabel("Pause VPN")
        .accessibilityHint("Keeps the session signed in and sends traffic outside the tunnel until you resume.")
    }
}
