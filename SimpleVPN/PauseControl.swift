// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  PauseControl.swift
//  A pause control the width of its two choices: at rest it's a single Liquid
//  Glass pause pill; as the pointer moves in it morphs into two glass buttons —
//  "Block" (stop, keeps traffic off the network) and "Outside" (traffic goes
//  outside the VPN). The two-choice split is deliberate: sending traffic outside
//  the VPN is a real leak and should never be a hidden menu item.
//
//  Iconography (kept consistent app-wide): stop.fill = block/hold;
//  road.lane.arrowtriangle.2.inward = send OUTSIDE the VPN (the risky bypass; a
//  lane-diversion sign — traffic routed AROUND — matching the
//  sidebar row + the paused banner). arrow.triangle.branch is reserved elsewhere
//  for "route OVER another VPN" and must NOT be used for the outside/bypass action.
//

import SwiftUI

struct PauseControl: View {
    var height: CGFloat = 32
    var width: CGFloat = 168
    let onBlock: () -> Void        // hold: transport paused, no traffic leaves
    let onRouteAround: () -> Void  // bypass: traffic goes outside the VPN

    @State private var expanded = false
    @Namespace private var glass
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        content
            .frame(width: width, height: height)
            .onHover { hovering in
                withAnimation(reduceMotion ? .none : .snappy(duration: 0.28)) { expanded = hovering }
            }
            .help("Pause — block traffic, or route it around the VPN")
    }

    @ViewBuilder private var content: some View {
        if #available(macOS 26, *) {
            GlassEffectContainer(spacing: 6) {
                if expanded {
                    HStack(spacing: 6) {
                        segment("stop.fill", "Block", .red, action: onBlock)
                            .glassEffectID("lead", in: glass)
                        segment("road.lane.arrowtriangle.2.inward", "Outside", .orange, action: onRouteAround)
                            .glassEffectID("trail", in: glass)
                            .glassEffectTransition(.materialize)
                    }
                } else {
                    segment("pause.fill", nil, .orange, action: {})
                        .glassEffectID("lead", in: glass)
                }
            }
        } else {
            fallback
        }
    }

    @available(macOS 26, *)
    private func segment(_ icon: String, _ label: String?, _ tint: Color, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 5) {
                Image(systemName: icon)
                if let label { Text(label).font(.callout.weight(.medium)) }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .foregroundStyle(tint)
        .glassEffect(.regular.tint(tint.opacity(0.22)).interactive(), in: .capsule)
    }

    // Pre-26 fallback: at rest a bordered pause; on hover the two explicit choices.
    private var fallback: some View {
        Group {
            if expanded {
                HStack(spacing: 6) {
                    Button { onBlock() } label: { Label("Block", systemImage: "stop.fill").frame(maxWidth: .infinity) }
                        .tint(.red)
                    Button { onRouteAround() } label: { Label("Outside", systemImage: "road.lane.arrowtriangle.2.inward").frame(maxWidth: .infinity) }
                        .tint(.orange)
                }
                .buttonStyle(.borderedProminent)
            } else {
                Button {} label: { Image(systemName: "pause.fill").frame(maxWidth: .infinity, maxHeight: .infinity) }
                    .buttonStyle(.bordered)
            }
        }
    }
}
