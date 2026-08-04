// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  MTUField.swift
//  THE MTU control for every engine that exposes one. Three editors had three
//  different controls for the same user-facing number: WireGuard and OpenConnect
//  used ValidatedNumberField (type it), while the Proxy Tunnel used a
//  `Stepper(step: 4)` over a 925-wide range — thirty clicks to get from 1500 to
//  1380, with no way to type the value at all.
//
//  One control, both idioms: type the number (validated against the engine's own
//  range, so a value the tunnel would refuse never gets stored) and nudge it with
//  a stepper for the "lower it a bit until transfers stop stalling" case that is
//  what an MTU is usually being changed for. Ranges always come from the config
//  type's own `mtuRange` so the UI bound and the stored bound can't drift.
//
//  The value is Optional for engines whose empty state means "auto" (WireGuard,
//  OpenConnect); engines whose model has no auto (the Proxy Tunnel's plain Int)
//  bind through `MTUField(value: Binding<Int>, …)`.
//

import SwiftUI

struct MTUField<Label: View>: View {
    @ViewBuilder let label: Label
    /// nil = the engine's own default ("auto"), for the engines that have one.
    @Binding var value: Int?
    let range: ClosedRange<Int>
    /// What an empty field means, shown as the field's prompt ("auto", "1420").
    let prompt: String
    let invalidMessage: String
    /// Step for the nudge buttons. 10 by default — big enough to be useful over a
    /// 200+ wide range, small enough to land on the value someone was told to use.
    var step: Int = 10

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                ValidatedNumberField(label: { label }, prompt: prompt, value: $value,
                                     range: range, invalidMessage: invalidMessage)
                Stepper(value: stepperValue, in: range, step: step) { EmptyView() }
                    .labelsHidden()
                    // The stepper is a nudge on the field beside it, not a second
                    // control with its own name — VoiceOver reads the field.
                    .accessibilityLabel("Adjust MTU")
                    .accessibilityValue(value.map(String.init) ?? prompt)
            }
        }
    }

    /// The stepper needs a concrete Int. An empty ("auto") field starts nudging
    /// from the middle of the legal range, which is where the engine's own default
    /// sits for every range we ship — never from 0, and never silently storing a
    /// value just because the stepper was rendered.
    private var stepperValue: Binding<Int> {
        Binding(
            get: { value ?? (range.lowerBound + range.upperBound) / 2 },
            set: { value = min(max($0, range.lowerBound), range.upperBound) })
    }
}

extension MTUField where Label == EngineSettingLabel {
    /// The common case: an engine spec supplies the label, and "changed" comes
    /// from the spec's declared default.
    init(spec: EngineSettingSpec, value: Binding<Int?>, range: ClosedRange<Int>,
         prompt: String, invalidMessage: String, step: Int = 10) {
        self.init(label: { EngineSettingLabel(spec: spec, value: value.wrappedValue) },
                  value: value, range: range, prompt: prompt,
                  invalidMessage: invalidMessage, step: step)
    }
}

/// Non-optional binding for engines whose model always carries an MTU (the Proxy
/// Tunnel's `ProxyTunnelConfig.mtu`): the field can be cleared on screen, but a
/// cleared field restores the engine default rather than storing nothing.
struct RequiredMTUField<Label: View>: View {
    @ViewBuilder let label: Label
    @Binding var value: Int
    let range: ClosedRange<Int>
    let engineDefault: Int
    let invalidMessage: String
    var step: Int = 10

    var body: some View {
        MTUField(label: { label },
                 value: Binding(get: { value }, set: { value = $0 ?? engineDefault }),
                 range: range, prompt: String(engineDefault),
                 invalidMessage: invalidMessage, step: step)
    }
}
