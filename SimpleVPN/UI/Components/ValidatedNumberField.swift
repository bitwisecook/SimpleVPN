// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ValidatedNumberField.swift
//  THE numeric control for every editor in the app. A field must never accept a
//  value the engine will reject (a silent connect failure) nor reject one it
//  accepts (needless blocking) — and the problem must surface INLINE, in the
//  editor, next to the field that caused it.
//
//  Grew up inside OpenVPNOptionsForm as a private helper; promoted here so the
//  WireGuard / SSH / OpenConnect / native editors share one behaviour instead of
//  each shipping a bare TextField with no range at all. The legal range always
//  comes from the config type's own `…Range` block (OpenVPNOverrides.portRange,
//  WireGuardConfig.mtuRange, …) so the UI bound and the stored bound can't drift.
//

import SwiftUI

/// Numeric text field over an optional Int with range validation: empty = default
/// (nil), out-of-range shows an inline error and stores nothing.
struct ValidatedNumberField<Label: View>: View {
    @ViewBuilder let label: Label
    let prompt: String
    @Binding var value: Int?
    let range: ClosedRange<Int>
    let invalidMessage: String

    @State private var text = ""
    @State private var invalid = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            LabeledContent {
                TextField(prompt, text: $text)
                    .multilineTextAlignment(.trailing)
                    .frame(maxWidth: 120).frame(maxWidth: .infinity, alignment: .trailing)
                    .onChange(of: text) { _, newValue in commit(newValue) }
                    .onChange(of: value) { _, newValue in
                        // External change (Reset to Default / Reset All): resync.
                        let shown = Int(text.trimmingCharacters(in: .whitespaces))
                        if newValue != shown { text = newValue.map(String.init) ?? ""; invalid = false }
                    }
                    .onAppear { text = value.map(String.init) ?? "" }
            } label: { label }
            if invalid {
                Text(invalidMessage)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .accessibilityLabel("Error: \(invalidMessage)")
            }
        }
    }

    private func commit(_ newValue: String) {
        let trimmed = newValue.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty {
            value = nil; invalid = false
        } else if let n = Int(trimmed), range.contains(n) {
            value = n; invalid = false
        } else {
            invalid = true   // keep the last good stored value
        }
    }
}
