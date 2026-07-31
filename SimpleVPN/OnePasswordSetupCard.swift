// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OnePasswordSetupCard.swift
//  The inline walkthrough shown the first time someone chooses 1Password as
//  their sign-in: one card that says which of the four setup steps is missing
//  and offers the button that fixes it.
//
//  It replaced a static "install 1Password and turn on Integrate with other
//  apps" warning that was shown whether or not any of that was true, named a
//  setting 1Password no longer has, and had no way to tell "not installed" from
//  "installed but the SDK setting is off" — the failure people actually hit.
//
//  The check itself lives in OnePasswordPreflight (Core, testable); this file is
//  presentation plus the small object the two surfaces share to run it. Nothing
//  here starts a lookup on its own: the surface asks, on an explicit user action
//  (choosing 1Password, or clicking Check Again).
//
//  No spinner: the first-connect card is inserted with a transition, and
//  platform-backed views inside an animated container are what the layout-loop
//  rule exists for — "Checking…" as plain text says the same thing.
//

import SwiftUI

/// Runs the setup check for one surface and holds its answer.
@MainActor @Observable final class OnePasswordPreflightModel {
    /// nil = never checked, so the card shows nothing at all.
    private(set) var state: OnePasswordPreflight.State?
    private(set) var checking = false

    /// Record something learned WITHOUT a lookup — the prompt-free probe saying
    /// 1Password isn't installed at all.
    func note(_ state: OnePasswordPreflight.State) {
        guard !checking else { return }
        self.state = state
    }

    /// The check itself. Only ever called from an explicit user action; it can
    /// raise 1Password's approval prompt, which is exactly what it's for.
    @discardableResult
    func check(account: String) async -> OnePasswordPreflight.State {
        checking = true
        defer { checking = false }
        let result = await OnePasswordPreflight.run(account: account)
        state = result
        return result
    }

    /// As `check`, unless the integration has already been proven to work — a
    /// verified setup goes straight to the quiet confirmation, no prompt.
    @discardableResult
    func checkIfNeeded(account: String) async -> OnePasswordPreflight.State {
        guard OnePasswordPreflight.shouldRun(verified: OnePasswordPreflight.isVerified()) else {
            let ready = OnePasswordPreflight.State.ready(vaults: [])
            state = ready
            return ready
        }
        return await check(account: account)
    }
}

/// The card. Renders one state; the surface owns the model and the retry.
struct OnePasswordSetupCard: View {
    let model: OnePasswordPreflightModel
    /// Tighter type for the first-connect card, which is already a card.
    var compact = false
    /// Ask for the account name here. False where the surface already has an
    /// Account field a couple of rows away — one ask, in one place.
    var asksForAccount = false
    var onAccount: (String) -> Void = { _ in }
    let onCheckAgain: () -> Void

    @Environment(\.openURL) private var openURL

    private var titleFont: Font { compact ? .callout.weight(.semibold) : .body.weight(.semibold) }

    var body: some View {
        if model.checking {
            Label("Checking 1Password\u{2026}", systemImage: "ellipsis.circle")
                .font(.callout).foregroundStyle(.secondary)
        } else if let state = model.state {
            switch state {
            case .ready:
                // Quiet on purpose: a working integration is not news.
                Label("1Password is connected", systemImage: "checkmark.circle.fill")
                    .font(.callout).foregroundStyle(.green)
                    .accessibilityLabel("1Password is connected")
            default:
                walkthrough(state)
            }
        }
    }

    private func walkthrough(_ state: OnePasswordPreflight.State) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label {
                Text(OnePasswordPreflight.headline(for: state))
                    .font(titleFont)
                    .fixedSize(horizontal: false, vertical: true)
            } icon: {
                // Every state that gets here is something still to do.
                Image(systemName: OnePasswordPreflight.symbol(for: state))
                    .foregroundStyle(.orange)
            }
            let steps = OnePasswordPreflight.steps(for: state)
            if !steps.isEmpty {
                VStack(alignment: .leading, spacing: 5) {
                    ForEach(Array(steps.enumerated()), id: \.element.id) { index, step in
                        stepRow(number: index + 1, step: step)
                    }
                }
            }
            if state == .needsAccount, asksForAccount {
                OnePasswordAccountPrompt(onSubmit: onAccount)
            }
            buttons(state)
        }
        .padding(compact ? 10 : 12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 10))
        .accessibilityElement(children: .contain)
    }

    private func stepRow(number: Int, step: UserFacingError.Step) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 7) {
            Image(systemName: "\(number).circle.fill")
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                // LocalizedStringKey so the **bold** UI names render as bold.
                Text(LocalizedStringKey(step.text))
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                if let note = step.note {
                    Text(LocalizedStringKey(note))
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Step \(number). \(step.text.replacingOccurrences(of: "**", with: ""))")
    }

    @ViewBuilder private func buttons(_ state: OnePasswordPreflight.State) -> some View {
        HStack(spacing: 8) {
            switch state {
            case .notInstalled:
                Button("Get 1Password") {
                    if let url = URL(string: "https://1password.com/downloads/mac") { openURL(url) }
                }
                .buttonStyle(.glass)
            case .integrationOff, .waitingForApproval, .failed:
                // Same resolution as the failure sheet's action: by bundle id,
                // because 1Password can live anywhere.
                Button("Open 1Password") { UserFacingErrorSheet.openOnePassword() }
                    .buttonStyle(.glass)
            case .needsAccount, .ready:
                EmptyView()
            }
            Button("Check Again", action: onCheckAgain)
            Spacer(minLength: 0)
        }
        .controlSize(.small)
        .padding(.top, 2)
    }
}

/// "Which 1Password account?" asked where the question came up, rather than
/// pointing at a field on another screen. The browse popover used to reach this
/// state and offer nothing but a Refresh button that could only fail again.
struct OnePasswordAccountPrompt: View {
    var showsCaption = true
    let onSubmit: (String) -> Void

    @State private var name = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                TextField("1Password account name", text: $name)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    .onSubmit(submit)
                Button("Continue", action: submit)
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            if showsCaption {
                Text("The name at the top left of 1Password\u{2019}s sidebar. SimpleVPN remembers it for your other VPNs.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func submit() {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }
        onSubmit(trimmed)
    }
}
