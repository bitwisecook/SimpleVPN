// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// AuthenticationControls.swift
// One wording and one behaviour for the consent to retain a password. The
// binding owns persistence because different VPN backends use different secure
// stores; this view owns only the common, user-facing decision.

import SwiftUI

/// The compact, native control for choosing where a VPN's sign-in comes from.
///
/// This deliberately consumes `SignInSourceCatalog`'s options rather than
/// inventing a second list for the connection screen. The detailed chooser
/// remains the setup surface for a password app; this is the visible first
/// choice immediately above the fields it changes.
struct SignInSourcePicker: View {
    let options: [SignInSourceOption]
    let selection: SignInSourceID?
    let onChoose: (SignInSourceOption) -> Void

    private var selectableOptions: [SignInSourceOption] {
        options.filter { $0.role == .fetches && $0.storedKind != nil }
    }

    /// A source can become unavailable after a VPN selected it (for example,
    /// 1Password can be quit). AppKit's menu Picker requires its binding value
    /// to have a tag in the current menu; feeding it an absent tag logs an
    /// invalid-configuration warning and can swallow the next click. Keep the
    /// actual source in the profile, but present the first available choice until
    /// the recovery surface takes over.
    private var visibleSelection: SignInSourceID? {
        guard selectableOptions.contains(where: { $0.id == selection }) else {
            return selectableOptions.first?.id
        }
        return selection
    }

    var body: some View {
        Picker("Where your sign-in comes from", selection: Binding(
            get: { visibleSelection },
            set: { id in
                guard let id,
                      let option = selectableOptions.first(where: { $0.id == id })
                else { return }
                onChoose(option)
            })) {
                ForEach(selectableOptions) { option in
                    Label(title(for: option), systemImage: option.symbol)
                        .tag(Optional(option.id))
                }
            }
            .pickerStyle(.menu)
            // The surrounding GridRow supplies the visible label.
            // label. Keep Picker's label for VoiceOver, but do not render it twice.
            .labelsHidden()
            .accessibilityHint("Choose whether you type a sign-in, save it in SimpleVPN, or use an available password app.")
    }

    /// Both local-keychain choices lead to the same familiar credentials
    /// fields. Whether they are retained is the Save password checkbox directly
    /// below, rather than a distinction hidden in the popup's wording.
    private func title(for option: SignInSourceOption) -> String {
        switch option.id {
        case .typeEachTime, .saveInSimpleVPN:
            "Username + Password"
        default:
            option.title
        }
    }
}

struct PasswordSavingToggle: View {
    @Binding var isOn: Bool

    var body: some View {
        Toggle("Save password", isOn: $isOn)
            .toggleStyle(.checkbox)
            .help("Keep this password in the Apple keychain for future connections")
            .accessibilityHint("Off means SimpleVPN does not retain the password after this session.")
    }
}

/// The one configuration surface for an optional verification code.  Both the
/// first-connect walkthrough and the ordinary manual sign-in form use this so
/// the label, template contract and disabled state cannot drift.
struct VerificationCodeConfiguration: View {
    @Binding var required: Bool
    @Binding var passwordTemplate: String
    var requiredByServer = false

    var body: some View {
        Toggle("Verification code required", isOn: $required)
            .toggleStyle(.checkbox)
            .disabled(requiredByServer)
            .help(requiredByServer
                  ? "This VPN's configuration requires a verification code."
                  : "Turn this on when the VPN asks for a fresh verification code as well as your password.")

        DisclosureGroup("Advanced Verification Code Settings") {
            VStack(alignment: .leading, spacing: 6) {
                TextField("Password template", text: $passwordTemplate)
                    .textFieldStyle(.roundedBorder)
                    .textContentType(.none)
                Text("Use {password} and {otp}. The default sends the password followed by the verification code.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.top, 4)
        }
        .disabled(!required || requiredByServer)
        .help(requiredByServer
              ? "This VPN sends its verification code in a separate server challenge."
              : "Set how this VPN combines your password and verification code.")
    }
}
