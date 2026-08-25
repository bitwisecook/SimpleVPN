// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// AuthenticationControls.swift
// One wording and one behaviour for the consent to retain a password. The
// binding owns persistence because different VPN backends use different secure
// stores; this view owns only the common, user-facing decision.

import SwiftUI

/// The visible, native control for choosing where a VPN's sign-in comes from.
///
/// This deliberately consumes `SignInSourceCatalog`'s options rather than
/// inventing a second list for the connection screen. Sources are buttons rather
/// than a popup so a fresh install shows what is actually available on this Mac
/// without making the person open a menu to discover it.
struct SignInSourcePicker: View {
    let options: [SignInSourceOption]
    let selection: SignInSourceID?
    let onChoose: (SignInSourceOption) -> Void

    /// The two old manual catalogue rows differed only in whether the Save
    /// checkbox was initially on. Here that checkbox is visible with the fields,
    /// so present one Keychain choice and leave its value alone when it is chosen.
    private var selectableOptions: [SignInSourceOption] {
        let fetchers = options.filter { $0.role == .fetches && $0.storedKind != nil }
        guard var manual = fetchers.first(where: { $0.id == .saveInSimpleVPN })
                ?? fetchers.first(where: { $0.id == .typeEachTime }) else {
            return fetchers
        }
        let canSave = fetchers.contains { $0.id == .saveInSimpleVPN }
        manual.id = .saveInSimpleVPN
        manual.title = canSave ? "Keychain" : "Username + Password"
        manual.summary = canSave
            ? "Type the sign-in here; the Save checkbox decides whether macOS keeps it in Keychain."
            : "Type the sign-in here each time. This VPN does not allow SimpleVPN to save it."
        manual.explanation = manual.summary
        manual.symbol = canSave ? "key.fill" : "keyboard"
        manual.remembers = nil
        return [manual] + fetchers.filter {
            $0.id != .typeEachTime && $0.id != .saveInSimpleVPN
        }
    }

    var body: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 150, maximum: 230),
                                     spacing: 8, alignment: .leading)],
                  alignment: .leading, spacing: 8) {
            ForEach(selectableOptions) { option in
                let selected = isSelected(option)
                Button { onChoose(option) } label: {
                    HStack(spacing: 9) {
                        Image(systemName: option.symbol)
                            .font(.title3)
                            .frame(width: 24)
                        Text(option.title)
                            .font(.callout.weight(.medium))
                            .lineLimit(2)
                        Spacer(minLength: 4)
                        if selected {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(.tint)
                        }
                    }
                    .frame(maxWidth: .infinity, minHeight: 40, alignment: .leading)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .contentShape(Rectangle())
                    .background(selected ? Color.accentColor.opacity(0.13)
                                         : Color.secondary.opacity(0.07),
                                in: RoundedRectangle(cornerRadius: 9, style: .continuous))
                    .overlay {
                        RoundedRectangle(cornerRadius: 9, style: .continuous)
                            .strokeBorder(selected ? Color.accentColor : Color.secondary.opacity(0.35),
                                          lineWidth: selected ? 1.5 : 1)
                    }
                }
                .buttonStyle(.plain)
                .help(option.explanation)
                .accessibilityLabel(option.title)
                .accessibilityValue(selected ? "Selected" : "Not selected")
                .accessibilityHint(option.explanation)
                .accessibilityAddTraits(selected ? .isSelected : [])
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Where your sign-in comes from")
    }

    private func isSelected(_ option: SignInSourceOption) -> Bool {
        if option.id == .saveInSimpleVPN {
            return selection == .saveInSimpleVPN || selection == .typeEachTime
        }
        return selection == option.id
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
