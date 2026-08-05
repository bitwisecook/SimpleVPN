// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  YubiKeySignInSection.swift
//  The security-key rows of a VPN's Sign-In tab: whether a key supplies this VPN's
//  verification code, which of the four mechanisms, and how the code reaches the
//  gateway.
//
//  A SELF-CONTAINED `Section` taking a binding, so the host editor's own diff is
//  one line. Every row goes through `EngineSettingRow`/`EngineSettingLabel` off
//  `YubiKeySettings`, which is what gives each one its bold-when-changed state, its
//  plain-English summary, its manual deep link and its accessibility label from ONE
//  declaration — the house contract for a new settings surface (AGENTS.md).
//
//  MUTUAL EXCLUSION IS RENDERED, NOT ASSUMED. `YubiKeyConflicts` decides; this file
//  only shows what it decided. A control that cannot change anything is visibly
//  dead AND says why, in `.help` and in its `accessibilityValue` — the house
//  dead-control contract, and the difference between "greyed out" and "greyed out
//  for a reason you can read".
//

import SwiftUI

struct YubiKeySignInSection: View {

    @Binding var config: YubiKeyAuthConfig
    /// The facts the exclusions turn on, gathered by the host (which knows the
    /// profile). Everything except `config`, which comes from the binding.
    let inputs: YubiKeyConflictInputs
    /// What is plugged in and whether `ykman` is here.
    let presence: SecurityKeyPresence
    /// The editor is under an MDM configuration lock.
    var locked = false
    /// Re-scan. The host owns it because it also owns the polling.
    let rescan: () -> Void

    private var specs: EngineSettingCatalog { YubiKeySettings.specs }

    /// The exclusions, computed against the LIVE binding rather than the snapshot
    /// the host passed in, so flipping a row updates the warnings immediately.
    private var conflicts: [YubiKeyConflict] {
        var live = inputs
        live.config = config
        return YubiKeyConflicts.all(live)
    }
    private var blockingConflict: YubiKeyConflict? { conflicts.first(where: \.isBlocking) }
    private var notes: [YubiKeyConflict] { conflicts.filter { !$0.isBlocking } }

    /// Why the master switch cannot be turned on. Nil when it can.
    private var enableDisabledReason: String? {
        if locked { return "Your administrator manages this VPN\u{2019}s settings." }
        // "This VPN doesn't ask for a code" is the one exclusion that applies
        // BEFORE the switch is on, so it is the only one that can disable it.
        var live = inputs
        var probe = config
        probe.enabled = true
        live.config = probe
        return YubiKeyConflicts.all(live).first { $0 == .noCodeWanted }?.explanation
    }

    var body: some View {
        Section("Security Key") {
            EngineSettingRow(spec: specs["yk.enabled"],
                             changed: specs["yk.enabled"].isChanged(config.enabled),
                             disabledReason: enableDisabledReason) {
                Toggle(isOn: $config.enabled) {
                    EngineSettingLabel(spec: specs["yk.enabled"], value: config.enabled)
                }
                .labelsHidden()
            }

            if config.enabled {
                whatIsPluggedIn
                if let blockingConflict {
                    conflictLabel(blockingConflict, blocking: true)
                }
                mechanismRow
                if config.mechanism == .oathCode { oathAccountRow }
                if config.mechanism == .challengeResponse { slotRow }
                if config.mechanism != .staticPassword { deliveryRow }
                serialRow
                waitRow
                armRow
                ForEach(Array(notes.enumerated()), id: \.offset) { _, note in
                    conflictLabel(note, blocking: false)
                }
                if config.mechanism.needsManagerTool, !presence.managerToolInstalled {
                    EnablementBanner(guidance: YubiKeyEnablement.installManagerTool)
                }
                scopeHonestyFootnote
            }
        }
    }

    // MARK: Rows

    @ViewBuilder private var mechanismRow: some View {
        EngineSettingRow(spec: specs["yk.mechanism"],
                         changed: specs["yk.mechanism"].isChanged(config.mechanism),
                         disabledReason: locked ? enableDisabledReason : nil) {
            Picker(selection: $config.mechanism) {
                ForEach(YubiKeyCodeMechanism.allCases) { mechanism in
                    Text(mechanism.title).tag(mechanism)
                }
            } label: {
                EngineSettingLabel(spec: specs["yk.mechanism"], value: config.mechanism)
            }
            .labelsHidden()
            .accessibilityValue(config.mechanism.title)
        }
        // The chosen mechanism's own sentence, always visible — the four are not
        // self-explanatory from their names alone, and a Picker shows no summary.
        Text(config.mechanism.summary)
            .font(.callout).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    /// Inert when the PROFILE takes the code out of the password entirely: a
    /// `static-challenge` directive means the engine answers the server's own
    /// prompt, so there is no join left to choose. A dead control that says why,
    /// rather than one that silently does nothing.
    @ViewBuilder private var deliveryRow: some View {
        EngineSettingRow(spec: specs["yk.delivery"],
                         changed: specs["yk.delivery"].isChanged(config.delivery),
                         disabledReason: inputs.staticChallenge
                            ? "This VPN\u{2019}s own configuration asks the server for the code "
                                + "separately, so there is nothing to join."
                            : (locked ? enableDisabledReason : nil)) {
            Picker(selection: $config.delivery) {
                ForEach(YubiKeyCodeDelivery.allCases) { delivery in
                    Text(delivery.title).tag(delivery)
                }
            } label: {
                EngineSettingLabel(spec: specs["yk.delivery"], value: config.delivery)
            }
            .labelsHidden()
            .accessibilityValue(config.delivery.title)
        }
        Text(config.delivery.summary)
            .font(.callout).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder private var oathAccountRow: some View {
            EngineSettingRow(spec: specs["yk.oath-account"],
                             changed: specs["yk.oath-account"].isChanged(config.oathAccount),
                             disabledReason: locked ? enableDisabledReason : nil) {
                // LabeledContent + TextField, and the example goes in `prompt:` —
                // NOT in the title position, which renders as visible content and
                // is read by VoiceOver as the field's NAME. Twenty-six sites in
                // this app were fixed for exactly that bug; this is not the
                // twenty-seventh.
                LabeledContent {
                    TextField("", text: $config.oathAccount,
                              prompt: Text(verbatim: "Example:me@example.com"))
                        .autocorrectionDisabled()
                        .accessibilityLabel(specs["yk.oath-account"].name)
                        .accessibilityValue(config.oathAccount.isEmpty
                            ? "not set" : config.oathAccount)
                } label: {
                    EngineSettingLabel(spec: specs["yk.oath-account"], value: config.oathAccount)
                }
            }
            Text("The name as your key lists it \u{2014} run `ykman oath accounts list` in Terminal to "
                 + "see them. SimpleVPN passes the name to Yubico\u{2019}s tool; the code itself never "
                 + "goes on a command line.")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
    }

    private var slotRow: some View {
        EngineSettingRow(spec: specs["yk.slot"],
                         changed: specs["yk.slot"].isChanged(config.slot),
                         disabledReason: locked ? enableDisabledReason : nil) {
            Picker(selection: $config.slot) {
                ForEach(YubiKeySlot.allCases, id: \.self) { slot in
                    Text("\(slot.displayName) \u{2014} \(slot.touchDescription)").tag(slot)
                }
            } label: {
                EngineSettingLabel(spec: specs["yk.slot"], value: config.slot)
            }
            .labelsHidden()
            .accessibilityValue(config.slot.displayName)
        }
    }

    private var serialRow: some View {
        EngineSettingRow(spec: specs["yk.serial"],
                         changed: specs["yk.serial"].isChanged(config.serial),
                         disabledReason: locked ? enableDisabledReason : nil) {
            LabeledContent {
                TextField("", text: $config.serial,
                          prompt: Text(verbatim: presence.keys.count > 1
                                       ? "e.g. 12345678" : "any key that\u{2019}s plugged in"))
                    .autocorrectionDisabled()
                    .accessibilityLabel(specs["yk.serial"].name)
                    .accessibilityValue(serialAccessibilityValue)
            } label: {
                EngineSettingLabel(spec: specs["yk.serial"], value: config.serial)
            }
        }
    }

    private var serialAccessibilityValue: String {
        let trimmed = config.serial.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { return "not set, so any security key that is plugged in will be used" }
        if config.normalizedSerial == nil {
            return "\(trimmed). Problem: a serial number is digits only, so this will be ignored"
        }
        return trimmed
    }

    /// `ValidatedNumberField` carries its own label and its own "that isn't a valid
    /// number" message, so it is used directly rather than wrapped in an
    /// `EngineSettingRow` — the same shape the OpenVPN options form uses for every
    /// numeric setting. The spec still supplies the name and the changed state.
    private var waitRow: some View {
        ValidatedNumberField(
            label: { EngineSettingLabel(spec: specs["yk.wait-seconds"],
                                        value: config.waitSeconds) },
            prompt: "\(Int(YubiKeyCapture.defaultWait))",
            value: Binding(
                get: { config.waitSeconds },
                set: { config.waitSeconds = $0 ?? Int(YubiKeyCapture.defaultWait) }),
            range: 5...120,
            invalidMessage: "Enter a number of seconds between 5 and 120.")
            .disabled(locked)
    }

    private var armRow: some View {
        EngineSettingRow(spec: specs["yk.arm-automatically"],
                         changed: specs["yk.arm-automatically"].isChanged(config.armAutomatically),
                         disabledReason: locked ? enableDisabledReason : nil) {
            Toggle(isOn: $config.armAutomatically) {
                EngineSettingLabel(spec: specs["yk.arm-automatically"],
                                   value: config.armAutomatically)
            }
            .labelsHidden()
        }
    }

    // MARK: What's plugged in

    private var whatIsPluggedIn: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: presence.hasTypingKey ? "checkmark.circle" : "questionmark.circle")
                .foregroundStyle(presence.hasTypingKey ? AnyShapeStyle(.secondary)
                                                       : AnyShapeStyle(.orange))
                .accessibilityHidden(true)      // the text says the same thing
            VStack(alignment: .leading, spacing: 2) {
                Text(presence.summary)
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                if let key = presence.keys.first {
                    Text("\(key.familyName) \u{2014} \(key.interfaceSummary)")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 8)
            Button("Check Again", action: rescan)
                .accessibilityLabel("Check again for a security key")
        }
        // A container (it holds a button), with its own sentence.
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Security keys plugged in. \(presence.summary)")
    }

    // MARK: Conflicts

    private func conflictLabel(_ conflict: YubiKeyConflict, blocking: Bool) -> some View {
        Label(conflict.explanation,
              systemImage: blocking ? "exclamationmark.triangle.fill" : "info.circle")
            .font(.callout)
            .foregroundStyle(blocking ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
            .fixedSize(horizontal: false, vertical: true)
            // The house rule for a validation message: it announces its ROLE, not
            // just its colour.
            .accessibilityLabel((blocking ? "Problem: " : "") + conflict.explanation)
    }

    /// SCOPE HONESTY, in the editor as well as at connect time. A Yubico OTP is
    /// checked by the SERVER; SimpleVPN carries it. Saying anything stronger would
    /// make a rejected code look like this app's fault.
    @ViewBuilder private var scopeHonestyFootnote: some View {
        if config.mechanism == .yubicoOTP {
            Text("SimpleVPN checks that the code has the right shape and passes it on. Whether it is "
                 + "valid is decided by your VPN\u{2019}s server (or Yubico\u{2019}s validation "
                 + "service) \u{2014} SimpleVPN cannot tell, and does not try to.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

// MARK: - "You can turn this on"

/// The enablement guidance for `ykman`, in the same shape and the same one banner
/// every other vendor uses (`EnablementGuidance` / `EnablementBanner`) rather than
/// a second idiom for the same job.
///
/// SimpleVPN NEVER INSTALLS IT. The command is shown; the user runs it.
nonisolated enum YubiKeyEnablement {

    /// Yubico's own current documentation for the tool. One place, auditable, same
    /// rule as `VendorDocs`: a link that 404s is worse than no link.
    static let ykmanDocs = VendorDocs.Page(
        title: "YubiKey Manager (ykman) CLI guide",
        url: URL(string: "https://docs.yubico.com/software/yubikey/tools/ykman/") ??
            URL(fileURLWithPath: "/"))

    static let installManagerTool = EnablementGuidance(
        benefit: "Install Yubico\u{2019}s own command-line tool and SimpleVPN can ask your security key "
            + "for this VPN\u{2019}s verification code when you connect \u{2014} no typing, and the "
            + "key\u{2019}s secret never leaves the key.",
        example: [
            .init(text: "brew install ykman",
                  caption: "Install Yubico\u{2019}s tool (SimpleVPN never installs it for you)"),
            .init(text: "ykman oath accounts list",
                  caption: "Check it can see your key, and list the accounts on it"),
        ],
        doc: ykmanDocs)
}
