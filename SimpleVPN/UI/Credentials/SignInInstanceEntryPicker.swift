// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SignInInstanceEntryPicker.swift
//  The per-VPN half of the three-level model: WHICH vault, then WHICH entry inside
//  it — asked as two numbered steps rather than as one flat list of fields.
//
//  WHY TWO STEPS AND NOT THREE FIELDS IN A ROW. "Entry path", "username" and
//  (somewhere else entirely) "database" read as three unrelated boxes, and the one
//  that decides which vault is being read is the one that used to be invisible from
//  here. Numbering them says what is going on: you are choosing a place, and then
//  something inside that place. The second step's own heading NAMES the place, so
//  the pair reads as one sentence — "which entry in “Work”" — and a VoiceOver user
//  hears the step number and its state as the control's value, because the visual
//  numbering reaches nobody who cannot see it.
//
//  Step 1 is skipped ENTIRELY for a vendor that declares `SourceCardinality.single`
//  (see SignInSourceInstances.swift): 1Password, KeePassXC, Keeper and Bitwarden
//  each have exactly one thing to talk to on this Mac, and a one-item picker is a
//  question with no answer. Those vendors render step 2 alone, unnumbered — which is
//  exactly what they showed before.
//
//  Nothing here holds a secret. A database password is not a per-VPN setting and
//  never becomes one (KeePassUnlock.swift); what this view writes is an instance id,
//  an entry reference and an optional username.
//

import SwiftUI

struct SignInInstanceEntryPicker: View {

    let vendor: LocalVaultVendor
    /// Which vault this VPN reads. nil = the one SimpleVPN set up (which is what a
    /// profile written before instances existed means).
    @Binding var instance: SourceInstanceID?
    /// Which entry inside it.
    @Binding var entry: String
    /// Which login, when one entry could serve several. Optional everywhere.
    @Binding var account: String
    /// Step 2's own field copy, which is per vendor: an address for KeePassXC, a
    /// record path for Keeper, an entry path for a `.kdbx`.
    var entryPrompt: String
    var accountLabel: String
    /// "Set Up Databases…" / "…Stores…" / "…Servers…" — the vendor's OWN plural, never
    /// the word "instance" and never "database" for something that is not one. Opens
    /// Settings ▸ Sign-In Sources at this vendor; nil in a host with no way to open a
    /// window.
    var onConfigure: (() -> Void)?

    @State private var settings = SignInSourceSettingsStore.shared
    @State private var sources = SignInSourceAvailability.shared

    private var instances: [SourceInstance] { settings.instances(for: vendor) }
    private var resolution: SourceInstanceResolution {
        SourceInstanceResolver.resolve(id: instance, vendor: vendor, instances: instances)
    }
    private var chosenName: String? { resolution.instance?.name }
    /// Two steps only where there is genuinely a choice of vault to make.
    private var showsStepOne: Bool { vendor.cardinality.allowsSeveral }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if showsStepOne { stepOne }
            stepTwo
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .onAppear { sources.refresh() }
    }

    // MARK: Step 1 — which vault

    @ViewBuilder private var stepOne: some View {
        VStack(alignment: .leading, spacing: 4) {
            stepHeading(1, title: SignInSourceSteps.stepOneTitle(vendor: vendor),
                        summary: SignInSourceSteps.stepOneSummary(vendor: vendor))
            if instances.isEmpty {
                // An enablement state, not a fault: one file picker away from
                // working, and the button that gets there is right here.
                Label(SourceInstanceResolution.noneConfigured.sentence(vendor: vendor),
                      systemImage: "exclamationmark.triangle.fill")
                    .font(.callout).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel(SignInSourceSteps.stepOneTitle(vendor: vendor))
                    .accessibilityValue(SignInSourceSteps.spokenStep(1, of: vendor, chosen: nil))
            } else {
                Picker(SignInSourceSteps.stepOneTitle(vendor: vendor),
                       selection: Binding(get: { instance ?? instances.first?.id },
                                          set: { instance = $0 })) {
                    ForEach(instances) { candidate in
                        Text(candidate.name).tag(Optional(candidate.id))
                    }
                    // A profile naming a vault that has gone keeps its own row, so
                    // the picker shows what it says rather than silently jumping to
                    // somebody else's vault.
                    if case .chosenIsGone(let stale) = resolution {
                        Text("Not set up any more").tag(Optional(stale))
                    }
                }
                .labelsHidden()
                .accessibilityLabel(SignInSourceSteps.stepOneTitle(vendor: vendor))
                .accessibilityValue(SignInSourceSteps.spokenStep(1, of: vendor, chosen: chosenName))
                .accessibilityHint("Chooses which \(vendor.instanceNoun) this VPN reads its "
                                   + "sign-in from. Set them up in SimpleVPN\u{2019}s settings.")
                .accessibilityIdentifier("signin-instance-\(vendor.settingSlug)")
                stateLine
            }
            if let onConfigure {
                Button(instances.isEmpty
                       ? "Set Up \(vendor.instanceNounPlural.capitalized)\u{2026}"
                       : "Manage \(vendor.instanceNounPlural.capitalized)\u{2026}",
                       action: onConfigure)
                    .buttonStyle(.borderless)
                    .controlSize(.small)
                    .help("Opens Settings \u{25B8} Sign-In Sources, where your "
                          + "\(vendor.instanceNounPlural) are set up")
                    .accessibilityHint("Opens SimpleVPN\u{2019}s settings, where you add, rename "
                                       + "and point at your \(vendor.instanceNounPlural).")
                    .accessibilityIdentifier("signin-manage-instances-\(vendor.settingSlug)")
            }
        }
    }

    /// What the CHOSEN vault can do right now — level 2's own four-state answer, in
    /// the same words the settings pane and the chooser use.
    @ViewBuilder private var stateLine: some View {
        let availability = sources.facts.rawAvailability(vendor, instance: instance)
        let copy = LocalVaultCopyBook.copy(for: vendor)
        let sentence: String = {
            if case .chosenIsGone = resolution { return resolution.sentence(vendor: vendor) }
            switch availability {
            case .ready: return "Ready to use."
            case .notInstalled: return "Not found on this Mac."
            case .unchecked(let ceiling): return copy.uncheckedNote ?? ceiling.fallbackNote
            case .blocked(let block): return copy.headline(for: block)
            }
        }()
        let ok = availability.isReady && resolution.isUsable
        Label(sentence, systemImage: ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
            .font(.callout)
            .foregroundStyle(ok ? Color.secondary : Color.orange)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityElement(children: .combine)
            .accessibilityLabel("This \(vendor.instanceNoun) on this Mac")
            .accessibilityValue(sentence)
        // THE ENABLEMENT BANNER APPLIES PER VAULT, not just per vendor: "you haven't
        // chosen a file yet" and "type its password" are things to do to THIS
        // database, and the person reading this screen has none of the settings pane's
        // fields in front of them.
        if case .blocked(let block) = availability, block.wantsEnablementBanner,
           let guidance = copy.guidance(for: block) {
            EnablementBanner(guidance: guidance)
        }
    }

    // MARK: Step 2 — which entry

    @ViewBuilder private var stepTwo: some View {
        VStack(alignment: .leading, spacing: 4) {
            if showsStepOne {
                stepHeading(2,
                            title: SignInSourceSteps.stepTwoTitle(vendor: vendor,
                                                                  instanceName: chosenName),
                            summary: SignInSourceSteps.stepTwoSummary(vendor: vendor))
            }
            // `LabeledContent { TextField("", …, prompt:) }` — the house idiom. The
            // title argument is EMPTY, always: an example passed as a title renders
            // where the value goes and is read out as the field's name.
            LabeledContent {
                TextField("", text: $entry, prompt: Text(verbatim: entryPrompt))
                    .autocorrectionDisabled()
                    .accessibilityLabel(showsStepOne
                        ? SignInSourceSteps.stepTwoTitle(vendor: vendor, instanceName: chosenName)
                        : "Which entry")
                    .accessibilityValue(SignInSourceSteps.spokenStep(
                        2, of: vendor, chosen: entry.isEmpty ? nil : entry))
                    .accessibilityIdentifier("signin-entry-\(vendor.settingSlug)")
            } label: {
                Text("Entry")
            }
            LabeledContent {
                TextField("", text: $account, prompt: Text(verbatim: "Optional"))
                    .autocorrectionDisabled()
                    .accessibilityLabel(accountLabel)
                    .accessibilityValue(account.isEmpty ? "Not set" : account)
                    .accessibilityIdentifier("signin-entry-account-\(vendor.settingSlug)")
            } label: {
                Text(accountLabel)
            }
        }
    }

    // MARK: One step's heading

    /// The number, the question, and one line saying what belongs in it. A header
    /// trait so a VoiceOver user can navigate step to step.
    @ViewBuilder private func stepHeading(_ number: Int, title: String,
                                         summary: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(title)
                .font(.callout.weight(.semibold))
                .fixedSize(horizontal: false, vertical: true)
            Text(summary)
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
        .accessibilityLabel("\(title). \(summary)")
    }
}
