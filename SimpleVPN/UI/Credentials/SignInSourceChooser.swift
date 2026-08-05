// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SignInSourceChooser.swift
//  "How do you want to sign in?" — the first-run chooser, plus the two small
//  surfaces that keep a RETURNING user from ever being asked again: the one-line
//  "this is how you sign in" summary with its quiet Change button, and the
//  recovery notice for when the source someone chose has gone away.
//
//  The rows come from `SignInSourceCatalog` (pure); this file only draws them.
//  Two classes, and the difference has to survive being read aloud:
//
//   • FETCHABLE rows are Buttons in a radio-like group. Tab reaches each one,
//     Space picks it, the selected one carries `.isSelected`, and choosing one
//     is ANNOUNCED — a blind user hears which way they just chose.
//   • POINTER rows are not selectable at all. They hold an "Open <app>" button
//     and say, in words, that SimpleVPN can't read that app. The wording carries
//     the distinction, never the styling: a screen reader gets the same sentence
//     a sighted user gets, because the row's own summary IS the sentence.
//
//  Hover and VoiceOver are fed from ONE string (`option.explanation`) — a
//  hover-only explanation is invisible to VoiceOver, which is a house rule
//  (Docs/Accessibility.md rule 1), and two strings drift.
//
//  No spinners anywhere: this view is inserted inside an animated container
//  (FirstConnectSetupCard's transition), and platform-backed views in a
//  transform-animated container are what the layout-loop rule exists for.
//  "Checking…" as plain text says the same thing.
//

import SwiftUI
import AppKit

struct SignInSourceChooser: View {

    let options: [SignInSourceOption]
    /// The row currently chosen, if any. Pointer rows are never the selection.
    let selection: SignInSourceID?
    let onChoose: (SignInSourceOption) -> Void
    let onOpenApp: (SignInSourceOption) -> Void
    /// "Configure…" on a vendor row — opens Settings ▸ Sign-In Sources for that
    /// vendor. nil in a host that has no way to open a window (previews, and the
    /// compact first-connect card if it ever wants the row without the button).
    var onConfigure: ((LocalVaultVendor) -> Void)?
    /// Tighter type inside the first-connect card, which is already a card.
    var compact = false
    /// Put the keyboard on the chooser when it appears. The first-run card does;
    /// the Change popover does; a chooser shown inline beside filled-in fields
    /// should not steal focus from them.
    var focusesOnAppear = true

    @FocusState private var focused: SignInSourceID?

    private var fetchable: [SignInSourceOption] { options.filter { $0.role == .fetches } }
    private var pointers: [SignInSourceOption] { options.filter { $0.role == .hint } }

    var body: some View {
        VStack(alignment: .leading, spacing: compact ? 10 : 14) {
            VStack(alignment: .leading, spacing: 2) {
                Text(SignInSourceCatalog.title)
                    .font(compact ? .callout.weight(.semibold) : .body.weight(.semibold))
                Text(SignInSourceCatalog.subtitle)
                    .font(.caption).foregroundStyle(.secondary)
            }
            .accessibilityElement(children: .combine)

            VStack(alignment: .leading, spacing: 6) {
                Text(SignInSourceCatalog.fetchableHeading)
                    .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                    .accessibilityAddTraits(.isHeader)
                ForEach(fetchable) { option in
                    fetchableRow(option)
                }
            }

            if !pointers.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(SignInSourceCatalog.pointerHeading)
                            .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                            .accessibilityAddTraits(.isHeader)
                        Text(SignInSourceCatalog.pointerCaption)
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .accessibilityElement(children: .combine)
                    ForEach(pointers) { option in
                        pointerRow(option)
                    }
                }
            }

            // The footnote NAMES the pane and a button OPENS it. Both, deliberately:
            // the sentence is what a VoiceOver user hears and what someone following
            // along reads, and a button whose destination is invisible is the
            // hover-only failure wearing a different hat.
            VStack(alignment: .leading, spacing: 4) {
                Text(SignInSourceCatalog.autoFillFootnote)
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Button("Open AutoFill Settings\u{2026}") {
                    SignInSourceCatalog.openAutoFillSettings()
                }
                .buttonStyle(.borderless)
                .controlSize(.small)
                .help("Opens \(SignInSourceCatalog.autoFillSettingsPath)")
                .accessibilityLabel("Open AutoFill settings")
                .accessibilityHint("Opens \(SignInSourceCatalog.autoFillSettingsPath), where you "
                                   + "switch a password app on for filling in fields.")
                .accessibilityIdentifier("signin-open-autofill-settings")
            }
            // Holds a button, so a container with its own sentence — never .combine.
            .accessibilityElement(children: .contain)
            .accessibilityLabel(SignInSourceCatalog.autoFillFootnote)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        // A container, not a combined element: it is full of buttons, and a
        // row-wide .combine would swallow every one of them.
        .accessibilityElement(children: .contain)
        .accessibilityLabel(SignInSourceCatalog.title)
        .onAppear {
            guard focusesOnAppear else { return }
            // The keyboard lands on the choice already made, or on the first one
            // offered — never nowhere.
            focused = selection ?? fetchable.first?.id
        }
    }

    // MARK: Fetchable row — SimpleVPN gets your sign-in

    /// A fetchable row, plus — for a vendor row — the "Configure…" button beside it.
    ///
    /// The two are SIBLINGS in an HStack, never nested. A `Button` inside another
    /// `Button`'s label does not work on macOS, and a row-wide
    /// `.accessibilityElement(children: .combine)` silently swallows any button
    /// inside it (the wave-3 bug class in Docs/Accessibility.md rule 4). So a row
    /// with a Configure button becomes a `.contain` container with its own spoken
    /// sentence, while a plain row keeps the cheaper `.combine`.
    ///
    /// A row whose code has never been proven also carries its maturity: the full
    /// notice (with the report link that is the only thing which clears it) where
    /// there is room, and just the chip in the compact first-connect card, where a
    /// paragraph per row would bury the question being asked. Either way the state
    /// is on screen and in the row's spoken value — it is never only a chip and
    /// never only a paragraph.
    @ViewBuilder private func fetchableRow(_ option: SignInSourceOption) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            fetchableRowBody(option)
            if showsMaturityBanner, let notice = option.maturityNotice {
                MaturityBanner(notice: notice,
                               request: .init(kind: nil, profileID: nil,
                                              reason: .untestedSource))
            }
        }
    }

    /// True where the row has room for the whole notice. The compact card shows
    /// the chip instead (see `radioRow`).
    private var showsMaturityBanner: Bool { !compact }

    @ViewBuilder private func fetchableRowBody(_ option: SignInSourceOption) -> some View {
        if let vendor = option.configurableVendor, onConfigure != nil {
            HStack(alignment: .top, spacing: 8) {
                radioRow(option)
                Button("Configure\u{2026}") { onConfigure?(vendor) }
                    .buttonStyle(.glass)
                    .controlSize(.small)
                    .help("Turn \(option.title) off, or tell SimpleVPN where its tool is")
                    .accessibilityLabel("Configure \(option.title)")
                    .accessibilityHint("Opens SimpleVPN\u{2019}s settings, where you can turn "
                                       + "\(option.title) off or set where its tool is.")
                    .accessibilityIdentifier("signin-configure-\(option.id.rawValue)")
            }
            // Holds two buttons: a container with its own sentence, never .combine.
            .accessibilityElement(children: .contain)
            .accessibilityLabel("\(option.title). \(option.summary)")
            .accessibilityValue(option.spokenStateAndMaturity)
        } else {
            radioRow(option)
        }
    }

    private func radioRow(_ option: SignInSourceOption) -> some View {
        let isSelected = option.id == selection
        return Button {
            onChoose(option)
            AccessibilityAnnouncer.sayNow(SignInSourceCatalog.announcement(for: option))
        } label: {
            HStack(alignment: .top, spacing: 9) {
                Image(systemName: isSelected ? "largecircle.fill.circle" : "circle")
                    .foregroundStyle(isSelected ? AnyShapeStyle(.tint) : AnyShapeStyle(.tertiary))
                    .accessibilityHidden(true)   // selection rides the row's trait
                Image(systemName: option.symbol)
                    .frame(width: 18)
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)   // decorative; the title says what it is
                VStack(alignment: .leading, spacing: 2) {
                    // MATURITY SITS BESIDE THE TITLE, AND IT IS NOT AVAILABILITY.
                    // The state note below says what this source can do on this Mac
                    // right now; the chip says whether anyone has ever proven the
                    // code that talks to it. A source can be ready to use AND
                    // untested — that is the normal state of a new adapter, not a
                    // contradiction — so the two are drawn in different places and
                    // spoken as separate clauses.
                    HStack(spacing: 6) {
                        Text(option.title).font(.callout.weight(isSelected ? .semibold : .regular))
                        if !showsMaturityBanner, let notice = option.maturityNotice {
                            MaturityBadge(notice: notice)
                        }
                    }
                    Text(option.summary)
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    stateNote(option)
                }
                Spacer(minLength: 0)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .focused($focused, equals: option.id)
        .help(option.explanation)
        // Label / value / hint carry exactly what the hover does — a hover-only
        // explanation would be invisible to VoiceOver.
        .accessibilityElement(children: .combine)
        .accessibilityLabel(option.title)
        // State first, maturity second — two facts, one sentence. The chip beside
        // the title is hidden, so this is how it reaches VoiceOver.
        .accessibilityValue(option.spokenStateAndMaturity)
        .accessibilityHint("\(option.summary) \(option.explanation)")
        .accessibilityAddTraits(isSelected ? [.isButton, .isSelected] : .isButton)
        .accessibilityIdentifier("signin-source-\(option.id.rawValue)")
    }

    /// The "something has to happen first" half of a row: the headline, then
    /// either short steps or the enablement banner. Shown inline rather than
    /// behind a disclosure — a step you cannot see is a step nobody takes.
    @ViewBuilder private func stateNote(_ option: SignInSourceOption) -> some View {
        switch option.state {
        case .ready:
            EmptyView()
        case .unchecked(let note):
            Text(note)
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        case .needsSetup(let headline, let steps):
            VStack(alignment: .leading, spacing: 3) {
                Label(headline, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
                ForEach(Array(steps.enumerated()), id: \.offset) { index, step in
                    HStack(alignment: .firstTextBaseline, spacing: 5) {
                        Text("\(index + 1).")
                            .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        // LocalizedStringKey so **bold** names the real thing on
                        // screen and `code` renders as something to type.
                        Text(LocalizedStringKey(step))
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                if let guidance = option.guidance {
                    EnablementBanner(guidance: guidance)
                }
            }
            .padding(.top, 1)
        }
    }

    // MARK: Pointer row — where else to look

    private func pointerRow(_ option: SignInSourceOption) -> some View {
        HStack(alignment: .top, spacing: 9) {
            Image(systemName: option.symbol)
                .frame(width: 18)
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(option.title).font(.callout)
                Text(option.summary)
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 4) {
                Button("Open \(option.title)") { onOpenApp(option) }
                    .buttonStyle(.glass)
                    .controlSize(.small)
                    .help(option.explanation)
                    .accessibilityHint(option.explanation)
                // An app that ships an AutoFill extension can fill our fields once
                // it is switched on — so the row offers the switch, not just its
                // address. The address stays in the row's own sentence.
                if option.fillsThroughAutoFill {
                    Button("AutoFill Settings\u{2026}") {
                        SignInSourceCatalog.openAutoFillSettings()
                    }
                    .buttonStyle(.borderless)
                    .controlSize(.small)
                    .help("Opens \(SignInSourceCatalog.autoFillSettingsPath), where you switch "
                          + "\(option.title) on for filling in fields")
                    .accessibilityLabel("Open AutoFill settings for \(option.title)")
                    .accessibilityHint("Opens \(SignInSourceCatalog.autoFillSettingsPath), where "
                                       + "you switch \(option.title) on for filling in fields.")
                }
            }
        }
        .padding(.vertical, 2)
        // Contains a button, so: a container with its own sentence, never a
        // .combine (which would swallow the button).
        .accessibilityElement(children: .contain)
        .accessibilityLabel(SignInSourceCatalog.pointerAccessibilityLabel(option))
        .accessibilityValue(option.accessibilityStateValue)
        .accessibilityIdentifier("signin-hint-\(option.id.rawValue)")
    }
}

// MARK: - Returning: how you sign in now, and the quiet way to change it

/// One line for a VPN that is already set up, plus a Change button. This is the
/// whole "don't re-ask" half of the flow: a returning user sees a statement, not
/// a question, and the way back is one click without a trip to Manage VPNs.
struct SignInSourceSummary: View {
    let option: SignInSourceOption?
    let footnote: String?
    let onChange: () -> Void

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Label(option.map { "Your sign-in comes from \($0.title)." }
                        ?? "Your sign-in is set up.",
                      systemImage: option?.symbol ?? "person.badge.key")
                    .font(.callout).foregroundStyle(.secondary)
                if let footnote {
                    Text(footnote)
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 8)
            Button("Change\u{2026}", action: onChange)
                .buttonStyle(.borderless)
                .controlSize(.small)
                .help("Choose a different way to sign in to this VPN")
                .accessibilityLabel("Change how you sign in")
                .accessibilityHint("Choose a different way to sign in to this VPN.")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(option.map { "Your sign-in comes from \($0.title)" }
                            ?? "Your sign-in is set up")
    }
}

// MARK: - The chooser as a popover (the "Change…" path)

extension View {
    /// The chooser, reachable from anywhere a VPN's sign-in is on screen. Same
    /// rows, same wording, same announcements as the first-run card — one
    /// chooser, two places it can appear, so the two can never drift.
    ///
    /// ESC closes it (the house rule for every popover); focus lands on the
    /// choice already made.
    func signInChooserPopover(isPresented: Binding<Bool>,
                              vpn: VPNController,
                              profile: VPNController.Profile,
                              allowsPasswordSave: Bool,
                              sources: SignInSourceAvailability) -> some View {
        popover(isPresented: isPresented, arrowEdge: .bottom) {
            SignInChooserPopover(vpn: vpn, profile: profile,
                                 allowsPasswordSave: allowsPasswordSave, sources: sources,
                                 isPresented: isPresented)
        }
    }
}

/// The popover's contents. A view of its own so it can own the probe refresh and
/// the Done button without every host repeating them.
struct SignInChooserPopover: View {
    let vpn: VPNController
    let profile: VPNController.Profile
    let allowsPasswordSave: Bool
    let sources: SignInSourceAvailability
    @Binding var isPresented: Bool
    @Environment(SettingsRouter.self) private var router: SettingsRouter?

    private var source: CredentialSource { vpn.credentialSource(for: profile.id) }
    private var auth: VPNAuthConfig { vpn.authConfig(for: profile.id) }
    private var facts: SignInSourceFacts { sources.facts(allowsPasswordSave: allowsPasswordSave) }

    private var selectedID: SignInSourceID? {
        switch source.kind {
        case .manual: auth.rememberCredentials ? .saveInSimpleVPN : .typeEachTime
        case .applePasswords: .applePasswords
        default: LocalVaultRegistry.adapter(for: source.kind).map { .vault($0.vendor) }
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SignInSourceChooser(
                options: SignInSourceCatalog.options(facts),
                selection: selectedID,
                onChoose: { choose($0) },
                onOpenApp: { open($0) },
                onConfigure: { configure($0) })
            HStack {
                Spacer()
                Button("Done") { isPresented = false }
                    .keyboardShortcut(.cancelAction)   // ESC closes, house rule
            }
        }
        .padding(14)
        .frame(width: 420)
        .onAppear { sources.refresh() }
        .task { await sources.deepScan() }
        // Same live refresh as the first-run card: an app started or a CLI
        // installed while this is open must change what is on offer, and
        // following an enablement banner must flip its row without a restart.
        .task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(2))
                sources.refresh()
                await sources.recheckIfDue()
            }
        }
    }

    private func choose(_ option: SignInSourceOption) {
        guard let kind = option.storedKind else { return }
        var s = source
        s.kind = kind
        var a = auth
        if let remembers = option.remembers { a.rememberCredentials = remembers }
        Task {
            try? await vpn.setCredentialSource(s, for: profile.id)
            if a != auth { try? await vpn.setAuthConfig(a, for: profile.id) }
            if option.id == .typeEachTime { vpn.forgetSavedSignIn(id: profile.id) }
        }
    }

    /// Open Settings ▸ Sign-In Sources at this vendor. Routes through the SAME
    /// `SettingsRouter` intent a global search hit uses, so there is one way to be
    /// sent to a setting rather than a second one that can drift.
    private func configure(_ vendor: LocalVaultVendor) {
        isPresented = false
        router?.go(to: SignInSourceSettings.enabledSettingID(vendor))
        NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
        AccessibilityAnnouncer.sayNow(
            "Opening SimpleVPN settings for \(vendor.displayTitle).")
    }

    private func open(_ option: SignInSourceOption) {
        guard let bundleID = option.appBundleID,
              let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID)
        else { return }
        NSWorkspace.shared.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration())
        AccessibilityAnnouncer.sayNow("Opening \(option.title). Copy your password, then paste it below.")
    }
}

/// The source someone chose has gone away. Said BEFORE the connect that would
/// fail, with both ways out — because "1Password isn't running" discovered as an
/// AUTH_FAILED five seconds into a connect is the worst version of this.
struct SignInSourceRecoveryNotice: View {
    let kind: CredentialSourceKind
    let onTypeItOnce: () -> Void
    let onChange: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label {
                VStack(alignment: .leading, spacing: 2) {
                    Text(SignInFlow.unavailableHeadline(kind))
                        .font(.callout.weight(.semibold))
                        .fixedSize(horizontal: false, vertical: true)
                    Text(SignInFlow.recoveryLine)
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            }
            HStack(spacing: 8) {
                Button("Type It This Time", action: onTypeItOnce)
                    .buttonStyle(.glass)
                    .help("Show the username and password fields for this connect only \u{2014} your setup is left alone")
                    .accessibilityHint("Shows the username and password fields for this connect only. Your saved choice is left alone.")
                Button("Change\u{2026}", action: onChange)
                    .help("Choose a different way to sign in to this VPN")
                    .accessibilityLabel("Change how you sign in")
                Spacer(minLength: 0)
            }
            .controlSize(.small)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 10))
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(SignInFlow.unavailableHeadline(kind)) \(SignInFlow.recoveryLine)")
    }
}
