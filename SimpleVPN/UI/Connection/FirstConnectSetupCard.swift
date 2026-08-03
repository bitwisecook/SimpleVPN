// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  FirstConnectSetupCard.swift
//  First-connect hand-holding for the detail column. An imported config
//  describes the TRANSPORT, not the sign-in, so until a VPN has connected
//  successfully once this card asks the two questions that otherwise ambush
//  people at connect time — one-time code? and where does the sign-in live? —
//  including the 1Password drag-in. ConnectionDetailView decides when it shows.
//

import SwiftUI
import UniformTypeIdentifiers

/// First-connect hand-holding. An imported config describes the TRANSPORT, not
/// the sign-in — so until this VPN has connected successfully once, the main
/// window itself asks the two questions that otherwise ambush people at connect
/// time: "do you also enter a one-time code?" and "where does your sign-in
/// live?" — with the password-manager choice (and its drag-in) right here, no
/// trip to Manage VPNs. Disappears forever after the first proven connect.
struct FirstConnectSetupCard: View {   // was private — internal for the file split
    @Bindable var vpn: VPNController
    let profile: VPNController.Profile
    @Binding var dismissed: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// Marching-ants phase for the drop well (pure Shape drawing — safe).
    @State private var dashPhase: CGFloat = 0
    @State private var apServer = ""
    /// A multi-selection drag, waiting to be narrowed to the one item this VPN
    /// signs in with. Empty = nothing pending.
    @State private var choices: [OnePasswordDrop] = []
    /// The 1Password setup check — run when 1Password is CHOSEN here, never on
    /// appear, and skipped once the integration has been proven to work.
    @State private var preflight = OnePasswordPreflightModel()
    /// Collapses the several deliveries macOS makes of one drag into one apply.
    @State private var drops = OnePasswordDropCollector()

    private var auth: VPNAuthConfig { vpn.authConfig(for: profile.id) }
    private var source: CredentialSource { vpn.credentialSource(for: profile.id) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Before your first connect", systemImage: "hand.wave")
                    .font(.callout.weight(.semibold))
                Spacer()
                Button { dismissed = true } label: { Image(systemName: "xmark") }
                    .buttonStyle(.borderless)
                    .help("Hide until next launch — this card comes back until a connect succeeds")
            }
            Text("The configuration file says how to reach \(profile.name) — but not how you sign in. Two quick questions:")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Toggle(isOn: otpBinding) {
                VStack(alignment: .leading, spacing: 1) {
                    Text("I also enter a one-time code")
                    Text("A short code from an authenticator app, a key fob, or a text message.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .toggleStyle(.checkbox)

            Picker("My sign-in is kept", selection: sourceKindBinding) {
                Text("I'll type it in").tag(CredentialSourceKind.manual)
                Text("in 1Password").tag(CredentialSourceKind.onePassword)
                Text("in Apple Passwords").tag(CredentialSourceKind.applePasswords)
            }
            .pickerStyle(.menu)
            .fixedSize()

            switch source.kind {
            case .manual:
                EmptyView()   // the credential form directly below IS the answer
            case .onePassword:
                // Same walkthrough as the editor, in the smaller type this card
                // uses — with the account asked for here, since this card has no
                // Account field of its own to point at.
                OnePasswordSetupCard(model: preflight, compact: true, asksForAccount: true,
                                     onAccount: { useAccount($0) },
                                     onCheckAgain: { checkOnePassword(force: true) })
                onePasswordWell
                Text("Dragging the item itself fills in everything SimpleVPN needs. Dragging one of its fields fills in less.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            case .applePasswords:
                HStack {
                    TextField("Website or server the password is saved for", text: $apServer)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .onSubmit(saveApplePasswords)
                    Button("Use") { saveApplePasswords() }.buttonStyle(.glass)
                        .disabled(apServer.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                .onAppear {
                    apServer = source.reference.isEmpty ? profile.server : source.reference
                }
            }
        }
        .padding(14)
        .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 12))
        .accessibilityElement(children: .contain)
    }

    /// The drag-in target, with a quiet "things can be dropped here" rhythm:
    /// slowly marching dashes and an occasional key wiggle (both suppressed
    /// under Reduce Motion, and both stop once an item is linked).
    private var onePasswordWell: some View {
        let linked = !source.reference.isEmpty
        return RoundedRectangle(cornerRadius: 8, style: .continuous)
            .strokeBorder(style: StrokeStyle(lineWidth: 1.5, dash: [5], dashPhase: dashPhase))
            .foregroundStyle(linked ? AnyShapeStyle(.tertiary) : AnyShapeStyle(.tint))
            .frame(height: 52)
            .overlay {
                Label(linked ? "Linked to \(linkedName) — drag another item to change"
                             : "Drag the item from 1Password here",
                      systemImage: linked ? "checkmark.circle.fill" : "key.fill")
                    .font(.callout)
                    .foregroundStyle(linked ? AnyShapeStyle(.green) : AnyShapeStyle(.secondary))
                    .symbolEffect(.wiggle, options: .repeat(.periodic(delay: 4)),
                                  isActive: !reduceMotion && !linked)
            }
            .contentShape(Rectangle())
            // 1Password's own drag payload first (it names account, vault AND
            // item), then a link, then op://, then the bare title — see
            // OnePasswordDropItem.
            .onDrop(of: OnePasswordDropItem.acceptedContentTypes, isTargeted: nil) { providers, _ in
                guard OnePasswordDropItem.canAccept(providers) else { return false }
                Task {
                    // Through the collector: macOS delivers one drag more than
                    // once, and applying each delivery turned a single dropped
                    // item into a "which one?" chooser.
                    guard let dropped = await drops.collect(providers),
                          let first = dropped.first else { return }
                    // A VPN signs in with one item; several were dragged, so ask.
                    if dropped.count > 1 { choices = dropped; return }
                    link(first)
                }
                return true
            }
            .popover(isPresented: Binding(get: { !choices.isEmpty },
                                          set: { if !$0 { choices = [] } })) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Which item is this VPN\u{2019}s sign-in?").font(.callout.weight(.semibold))
                    ForEach(Array(choices.enumerated()), id: \.element.id) { index, drop in
                        Button(drop.displayName(position: index + 1)) { link(drop) }
                            .buttonStyle(.link)
                    }
                }
                .padding(12)
                .frame(minWidth: 220)
            }
            .task(id: linked) {
                guard !reduceMotion, !linked else { return }
                dashPhase = 0
                withAnimation(.linear(duration: 1.8).repeatForever(autoreverses: false)) {
                    dashPhase = -10   // one full dash+gap cycle → seamless march
                }
            }
    }

    private var otpBinding: Binding<Bool> {
        Binding(get: { auth.requiresOTP },
                set: { on in
                    var a = auth
                    a.requiresOTP = on
                    Task { try? await vpn.setAuthConfig(a, for: profile.id) }
                })
    }

    private var sourceKindBinding: Binding<CredentialSourceKind> {
        Binding(get: { source.kind },
                set: { kind in
                    var s = source
                    s.kind = kind
                    Task { try? await vpn.setCredentialSource(s, for: profile.id) }
                    // Choosing 1Password is the first genuine need for a
                    // 1Password lookup — and the only moment this card is
                    // allowed to raise its approval prompt.
                    if kind == .onePassword { checkOnePassword(force: false) }
                })
    }

    /// The setup check. `force` is the Check Again button, which re-checks even
    /// a verified integration — the way back from "it worked yesterday".
    private func checkOnePassword(force: Bool) {
        let account = OnePasswordAccountMemory.effectiveAccount(profile: source.account)
        Task {
            if force { await preflight.check(account: account) }
            else { await preflight.checkIfNeeded(account: account) }
        }
    }

    /// The account name typed into the card's prompt: kept for this VPN, and
    /// checked straight away so the answer lands where the question was asked.
    private func useAccount(_ name: String) {
        var s = source
        s.account = name
        Task {
            try? await vpn.setCredentialSource(s, for: profile.id)
            // A name is only remembered app-wide once it has actually worked —
            // the check itself does that.
            await preflight.check(account: name)
        }
    }

    /// A dragged item is linked by its 1Password id — exact, and immune to
    /// renaming, but not something to read back at anyone.
    private var linkedName: String {
        OnePasswordDrop.looksLikeItemID(source.reference)
            ? "your 1Password item"
            : "\u{201C}\(source.reference)\u{201D}"
    }

    /// Point this VPN's sign-in at a dropped item. The 1Password payload carries
    /// account and vault UUIDs as well as the item's, which is what keeps this
    /// card a one-drag setup — 1Password won't answer without knowing which
    /// account to ask.
    private func link(_ dropped: OnePasswordDrop) {
        choices = []
        var s = source
        s.kind = .onePassword
        s.reference = dropped.reference
        if !dropped.vault.isEmpty { s.vault = dropped.vault }
        if !dropped.account.isEmpty {
            s.account = dropped.account
            // The dragged item names its account, and the SDK takes that UUID as
            // readily as the sidebar name — so one drag answers "which account?"
            // for every other VPN too.
            OnePasswordAccountMemory.seed(dropped.account)
        }
        Task { try? await vpn.setCredentialSource(s, for: profile.id) }
    }

    private func saveApplePasswords() {
        var s = source
        s.kind = .applePasswords
        s.reference = apServer.trimmingCharacters(in: .whitespaces)
        Task { try? await vpn.setCredentialSource(s, for: profile.id) }
    }
}
