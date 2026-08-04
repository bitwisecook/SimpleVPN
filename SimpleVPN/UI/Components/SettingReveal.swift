// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SettingReveal.swift
//  THE "take me to that setting" machinery, shared by every editor. Four things
//  have to happen for a jump to actually land somewhere usable, and each of them
//  used to be either hand-written in OpenVPNOptionsForm or missing entirely:
//
//   1. IDENTITY — the row carries `.id(settingID)` so a ScrollViewReader can
//      reach it (`SettingsRevealScroll`, applied to each editor's Form).
//   2. PULSE — a short animated highlight, so the eye finds the row the scroll
//      just moved to. Reduce Motion gets the highlight without the animation.
//   3. KEYBOARD FOCUS — the target control takes focus, so the jump lands on
//      something you can immediately type into or toggle (Docs/Accessibility.md's
//      initial-focus rule, applied to arrivals as well as openings).
//   4. VOICEOVER — accessibility focus moves to the row AND the announcement
//      names the setting, because a scroll plus a colour wash is imperceptible.
//
//  HARD INVARIANT (AGENTS.md, the layout-loop crash): the pulse is a BACKGROUND
//  SHAPE whose opacity animates. It never scales, offsets or otherwise
//  transform-animates a container — these rows hold Toggles, Pickers and
//  SecureFields, and platform-backed views inside a transform-animated container
//  is the documented cause of the layout-loop crash. Animate colour, never
//  geometry.
//

import SwiftUI

// MARK: - Row identity, pulse and VoiceOver focus

private struct SettingRevealModifier: ViewModifier {
    let settingID: String

    @Environment(SettingsSearch.self) private var search: SettingsSearch?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// The pulse's own opacity. Pure SwiftUI state driving a fill colour — the
    /// only thing that animates.
    @State private var pulse: Double = 0
    @State private var pulseTask: Task<Void, Never>?
    /// Which reveal generation this row already responded to, so a row that is
    /// UNHIDDEN by the reveal (the proxy sub-form, the cipher disclosure) still
    /// pulses when it appears a moment later, and only once.
    @State private var handledGeneration = 0
    @AccessibilityFocusState private var axFocused: Bool

    func body(content: Content) -> some View {
        content
            .id(settingID)
            // Background, not overlay: a wash behind the row, never over its
            // controls. `-8` horizontal padding reaches the grouped row's inset
            // so the highlight looks like the row rather than like the text.
            .background {
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(Color.accentColor.opacity(pulse))
                    .padding(.horizontal, -8)
                    .allowsHitTesting(false)
                    .accessibilityHidden(true)
            }
            .accessibilityFocused($axFocused)
            .onChange(of: search?.revealGeneration ?? 0) { respond() }
            .onAppear { respond() }
            .onDisappear { pulseTask?.cancel() }
    }

    private func respond() {
        guard let search, search.revealTargetID == settingID,
              search.revealGeneration != handledGeneration else { return }
        handledGeneration = search.revealGeneration
        axFocused = true
        // THE ROW ANNOUNCES, not the scroll host. The host said "Showing X, in Y"
        // whether or not any row existed to show — and five of the six editors
        // gate rows on the config, so for those the sentence was simply false.
        // Announcing from here means the claim is made by something that is, by
        // construction, on screen. (`SettingsSearch.reveal` says the honest
        // opposite when the row is gated out — see `SettingVisibility`.)
        if let s = search.setting(settingID) {
            let group = s.canonicalGroup?.title
            AccessibilityAnnouncer.sayNow(group.map { "Showing \(s.name), in \($0)" }
                                          ?? "Showing \(s.name)")
        }
        pulseTask?.cancel()
        pulseTask = Task { @MainActor in
            if reduceMotion {
                // Reduce Motion: the highlight APPEARS and then goes, with no
                // animation at all — the information is "this row", not the motion.
                pulse = 0.20
                try? await Task.sleep(for: .seconds(1.6))
                guard !Task.isCancelled else { return }
                pulse = 0
            } else {
                withAnimation(.easeInOut(duration: 0.28)) { pulse = 0.24 }
                try? await Task.sleep(for: .milliseconds(300))
                guard !Task.isCancelled else { return }
                withAnimation(.easeInOut(duration: 0.36)) { pulse = 0.08 }
                try? await Task.sleep(for: .milliseconds(380))
                guard !Task.isCancelled else { return }
                withAnimation(.easeInOut(duration: 0.28)) { pulse = 0.24 }
                try? await Task.sleep(for: .milliseconds(300))
                guard !Task.isCancelled else { return }
                withAnimation(.easeOut(duration: 0.55)) { pulse = 0 }
            }
        }
    }
}

// MARK: - Keyboard focus for the row's control

/// Applied to the CONTROL, not the row: keyboard focus belongs on the thing you
/// type into or toggle. `EngineSettingRow` and the OpenVPN form's `SettingRow`
/// each own the `@FocusState` and hand it here, so one edit gave every row in
/// every editor a focusable jump target.
private struct SettingRevealFocus: ViewModifier {
    let settingID: String
    @FocusState.Binding var focused: Bool
    @Environment(SettingsSearch.self) private var search: SettingsSearch?
    @State private var handledGeneration = 0

    func body(content: Content) -> some View {
        content
            .focused($focused)
            .onChange(of: search?.revealGeneration ?? 0) { take() }
            .onAppear { take() }
    }

    private func take() {
        guard let search, search.revealTargetID == settingID,
              search.revealGeneration != handledGeneration else { return }
        handledGeneration = search.revealGeneration
        // A beat behind the scroll: focusing a control that is still off-screen
        // makes AppKit scroll it into view itself, fighting the ScrollViewReader.
        Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(120))
            focused = true
        }
    }
}

extension View {
    /// Row half: identity for the scroll, the pulse, and VoiceOver focus.
    func settingReveal(_ settingID: String) -> some View {
        modifier(SettingRevealModifier(settingID: settingID))
    }
    /// Control half: keyboard focus on arrival.
    func settingRevealFocus(_ settingID: String, focused: FocusState<Bool>.Binding) -> some View {
        modifier(SettingRevealFocus(settingID: settingID, focused: focused))
    }
}

// MARK: - The scroll host

/// Wraps an editor's `Form` in a `ScrollViewReader` and performs the scroll and
/// the VoiceOver announcement when a reveal fires. One modifier per form, in
/// place of the hand-written `ScrollViewReader { proxy in … onChange … }` that
/// existed only in the OpenVPN options form.
private struct SettingsRevealScroll<Content: View>: View {
    @Environment(SettingsSearch.self) private var search: SettingsSearch?
    @ViewBuilder let content: Content

    /// The generation this form already scrolled for. Needed because the scroll
    /// now runs from TWO places, and must happen once.
    @State private var handledGeneration = 0

    var body: some View {
        ScrollViewReader { proxy in
            content
                .onChange(of: search?.revealGeneration ?? 0) { scroll(proxy) }
                // CROSS-TAB REVEALS. `SettingsEditorShell` selects the destination
                // tab, so this Form is CREATED after the generation changed and its
                // `onChange` above never fires — the reveal then only pulsed and
                // focused, and it LOOKED like it worked purely because AppKit
                // scrolls a focused control into view. A DISABLED row (an MDM lock,
                // an inert setting) takes no focus, so the pulse happened
                // off-screen with nothing to see. Same scroll, same guard, from
                // "the form just appeared with a target already pending".
                .onAppear { scroll(proxy) }
        }
    }

    private func scroll(_ proxy: ScrollViewProxy) {
        guard let search, let id = search.revealTargetID,
              search.revealGeneration != handledGeneration else { return }
        handledGeneration = search.revealGeneration
        Task { @MainActor in
            // Let any container the reveal just opened (a collapsed
            // CollapsibleSettingsSection, a conditionally-rendered sub-form) lay
            // out before scrolling to a row that may not have existed a frame ago.
            try? await Task.sleep(for: .milliseconds(80))
            withAnimation { proxy.scrollTo(id, anchor: .center) }
        }
        // The announcement is the ROW's (SettingRevealModifier): it is the only
        // thing that knows the row exists.
    }
}

// MARK: - Unhiding a target before the scroll

/// Give an editor a chance to open a purely-VISUAL container that hides the
/// reveal target (a disclosure, a sub-form toggle) before the scroll runs — the
/// pattern `OpenVPNOptionsForm` hand-wrote for its proxy rows and cipher strings,
/// as one shared modifier so the other five editors have the idiom too.
///
/// STRICTLY for view state. A gate that is part of the CONFIG (Tailscale's exit
/// node, IPsec's XAuth, the Protocol picker) must NOT be flipped to satisfy a
/// jump — that edits the user's VPN because they asked a question about it. Those
/// are declared in `SettingVisibility` instead, and the reveal says so.
private struct SettingRevealUnhide: ViewModifier {
    let unhide: (String) -> Void
    @Environment(SettingsSearch.self) private var search: SettingsSearch?
    @State private var handledGeneration = 0

    func body(content: Content) -> some View {
        content
            .onChange(of: search?.revealGeneration ?? 0) { act() }
            // Same reason the scroll needs it: a cross-tab reveal creates this
            // view after the generation changed.
            .onAppear { act() }
    }

    private func act() {
        guard let search, let id = search.revealTargetID,
              search.revealGeneration != handledGeneration else { return }
        handledGeneration = search.revealGeneration
        unhide(id)
    }
}

extension View {
    /// Make this form the scroll target for setting reveals.
    func revealsSettings() -> some View {
        SettingsRevealScroll { self }
    }

    /// Open this form's own visual containers for a reveal target. See
    /// `SettingRevealUnhide` for what may and may not be flipped here.
    func unhidesRevealTarget(_ unhide: @escaping (String) -> Void) -> some View {
        modifier(SettingRevealUnhide(unhide: unhide))
    }
}
