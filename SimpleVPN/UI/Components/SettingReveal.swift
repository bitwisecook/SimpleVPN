// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SettingReveal.swift
//  THE "take me to that setting" machinery, shared by every editor. FIVE things
//  have to happen, IN ORDER, for a jump to land somewhere usable:
//
//   1. TAB — `SettingsEditorShell` selects the tab the target lives on.
//   2. OPEN — every collapsible container between the form and the target opens
//      (`expandsForReveal`). A reveal that lands on a closed disclosure is
//      indistinguishable from a reveal that did nothing.
//   3. SCROLL — the form scrolls the row as near the centre as it can get
//      (`SettingsRevealScroll`, applied to each editor's Form as `revealsSettings`).
//   4. HIGHLIGHT — and only NOW: a clearly blue wash on the row, held long enough
//      to look up and find it, then faded back to normal. Started any earlier and
//      it plays while the row is still travelling, or — across a tab switch —
//      before the row is on screen at all.
//   5. KEYBOARD + VOICEOVER — the target control takes focus and the row is
//      announced, because a blue glow tells a VoiceOver user nothing.
//
//  THE BUG THIS SHAPE EXISTS TO PREVENT. Steps 2–5 each used to fire off
//  `onChange(of: revealGeneration)`, latch "handled this generation", and be done.
//  For a CROSS-TAB reveal every one of them ran while the destination form was not
//  the selected tab: `ScrollViewProxy.scrollTo` silently does nothing for a row
//  that isn't laid out, the highlight played somewhere nobody was looking — and
//  because the generation was already latched, the `onAppear` retry that runs when
//  the tab does come up was guarded out. The form sat at the top of its scroll with
//  nothing marked, from both entry points (a help popover's related link and a
//  `SettingJumpLink`). So:
//
//   • the scroll is NOT latched while the form is off screen, and it is RETRIED
//     across a window long enough to outlast the tab switch and the disclosure
//     animation (`SettingRevealScrollState`, which is a value type precisely so
//     those two rules are testable without a view hierarchy);
//   • the highlight and the focus WAIT for the scroll host to say it has landed
//     (`SettingsSearch.revealDidArrive`) instead of guessing with a fixed delay;
//   • containers open on `onAppear` as well as `onChange`, and are not latched at
//     all — opening a container that is already open is free.
//
//  HARD INVARIANT (AGENTS.md, the layout-loop crash): the highlight is a BACKGROUND
//  SHAPE whose opacity animates. It never scales, offsets or otherwise
//  transform-animates a container — these rows hold Toggles, Pickers and
//  SecureFields, and platform-backed views inside a transform-animated container
//  is the documented cause of the layout-loop crash. Animate colour, never
//  geometry. It also means the fade cannot reflow anything, so it can never
//  disturb the scroll position step 3 just settled.
//

import SwiftUI

// MARK: - Waiting for the arrival

/// Wait until the scroll host says the reveal has landed, or give up.
///
/// A POLL rather than a continuation, deliberately: the arrival is `@Observable`
/// state, which a view modifier can only observe from a `body`, and this runs
/// inside a Task. Bounded so a form with no scroll host at all (a preview, a
/// surface nobody has given `revealsSettings()` to yet) still highlights its row
/// rather than silently never doing it.
@discardableResult
private func awaitRevealArrival(_ search: SettingsSearch, generation: Int) async -> Bool {
    for _ in 0..<SettingRevealScrollState.arrivalPollCount {
        if search.arrivedGeneration == generation { return true }
        try? await Task.sleep(for: SettingRevealScrollState.arrivalPollInterval)
        if Task.isCancelled { return false }
    }
    return false
}

// MARK: - Row identity, highlight and VoiceOver focus

private struct SettingRevealModifier: ViewModifier {
    let settingID: String

    @Environment(SettingsSearch.self) private var search: SettingsSearch?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// The highlight's own opacity. Pure SwiftUI state driving a fill colour — the
    /// only thing that animates.
    @State private var highlight: Double = 0
    @State private var highlightTask: Task<Void, Never>?
    /// Which reveal generation this row already responded to, so a row that is
    /// UNHIDDEN by the reveal (the proxy sub-form, the cipher disclosure) still
    /// lights up when it appears a moment later, and only once.
    @State private var handledGeneration = 0
    @AccessibilityFocusState private var axFocused: Bool

    /// HOW BLUE. The accent colour already means "this is the thing" everywhere
    /// else in the app, and this much of it reads as the row being pointed out.
    ///
    /// The predecessor shimmered between 0.24 and 0.08 and back over about a
    /// second, which is a rendering artefact rather than an answer to "which row
    /// did I just ask for?". It is also why the value is HELD rather than pulsed:
    /// the user has to be able to look up, find the row, and still see it marked.
    private static let peak = 0.34
    /// Long enough to be seen and understood before it goes.
    private static let hold = Duration.milliseconds(1600)

    func body(content: Content) -> some View {
        content
            .id(settingID)
            // Background, not overlay: a wash behind the row, never over its
            // controls. `-8` horizontal padding reaches the grouped row's inset
            // so the highlight looks like the row rather than like the text.
            .background {
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(Color.accentColor.opacity(highlight))
                    .padding(.horizontal, -8)
                    .allowsHitTesting(false)
                    // Decoration for the eye. The row's spoken value is its
                    // control's; the announcement below is what carries this.
                    .accessibilityHidden(true)
            }
            .accessibilityFocused($axFocused)
            .onChange(of: search?.revealGeneration ?? 0) { respond() }
            .onAppear { respond() }
            .onDisappear { highlightTask?.cancel() }
    }

    private func respond() {
        guard let search, search.revealTargetID == settingID,
              search.revealGeneration != handledGeneration else { return }
        handledGeneration = search.revealGeneration
        let generation = search.revealGeneration
        highlightTask?.cancel()
        highlightTask = Task { @MainActor in
            // STEP 4 WAITS FOR STEP 3. Latching the generation above is what stops
            // this row responding twice; it is NOT permission to start now.
            await awaitRevealArrival(search, generation: generation)
            guard !Task.isCancelled else { return }

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

            if reduceMotion {
                // Reduce Motion: the highlight APPEARS, stays for the same time, and
                // then goes, with no animation at all — the information is "this
                // row", not the motion.
                highlight = Self.peak
                try? await Task.sleep(for: Self.hold)
                guard !Task.isCancelled else { return }
                highlight = 0
            } else {
                withAnimation(.easeOut(duration: 0.18)) { highlight = Self.peak }
                try? await Task.sleep(for: Self.hold)
                guard !Task.isCancelled else { return }
                // "Animate away" is a FADE to the row's normal appearance and
                // nothing else: no slide, no scale, nothing that moves.
                withAnimation(.easeInOut(duration: 0.5)) { highlight = 0 }
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
    @State private var focusTask: Task<Void, Never>?

    func body(content: Content) -> some View {
        content
            .focused($focused)
            .onChange(of: search?.revealGeneration ?? 0) { take() }
            .onAppear { take() }
            .onDisappear { focusTask?.cancel() }
    }

    private func take() {
        guard let search, search.revealTargetID == settingID,
              search.revealGeneration != handledGeneration else { return }
        handledGeneration = search.revealGeneration
        let generation = search.revealGeneration
        focusTask?.cancel()
        focusTask = Task { @MainActor in
            // BEHIND THE SCROLL, and now for a reason the code can check rather
            // than a hopeful delay: focusing a control that is still off-screen
            // makes AppKit scroll it into view itself, fighting the
            // ScrollViewReader.
            await awaitRevealArrival(search, generation: generation)
            guard !Task.isCancelled else { return }
            focused = true
        }
    }
}

extension View {
    /// Row half: identity for the scroll, the highlight, and VoiceOver focus.
    func settingReveal(_ settingID: String) -> some View {
        modifier(SettingRevealModifier(settingID: settingID))
    }
    /// Control half: keyboard focus on arrival.
    func settingRevealFocus(_ settingID: String, focused: FocusState<Bool>.Binding) -> some View {
        modifier(SettingRevealFocus(settingID: settingID, focused: focused))
    }
}

// MARK: - The scroll host

/// A scroll host's bookkeeping, as a VALUE so the two rules that were got wrong
/// are testable without a view hierarchy:
///
///  • a reveal that fires while the form is OFF SCREEN must not be marked handled,
///    or the `onAppear` that runs when its tab is selected is guarded out and the
///    form never scrolls at all;
///  • once handled, neither path may fire again for the same generation.
struct SettingRevealScrollState: Equatable, Sendable {
    private(set) var handledGeneration = 0
    private(set) var onScreen = false

    /// A reveal fired. True when the scroll should run now.
    mutating func revealed(generation: Int) -> Bool {
        guard onScreen, generation != 0, generation != handledGeneration else { return false }
        handledGeneration = generation
        return true
    }

    /// The form appeared — a tab switch either built it or made it visible. True
    /// when a reveal is still owed a scroll.
    mutating func appeared(pendingGeneration: Int) -> Bool {
        onScreen = true
        guard pendingGeneration != 0, pendingGeneration != handledGeneration else { return false }
        handledGeneration = pendingGeneration
        return true
    }

    mutating func disappeared() { onScreen = false }

    /// The retry schedule, as gaps between attempts. MORE THAN ONE ATTEMPT is the
    /// invariant: a `ScrollViewReader` cannot scroll to a row that isn't laid out
    /// yet, and between the reveal and a laid-out row sit a tab switch and a
    /// disclosure opening — neither of which reports when it is done. Attempting
    /// again a few times over half a second costs nothing (a `scrollTo` to where we
    /// already are is a no-op) and is the difference between landing and not.
    static let attempts: [Duration] = [.milliseconds(70), .milliseconds(140),
                                       .milliseconds(190), .milliseconds(190)]
    /// The gap after the last attempt before the arrival is published, so the
    /// highlight starts on a row that has stopped moving.
    static let settleDelay = Duration.milliseconds(80)
    /// How long the row's highlight will wait for that arrival before giving up and
    /// showing itself anyway. Comfortably longer than the schedule above, so the
    /// timeout is the fallback for "this form has no scroll host", never the
    /// ordinary path.
    static let arrivalPollInterval = Duration.milliseconds(50)
    static let arrivalPollCount = 30
    static var arrivalTimeout: Duration { arrivalPollInterval * arrivalPollCount }
    /// The whole choreography: every attempt, plus the settle. What the reveal's own
    /// state has to outlive.
    static var scrollWindow: Duration {
        attempts.reduce(Duration.zero, +) + settleDelay
    }
}

/// Wraps an editor's `Form` in a `ScrollViewReader`, performs the scroll, and
/// publishes the arrival that the highlight and the keyboard focus wait for. One
/// modifier per form, in place of the hand-written `ScrollViewReader { proxy in …
/// onChange … }` that once existed only in the OpenVPN options form.
private struct SettingsRevealScroll<Content: View>: View {
    @Environment(SettingsSearch.self) private var search: SettingsSearch?
    @ViewBuilder let content: Content

    @State private var state = SettingRevealScrollState()
    @State private var scrollTask: Task<Void, Never>?

    var body: some View {
        ScrollViewReader { proxy in
            content
                .onChange(of: search?.revealGeneration ?? 0) { revealed(proxy) }
                // CROSS-TAB REVEALS, both flavours. `SettingsEditorShell` selects
                // the destination tab, so either this Form is CREATED after the
                // generation changed (and the `onChange` above never fires for it),
                // or it already existed off screen and the `onChange` fired against
                // a hierarchy with nothing laid out to scroll. Same scroll, from
                // "the form is on screen with a target already pending".
                .onAppear { appeared(proxy) }
                .onDisappear { state.disappeared(); scrollTask?.cancel() }
        }
    }

    private func revealed(_ proxy: ScrollViewProxy) {
        guard let generation = search?.revealGeneration,
              state.revealed(generation: generation) else { return }
        run(proxy, generation: generation)
    }

    private func appeared(_ proxy: ScrollViewProxy) {
        guard let generation = search?.revealGeneration,
              state.appeared(pendingGeneration: generation) else { return }
        run(proxy, generation: generation)
    }

    private func run(_ proxy: ScrollViewProxy, generation: Int) {
        guard let search, let id = search.revealTargetID else { return }
        scrollTask?.cancel()
        scrollTask = Task { @MainActor in
            for (index, gap) in SettingRevealScrollState.attempts.enumerated() {
                try? await Task.sleep(for: gap)
                guard !Task.isCancelled else { return }
                // `anchor: .center` is "as near the centre as it can get" — SwiftUI
                // clamps it, so a row near the top or the bottom of the form ends up
                // as close as the content allows rather than refusing to move.
                if index == 0 {
                    withAnimation(.easeInOut(duration: 0.28)) { proxy.scrollTo(id, anchor: .center) }
                } else {
                    // A correction, not a journey: unanimated, so a re-attempt that
                    // finds us already there shows nothing at all.
                    proxy.scrollTo(id, anchor: .center)
                }
            }
            try? await Task.sleep(for: SettingRevealScrollState.settleDelay)
            guard !Task.isCancelled else { return }
            search.revealDidArrive(id: id, generation: generation)
        }
    }
}

// MARK: - Opening what the target is hidden inside

/// What a collapsible container holds — the question a reveal has to answer before
/// it scrolls, because a scroll that lands on a closed disclosure is
/// indistinguishable from a scroll that didn't happen.
enum RevealContainerScope: Equatable, Sendable {
    /// Everything in one canonical group (`CollapsibleSettingsSection`, which is how
    /// every editor's Security and Advanced groups collapse).
    case group(SettingGroup)
    /// A named set of ids — a disclosure nested INSIDE a section, where the group
    /// is the section's and says nothing about the disclosure.
    case settings(Set<String>)

    /// Whether a reveal of `id` (whose canonical group is `group`) is inside here.
    func holds(_ id: String, group: SettingGroup?) -> Bool {
        switch self {
        case .group(let wanted): group == wanted
        case .settings(let ids): ids.contains(id)
        }
    }
}

private struct SettingRevealExpand: ViewModifier {
    @Binding var isExpanded: Bool
    let scope: RevealContainerScope
    @Environment(SettingsSearch.self) private var search: SettingsSearch?

    func body(content: Content) -> some View {
        content
            .onChange(of: search?.revealGeneration ?? 0) { open() }
            // Same reason the scroll needs it: a cross-tab reveal creates this
            // container after the generation changed. DELIBERATELY NOT latched on a
            // handled generation — opening a container that is already open is
            // free, and a latch is exactly what let the first responder win and the
            // rest of the reveal miss.
            .onAppear { open() }
    }

    private func open() {
        guard let search, let id = search.revealTargetID, !isExpanded,
              scope.holds(id, group: search.revealGroup) else { return }
        withAnimation(.snappy) { isExpanded = true }
    }
}

extension View {
    /// Make this form the scroll target for setting reveals, and the thing that says
    /// when a reveal has landed.
    func revealsSettings() -> some View {
        SettingsRevealScroll { self }
    }

    /// Open this collapsible container when a reveal targets something inside it.
    /// THE general answer to "the row is in a collapsed section": every
    /// `CollapsibleSettingsSection` in every editor carries it, and a hand-rolled
    /// `DisclosureGroup` inside a section names its ids.
    func expandsForReveal(_ isExpanded: Binding<Bool>,
                          holding scope: RevealContainerScope) -> some View {
        modifier(SettingRevealExpand(isExpanded: isExpanded, scope: scope))
    }
}

// MARK: - Unhiding a target that is behind a toggle rather than a disclosure

/// Give an editor a chance to open a purely-VISUAL gate that hides the reveal
/// target — a sub-form behind a master toggle — before the scroll runs.
/// `expandsForReveal` covers a collapsible container; this covers the cases that
/// aren't one.
///
/// STRICTLY for view state. A gate that is part of the CONFIG (Tailscale's exit
/// node, IPsec's XAuth, the Protocol picker) must NOT be flipped to satisfy a
/// jump — that edits the user's VPN because they asked a question about it. Those
/// are declared in `SettingVisibility` instead, and the reveal says so.
private struct SettingRevealUnhide: ViewModifier {
    let unhide: (String) -> Void
    @Environment(SettingsSearch.self) private var search: SettingsSearch?

    func body(content: Content) -> some View {
        content
            .onChange(of: search?.revealGeneration ?? 0) { act() }
            // Same reason as `expandsForReveal`, and unlatched for the same reason:
            // every caller's action is idempotent (it sets a Bool true).
            .onAppear { act() }
    }

    private func act() {
        guard let search, let id = search.revealTargetID else { return }
        unhide(id)
    }
}

extension View {
    /// Open this form's own non-collapsible visual gates for a reveal target. See
    /// `SettingRevealUnhide` for what may and may not be flipped here.
    func unhidesRevealTarget(_ unhide: @escaping (String) -> Void) -> some View {
        modifier(SettingRevealUnhide(unhide: unhide))
    }
}

// MARK: - Back

/// "Take me back where I was." A reveal moves the user across a tab boundary and
/// down a long form; without this the only way back is to remember where you were,
/// which is the one thing following a link makes you stop doing.
///
/// Installed by `SettingsEditorShell`, so every editor has it whether or not the
/// user ever follows a link — the ask was for general navigation, not for an
/// undo of the last jump. ⌘[ is the macOS convention.
struct SettingsBackButton: View {
    let search: SettingsSearch

    var body: some View {
        Button { search.goBack() } label: {
            Label("Back", systemImage: "chevron.backward")
        }
        .disabled(!search.canGoBack)
        .keyboardShortcut("[", modifiers: .command)
        .help(search.backDestination.map { "Back to \u{201C}\($0)\u{201D}" }
              ?? "Back to where you came from")
        // "Back" alone answers nothing — back WHERE? The destination rides the
        // value, so it is spoken without being part of the button's name.
        .accessibilityLabel("Back")
        .accessibilityValue(search.backDestination ?? "nowhere to go back to")
        .accessibilityHint(search.backDestination.map { "Returns to \($0)" }
                           ?? "Returns to wherever you followed a link from")
    }
}
