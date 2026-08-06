// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  Reorder.swift
//  ONE reorder affordance for every ordered list in the app: the index maths, the
//  words, the drag payload, the drop indicator, and — the part that matters most —
//  the Move Up / Move Down commands that make reordering possible without a mouse.
//
//  WHY THIS IS SHARED AND NOT THREE IMPLEMENTATIONS
//
//  Three lists want reordering (the servers table, the Custom Routing rule lists,
//  and later the VPN list), and they have nothing in common structurally: one is a
//  `Table`, one is a `ForEach` in a `VStack` inside a `Form` section, and one is a
//  sidebar `List`. What they DO have in common is every user-visible decision —
//  what a move is called, what VoiceOver says after one, what happens at the ends
//  of the list, whether a row may move at all, and what the drop indicator looks
//  like. So the mechanism is the decisions, not the container: a list supplies
//  `ReorderCommands` (what the rows are called, where the moving one is, and how to
//  write the new order down) and gets the whole affordance back.
//
//  THE ACCESSIBILITY RULE THAT SHAPES THE API
//
//  Drag is never the only way (Docs/Accessibility.md rule 7). That is why `move` is
//  a plain `(from, to) -> Void` closure rather than anything gesture-shaped: the
//  same closure serves the pointer, the buttons, the context menu and the tests.
//  Every list therefore gets Move Up / Move Down for free and cannot ship the drag
//  without them. Each command names WHAT moves and WHERE IT LANDED
//  (`ReorderCopy.landed`), the landing is announced through the house announcer,
//  and a command that cannot run says why in `.help` AND `.accessibilityValue`
//  (rule 5) instead of being silently inert.
//
//  THE CRASH INVARIANT, AND WHY THE PREVIEW IS A SEPARATE VIEW
//
//  A drag animates a transform, and the house rule (AGENTS.md, the layout-loop
//  crash) forbids a platform-backed view — `TextField`, `Toggle`, `Picker`,
//  `ProgressView`, anything `NSTextView`-backed — inside a transform-animated
//  container. Every reorderable row in this app contains at least one. So:
//    • `Table` rows are dragged by AppKit, which snapshots the row to a static
//      image before the drag begins — the live controls are never transformed.
//    • Hand-rolled rows use `reorderDraggable(...)`, which REQUIRES a preview and
//      whose preview is `ReorderDragPreview` — text on a glass capsule, no
//      controls. The live row is left untouched and untransformed.
//  There is no code path here that puts a live control into a drag representation.
//
//  ORDER IS SOMETIMES SEMANTICS. `ReorderCommands.subject` is the row's own
//  sentence, not "row 3", because in a first-match-wins list (Custom Routing) a
//  move changes where traffic goes and the spoken confirmation has to name the rule
//  that moved and the position it now holds.
//

import SwiftUI
import UniformTypeIdentifiers

// MARK: - The maths (pure, total, and the part tests pin)

/// Index maths for reordering, total over bad input: a nonsense index returns the
/// list unchanged rather than trapping. Every reorder in the app goes through
/// these two functions, so "what does a move mean" has exactly one answer.
nonisolated enum Reorder {

    /// Move the item at `source` so that it ENDS UP at index `destination`.
    ///
    /// Destination is stated in result coordinates on purpose. SwiftUI's
    /// `move(fromOffsets:toOffset:)` states it in pre-removal coordinates, which is
    /// why "move down one" reads as `to: index + 2` there — an off-by-one waiting
    /// to happen every time somebody writes it by hand.
    static func moved<T>(_ items: [T], from source: Int, to destination: Int) -> [T] {
        guard items.indices.contains(source), items.count > 1 else { return items }
        let clamped = min(max(destination, 0), items.count - 1)
        guard clamped != source else { return items }
        var out = items
        out.insert(out.remove(at: source), at: clamped)
        return out
    }

    /// Move the item at `source` so it sits immediately BEFORE whatever is at
    /// `target` right now — the shape a drop between two rows has. `target ==
    /// items.count` means "past the last row", i.e. the end.
    static func moved<T>(_ items: [T], from source: Int, insertingBefore target: Int) -> [T] {
        guard items.indices.contains(source) else { return items }
        let t = min(max(target, 0), items.count)
        return moved(items, from: source, to: source < t ? t - 1 : t)
    }

    /// Where a one-step move lands, or nil when there is nowhere to go. Nil is how
    /// Move Up on the first row and Move Down on the last become no-ops instead of
    /// arithmetic on an index that doesn't exist.
    static func destination(from source: Int, delta: Int, count: Int) -> Int? {
        guard count > 1, source >= 0, source < count else { return nil }
        let to = source + delta
        guard to >= 0, to < count else { return nil }
        return to
    }
}

// MARK: - The words

/// Every string the reorder affordance says, in one pure place — so the servers
/// table, the rule lists and the VPN list cannot drift into three vocabularies for
/// the same gesture, and so a test can assert what VoiceOver hears without
/// building a view.
nonisolated enum ReorderCopy {

    /// The menu-item wording. Apple's own ("Move Up" / "Move Down"), title case,
    /// no arrows in the words — the glyph is the arrow.
    static let moveUpTitle = "Move Up"
    static let moveDownTitle = "Move Down"

    /// The button/menu-item accessibility label: what moves, and which way.
    static func moveUp(_ subject: String) -> String { "Move \(subject) up" }
    static func moveDown(_ subject: String) -> String { "Move \(subject) down" }

    /// "2 of 5" — a position, in the form VoiceOver already uses for list rows.
    static func position(_ index: Int, of count: Int) -> String { "\(index + 1) of \(count)" }

    /// What is announced after a move: what moved, and WHERE IT LANDED. A bare
    /// "Moved" tells a screen-reader user that something happened and nothing
    /// about the outcome, which in a first-match-wins list is the only part that
    /// matters.
    static func landed(_ subject: String, at index: Int, of count: Int) -> String {
        "Moved \(subject) to \(position(index, of: count))"
    }

    /// Why Move Up is unavailable on the first row — and Move Down on the last.
    /// A reason, not a dead button (Docs/Accessibility.md rule 5).
    static func alreadyFirst(_ subject: String) -> String { "\(subject) is already first." }
    static func alreadyLast(_ subject: String) -> String { "\(subject) is already last." }

    /// Nothing is selected, so there is nothing to move.
    static let nothingSelected = "Choose a row first, then move it."

    /// One row cannot be moved on its own.
    static let onlyOne = "There is only one row, so there is no order to change."

    /// The drag handle's own words. The handle is the ONE hover-discoverable part
    /// of this affordance, so it says what it is and points at the commands that
    /// don't need a pointer.
    static func gripHelp(_ subject: String) -> String {
        "Drag to move \(subject). Or use the up and down buttons \u{2014} they do the same thing."
    }

    /// The handle's tooltip where the handle is also the row's NUMBER — a list
    /// whose order is its meaning (first match wins) earns a visible position.
    static func gripHelp(_ subject: String, position index: Int, count: Int) -> String {
        "\(subject) is \(ReorderCopy.position(index, of: count)). Drag to move it, or use the"
            + " up and down buttons \u{2014} they do the same thing."
    }
}

// MARK: - The drag payload

extension UTType {
    /// SimpleVPN's private "a row is being reordered" type, declared in
    /// `SimpleVPN/Info.plist`. Private and app-specific on purpose: a generic text
    /// or data type would let a rule row be dropped into an address field, and let
    /// any dragged text land in a rule list as a reorder.
    /// `nonisolated` because `ReorderPayload.transferRepresentation` is: this file
    /// compiles under the app's MainActor default isolation, and a Transferable's
    /// representation is built off the main actor.
    nonisolated static let simpleVPNReorderRow = UTType(exportedAs: "com.bragi0.SimpleVPN.reorder-row")
}

/// What a dragged row carries: which row, and which list it came from.
///
/// `listID` is load-bearing rather than decorative. The Custom Routing tab shows a
/// route rule list and a resolver rule list at once, and a route rule dropped into
/// the resolver list would be a reorder of something that isn't there. Every drop
/// target checks the list first and refuses a foreign payload.
nonisolated struct ReorderPayload: Codable, Sendable, Transferable {
    /// The row's stable identity, as a string — a UUID for a rule, a host:port:proto
    /// id for a server, a profile id for a VPN.
    var rowID: String
    /// Which list this row belongs to.
    var listID: String

    init(rowID: String, listID: String) {
        self.rowID = rowID
        self.listID = listID
    }

    static var transferRepresentation: some TransferRepresentation {
        CodableRepresentation(contentType: .simpleVPNReorderRow)
    }
}

// MARK: - The commands

/// What one list must be able to answer for the shared affordance: what is moving,
/// where it is, how long the list is, and how to write the new order down.
///
/// Deliberately a value rather than a protocol: it is built fresh in `body` from
/// whatever the list already knows, so it can never hold a stale index — the bug
/// class that makes a reorder move the wrong row.
@MainActor
struct ReorderCommands {

    /// The moving row in words ("London", "the Accept 10.0.0.0/8 rule"). Feeds
    /// every label and the spoken confirmation, so it must read as a noun phrase.
    var subject: String
    /// Where it is now, or nil when nothing is chosen.
    var index: Int?
    /// How many rows the list has.
    var count: Int
    /// Why this list (or this row) cannot be reordered at all — an MDM lock, an
    /// active sort, a row the configuration pins. nil = it can move.
    var blocked: String?
    /// What to say when there is no selection. Lists with a selection model
    /// override the default; per-row controls never see it.
    var nothingSelected: String = ReorderCopy.nothingSelected
    /// Write the new order down. `from`/`to` are both result-coordinate indices
    /// (see `Reorder.moved(_:from:to:)`). This is the list's OWN persistence path —
    /// the affordance introduces no storage of its own.
    var move: (Int, Int) -> Void

    init(subject: String, index: Int?, count: Int, blocked: String? = nil,
         nothingSelected: String = ReorderCopy.nothingSelected,
         move: @escaping (Int, Int) -> Void) {
        self.subject = subject
        self.index = index
        self.count = count
        self.blocked = blocked
        self.nothingSelected = nothingSelected
        self.move = move
    }

    /// Why Move Up can't run, or nil when it can.
    var upReason: String? { reason(delta: -1) }
    /// Why Move Down can't run, or nil when it can.
    var downReason: String? { reason(delta: 1) }

    private func reason(delta: Int) -> String? {
        if let blocked { return blocked }
        guard count > 1 else { return ReorderCopy.onlyOne }
        guard let index else { return nothingSelected }
        if Reorder.destination(from: index, delta: delta, count: count) == nil {
            return delta < 0 ? ReorderCopy.alreadyFirst(subject) : ReorderCopy.alreadyLast(subject)
        }
        return nil
    }

    /// One step up. A no-op — never a crash — on the first row, on a blocked row,
    /// and with nothing selected.
    func moveUp() { step(-1) }
    /// One step down. Same guarantees.
    func moveDown() { step(1) }

    private func step(_ delta: Int) {
        guard blocked == nil, let index,
              let to = Reorder.destination(from: index, delta: delta, count: count) else { return }
        move(index, to)
        // The user asked for this and it is finished: immediate, not debounced —
        // the click IS the debounce (Docs/Accessibility.md rule 2).
        AccessibilityAnnouncer.sayNow(ReorderCopy.landed(subject, at: to, of: count))
    }

    /// Move `subject` so it lands where `target` is now — the drop's shape, routed
    /// through the same closure and the same announcement as the buttons.
    func drop(from source: Int, insertingBefore target: Int) {
        guard blocked == nil, count > 1, source >= 0, source < count else { return }
        let t = min(max(target, 0), count)
        let to = source < t ? t - 1 : t
        guard to != source else { return }
        move(source, to)
        AccessibilityAnnouncer.sayNow(ReorderCopy.landed(subject, at: to, of: count))
    }
}

// MARK: - The controls

/// Move Up / Move Down as a pair of small chevron buttons. THE keyboard and
/// Switch Control path, and the reason a drag may exist at all.
///
/// Used two ways, identically worded: the servers table puts one pair in its bottom
/// bar acting on the selected row (the System Settings idiom, beside `+`/`−`), and
/// each Custom Routing rule row carries its own pair (those rows have no bottom bar
/// and no selection).
struct ReorderButtons: View {
    let commands: ReorderCommands
    /// Claim ⌘⌥↑ / ⌘⌥↓. At most ONE pair per window may: two views claiming the
    /// same key equivalent make it ambiguous, and the Custom Routing tab shows two
    /// rule lists at once with a pair on every row.
    var shortcuts = false

    var body: some View {
        HStack(spacing: 2) {
            button(systemImage: "chevron.up",
                   label: ReorderCopy.moveUp(commands.subject),
                   title: ReorderCopy.moveUpTitle,
                   reason: commands.upReason,
                   shortcut: shortcuts ? KeyEquivalent.upArrow : nil,
                   action: commands.moveUp)
            button(systemImage: "chevron.down",
                   label: ReorderCopy.moveDown(commands.subject),
                   title: ReorderCopy.moveDownTitle,
                   reason: commands.downReason,
                   shortcut: shortcuts ? KeyEquivalent.downArrow : nil,
                   action: commands.moveDown)
        }
    }

    @ViewBuilder
    private func button(systemImage: String, label: String, title: String,
                        reason: String?, shortcut: KeyEquivalent?,
                        action: @escaping () -> Void) -> some View {
        let b = Button(action: action) {
            Image(systemName: systemImage)
                // The app-wide 22×22 minimum for a glyph target.
                .frame(width: 22, height: 22)
                .contentShape(Rectangle())
        }
        .disabled(reason != nil)
        // The same sentence to the pointer and to VoiceOver — a disabled control
        // says why, and never only on hover.
        .help(reason ?? title)
        .accessibilityLabel(label)
        .accessibilityValue(reason ?? whereItWouldLand(systemImage == "chevron.up" ? -1 : 1))
        if let shortcut {
            b.keyboardShortcut(shortcut, modifiers: [.command, .option])
        } else {
            b
        }
    }

    /// "to 2 of 5" — said BEFORE the move, so a VoiceOver user knows what the
    /// button will do rather than having to do it and listen.
    private func whereItWouldLand(_ delta: Int) -> String {
        guard let index = commands.index,
              let to = Reorder.destination(from: index, delta: delta, count: commands.count) else {
            return ReorderCopy.position(commands.index ?? 0, of: commands.count)
        }
        return "to \(ReorderCopy.position(to, of: commands.count))"
    }
}

/// The same two commands as context-menu items. A context menu is never the only
/// path (Docs/Accessibility.md) — this always accompanies `ReorderButtons`, it
/// never replaces them. It exists because right-clicking a row is what a Mac user
/// tries first, and because VO-⇧-M reaches it.
struct ReorderMenuItems: View {
    let commands: ReorderCommands

    var body: some View {
        Button(ReorderCopy.moveUpTitle, systemImage: "chevron.up", action: commands.moveUp)
            .disabled(commands.upReason != nil)
            .accessibilityLabel(ReorderCopy.moveUp(commands.subject))
            .accessibilityValue(commands.upReason ?? "")
        Button(ReorderCopy.moveDownTitle, systemImage: "chevron.down", action: commands.moveDown)
            .disabled(commands.downReason != nil)
            .accessibilityLabel(ReorderCopy.moveDown(commands.subject))
            .accessibilityValue(commands.downReason ?? "")
    }
}

/// The drag handle for a hand-rolled row. `Table` needs none — the whole AppKit row
/// is the handle, and AppKit draws its own — so this only appears where the row is a
/// SwiftUI view. A handle rather than the whole row, because these rows are full of
/// text fields and dragging from one of those must still select text.
///
/// `position` turns the handle INTO the row's number. Where the order is the meaning
/// — a first-match-wins rule list — a visible 1, 2, 3 is what makes a drag legible:
/// you can see which rule wins before and after, not just that something moved.
/// Where the order is only a preference, leave it nil and get a grip glyph.
///
/// `accessibilityHidden` on purpose: it is a pointer affordance whose function is
/// already reachable as two named buttons, and the position it shows rides the row's
/// own sentence (Docs/Accessibility.md rule 4) rather than being read twice.
struct ReorderGrip: View {
    let subject: String
    var position: Int?
    var count: Int = 0
    var blocked: String?

    var body: some View {
        Group {
            if let position {
                Text("\(position + 1)").font(.caption.monospacedDigit())
            } else {
                Image(systemName: "line.3.horizontal").font(.caption)
            }
        }
        .foregroundStyle(blocked == nil ? AnyShapeStyle(.tertiary) : AnyShapeStyle(.quaternary))
        .frame(width: 18, height: 22)
        .contentShape(Rectangle())
        .help(blocked ?? position.map { ReorderCopy.gripHelp(subject, position: $0, count: count) }
                        ?? ReorderCopy.gripHelp(subject))
        .accessibilityHidden(true)
    }
}

/// Where the dragged row will land. Drawn between rows, above the row it will
/// insert before — so in a first-match-wins list you can see which rule ends up
/// above which BEFORE letting go.
///
/// A plain shape, drawn and undrawn without an animated transform: it sits in the
/// same stack as live controls, and the house rule keeps transforms away from them.
struct ReorderInsertionLine: View {
    var body: some View {
        Capsule()
            .fill(Color.accentColor)
            .frame(height: 2)
            .padding(.horizontal, 2)
            .accessibilityHidden(true)
    }
}

/// What is under the pointer during a drag: the row's own sentence on a glass
/// capsule. Text only — this is the view the drag transform animates, and no
/// platform-backed control may be inside it (AGENTS.md, the layout-loop crash).
struct ReorderDragPreview: View {
    let subject: String

    var body: some View {
        Text(subject)
            .font(.callout)
            .lineLimit(1)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .glassEffect(in: .capsule)
    }
}

// MARK: - Wiring a hand-rolled row up

extension View {
    /// Make this row a reorder drag SOURCE with a static preview.
    ///
    /// The preview argument is not optional and not a snapshot of `self`: these rows
    /// hold pickers and text fields, and the drag representation is the one place
    /// they must not appear.
    func reorderDraggable(_ payload: ReorderPayload, subject: String,
                          enabled: Bool = true) -> some View {
        // `if enabled` rather than a conditional modifier: a `.draggable` that is
        // present but refuses would still show a drag cursor over a row that cannot
        // move, which is a promise the list can't keep.
        Group {
            if enabled {
                self.draggable(payload) { ReorderDragPreview(subject: subject) }
            } else {
                self
            }
        }
    }

    /// Make this row a drop TARGET meaning "the dragged row lands where I am now".
    ///
    /// `indicator` is the shared "draw the insertion line above row n" state, so the
    /// list can show where the row will land — which in a first-match-wins list is
    /// the same question as which rule will win. Pass `count` as the index for a
    /// strip below the last row ("move it to the end"), which no row target can
    /// express.
    ///
    /// A foreign payload (a rule dragged at the servers table, a resolver rule
    /// dragged at the route list) is REFUSED here. One thing this cannot do is
    /// refuse it earlier: `isTargeted` is handed a Bool and not the payload, so the
    /// insertion line appears for any reorder drag over the list and the drop is
    /// what checks the list id. Two rule lists live in one tab, so that is visible
    /// — and the alternative, a private drag type per list, would make the shared
    /// mechanism three mechanisms again.
    func reorderDropTarget(insertingBefore index: Int, listID: String,
                           indicator: Binding<Int?>,
                           drop: @escaping (ReorderPayload, Int) -> Void) -> some View {
        dropDestination(for: ReorderPayload.self) { payloads, _ in
            indicator.wrappedValue = nil
            guard let payload = payloads.first, payload.listID == listID else { return false }
            drop(payload, index)
            return true
        } isTargeted: { targeted in
            if targeted {
                indicator.wrappedValue = index
            } else if indicator.wrappedValue == index {
                // Only clear OUR line: leaving one row sends `false` after the next
                // row has already sent `true`, and clearing unconditionally would
                // blink the indicator off for every row the pointer crosses.
                indicator.wrappedValue = nil
            }
        }
    }
}
