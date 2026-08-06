// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ServersTable.swift
//  Edit VPN ▸ Servers. The addresses this VPN can be reached at, as a TABLE:
//  where it is (the flag), the user's name for it, the address, the port, and how
//  quick it was. `+` and `−` in a bottom bar. No separate "add" form anywhere.
//
//  WHY A TABLE, AND WHY THIS SHAPE
//
//  The form this replaces inverted its own hierarchy: `TextField("Name
//  (optional)")` was the largest thing in the row while the address — a server's
//  actual identity — was small grey caption text, so the boldest element on
//  screen was a placeholder for something optional. Five unrelated facts
//  (address, protocol, country, region and a two-clause probe error) shared one
//  caption line, and "Add a Server" was a permanent section whose row read as
//  "Address … vpn.example.com Port optional Add".
//
//  The precedents, and what each one settled:
//    • Transmit Favourites / Cyberduck Bookmarks / FileZilla Site Manager — the
//      canonical "servers with an optional nickname" list. All are
//      nickname-primary, which works only because a bookmark is ALWAYS named.
//      Ours usually is not, which is exactly why name-primary failed here.
//    • Mail's accounts list — the one that handles an OPTIONAL name correctly:
//      description when set, address when not, and never an empty placeholder as
//      the largest text. That rule lives in `RankedEndpoint.primaryLabel` and is
//      what names a row to VoiceOver.
//    • System Settings ▸ Network ▸ DNS servers — the add/remove idiom: a bordered
//      editable list, `+` appends a row already focused for typing, `−` removes
//      the selection, no separate add form. Login Items, Users & Groups and
//      Sidebar shortcuts all match. This is what deleted the "Add a Server"
//      section outright.
//    • Mullvad / Proton / NordVPN pickers — the flag as a leading icon.
//    • Mail's profile-provided accounts — a lock on rows the user cannot remove.
//      Servers that came from the VPN's own configuration are exactly that, and
//      that fact used to live in a footnote instead of on the row.
//
//  THE NESTED-SCROLL CONSTRAINT
//
//  `Form(.grouped)` scrolls and `Table` scrolls, and nesting two scroll views
//  misbehaves on macOS (the inner one eats the wheel, the outer one grows without
//  bound). So this pane is NOT a Form: it is a plain VStack — table, bottom bar,
//  footer — and the table is the only scrolling thing in it. The footer is short
//  by design so it can be static text rather than a second scroll view. This is
//  the app's first `Table`, so it sets that pattern.
//
//  Saves as it goes, like the form before it: a name commits on blur or submit
//  (never per keystroke — otherwise "Lon" is persisted on the way to "London"),
//  and a new row commits once it has an address. Nothing here needs a Save button
//  and there is no draft to lose by closing the window.
//
//  ACCESSIBILITY
//
//  A `Table`'s rows are AppKit rows rather than composable SwiftUI rows, so the
//  house "rows read as sentences" treatment (an `.accessibilityElement` on the
//  row) has nothing to attach to. Each CELL carries its own label and value
//  instead, and VoiceOver supplies the row/column context — which is what a table
//  is for. Two consequences are deliberate:
//    • The lock glyph and the flag are `accessibilityHidden`; their words ride the
//      value of the cell that contains them, the same rule the status dots follow.
//    • Every tooltip here is a second copy of a string that already reaches
//      VoiceOver (`ServersTableCopy`), so nothing is hover-only — including the
//      addresses a host currently points to, which are read from the locator's
//      cache and never resolved on hover.
//  The hint in an empty cell is a `prompt:` at placeholder contrast, never red:
//  a hint says what belongs here, red says this is needed and missing, and an
//  empty optional cell must not look like an empty required one.
//

import SwiftUI

struct ServersTable: View {
    @Bindable var vpn: VPNController
    let profileID: String

    @Environment(EndpointLocator.self) private var locator: EndpointLocator?
    @Environment(EndpointProbeStore.self) private var probes: EndpointProbeStore?
    @Environment(PublicIPMonitor.self) private var publicIP: PublicIPMonitor?
    /// Only for "which address is this tunnel actually on" — optional so the pane
    /// works identically in a window that doesn't carry the monitor.
    @Environment(ReachabilityMonitor.self) private var reach: ReachabilityMonitor?

    @State private var selection: ServerRow.ID?
    @State private var draft: Draft?
    @FocusState private var focus: Field?
    @AppStorage(endpointProbeDefaultsKey) private var probingOn = true

    /// One line in the table: a saved server, or the not-yet-saved row `+` added.
    ///
    /// The draft has to be a separate case rather than an empty `VPNEndpoint`,
    /// because a server with no address is not something the store can hold —
    /// `VPNEndpointList` drops hostless entries on decode precisely so a blank
    /// unremovable row can never be persisted.
    struct ServerRow: Identifiable, Equatable {
        static let draftID = "\u{1F}new"
        var item: RankedEndpoint?
        var id: String { item?.id ?? Self.draftID }
        var isDraft: Bool { item == nil }
    }

    /// The `+` row's contents until it has an address worth saving.
    private struct Draft: Equatable {
        var host = ""
        var port = ""
    }

    private enum Field: Hashable { case draftHost, draftPort }

    // MARK: The list

    private var endpoints: [VPNEndpoint] { vpn.endpoints(for: profileID) }

    private var home: GeoPoint? { EndpointRegions.home(publicIP: publicIP) }

    private var items: [RankedEndpoint] {
        EndpointRanking.ordered(EndpointRegions.ranked(endpoints, locator: locator, probes: probes),
                                home: home)
    }

    /// Saved servers in ranked order, then the draft — a new row always appears at
    /// the bottom where the `+` that made it is, never sorted into the middle.
    private var rows: [ServerRow] {
        items.map { ServerRow(item: $0) } + (draft == nil ? [] : [ServerRow(item: nil)])
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            table
            Divider()
            bottomBar
            Divider()
            footer
        }
        // User-initiated: they opened this pane to look at the servers. Re-driven
        // on a network change, because the numbers on screen were measured
        // somewhere the user no longer is — and on disconnect, which is the moment
        // this VPN's servers become measurable again. The per-row button is the
        // only OTHER thing that starts a check.
        .task(id: "\(NetworkMemory.shared.current?.key ?? "")\u{1F}\(connected)") {
            probes?.refresh(endpoints, kind: kind, profile: profileID)
        }
        // Blur commits, submit commits, a keystroke never does — so `vpn.f5.c` is
        // not persisted on the way to `vpn.f5.com`. Leaving the draft's fields
        // with nothing typed is a no-op, not an empty server.
        .onChange(of: focus) { _, now in
            if now != .draftHost, now != .draftPort { commitDraft() }
        }
    }

    private var table: some View {
        Table(of: ServerRow.self, selection: $selection) {
            TableColumn(ServersTableCopy.whereHeading) { row in whereCell(row) }
                .width(min: 44, ideal: 46, max: 64)
            TableColumn(ServersTableCopy.nameHeading) { row in nameCell(row) }
                .width(min: 80, ideal: 150)
            TableColumn(ServersTableCopy.addressHeading) { row in addressCell(row) }
                .width(min: 130, ideal: 230)
            TableColumn(ServersTableCopy.portHeading) { row in portCell(row) }
                .width(min: 54, ideal: 62, max: 90)
            TableColumn(ServersTableCopy.speedHeading) { row in speedCell(row) }
                .width(min: 96, ideal: 128, max: 170)
        } rows: {
            ForEach(rows) { TableRow($0) }
        }
        .tableStyle(.inset)
        // The Mac convention for a bordered editable list: Delete removes the
        // selection. The button stays visible too — macOS renders no affordance
        // for a keyboard-only delete (Docs/Accessibility.md rule 7).
        .onDeleteCommand(perform: removeSelected)
        .frame(minHeight: 150)
        .overlay { if rows.isEmpty { emptyState } }
    }

    // MARK: Cells

    @ViewBuilder
    private func whereCell(_ row: ServerRow) -> some View {
        if let item = row.item {
            EndpointFlagButton(item: item) { save($0) }
        } else {
            // Nothing to place until it has an address, and a flag we haven't
            // earned would be a claim rather than a guess.
            Image(systemName: "globe")
                .foregroundStyle(.tertiary)
                .help("SimpleVPN works out where a server is once it has an address.")
                .accessibilityLabel(ServersTableCopy.whereHeading)
                .accessibilityValue("Not known yet")
        }
    }

    @ViewBuilder
    private func nameCell(_ row: ServerRow) -> some View {
        if let item = row.item {
            ServerNameField(item: item) { text in rename(item, to: text) }
        } else {
            // A name is optional garnish; it can be typed once the row is a real
            // server. The hint still says which column this is.
            Text(ServersTableCopy.nameHint)
                .foregroundStyle(.tertiary)
                .accessibilityLabel(ServersTableCopy.nameHeading)
                .accessibilityValue(ServersTableCopy.noNameSet)
        }
    }

    @ViewBuilder
    private func addressCell(_ row: ServerRow) -> some View {
        if let item = row.item {
            let summary = ServersTableCopy.addressSummary(item, inUse: inUseAddress(item))
            HStack(spacing: 4) {
                Text(item.endpoint.host)
                    .lineLimit(1)
                    .truncationMode(.middle)
                if let live = inUseAddress(item), live != item.endpoint.host {
                    // The address actually carrying the session, visibly and not
                    // only in a tooltip. Suppressed when it IS the host, because
                    // "vpn.example.com → vpn.example.com" says nothing.
                    Text("\u{2192} \(live)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer(minLength: 0)
                if item.endpoint.userAdded != true {
                    Image(systemName: "lock.fill")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .help(ServersTableCopy.lockedHelp)
                        .accessibilityHidden(true)      // its words ride the cell's value
                }
            }
            .help(summary)
            .accessibilityElement(children: .combine)
            .accessibilityLabel(ServersTableCopy.addressHeading)
            .accessibilityValue(item.endpoint.userAdded == true
                                ? summary
                                : summary + " " + ServersTableCopy.lockedHelp)
        } else if let binding = draftHostBinding {
            // `prompt:`, never the title — a title is rendered as content by
            // LabeledContent and announced by VoiceOver as the field's NAME.
            TextField("", text: binding, prompt: Text(ServersTableCopy.addressHint))
                .textFieldStyle(.plain)
                .autocorrectionDisabled()
                .focused($focus, equals: .draftHost)
                .onSubmit { commitDraft() }
                .accessibilityLabel(ServersTableCopy.addressHeading)
                .accessibilityValue(ServersTableCopy.fieldValue(binding.wrappedValue,
                                                               whenEmpty: ServersTableCopy.noAddressYet))
        }
    }

    @ViewBuilder
    private func portCell(_ row: ServerRow) -> some View {
        if let item = row.item {
            let value = ServersTableCopy.portValue(item.endpoint.port, defaultPort: defaultPort)
            Group {
                if let port = item.endpoint.port {
                    Text(String(port)).monospacedDigit()
                } else {
                    Text(ServersTableCopy.portUnsetText).foregroundStyle(.tertiary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .trailing)
            .help(value)
            .accessibilityLabel(ServersTableCopy.portHeading)
            .accessibilityValue(value)
        } else if let binding = draftPortBinding {
            TextField("", text: binding, prompt: Text(ServersTableCopy.portHint))
                .textFieldStyle(.plain)
                .multilineTextAlignment(.trailing)
                .focused($focus, equals: .draftPort)
                .onSubmit { commitDraft() }
                .accessibilityLabel(ServersTableCopy.portHeading)
                .accessibilityValue(ServersTableCopy.fieldValue(binding.wrappedValue,
                                                               whenEmpty: ServersTableCopy.noPortYet))
        }
    }

    @ViewBuilder
    private func speedCell(_ row: ServerRow) -> some View {
        if let item = row.item {
            let state = ServersTableCopy.speed(item,
                                               probing: probes?.probing.contains(item.id) == true,
                                               inUse: inUseAddress(item) != nil)
            let spoken = ServersTableCopy.speedValue(state, detail: item.measurement?.detail)
            HStack(spacing: 4) {
                // Text, never a ProgressView: a spinner is platform-backed and the
                // house rule keeps those out of anything that might animate a
                // transform. "Checking…" is always safe.
                Text(state.text)
                    // Monospaced digits only where there ARE digits, so a column
                    // of timings lines up without setting words in figure widths.
                    .font(state.isMeasurement ? .body.monospacedDigit() : .body)
                    .foregroundStyle(state == .unchecked ? AnyShapeStyle(.tertiary)
                                                         : AnyShapeStyle(.secondary))
                    .lineLimit(1)
                    .help(spoken)
                    .accessibilityLabel(ServersTableCopy.speedHeading)
                    .accessibilityValue(spoken)
                Spacer(minLength: 0)
                probeButton(item)
            }
        } else {
            Text(ServersTableCopy.Speed.unsaved.text)
                .foregroundStyle(.tertiary)
                .help(ServersTableCopy.checkUnsavedHelp)
                .accessibilityLabel(ServersTableCopy.speedHeading)
                .accessibilityValue(ServersTableCopy.speedValue(.unsaved, detail: nil))
        }
    }

    /// Q1b: an explicit per-row check, reusing `EndpointProbeStore` — the same
    /// store, ladder and cache every other surface reads. There is no second
    /// probing path, and when the opt-in is off the button EXPLAINS rather than
    /// silently doing nothing.
    private func probeButton(_ item: RankedEndpoint) -> some View {
        let blocked = ServersTableCopy.probeBlockedReason(probingEnabled: probingOn,
                                                          connected: connected)
        return Button {
            probes?.refresh([item.endpoint], kind: kind, profile: profileID, force: true)
        } label: {
            Image(systemName: "speedometer")
        }
        .buttonStyle(.borderless)
        .disabled(blocked != nil)
        .help(blocked ?? ServersTableCopy.checkButtonHelp)
        .accessibilityLabel(ServersTableCopy.checkButtonLabel)
        .accessibilityValue(blocked ?? ServersTableCopy.checkButtonHelp)
    }

    // MARK: Bottom bar and footer

    private var bottomBar: some View {
        HStack(spacing: 8) {
            Button { addRow() } label: { Image(systemName: "plus") }
                .help(ServersTableCopy.addButtonHelp)
                .accessibilityLabel(ServersTableCopy.addButtonLabel)
            Button { removeSelected() } label: { Image(systemName: "minus") }
                .disabled(removeBlockedReason != nil)
                .help(removeBlockedReason ?? removeHelp)
                .accessibilityLabel(ServersTableCopy.removeButtonLabel)
                .accessibilityValue(removeBlockedReason ?? removeHelp)
            Spacer()
        }
        // Standard controls adopt the material; no custom glass surface is needed
        // here, and `.glass` is what the rest of the app already uses.
        .buttonStyle(.glass)
        .controlSize(.small)
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 6) {
            if connected {
                Text("You\u{2019}re connected through this VPN, so its servers aren\u{2019}t being"
                     + " speed-checked right now \u{2014} a check would go through the tunnel"
                     + " it\u{2019}s asking about. Disconnect to check them again.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                // A table has no region headings to imply an order, so the order
                // says what it means in words — the same sentence every other
                // server list uses.
                Text(EndpointRegions.orderExplanation(items: items, home: home))
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            // Only where there is a lock to explain — a footnote about rows that
            // aren't on screen is how this pane got its reputation.
            if items.contains(where: { $0.endpoint.userAdded != true }) {
                Text(ServersTableCopy.lockFootnote)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Toggle(ServersTableCopy.probeToggleTitle, isOn: $probingOn)
                .onChange(of: probingOn) {
                    if probingOn {
                        probes?.refresh(endpoints, kind: kind, profile: profileID, force: true)
                    } else { probes?.clear() }
                }
            Text(ServersTableCopy.probeToggleDetail)
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
    }

    private var emptyState: some View {
        VStack(spacing: 4) {
            Text(ServersTableCopy.emptyTitle).font(.headline)
            Text(ServersTableCopy.emptyDetail)
                .font(.callout).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(24)
        .accessibilityElement(children: .combine)
    }

    // MARK: Facts about this profile

    private var kind: VPNKind {
        vpn.profiles.first { $0.id == profileID }?.kind ?? .openVPN
    }

    private var defaultPort: Int { VPNProbeTarget.defaultPort(for: kind) }

    /// Up or coming up — see VPNController.isEngaged.
    private var connected: Bool { vpn.isEngaged(id: profileID) }

    /// The address the live tunnel is on, if this row is the server carrying it.
    /// Read from the transport's own sample; nothing is resolved to answer it.
    private func inUseAddress(_ item: RankedEndpoint) -> String? {
        guard connected, let stats = reach?.stats(for: profileID) else { return nil }
        guard ServersTableCopy.isInUse(item, serverIP: stats.serverIP,
                                       serverEndpoint: stats.serverEndpoint) else { return nil }
        let ip = (stats.serverIP ?? "").trimmingCharacters(in: .whitespaces)
        return ip.isEmpty ? item.endpoint.host : ip
    }

    private var selectedItem: RankedEndpoint? {
        guard let selection else { return nil }
        return items.first { $0.id == selection }
    }

    private var removeBlockedReason: String? {
        if selection == ServerRow.draftID, draft != nil { return nil }
        return ServersTableCopy.removeBlockedReason(hasSelection: selectedItem != nil,
                                                    userAdded: selectedItem?.endpoint.userAdded == true)
    }

    private var removeHelp: String {
        selection == ServerRow.draftID
            ? ServersTableCopy.discardDraftHelp
            : ServersTableCopy.removeButtonHelp
    }

    // MARK: Editing

    private var draftHostBinding: Binding<String>? {
        guard draft != nil else { return nil }
        return Binding(get: { draft?.host ?? "" }, set: { draft?.host = $0 })
    }

    private var draftPortBinding: Binding<String>? {
        guard draft != nil else { return nil }
        return Binding(get: { draft?.port ?? "" }, set: { draft?.port = $0 })
    }

    /// `+`: append a row that already says what to type, and put the cursor in it.
    private func addRow() {
        if draft == nil { draft = Draft() }
        selection = ServerRow.draftID
        focus = .draftHost
    }

    /// `−`: discard the draft, or remove a server the user added. A server the
    /// configuration provides is never removed here — the button is disabled and
    /// says why, and the row carries a lock.
    private func removeSelected() {
        if selection == ServerRow.draftID {
            draft = nil
            selection = nil
            return
        }
        guard let item = selectedItem, item.endpoint.userAdded == true else { return }
        selection = nil
        Task { await vpn.removeEndpoint(id: item.endpoint.id, for: profileID) }
    }

    /// Validate before committing: a row with no address is held, not stored.
    private func commitDraft() {
        guard let draft else { return }
        let host = draft.host.trimmingCharacters(in: .whitespaces)
        guard !host.isEmpty else { return }
        var e = VPNEndpoint(host: EndpointDiscovery.normalizedHost(host))
        e.port = Int(draft.port.trimmingCharacters(in: .whitespaces))
            ?? EndpointDiscovery.portHint(from: host)
        e.userAdded = true
        self.draft = nil
        focus = nil
        selection = e.id
        save(e)
    }

    private func rename(_ item: RankedEndpoint, to text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        let current = item.endpoint.label?.trimmingCharacters(in: .whitespaces) ?? ""
        guard trimmed != current else { return }
        var e = item.endpoint
        e.label = trimmed.isEmpty ? nil : trimmed
        save(e)
    }

    private func save(_ endpoint: VPNEndpoint) {
        Task { await vpn.updateEndpoint(endpoint, for: profileID) }
    }
}

/// The name cell. Its own view so the typed text can live in local state and be
/// committed on blur or submit — never per keystroke, which would persist "Lon"
/// on the way to "London" and write the profile back four times over.
private struct ServerNameField: View {
    let item: RankedEndpoint
    let commit: (String) -> Void

    @State private var text: String
    @FocusState private var focused: Bool

    init(item: RankedEndpoint, commit: @escaping (String) -> Void) {
        self.item = item
        self.commit = commit
        _text = State(initialValue: item.endpoint.label ?? "")
    }

    var body: some View {
        // `prompt:` is the placeholder. The title stays empty on purpose: a title
        // is rendered as visible content by LabeledContent and announced by
        // VoiceOver as the field's NAME, so an example passed there reads as
        // though the field were already filled in.
        TextField("", text: $text, prompt: Text(ServersTableCopy.nameHint))
            .textFieldStyle(.plain)
            .focused($focused)
            .onSubmit { commit(text) }
            .onChange(of: focused) { _, isFocused in if !isFocused { commit(text) } }
            // The table reorders as probe results land. If this cell is handed a
            // different server, re-read from the model rather than carry the
            // previous row's half-typed name into it.
            .onChange(of: item.id) { text = item.endpoint.label ?? "" }
            .accessibilityLabel("Name for \(item.address)")
            .accessibilityValue(ServersTableCopy.fieldValue(text,
                                                           whenEmpty: ServersTableCopy.noNameSet))
    }
}
