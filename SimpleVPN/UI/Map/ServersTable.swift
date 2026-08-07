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
//  ORDER: WHOSE IS IT?
//
//  The table used to RANK its rows and nothing else — quickest measured first, else
//  nearest. Manual order and automatic ranking are in direct conflict, so one has to
//  win, and the answer is that the user's does. The evidence for choosing that way
//  round: nothing in this app connects in ranked order. Picking a server writes the
//  server/port/protocol overrides explicitly (`EndpointSection.select`), and
//  OpenVPN's own failover walks the configuration's `remote` lines, not this list. So
//  ranking was never deciding where a connection went — it was deciding what to
//  OFFER first, which is exactly the thing somebody rearranging rows is expressing an
//  opinion about. `EndpointRanking.ordered` therefore stops sorting the moment any
//  row carries a position, and a later probe fills in the Speed column without moving
//  anything.
//
//  Three consequences, all deliberate:
//    • THE FIRST DRAG TURNS THE RANKING OFF, visibly. This table declares no sort key
//      on any column, so there is no column sort to refuse or to clear — but the
//      ranking IS a sort, and a drag that left it in place would be undone by the
//      next probe. The footer sentence changes and "Use automatic order" appears, so
//      the switch is stated and reversible rather than silent.
//    • A CONFIGURATION-PROVIDED SERVER CAN BE MOVED. Its lock is about EXISTENCE —
//      only the configuration adds or removes it — not about description or
//      position; the user can already rename it and correct its country. A position
//      changes the order SimpleVPN offers it in and never rewrites the .ovpn, and the
//      lock glyph travels with the row, so moving one cannot misrepresent where it
//      came from. `ServersTableCopy.lockedHelp` says all of that in words.
//    • THE PICKERS FOLLOW. `EndpointRanking.grouped` groups a manual order into RUNS
//      rather than gathering each region, because gathering is part of the automatic
//      ordering and would rearrange a hand-made list behind the user's back. Every
//      region heading still names the region it is over; a region may simply appear
//      twice. Flattening the groups reproduces this table's order exactly, so the
//      connection page's dropdown and the sidebar's picker agree with it.
//
//  The affordance itself is shared (`UI/Components/Reorder.swift`) — same words, same
//  Move Up / Move Down, same drop indicator as the Custom Routing rule lists.
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
    /// Configuration files dropped ON this table, or chosen from the button beside
    /// `+` and `−`. Dropping a second `.ovpn` from the same provider onto a server
    /// list reads as "these are more servers", which is exactly what it means.
    @State private var serverFilesRequest: ServerConfigurationRequest?

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
        // The file panel and the sheet for whatever the drop (or the button) named.
        // One host for both paths, so the drag and the menu item cannot behave
        // differently.
        .serverConfigurationImport(vpn: vpn, request: $serverFilesRequest)
    }

    /// This VPN, when there is one to name. Nil only while a profile is being
    /// removed out from under an open editor.
    private var profile: VPNController.Profile? {
        vpn.profiles.first { $0.id == profileID }
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
            // The NATIVE table reorder, which on macOS 26 is exactly this pair and
            // nothing else: `TableRow.draggable` to pick a row up and
            // `dropDestination(for:action:)` on the ForEach to be told the index it
            // was let go at. `Table` has no `onMove` and no `moveDisabled` — those
            // live on `DynamicViewContent`/`View`, i.e. `List` — so this is the path
            // rather than a hand-rolled hit-test, and AppKit draws the insertion
            // line, the row snapshot and the drop animation itself.
            //
            // That snapshot is also what keeps the drag away from live controls: an
            // NSTableView drags a static image of the row, so the `TextField` in the
            // name cell is never inside the animating transform (AGENTS.md's
            // layout-loop invariant). Nothing here supplies a custom preview,
            // because `TableRowContent.draggable` has no preview overload — one more
            // reason the platform path is the safe one.
            ForEach(rows) { row in
                if row.isDraft {
                    // A row that isn't a server yet has no place in the order.
                    TableRow(row)
                        .contextMenu { rowMenu(row) }
                } else {
                    TableRow(row)
                        .draggable(ReorderPayload(rowID: row.id, listID: Self.listID))
                        .contextMenu { rowMenu(row) }
                }
            }
            .dropDestination(for: ReorderPayload.self) { index, payloads in
                drop(payloads, at: index)
            }
        }
        .tableStyle(.inset)
        // The Mac convention for a bordered editable list: Delete removes the
        // selection. The button stays visible too — macOS renders no affordance
        // for a keyboard-only delete (Docs/Accessibility.md rule 7).
        .onDeleteCommand(perform: removeSelected)
        .frame(minHeight: 150)
        .overlay { if rows.isEmpty { emptyState } }
        // DROPPING A CONFIGURATION ON A SERVER LIST MEANS "MORE SERVERS". The
        // comparison is `ConfigurationKinship`'s and the decision is the sheet's —
        // nothing merges without being shown first, and a file that differs in who
        // this VPN trusts is never merged at all.
        .modifier(ServersTableConfigurationDrop(profile: profile, request: $serverFilesRequest))
    }

    /// The row context menu. Right-clicking a row is what a Mac user tries first,
    /// and VO-⇧-M reaches it — but it is never the only path: the same two commands
    /// are Tab-reachable buttons in the bottom bar (Docs/Accessibility.md).
    @ViewBuilder
    private func rowMenu(_ row: ServerRow) -> some View {
        ReorderMenuItems(commands: reorderCommands(for: row))
        if manuallyOrdered {
            Divider()
            Button(ServersTableCopy.automaticOrderLabel, action: useAutomaticOrder)
        }
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
                // THREE PROVENANCES, THREE GLYPHS — or none. A lock means only the
                // configuration can add or remove this row; a globe means it came
                // from a provider's published list (removable, and refreshable); a
                // bare row is one the user typed. The provider row used to wear the
                // lock, which was wrong about the only thing a lock is for.
                if let note = provenanceNote(item) {
                    Image(systemName: note.symbol)
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .help(note.help)
                        .accessibilityHidden(true)      // its words ride the cell's value
                }
            }
            .help(summary)
            .accessibilityElement(children: .combine)
            .accessibilityLabel(ServersTableCopy.addressHeading)
            .accessibilityValue(provenanceNote(item).map { summary + " " + $0.help } ?? summary)
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
            Divider().frame(height: 16)
            // THE keyboard path. Beside `+`/`−` where System Settings puts a
            // bordered list's actions, and the reason the drag is allowed to exist:
            // a drag-only order is unusable without a pointer. This is the one pair
            // in the window that may claim ⌘⌥↑/⌘⌥↓.
            ReorderButtons(commands: reorderCommands(for: selectedRow), shortcuts: true)
            Divider().frame(height: 16)
            // THE KEYBOARD PATH FOR DRAG-TO-MERGE, and the reason the drop target
            // above is allowed to exist at all: a drag-only affordance is unusable
            // without a pointer (Docs/Accessibility.md rule 7), which is the same
            // rule that put Move Up / Move Down beside `+` and `−`.
            Button { chooseConfigurationFiles() } label: {
                Image(systemName: "arrow.down.doc")
                    .frame(width: 22, height: 22).contentShape(Rectangle())
            }
            .disabled(profile == nil || !ServerConfigurationRequest.canTake(kind))
            .help(addFromFilesReason ?? ServersTableCopy.addFromFilesHelp)
            .accessibilityLabel(ConfigurationDropCopy.menuTitle)
            .accessibilityValue(addFromFilesReason ?? ServersTableCopy.addFromFilesHelp)
            if manuallyOrdered {
                Button(ServersTableCopy.automaticOrderLabel, action: useAutomaticOrder)
                    .help(ServersTableCopy.automaticOrderHelp)
                    .accessibilityLabel(ServersTableCopy.automaticOrderLabel)
                    .accessibilityValue(ServersTableCopy.automaticOrderHelp)
            }
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
            // Said while the app is still doing the ordering, so a user learns what
            // a drag will REPLACE before they try it. Once they have their own
            // order the sentence above already describes it, and repeating the
            // offer would be advice about something already done.
            if !manuallyOrdered, items.count > 1 {
                Text(ServersTableCopy.dragHint)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            // Says the drop exists. An affordance nobody can find is not an
            // affordance, and this one is invisible until somebody happens to try it
            // — the button beside the reorder pair is named in the same sentence so
            // the pointer-free path is discovered at the same moment.
            if ServerConfigurationRequest.canTake(kind) {
                Text(ServersTableCopy.addFromFilesHint)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            // Only where there is a lock to explain — a footnote about rows that
            // aren't on screen is how this pane got its reputation.
            if items.contains(where: { $0.endpoint.userAdded != true && !$0.endpoint.isRemovable }) {
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

    /// Where this row came from, as a glyph plus the sentence that rides the cell's
    /// spoken value. Nil for a server the user typed in — that needs no explaining,
    /// and a glyph on every row explains nothing.
    private func provenanceNote(_ item: RankedEndpoint) -> (symbol: String, help: String)? {
        if let raw = item.endpoint.fromProvider,
           let id = VPNServiceProviderID(rawValue: raw) {
            let name = VPNServiceProviderCatalog.provider(id).displayName
            var help = ServersTableCopy.fromProviderHelp(name)
            if item.endpoint.peerPublicKey != nil {
                help += " " + ServersTableCopy.carriesPeerKeyHelp
            }
            return ("globe", help)
        }
        if item.endpoint.userAdded != true { return ("lock.fill", ServersTableCopy.lockedHelp) }
        return nil
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

    // MARK: Order

    /// This table's identity in a drag payload, so a rule row from another pane can
    /// never be interpreted here as one of these servers.
    private static let listID = "vpn.servers"

    /// True once the user has placed any of these servers by hand.
    private var manuallyOrdered: Bool { EndpointRanking.isManuallyOrdered(items) }

    private var selectedRow: ServerRow? {
        guard let selection else { return nil }
        return rows.first { $0.id == selection }
    }

    /// The shared Move Up / Move Down commands for one row (nil = the selection,
    /// whatever it is). The list supplies four facts and gets the whole affordance:
    /// what the row is called, where it is, how long the list is, and how to write
    /// a new order down.
    /// Persisting a new order writes it through the endpoint annotation blob — the
    /// same store, save and cache a name or a corrected country goes through.
    ///
    /// The first move is also what switches the automatic ranking OFF, and that is
    /// deliberate rather than incidental: this table has no column sort to clear
    /// (its `TableColumn`s declare no sort key), but the ranking IS a sort, so a
    /// drag that left it in place would be silently undone by the next probe. The
    /// switch is visible — the footer sentence changes and a "Use automatic order"
    /// button appears — so nothing is taken away without a way back.
    private func reorderCommands(for row: ServerRow?) -> ReorderCommands {
        let list = items
        let index = row?.item.flatMap { item in list.firstIndex { $0.id == item.id } }
        let controller = vpn
        let profile = profileID
        return ReorderCommands(
            subject: row?.item.map(ServersTableCopy.moveSubject) ?? ServersTableCopy.moveSubjectNone,
            index: index,
            count: list.count,
            // A locked row moves like any other — the lock is about existence, not
            // position (ServersTableCopy.lockedHelp). The draft is the one row that
            // cannot: it isn't a server yet.
            blocked: row?.isDraft == true ? ServersTableCopy.moveDraftBlocked : nil,
            nothingSelected: ServersTableCopy.moveNothingSelected,
            move: { from, to in
                let reordered = Reorder.moved(list, from: from, to: to)
                guard reordered.map(\.id) != list.map(\.id) else { return }
                let ids = reordered.map(\.id)
                Task { await controller.setEndpointOrder(ids, for: profile) }
            })
    }

    /// A drop from the table's own drag. `index` arrives in `rows` coordinates and
    /// may point past the last server (the draft row, or the end of the list).
    private func drop(_ payloads: [ReorderPayload], at index: Int) {
        guard let payload = payloads.first, payload.listID == Self.listID,
              let from = items.firstIndex(where: { $0.id == payload.rowID }) else { return }
        let commands = reorderCommands(for: rows.first { $0.id == payload.rowID })
        commands.drop(from: from, insertingBefore: min(index, items.count))
    }

    /// Why the "add servers from files" button is dead, or nil when it can run. A
    /// disabled button says why, in `.help` and in its spoken value both.
    private var addFromFilesReason: String? {
        guard let profile else { return ServersTableCopy.addFromFilesNoVPN }
        return ServerConfigurationRequest.canTake(profile.kind)
            ? nil : ConfigurationDropCopy.wrongKindOfVPN(profile.name)
    }

    private func chooseConfigurationFiles() {
        guard let profile, ServerConfigurationRequest.canTake(profile.kind) else { return }
        serverFilesRequest = ServerConfigurationRequest(profile: profile)
    }

    private func useAutomaticOrder() {
        Task {
            await vpn.clearEndpointOrder(for: profileID)
            AccessibilityAnnouncer.sayNow(ServersTableCopy.automaticOrderRestored)
        }
    }

    private var removeBlockedReason: String? {
        if selection == ServerRow.draftID, draft != nil { return nil }
        return ServersTableCopy.removeBlockedReason(hasSelection: selectedItem != nil,
                                                    removable: selectedItem?.endpoint.isRemovable == true)
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
        guard let item = selectedItem, item.endpoint.isRemovable else { return }
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

/// The table's own drop target, in a modifier because the profile can be nil for a
/// render or two while one is being removed — and a drop destination that appeared
/// and disappeared under the pointer would be worse than none.
private struct ServersTableConfigurationDrop: ViewModifier {
    let profile: VPNController.Profile?
    @Binding var request: ServerConfigurationRequest?

    func body(content: Content) -> some View {
        if let profile {
            content.serverConfigurationDropTarget(profile: profile, request: $request)
        } else {
            content
        }
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
