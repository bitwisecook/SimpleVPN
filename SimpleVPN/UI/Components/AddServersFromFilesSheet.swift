// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  AddServersFromFilesSheet.swift
//  DROP A SECOND CONFIGURATION ON A VPN YOU ALREADY HAVE — the drop targets, the
//  menu equivalent, and the sheet that shows what would happen before it happens.
//
//  THE GESTURE THIS SERVES. Somebody downloads six `.ovpn` files from their
//  provider. Five of them are the file they already imported with one word changed —
//  Docs/ServiceBundles.md §2 measured exactly this: all 3,576 of IPVanish's configs
//  hash identically once the hostname is substituted. Importing all six makes six
//  VPNs that are the same VPN. Dropping them on the one they already have should
//  offer to add them as more SERVERS instead.
//
//  WHAT THE DROP MAY AND MAY NOT DECIDE, which is the whole safety argument:
//   • The comparison is `ConfigurationKinship`, shared with the provider path rather
//     than reinvented — a second definition of "the same configuration" would be a
//     second answer to a question that must have one.
//   • A difference in WHERE it connects merges. That is the feature.
//   • A difference in WHO YOU ARE is reported and never applied: the stored sign-in
//     is left alone, because something that works must not be replaced by a file.
//   • A difference in WHO YOU TRUST — the `<ca>`, `verify-x509-name`, the cipher, the
//     port — NEVER merges, however many of the other files did. It is offered as its
//     own VPN instead, through the ordinary import pipeline (`handleImport`), so
//     there is no private path that skips what an import already refuses.
//  Nothing in this file can weaken any of that: the sheet renders verdicts it did
//  not compute and cannot overrule.
//
//  ALL-OR-NOTHING PER FILE, AND NOTHING SILENT. Six files produce six lines, each
//  saying what it will do, and a drop that adds nothing says so rather than looking
//  like it worked. There are no per-file tick boxes — the decision the user makes is
//  "apply what this sheet describes", and the sheet describes every file.
//
//  DRAG IS NEVER THE ONLY WAY (Docs/Accessibility.md rule 7, the same rule that gives
//  every reorderable list its Move Up / Move Down). Every drop target here has a
//  named menu item beside it — `ConfigurationDropCopy.menuTitle` — which opens the
//  ordinary file panel and lands in this same sheet. The sheet's list is a STRUCTURE:
//  one element per file, each naming the file and saying in words what happens to it,
//  because a diff is something to navigate rather than a picture (rule 6).
//
//  THE LAYOUT-LOOP INVARIANT. A sheet is the one container in this app whose geometry
//  is fixed, but it is also exactly where the crash comes back, so: fixed frame, no
//  `ProgressView`, no `TextField`, no `Toggle`, and nothing in here animates a
//  transform around a platform-backed view. The "checking" state is text.
//

import SwiftUI
import UniformTypeIdentifiers

// MARK: - What the window is being asked for

/// One VPN's pending "add servers from files" question.
///
/// It carries the profile rather than just its id because the sheet has to name the
/// VPN before anything is read, and because the KIND decides whether there is a
/// comparison to make at all.
///
/// `urls == nil` means "the user picked the menu item and is still choosing files" —
/// the window shows the file panel. Non-nil means the files have arrived (dropped, or
/// chosen) and the sheet can open. One value serves both paths so the two entry
/// points cannot drift into two behaviours.
struct ServerConfigurationRequest: Identifiable, Equatable {

    let profileID: String
    let profileName: String
    let kind: VPNKind
    var urls: [URL]?

    var id: String {
        profileID + "\u{1F}" + (urls?.map(\.path).joined(separator: "\u{1F}") ?? "")
    }

    init(profile: VPNController.Profile, urls: [URL]? = nil) {
        self.profileID = profile.id
        self.profileName = profile.name
        self.kind = profile.kind
        self.urls = urls
    }

    /// Can servers be added to a VPN of this kind from a file?
    ///
    /// Only where there IS a configuration file to compare against. An SSH tunnel or
    /// an F5 BIG-IP APM is configured by arguments and has no `.ovpn` or `.conf`, so
    /// "is this the same VPN somewhere else?" has nothing to be asked of — and a
    /// drop target that accepted one would have to invent an answer.
    static func canTake(_ kind: VPNKind) -> Bool {
        kind == .openVPN || kind == .wireGuard
    }

    /// What the file panel offers. `.data` and `.plainText` are in the list for the
    /// same reason the import panel has them: providers ship `.ovpn`, `.conf` and
    /// occasionally a bare text file, and the CONTENT is the real gate
    /// (`ConfigDetector`), not the extension.
    static let fileTypes: [UTType] = {
        var t: [UTType] = [UI.ovpnType, .data, .plainText]
        if let conf = UTType(filenameExtension: "conf") { t.append(conf) }
        return t
    }()
}

// MARK: - Wiring a surface up

extension View {

    /// Make this row (or this table) mean "these files are more servers for THIS
    /// VPN" when a configuration is dropped on it.
    ///
    /// A no-op on a VPN kind that has no configuration to compare against, so the
    /// window-wide import target keeps the drop and the file becomes its own VPN —
    /// which is the right answer there and the only honest one.
    ///
    /// The highlight is the same one the two existing file-drop targets draw
    /// (`ImportUI.swift`), with different words: a drop that means "add servers to
    /// London" must not look identical to one that means "import a new VPN".
    func serverConfigurationDropTarget(profile: VPNController.Profile,
                                       request: Binding<ServerConfigurationRequest?>) -> some View {
        modifier(ServerConfigurationDropTarget(profile: profile, request: request))
    }

    /// Host the file panel and the sheet for whatever `request` names. Attach ONCE
    /// per window: the rows write into the binding, this presents the answer.
    func serverConfigurationImport(vpn: VPNController,
                                   request: Binding<ServerConfigurationRequest?>) -> some View {
        modifier(ServerConfigurationImport(vpn: vpn, request: request))
    }
}

private struct ServerConfigurationDropTarget: ViewModifier {
    let profile: VPNController.Profile
    @Binding var request: ServerConfigurationRequest?
    @State private var targeted = false

    func body(content: Content) -> some View {
        // `if` rather than a conditional modifier: a drop destination that is present
        // but refuses would still show a drop cursor over a VPN that cannot take one,
        // which is a promise the row can't keep. The kind never changes for a row, so
        // the branch never flips under SwiftUI's identity.
        if ServerConfigurationRequest.canTake(profile.kind) {
            content
                .dropDestination(for: URL.self) { urls, _ in
                    let files = urls.filter(\.isFileURL)
                    guard !files.isEmpty else { return false }
                    request = ServerConfigurationRequest(profile: profile, urls: files)
                    return true
                } isTargeted: { targeted = $0 }
                .overlay {
                    if targeted {
                        // DRAWN AND UNDRAWN WITHOUT AN ANIMATION, unlike the two
                        // window-wide file targets it borrows its look from. Those
                        // wrap a window; this wraps a SIDEBAR ROW, and a sidebar row
                        // holds a `Menu` and a glass control group — platform-backed
                        // views, which the house rule (AGENTS.md, the layout-loop
                        // crash) keeps out of anything animating around them. A
                        // highlight that simply appears costs nothing and removes the
                        // question entirely.
                        RoundedRectangle(cornerRadius: 8)
                            .strokeBorder(.tint, lineWidth: 2)
                            .background(.tint.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                            .allowsHitTesting(false)
                            // Decorative: the drop is a pointer affordance whose
                            // function is reachable as a named menu item, and a
                            // highlight VoiceOver reads would be noise mid-drag.
                            // NO `.help` HERE EITHER — a tooltip on a VPN row saying
                            // "add servers to it" would misdescribe the row, and
                            // macOS shows no tooltip during a drag anyway, so it
                            // would only ever appear at the wrong moment.
                            .accessibilityHidden(true)
                    }
                }
        } else {
            content
        }
    }
}

private struct ServerConfigurationImport: ViewModifier {
    @Bindable var vpn: VPNController
    @Binding var request: ServerConfigurationRequest?

    /// True while the menu path is still choosing files.
    private var choosing: Binding<Bool> {
        Binding(get: { request != nil && request?.urls == nil },
                set: { if !$0, request?.urls == nil { request = nil } })
    }

    /// Non-nil once the files exist, whichever way they arrived.
    private var arrived: Binding<ServerConfigurationRequest?> {
        Binding(get: { request?.urls == nil ? nil : request },
                set: { if $0 == nil { request = nil } })
    }

    func body(content: Content) -> some View {
        content
            .fileImporter(isPresented: choosing,
                          allowedContentTypes: ServerConfigurationRequest.fileTypes,
                          allowsMultipleSelection: true) { result in
                if case .success(let urls) = result, !urls.isEmpty {
                    request?.urls = urls
                } else {
                    request = nil
                }
            }
            .sheet(item: arrived) { pending in
                AddServersFromFilesSheet(vpn: vpn, request: pending)
            }
    }
}

// MARK: - The sheet

struct AddServersFromFilesSheet: View {

    @Bindable var vpn: VPNController
    let request: ServerConfigurationRequest

    @Environment(\.dismiss) private var dismiss

    /// Nil until the files have been read and compared. Reading is the only slow
    /// part and it is measured in milliseconds for the sizes involved.
    @State private var plan: ConfigurationDropMerge.Plan?
    /// Why there is nothing to show — a VPN whose own configuration could not be
    /// read, which is the one failure that is not per-file.
    @State private var blocked: String?
    @State private var applying = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    if let blocked {
                        note(blocked, symbol: "exclamationmark.triangle")
                    } else if let plan {
                        note(ConfigurationDropCopy.whatItWillNotDo, symbol: "lock.shield")
                        fileList(plan)
                    } else {
                        // Text, never a spinner: a platform-backed indicator is the
                        // shape this app crashed on, and "Checking…" is always safe.
                        Text("Checking the files\u{2026}")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 2)
            }
            Divider()
            buttons
        }
        .padding(18)
        .frame(width: 520, height: 520)
        .task { await load() }
    }

    // MARK: Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(ConfigurationDropCopy.title(vpn: request.profileName))
                .font(.headline)
            Text(ConfigurationDropCopy.subtitle(fileCount: request.urls?.count ?? 0))
                .font(.caption).foregroundStyle(.secondary)
            if let plan {
                Text(ConfigurationDropCopy.summary(plan))
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
    }

    // MARK: The files

    /// One element per file — a structure to navigate, not a paragraph. Each row
    /// names the file and says in words what will happen to it, and the glyph is
    /// hidden because its meaning is in the sentence beside it.
    private func fileList(_ plan: ConfigurationDropMerge.Plan) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            ForEach(plan.items) { item in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: ConfigurationDropCopy.symbol(item))
                        .foregroundStyle(item.refusedOnTrust ? AnyShapeStyle(.orange)
                                                             : AnyShapeStyle(.secondary))
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(ConfigurationDropCopy.rowTitle(item))
                            .font(.callout.weight(.medium))
                            .lineLimit(1).truncationMode(.middle)
                        Text(ConfigurationDropCopy.sentence(item))
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 0)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel(ConfigurationDropCopy.rowTitle(item))
                .accessibilityValue(ConfigurationDropCopy.sentence(item))
            }
        }
    }

    private func note(_ text: String, symbol: String) -> some View {
        Label {
            Text(text).fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: symbol)
        }
        .font(.callout).foregroundStyle(.secondary)
        .accessibilityElement(children: .combine)
    }

    // MARK: Buttons

    private var buttons: some View {
        HStack {
            Spacer()
            // THE SAFE ONE, and it owns Escape. Nothing here claims the default
            // action: this sheet changes a VPN, and Return should not.
            Button("Cancel") { decline() }
                .keyboardShortcut(.cancelAction)
            if let plan, !plan.separateImports.isEmpty {
                Button(ConfigurationDropCopy.separateImportTitle(count: plan.separateImports.count)) {
                    importSeparately(plan)
                }
                .buttonStyle(.glass)
                .help("Import through the ordinary import, exactly as if you had opened "
                      + "\(plan.separateImports.count == 1 ? "it" : "them") from the File menu.")
            }
            if let plan {
                let count = plan.serversToAdd.count
                Button(ConfigurationDropCopy.addTitle(count: count)) { apply(plan) }
                    .buttonStyle(.glassProminent)
                    .disabled(count == 0 || applying)
                    .help(count == 0 ? ConfigurationDropCopy.nothingToAdd(plan) : "")
                    .accessibilityValue(count == 0 ? ConfigurationDropCopy.nothingToAdd(plan) : "")
            }
        }
    }

    // MARK: Actions

    /// Read every dropped file and work out the plan.
    ///
    /// The read is `nil`-tolerant per file on purpose: one unreadable file in six is
    /// a reported line, not a shorter list, because a drop of six that quietly became
    /// five is how somebody re-downloads a file they already had.
    private func load() async {
        guard let urls = request.urls else { return }
        guard let existing = existingConfiguration() else {
            blocked = ConfigurationDropCopy.wrongKindOfVPN(request.profileName)
            return
        }
        var files: [(filename: String, text: String?)] = []
        for url in urls {
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            files.append((filename: url.lastPathComponent,
                          text: try? String(contentsOf: url, encoding: .utf8)))
        }
        let made = ConfigurationDropMerge.plan(
            vpnName: request.profileName,
            existing: existing,
            existingServers: vpn.endpoints(for: request.profileID),
            files: files)
        plan = made
        // The user made a gesture and is waiting for the answer: immediate, not the
        // debounced event path (Docs/Accessibility.md rule 2).
        AccessibilityAnnouncer.sayNow(ConfigurationDropCopy.summary(made))
    }

    /// The VPN's own configuration, in whichever of the two comparable shapes it is.
    private func existingConfiguration() -> ConfigurationDropMerge.Existing? {
        switch request.kind {
        case .wireGuard:
            return .wireGuard(vpn.wireGuardConfig(for: request.profileID))
        case .openVPN:
            guard let text = vpn.ovpnText(id: request.profileID),
                  !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
            return .openVPN(text)
        default:
            return nil
        }
    }

    /// Add the servers. Ordinary rows in the ordinary list, through the ordinary
    /// save — the same one a rename or a corrected country goes through.
    private func apply(_ plan: ConfigurationDropMerge.Plan) {
        let servers = plan.serversToAdd
        guard !servers.isEmpty else { return }
        applying = true
        let id = request.profileID
        Task {
            var list = vpn.endpointList(for: id)
            var known = Set(list.endpoints.map(\.id))
            for server in servers where !known.contains(server.id) {
                known.insert(server.id)
                list.endpoints.append(server)
            }
            await vpn.setEndpointList(list, for: id)
            AccessibilityAnnouncer.sayNow(
                ConfigurationDropCopy.applied(count: servers.count, vpn: request.profileName))
            dismiss()
        }
    }

    /// Keep the refused files as their own VPNs, through `handleImport` — the shared
    /// pipeline every other entry point uses, so a file that an import would refuse
    /// is refused here too, with the same words.
    private func importSeparately(_ plan: ConfigurationDropMerge.Plan) {
        guard let urls = request.urls else { return }
        let picked = plan.separateImports.compactMap { urls.indices.contains($0) ? urls[$0] : nil }
        guard !picked.isEmpty else { return }
        vpn.handleImport(of: picked)
        dismiss()
    }

    private func decline() {
        AccessibilityAnnouncer.sayNow(ConfigurationDropCopy.declined(request.profileName))
        dismiss()
    }
}
