// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConnectionView.swift
//  Main window — connection only. Startup flow (per Apple HIG onboarding guidance):
//   1. extension not activated → activation prompt + instructions
//   2. no VPNs configured → import / add prompt
//   3. otherwise → sidebar of VPNs + connection detail (status, connect/disconnect,
//      OTP entry, and the throughput graph once M6 lands).
//  VPN management (create/import/edit/remove/export) lives in its own window.
//
//  This is the SHELL of the window — the split view, sidebar, toolbar and the
//  startup prompts. The columns it presents live in files beside it:
//  ConnectionDetailView (+ConnectControl), ConnectionInspectorView,
//  ConnectionBanners and FirstConnectSetupCard — split out for size, not
//  redesigned.
//

import SwiftUI
import UniformTypeIdentifiers
// The native personal VPNs are listed here too now, and connecting one takes the
// same NEProxySettings its own editor builds.
import NetworkExtension
import os

/// Settings key: open the live-details (inspector) pane when the window opens.
let inspectorDefaultsKey = "ui.inspectorOpenByDefault"

struct ConnectionView: View {
    @Bindable var vpn: VPNController
    @Bindable var ext: ExtensionController
    @Bindable var labels: LabelStore
    @Environment(\.openWindow) private var openWindow
    @Environment(ReachabilityMonitor.self) private var reach: ReachabilityMonitor?
    @Environment(LinkStateMonitor.self) private var link: LinkStateMonitor?
    @Environment(ExtensionDoctor.self) private var extDoctor: ExtensionDoctor?
    @Environment(SubprocessTunnelManager.self) private var tunnelManager: SubprocessTunnelManager?
    @Environment(SubprocessTunnelStore.self) private var tunnels: SubprocessTunnelStore?
    @Environment(NativeVPNManager.self) private var nativeVPN: NativeVPNManager?
    @Environment(SettingsRouter.self) private var settingsRouter: SettingsRouter?
    /// Whether this window is the active one. Used as the "the user has been somewhere
    /// else and come back" signal — see `refreshOtherNeeds`.
    @Environment(\.controlActiveState) private var controlActiveState
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var showImporter = false
    /// The connect list's selection when it lands on a row that is NOT an NE profile
    /// — a subprocess tunnel or a native personal VPN. Kept separate from
    /// `vpn.selectedID` on purpose: that id is read by the menu bar, the map and the
    /// control plane, all of which mean "an NE profile", and putting a tunnel's id in
    /// it would make every one of them look up something that isn't there.
    @State private var otherSelection: String?
    /// What each non-profile connection still needs, keyed by its selection tag.
    ///
    /// COMPUTED INTO STATE, never in `body`: the answer needs a keychain query for
    /// the secret a tunnel's chosen method uses, and a view body runs on every
    /// redraw. `refreshOtherNeeds()` is driven from the configs changing and from the
    /// engines' live state, which is every moment the answer could have changed.
    @State private var otherNeeds: [String: ConnectNeed] = [:]
    /// The right-hand live-details pane. Closed by default (simple window);
    /// the Settings toggle changes the launch state, the toolbar button the moment.
    @AppStorage(inspectorDefaultsKey) private var inspectorOpenByDefault = false
    @State private var showInspector = false
    /// Sidebar visibility — starts closed when there's only one VPN (a list of
    /// one is noise); the standard sidebar toolbar button reopens it.
    @State private var columnVisibility: NavigationSplitViewVisibility = .automatic
    /// Crashes found at launch, offered once (see CrashDiagnostics).
    @State private var pendingCrashes: [CrashReport] = []
    @State private var showCrashReport = false
    /// The failure currently explained by the error sheet (mirror of
    /// VPNController.presentedFailure — see the .onChange below).
    @State private var shownFailure: UserFacingError?

    /// Sidebar dot — from the ONE shared derivation, so it can never disagree with
    /// the header pill, the menu bar or the route graph (they all used to compute
    /// their own, with two different captive-portal predicates).
    private func rowDot(_ p: VPNController.Profile) -> DotState {
        // For Tailscale mid sign-in the display status (connecting) must win over the
        // link monitor, which only knows the NE tunnel came up — not that the node
        // isn't on the network yet.
        let shown = vpn.displayStatus(for: p.id)
        if shown != p.status { return .from(status: shown) }
        return link?.dot(for: p.id) ?? .from(status: shown)
    }

    /// Whether the single native personal VPN slot is in use right now.
    private var nativeBackendActive: Bool {
        nativeVPN?.status == .connected || nativeVPN?.status == .connecting
    }

    // MARK: - The connections that are not NE profiles

    /// One row for a connection that is not an NE profile, flattened out of the two
    /// stores behind it so the sections have one shape to draw and one place to read
    /// readiness from.
    ///
    /// These rows are no longer a section of their own — see `connectSection`. They are
    /// interleaved with the NE profiles under whichever heading their scope names.
    private struct OtherConnection: Identifiable {
        /// The sidebar selection tag (prefixed).
        let id: String
        /// The config's own id — what a settings route names.
        let configID: String
        let name: String
        let kind: VPNKind
        /// Which heading this row appears under: what connecting it does to the Mac.
        let scope: ConnectionScope
        /// The port it opens, for a local-port row — what you have to aim something at.
        /// nil for a whole-Mac VPN.
        let portSummary: String?
        let dot: DotState
        let isActive: Bool
        /// The engine's last word: a failure message or a caution. nil when quiet.
        let note: String?
        let connect: () -> Void
        let stop: () -> Void
    }

    /// EVERY subprocess tunnel and EVERY native VPN the user has created, running or
    /// not.
    ///
    /// THE BUG THIS LINE IS. It used to read
    /// `tunnels.filter { tunnelManager.isActive($0.id) }`, so a subprocess-backed
    /// profile appeared in the connect window ONLY while already running — it could
    /// never show up before you connected it, and could not be connected from here
    /// because it was not here. A closed loop: the user added an F5 BIG-IP APM, saw
    /// it in Manage VPNs, and could not find it in the main window. The native side
    /// had the same shape one line down (only the ACTIVE config was listed).
    ///
    /// `vpn.profiles` were always listed whether connected or not, correctly. The
    /// asymmetry was historical: this section was built as a LIVE STATUS strip and
    /// then whole VPN kinds were filed into it. The rule now matches the rest of the
    /// window — never hide a profile the user created.
    private var otherConnections: [OtherConnection] {
        var rows: [OtherConnection] = []
        for t in tunnels?.tunnels ?? [] {
            let live = tunnelManager?.live[t.id]
            rows.append(OtherConnection(
                id: ConnectListing.tunnelTag + t.id, configID: t.id, name: t.name, kind: t.kind,
                scope: ConnectionScope.of(t), portSummary: ConnectListing.portSummary(t),
                dot: .from(subprocess: tunnelManager?.status(t.id) ?? .disconnected),
                isActive: tunnelManager?.isActive(t.id) == true,
                note: live?.status.failureText ?? live?.caution,
                connect: { [weak tunnelManager] in
                    // Everything this needs is stored: the readiness gate above has
                    // already established that the password / PIN the configured
                    // method uses is on file, so there is nothing to type here.
                    tunnelManager?.connect(t, password: KeychainCredentialStore
                        .loadCredentials(profile: "tunnel.\(t.id)")?.password)
                },
                stop: { [weak tunnelManager] in tunnelManager?.disconnect(t.id) }))
        }
        for c in nativeVPN?.configs ?? [] {
            let isActive = nativeBackendActive && nativeVPN?.activeConfigID == c.id
            rows.append(OtherConnection(
                id: ConnectListing.nativeTag + c.id, configID: c.id, name: c.name, kind: c.kind,
                scope: ConnectionScope.of(native: c), portSummary: nil,
                dot: isActive ? .from(status: nativeVPN?.status ?? .disconnected) : .off,
                isActive: isActive,
                note: isActive ? nativeVPN?.lastError : nil,
                connect: { [weak nativeVPN] in
                    guard let nativeVPN else { return }
                    let secrets = NativeVPNReadiness.storedSecrets(for: c)
                    // The same three inputs the editor's own Connect gathers — the
                    // stored secrets and this profile's Custom Routing proxy — read
                    // here rather than passed in, so connecting from the list and
                    // connecting from the editor start the tunnel identically.
                    let proxy = nativeProxySettings(for: c.id)
                    Task { await nativeVPN.connect(c, secret: secrets.base,
                                                   sharedSecret: secrets.groupPSK,
                                                   proxy: proxy) }
                },
                stop: { [weak nativeVPN] in nativeVPN?.disconnect() }))
        }
        return rows
    }

    /// ONE SECTION OF THE CONNECT LIST — every connection, of every kind, whose scope
    /// puts it under this heading.
    ///
    /// THE LINE THIS DRAWS, AND THE ONE IT REPLACES. The list used to be "VPNs" (the
    /// packet-tunnel extension) and "Other Connections" (everything else), which is our
    /// implementation showing through: an F5 BIG-IP APM was filed away from the VPNs it
    /// behaves identically to, and the second heading was named after not being the
    /// first. Both headings now answer the question a person can actually check — does
    /// connecting this change where my traffic goes, or does it hand me a port I have to
    /// aim something at (`ConnectionScope`, defined in ONTOLOGY.md).
    ///
    /// NE profiles and the other two stores are INTERLEAVED here rather than kept apart.
    /// That is the point: which of our three transports carries a connection is no longer
    /// visible in the sidebar, because it was never information the user could use.
    @ViewBuilder private func connectSection(_ scope: ConnectionScope) -> some View {
        // ONE ForEach PER SECTION, over ConnectOrder's tags — not one per store.
        //
        // This window used to draw two ForEaches (profiles, then everything else), which
        // had two consequences. The rows were in store order rather than the user's, so
        // this sidebar and Manage VPNs DISAGREED about arrangement — the thing the user
        // ruled out with "it should be in sync with the vpn configs window". And `onMove`
        // only reorders within a single ForEach, so drag-to-reorder was not expressible
        // here at all, which is what they reported.
        //
        // Both windows now read `ConnectOrder` and sort through `ConnectListing.sections`,
        // and neither keeps order state of its own, so there is nothing left to diverge.
        let order = ConnectOrder.of(vpn: vpn, tunnels: tunnels, native: nativeVPN)
        let tags = order.tags(in: scope)
        if !tags.isEmpty {
            Section {
                ForEach(tags, id: \.self) { tag in sidebarRow(for: tag) }
                    // Routed through `ConnectOrder.move` — the same `ReorderCommands` the
                    // buttons and menu items use, so the index maths, the refusals and the
                    // spoken announcement cannot fork into a second implementation. The
                    // section-local indices are what make a cross-heading drop
                    // UNREPRESENTABLE rather than merely rejected: a row's heading follows
                    // its configuration, so moving one across would silently change what
                    // connecting it does to this Mac.
                    .onMove { from, to in order.move(in: scope, from: from, to: to) }
            } header: {
                // A heading that regroups rows has to SAY what it groups: it is the only
                // place the new question is asked out loud, and VoiceOver reads the
                // heading before the rows under it (Docs/Accessibility.md). The sentence
                // is spoken AND shown on hover — never only on hover.
                Text(scope.sectionTitle)
                    .help(scope.explanation)
                    .accessibilityLabel(scope.spokenHeader)
            }
        }
    }

    /// The row for one arrangement tag, from whichever store owns it.
    ///
    /// A reorder moves rows and must change NO tag — the menu bar, the map and the
    /// settings routes all select by these, so a tag that moved with a row would break
    /// a route from the other window. `ConnectOrder` therefore orders tags and never
    /// mints them.
    @ViewBuilder private func sidebarRow(for tag: String) -> some View {
        if let p = vpn.profiles.first(where: { $0.id == tag }) {
            VPNSidebarRow(vpn: vpn, profile: p, labelDefs: labels.labels(for: p.id), dotState: rowDot(p))
                .tag(p.id)
                .contextMenu { sidebarMenu(p) }
        } else if let row = otherConnections.first(where: { $0.id == tag }) {
            otherConnectionRow(row).tag(row.id)
        }
    }

    private func otherConnectionRow(_ row: OtherConnection) -> some View {
        let notice = row.kind.maturityNotice
        let need = otherNeeds[row.id]
        // THE CAPTION, in priority order. Something missing outranks everything (that is
        // what the user has to act on), and the status word comes from the ONE
        // vocabulary — never a phrase invented here. Otherwise a local-port row says
        // WHICH PORT, which is the fact its section exists to make actionable, and a
        // whole-Mac row says only its kind: "it takes your traffic" is the heading's job.
        let caption = need.map { "\(row.kind.displayName) \u{00B7} \($0.statusWord)" }
            ?? [row.kind.displayName, row.portSummary].compactMap { $0 }.joined(separator: " \u{00B7} ")
        return HStack(spacing: 10) {
            // THE SAME BADGE, METRICS AND CONTROL AS `VPNSidebarRow`. These rows share a
            // section with the NE profiles now, so a shorter row with a bare dot and a
            // borderless glyph would redraw the transport split this change removed — the
            // user would still see which ones are "the other kind", just without a label
            // for it. The badge falls back to the KIND's symbol because these connections
            // never have a logo of their own.
            LogoBadge(id: row.configID, status: .disconnected, dotState: row.dot,
                      fallbackSymbol: row.kind.systemImage)
                .scaleEffect(1.15)
                .frame(width: 26, height: 26)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 5) {
                    Text(row.name).lineLimit(1)
                    // A kind nobody has proven: the chip is still true, and a row
                    // that is only configured is exactly where somebody decides
                    // whether to try it.
                    if let notice { MaturityBadge(notice: notice) }
                }
                // The sidebar is 220pt wide, so the SENTENCE lives in the detail pane's
                // banner and on this row's `.help`; what fits here is the fact that
                // there is something to do, or the port to aim at.
                Text(caption)
                    .font(.caption).lineLimit(1)
                    .foregroundStyle(need == nil ? AnyShapeStyle(.secondary) : AnyShapeStyle(.orange))
            }
            // One sentence per row; the (hidden) dot's state rides in words. The port
            // rides here too — a caption a screen reader never hears would make the
            // one actionable fact about a local port sighted-only.
            .accessibilityElement(children: .combine)
            .accessibilityLabel("\(row.name), \(row.kind.displayName)\(row.portSummary.map { ", \($0)" } ?? ""), \(row.dot.accessibilityDescription)\(notice.map { ", \($0.spokenValue)" } ?? "")")
            .accessibilityValue(need?.sentence ?? "")
            Spacer(minLength: 6)
            if row.isActive {
                // Every other Connect/Disconnect control in the app reports the live
                // state in its value (rule 1). The words come from DotState, which is the
                // status vocabulary — there is no NEVPNStatus behind a subprocess or
                // native tunnel to read instead.
                SidebarActionCircle(symbol: "stop.fill", tint: .red, help: "Disconnect",
                                    label: "Disconnect \(row.name)",
                                    value: row.dot.accessibilityDescription,
                                    action: row.stop)
            } else {
                // DISABLED, NEVER ABSENT — an absent button is indistinguishable
                // from a broken layout, and this row exists precisely so that a
                // profile which cannot connect yet is still visible and still says
                // what it needs. Grey rather than green when it cannot go, matching
                // `VPNSidebarRow`: a green Play that can only fail is a lie.
                SidebarActionCircle(
                    symbol: "play.fill", tint: need == nil ? .green : .gray,
                    help: need?.sentence ?? "Connect \(row.name)",
                    label: "Connect \(row.name)",
                    // THE STATUS WORD FIRST, then the reason. A Connect control in this
                    // window has to report the live state in its value from the ONE
                    // vocabulary (rule 1, asserted by VoiceOverWalkthroughTests); the
                    // sentence after it is what makes the disabled state actionable
                    // rather than merely dimmed.
                    value: need?.spokenValue ?? row.dot.accessibilityDescription,
                    disabled: need != nil, action: row.connect)
            }
        }
        // The same vertical metrics as `VPNSidebarRow`, so one section is one list.
        .padding(.vertical, 6)
        .frame(minHeight: 52)
    }

    /// This native VPN's Custom Routing proxy, as `NEVPNManager` wants it. Mirrors
    /// `NativeVPNView.nativeProxySettings()` — one committed source, read at connect
    /// time from the stored profile rather than from an editor's draft.
    private func nativeProxySettings(for profileID: String) -> NEProxySettings? {
        let auth = loadCustomRoutingProxyAuthFields(profileID: profileID)
        return vpn.customRouting(for: profileID).proxy.nativeApplyRequest(
            username: auth.username.isEmpty ? nil : auth.username,
            password: auth.password.isEmpty ? nil : auth.password)?
            .makeNEProxySettings()
    }

    /// Recompute what every non-profile connection still needs.
    ///
    /// One sweep of the installed command-line tools (rather than one per row), and
    /// at most one keychain query per row — see `SubprocessTunnelReadiness.liveFacts`.
    private func refreshOtherNeeds() {
        let installed = TunnelCLI.installed()
        let capability = !(nativeVPN?.needsEntitlement ?? false)
        var needs: [String: ConnectNeed] = [:]
        for t in tunnels?.tunnels ?? [] {
            if let need = SubprocessTunnelReadiness.need(for: t, installedTools: installed) {
                needs[ConnectListing.tunnelTag + t.id] = need
            }
        }
        for c in nativeVPN?.configs ?? [] {
            if let need = NativeVPNReadiness.need(for: c, hasPersonalVPNCapability: capability) {
                needs[ConnectListing.nativeTag + c.id] = need
            }
        }
        if needs != otherNeeds { otherNeeds = needs }
    }

    /// Take the user to the field that is missing: open Manage VPNs on this profile
    /// and reveal the setting — which expands its section, scrolls it to centre and
    /// highlights it. "Open the config window" is the weak version of this.
    private func revealSetting(_ settingID: String, profileID: String) {
        openWindow(id: "manage")
        settingsRouter?.go(to: settingID, profileID: profileID)
    }

    /// Deliberately jargon-free: this says what macOS wants and what to do, in the words
    /// someone who just wants their VPN would use. "System extension" is our problem, not
    /// theirs.
    private static func postApprovalToast(_ ext: ExtensionController) {
        ToastCenter.shared.post(
            "macOS needs your permission before SimpleVPN can make VPN connections.",
            symbol: "lock.shield", seconds: 12,
            actionTitle: "Allow\u{2026}") {
                Task { await ext.activate() }
            }
    }

    var body: some View {
        content
            .toasts()
            .navigationTitle("SimpleVPN")
            .task {
                await vpn.loadAll()
                // Deliberately NOT ext.activate() here: activating raises a macOS
                // approval dialog, and a first launch should show the app, not a security
                // prompt for something the user hasn't asked for yet. VPNController does
                // it on the first connect (see ensureExtensionReady).
                let doctor = extDoctor
                vpn.ensureExtensionReady = { [weak ext, weak doctor] in
                    guard let ext else { return true }
                    // The connect gate doubles as a doctor trigger: a wedged
                    // engine should be noticed the moment someone reaches for
                    // it. Fire-and-forget — the doctor single-flights and
                    // debounces, and its non-disruptive rungs never block or
                    // interrupt the connect that's about to run.
                    Task { [weak doctor] in await doctor?.checkUp(trigger: .connectGate) }
                    if ext.isActivated { return true }
                    // Ask ONCE. If approval is already outstanding, re-firing would put
                    // the same dialog up on every connect attempt, which trains people to
                    // dismiss it — the ActivationPrompt banner and its Retry button are
                    // the deliberate second chance.
                    if ext.needsApproval { Self.postApprovalToast(ext); return false }
                    await ext.activate()
                    if !ext.isActivated { Self.postApprovalToast(ext) }
                    return ext.isActivated
                }
                ToastCenter.shared.openWindow = { openWindow(id: $0) }
                // Did we die last time? Offer to report it, once, with the details
                // already gathered (see CrashDiagnostics).
                let crashes = CrashDiagnostics.pendingReports()
                if !crashes.isEmpty {
                    pendingCrashes = crashes
                    showCrashReport = true
                }
            }
            .sheet(isPresented: $showCrashReport) {
                CrashReportSheet(
                    reports: pendingCrashes,
                    facts: IssueReport.gather(vpn: vpn, tunnels: tunnels,
                                              nativeVPN: nativeVPN, wireguard: nil))
            }
            .task {
                // Also drive the app-wide reachability monitor from the main window
                // (start() is idempotent) so sidebar stall dots and the map don't
                // depend solely on the menu-bar label's lifecycle.
                reach?.start(connectedIDs: { vpn.profiles.filter { $0.status == .connected }.map(\.id) },
                             fetch: { await vpn.fetchStats(id: $0) })
            }
            // (SSO sign-in requests raise the in-app window from app scope now —
            // see SSOWindowOpener in SimpleVPNApp — so they surface even when
            // this window is closed.)
            .fileImporter(isPresented: $showImporter,
                          allowedContentTypes: [UI.ovpnType, .data, .plainText],
                          onCompletion: importConfig)
            .ovpnDropTarget(vpn: vpn)
            .importOutcomeAlert(vpn: vpn)
            .onChange(of: vpn.importRequested, initial: true) {
                // initial: the ⌘O menu item may set the flag before this window's
                // content exists; without it the flag would stick and go dead.
                if vpn.importRequested { vpn.importRequested = false; showImporter = true }
            }
            // Failures get a real explanation, not a raw string in an alert box:
            // title, one sentence, the numbered steps that fix it, and the
            // underlying text behind a disclosure (see UserFacingErrorSheet).
            // `presentedFailure` withholds it when the incident card is already
            // reporting the same event, so nothing is ever said twice.
            //
            // Mirrored into @State rather than bound straight through: reading
            // the controller inside onChange is what registers the observation
            // dependency, and `initial` catches a failure raised from the menu
            // bar before this window's content existed.
            .onChange(of: vpn.presentedFailure, initial: true) { _, failure in
                shownFailure = failure
            }
            .sheet(item: Binding(get: { shownFailure },
                                 set: { new in
                                     // Only a dismissal of the error STILL being
                                     // reported clears it — a retry that already
                                     // failed again must keep its new one.
                                     if new == nil, let shown = shownFailure, vpn.failure?.id == shown.id {
                                         vpn.clearFailure()
                                     }
                                     shownFailure = new
                                 })) { failure in
                UserFacingErrorSheet(
                    error: failure,
                    // The id is captured now: retrying clears the failure (which
                    // is what dismisses this sheet), so it can't be looked up later.
                    retry: vpn.failureProfileID.map { id in
                        { Task { await vpn.retryConnect(id: id) } }
                    },
                    openWindow: { openWindow(id: $0) })
            }
    }

    /// "You have no VPNs at all" — the ONLY state that earns the empty-state page.
    ///
    /// It used to ask whether a subprocess tunnel or a native VPN was RUNNING, which
    /// is the same mistake as the list filter: somebody whose only VPN was an F5
    /// BIG-IP APM opened the app and was told "No VPNs Configured", with an Import
    /// button, about a VPN they had just configured. Existence is the question.
    /// Asked through `ConnectListing`, not spelled out here: the empty-state page and the
    /// list must agree about what "you have nothing" means, and two hand-written
    /// existence checks are how they came to disagree in the first place.
    private var hasNothingConfigured: Bool {
        ConnectListing.isEmpty(profiles: listedProfiles,
                               tunnels: tunnels?.tunnels ?? [],
                               native: nativeVPN?.configs ?? [])
    }

    /// The NE profiles as the listing sees them — id plus the kind that places them.
    private var listedProfiles: [ConnectListing.Profile] {
        vpn.profiles.map { .init(id: $0.id, kind: $0.kind) }
    }

    @ViewBuilder private var content: some View {
        // The extension's state no longer gates the whole window. It used to open on
        // "System Extension Required", which is a demand made before the user has any
        // reason to care; approval is now asked for at the first connect, and only a
        // PENDING approval (one the user has already been shown) is worth a banner.
        // The three startup states cross-fade into each other (dropping a config
        // morphs the empty page into the real window) rather than hard-cutting.
        Group {
            if ext.needsApproval && !ext.isActivated {
                ActivationPrompt(ext: ext)
                    .transition(reduceMotion ? AnyTransition.opacity : AnyTransition(.blurReplace))
            } else if hasNothingConfigured {
                EmptyVPNsPrompt(importAction: { showImporter = true },
                                manageAction: { openWindow(id: "manage") },
                                dropAction: { vpn.handleImport(of: $0) })
                    .transition(reduceMotion ? AnyTransition.opacity : AnyTransition(.blurReplace))
            } else {
                splitView
                    .transition(reduceMotion ? AnyTransition.opacity : AnyTransition(.blurReplace))
            }
        }
        .animation(reduceMotion ? nil : .smooth(duration: 0.4), value: vpn.profiles.isEmpty)
        .animation(reduceMotion ? nil : .smooth(duration: 0.4), value: ext.isActivated)
    }

    /// The connect list's selection, spanning THREE stores.
    ///
    /// One `List` has one selection, and the rows now come from `vpn.profiles`, the
    /// subprocess store and the native store. A prefixed tag says which — and the
    /// write side is what keeps `vpn.selectedID` honest: it only ever holds an NE
    /// profile id, because the menu bar, the route graph and the control plane all
    /// read it meaning exactly that.
    private var listSelection: Binding<String?> {
        Binding(get: { otherSelection ?? vpn.selectedID },
                set: { new in
                    if let new, ConnectListing.isOtherTag(new) {
                        otherSelection = new
                    } else {
                        otherSelection = nil
                        vpn.selectedID = new
                    }
                })
    }

    /// The selected non-profile connection, if that is what the selection names.
    private var selectedOther: OtherConnection? {
        guard let otherSelection else { return nil }
        return otherConnections.first { $0.id == otherSelection }
    }

    private var splitView: some View {
        // Two columns + a real inspector (not a third split column): the live
        // telemetry pane is optional detail, closed by default to keep the window
        // simple. Its trailing home and content are unchanged — only whether it's
        // open is new.
        NavigationSplitView(columnVisibility: $columnVisibility) {
            List(selection: listSelection) {
                // Two headings, one question each, in `ConnectionScope.allCases` order —
                // whole-Mac first because that is what most people have. A section with
                // no rows draws nothing (see `connectSection`).
                connectSection(.wholeMac)
                connectSection(.localPort)
            }
            .navigationSplitViewColumnWidth(min: 220, ideal: 260)
            // Tab moves column by column — the whole sidebar is one focus
            // section, so Tab from the list lands in the detail pane instead of
            // walking every row.
            .focusSection()
            .toolbar {
                ToolbarItem {
                    Button { openWindow(id: "manage") } label: { Image(systemName: "slider.horizontal.3") }
                        .help("Manage VPNs")
                        .accessibilityLabel("Manage VPNs")
                }
            }
        } detail: {
            Group {
                if let row = selectedOther {
                    OtherConnectionDetailView(
                        name: row.name, kind: row.kind, dot: row.dot, isActive: row.isActive,
                        need: otherNeeds[row.id], engineNote: row.note,
                        connect: row.connect, stop: row.stop,
                        reveal: { revealSetting($0, profileID: row.configID) },
                        openSettings: { openWindow(id: "manage") })
                        .id(row.id)
                } else if let p = vpn.selected {
                    ConnectionDetailView(vpn: vpn, profile: p).id(p.id)
                } else {
                    ContentUnavailableView("Select a VPN", systemImage: "network")
                }
            }
            .inspector(isPresented: $showInspector) {
                Group {
                    if let p = vpn.selected {
                        ConnectionInspectorView(vpn: vpn, profile: p).id(p.id)
                    } else {
                        ContentUnavailableView("Live Details", systemImage: "chart.line.uptrend.xyaxis",
                            description: Text("Connect a VPN to see live traffic, the map and connection details."))
                    }
                }
                .inspectorColumnWidth(min: 320, ideal: 380)
            }
            .toolbar {
                ToolbarItem {
                    Button { showInspector.toggle() } label: { Image(systemName: "sidebar.trailing") }
                        .help(showInspector ? "Hide live details" : "Show live details — traffic, map and connection info")
                        .accessibilityLabel("Live details")
                        .accessibilityValue(showInspector ? "Shown" : "Hidden")
                }
            }
        }
        // No version subtitle: "ext unavailable" read as a problem when it just
        // means disconnected, and versions live in About + every diagnostic capture.
        .task {
            // Startup shape, applied once: the inspector follows its setting, and
            // a lone VPN doesn't need a list of one — the sidebar starts closed
            // (the toolbar button still opens it). Never touched again after
            // launch, so the user's own toggling always wins.
            showInspector = inspectorOpenByDefault
            if vpn.profiles.count <= 1 { columnVisibility = .detailOnly }
        }
        // What each non-profile connection still needs, gathered OUT of `body` (it
        // costs a keychain query per row) and refreshed at every moment the answer
        // could have changed: the configs themselves, and the engines' live state —
        // which is what changes when the user saves a password in the editor and
        // comes back here, or installs the tool a row was waiting for.
        .task { refreshOtherNeeds() }
        .onChange(of: tunnels?.tunnels ?? []) { refreshOtherNeeds() }
        .onChange(of: nativeVPN?.configs ?? []) { refreshOtherNeeds() }
        .onChange(of: tunnelManager?.live.mapValues(\.status) ?? [:]) { refreshOtherNeeds() }
        .onChange(of: nativeVPN?.status ?? .invalid) { refreshOtherNeeds() }
        // AND WHENEVER THIS WINDOW COMES BACK TO THE FRONT. The other triggers watch
        // the CONFIG, and two of the things a need turns on are not in it: a secret in
        // the keychain and a tool on disk. So saving a password in the editor without
        // touching any other field, or `brew install openconnect` in Terminal, would
        // otherwise leave the row insisting on something the user has just supplied —
        // which is the same dead end as hiding it. Coming back to this window is
        // exactly when that has happened.
        .onChange(of: controlActiveState) { _, new in
            if new != .inactive { refreshOtherNeeds() }
        }
        // The window keeps AppKit's stock `.inspector` resize behaviour: opening the
        // pane grows the window, closing it leaves the window as-is. Attempts to force
        // it to shrink back on close were more trouble than they were worth, so this is
        // deliberately left alone.
    }

    private func importConfig(_ result: Result<URL, Error>) {
        guard case let .success(url) = result else { return }
        vpn.handleImport(of: [url])
    }

    /// Right-click actions on a sidebar VPN: the whole lifecycle plus settings.
    @ViewBuilder private func sidebarMenu(_ p: VPNController.Profile) -> some View {
        if UI.isActive(p.status) {
            if vpn.pausedProfiles.contains(p.id) {
                Button("Resume") { Task { await vpn.resume(id: p.id) } }
            } else if p.status == .connected, vpn.uiPrefs(for: p.id).allowPause {
                Button("Pause") { Task { await vpn.pause(id: p.id) } }
            }
            Button("Disconnect") { vpn.disconnect(id: p.id) }
        } else if p.status == .disconnected || p.status == .invalid {
            Button("Connect") {
                vpn.selectedID = p.id
                Task {
                    // Full credentials on file → straight through; otherwise the
                    // detail form is already showing for typing.
                    await vpn.connectWithSavedCredentials(id: p.id)
                }
            }
        }
        Divider()
        ProbeVPNMenuItem(vpn: vpn, profile: p)
        Button("Settings…") {
            vpn.selectedID = p.id
            openWindow(id: "manage")
        }
    }
}

// MARK: - Startup states

private struct ActivationPrompt: View {
    @Bindable var ext: ExtensionController
    @Environment(\.openURL) private var openURL
    var body: some View {
        ContentUnavailableView {
            Label("System Extension Required", systemImage: "puzzlepiece.extension")
        } description: {
            VStack(spacing: 8) {
                Text("SimpleVPN runs tunnels in a system extension. Activate it, then approve it in System Settings if prompted.")
                Text(ext.status).font(.callout).foregroundStyle(.secondary)
            }
        } actions: {
            Button("Activate Extension") { Task { await ext.activate() } }
                .buttonStyle(.glassProminent)
            if ext.needsApproval {
                Button("Open Login Items & Extensions") {
                    if let url = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension") {
                        openURL(url)
                    }
                }
            }
        }
    }
}

private struct EmptyVPNsPrompt: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let importAction: () -> Void
    let manageAction: () -> Void
    /// The shared import pipeline (same one the open panel and Dock drops use), so a
    /// drop here can't take a different code path from every other way in.
    let dropAction: ([URL]) -> Void
    /// Highlighted while a config is over the window, so the drop reads as live rather
    /// than as decoration.
    @State private var targeted = false

    var body: some View {
        VStack(spacing: 22) {
            ContentUnavailableView {
                Label("No VPNs Configured", systemImage: "network.slash")
            } description: {
                // No format lecture up front: the import pipeline detects the
                // type itself (ConfigDetector — OpenVPN / WireGuard / Cisco).
                Text("Drop a configuration file here, import one, or add a VPN by hand. The type is worked out automatically.")
            } actions: {
                Button("Import Configuration…", action: importAction).buttonStyle(.glassProminent)
                Button("Add VPN…", action: manageAction).buttonStyle(.glass)
            }

            // The whole window already accepts drops (see .ovpnDropTarget), but with an
            // empty list nothing on screen SAYS so — and dragging a .ovpn onto the app is
            // the fastest way in. An explicit well makes the affordance discoverable
            // instead of a thing you'd have to guess at.
            VStack(spacing: 10) {
                Image(systemName: targeted ? "arrow.down.doc.fill" : "arrow.down.doc")
                    .font(.system(size: 38))
                    .foregroundStyle(targeted ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
                    .contentTransition(.symbolEffect(.replace))
                    // A tiny periodic wiggle hints "this is a live target" the same
                    // way the OTP shake hints "type here" — quiet, not looping motion.
                    .symbolEffect(.wiggle, options: .repeat(.periodic(delay: 5)),
                                  isActive: !reduceMotion && !targeted)
                    .accessibilityHidden(true)   // decorative; the text below says it all
                Text("Drag a VPN configuration here")
                    .font(.callout).foregroundStyle(.secondary)
                Text("OpenVPN (.ovpn / .conf), WireGuard (.conf), Cisco (.xml / .pcf), or a 1Password item")
                    .font(.caption).foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
            }
            .padding(.vertical, 26).padding(.horizontal, 34)
            .frame(maxWidth: 420)
            .background {
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .strokeBorder(style: StrokeStyle(lineWidth: 2, dash: [7, 5]))
                    .foregroundStyle(targeted ? AnyShapeStyle(.tint) : AnyShapeStyle(.tertiary))
            }
            .animation(.snappy(duration: 0.2), value: targeted)
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Drop zone for VPN configuration files")
            // Dragging isn't keyboard-operable — point at the path that is.
            .accessibilityHint("Use the Import Configuration button to choose a file instead.")
        }
        // Mirrors the window-wide handler's types, so the visible target and the
        // invisible one can't disagree about what's droppable.
        .dropDestination(for: URL.self) { urls, _ in
            dropAction(urls)
            return true
        } isTargeted: { targeted = $0 }
    }
}
