// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  AddServersFromProviderSheet.swift
//  ONE PROVIDER, ONE VPN, ONE REQUEST — the sheet that names the host before
//  contacting it, downloads with real progress, and applies through the ordinary
//  endpoint list.
//
//  THE SHAPE, top to bottom, and it is the order the decisions happen in:
//   1. WHAT THIS WILL DO AND WHAT IT WILL NOT. The provider's caveat, the host that
//      will be contacted, the size, and the flat statement that SimpleVPN cannot
//      sign anyone in. Before any button.
//   2. FETCH, with progress (`ProviderFetchProgress`) and a Stop that leaves the
//      previous list exactly as it was.
//   3. WHICH PLACES. Three thousand rows is not a feature; it is the feature failing.
//   4. ADD, which writes ordinary `VPNEndpoint`s onto an ordinary profile — after
//      which the ranking, the probing, the region grouping and the drag-to-reorder
//      that already exist do all the work the request actually asked for.
//
//  THE LAYOUT-LOOP INVARIANT, and this is the file where it bites. `ProgressView` is
//  platform-backed, and a platform-backed view inside a TRANSFORM-ANIMATED container
//  caused a real crash in this app. Two things keep it safe here:
//   • This is a sheet. Its container has a fixed frame and never animates its own
//     geometry, so nothing the indicator sits in is being transformed.
//   • The progress row RESERVES ITS HEIGHT whether or not it is showing. Appearing
//     and disappearing therefore changes no layout at all, so there is no size
//     animation for it to be inside of even implicitly.
//  Neither is an accident and neither should be removed.
//

import SwiftUI

struct AddServersFromProviderSheet: View {

    @Bindable var vpn: VPNController
    let profile: VPNController.Profile
    let provider: VPNServiceProvider

    @Environment(\.dismiss) private var dismiss
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// The list this fetch produced. Nil until one has.
    @State private var list: ProviderServerList?
    @State private var progress: ProviderFetchProgress?
    /// Set once the fetch has been running long enough to be worth drawing. Mullvad's
    /// 300 KB usually never gets here, which is the intended outcome.
    @State private var showsIndicator = false
    @State private var failure: String?
    @State private var chosenCountries: Set<String> = []
    @State private var task: Task<Void, Never>?
    @State private var consenting = false
    /// A fetch whose diff the rules HELD, waiting to be looked at.
    ///
    /// This is what turns "the update cannot proceed" into "the update needs your
    /// say-so": the fetch's own refusal is unchanged — nothing is written while this
    /// holds a value — and `ProviderListUpdateSheet` is the only thing in the app
    /// that can pass `confirmed: true`.
    @State private var pendingUpdate: PendingProviderListUpdate?

    private var store: ProviderServerListStore { .shared }

    /// Everything the policy needs, gathered here so the decision stays a function of
    /// its inputs and can be tested without a view.
    private var conditions: ProviderListFetchPolicy.Conditions {
        .init(enabled: ProviderListSettings.enabled,
              managedForbids: ManagedPolicy.disableProviderLists,
              onlyWhenConnected: ProviderListSettings.onlyWhenConnected,
              hasConsented: ProviderListSettings.hasConsented(provider.id),
              connectedProviders: connectedProviders)
    }

    /// Which providers a live tunnel currently goes through. Read from the profiles
    /// that are actually up, matched on the SHIPPED suffix.
    private var connectedProviders: Set<VPNServiceProviderID> {
        ProviderListFetchPolicy.connected(
            hosts: vpn.profiles.filter { vpn.isEngaged(id: $0.id) }.map(\.server))
    }

    private var refusal: ProviderListFetchPolicy.Refusal? {
        ProviderListFetchPolicy.refusal(for: provider, conditions)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    whatThisDoes
                    if let refusal, refusal != .needsConsent {
                        refusalNote(refusal.sentence)
                    }
                    if let failure { refusalNote(failure) }
                    if let list { places(list) }
                }
                .padding(.vertical, 2)
            }
            // FIXED HEIGHT, ALWAYS PRESENT. See this file's header: the indicator
            // must not change the layout when it appears.
            progressRow
            Divider()
            buttons
        }
        .padding(18)
        .frame(width: 460, height: 520)
        .onDisappear { task?.cancel() }
        .confirmationDialog(ProviderPickerCopy.consentTitle(provider),
                            isPresented: $consenting, titleVisibility: .visible) {
            Button(ProviderPickerCopy.consentConfirm(provider)) {
                ProviderListSettings.consent(to: provider.id)
                start()
            }
            Button("Not Now", role: .cancel) {}
        } message: {
            Text(ProviderPickerCopy.consentMessage(
                provider, throughTunnel: connectedProviders.contains(provider.id)))
        }
        // THE APPROVAL FLOW. Held here rather than in the fetch: producing a diff
        // changes nothing, and the only thing that can apply a held one is the
        // button on that sheet.
        .sheet(item: $pendingUpdate) { held in
            ProviderListUpdateSheet(pending: held) { applied in
                store.save(applied)
                list = applied
                // The "needs your say-so" note is answered now, so it goes; leaving
                // it up after an approval would say the opposite of what happened.
                failure = nil
            }
        }
        .task { list = store.list(provider.id) }
    }

    // MARK: Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Text("\(provider.displayName) servers for \u{201C}\(profile.name)\u{201D}")
                    .font(.headline)
                if let notice = provider.maturityNotice { MaturityBadge(notice: notice) }
            }
            if let list {
                Text(freshness(list))
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
    }

    /// Staleness as a CAPTION, never as a reason to go and fetch. No background
    /// refresh exists and none is implied.
    private func freshness(_ list: ProviderServerList) -> String {
        "\(list.servers.count) servers, last fetched "
            + list.fetchedAt.formatted(.relative(presentation: .named)) + "."
    }

    // MARK: What this does, before anything is pressed

    private var whatThisDoes: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(ProviderPickerCopy.detail(provider))
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
            if provider.blocked == nil, let host = provider.listURL?.host() {
                Label {
                    Text("SimpleVPN will contact \(host) and read nothing but their server list. "
                         + "It never signs you in.")
                } icon: {
                    Image(systemName: "lock.shield")
                }
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
            if let size = ProviderPickerCopy.downloadSize(provider) {
                Text(size).font(.caption).foregroundStyle(.tertiary)
            }
        }
    }

    private func refusalNote(_ text: String) -> some View {
        Label {
            Text(text).fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "exclamationmark.triangle")
        }
        .font(.callout)
        .foregroundStyle(.secondary)
        .accessibilityElement(children: .combine)
    }

    // MARK: Which places

    @ViewBuilder
    private func places(_ list: ProviderServerList) -> some View {
        let choices = ProviderEndpointImport.countryChoices(list)
        VStack(alignment: .leading, spacing: 6) {
            Text("Which places?")
                .font(.callout.weight(.semibold))
                .accessibilityAddTraits(.isHeader)
            Text("Pick the countries you want. Adding every server a provider publishes makes a "
                 + "list nobody scrolls \u{2014} choose a few, and come back for more.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(choices, id: \.code) { choice in
                Toggle(isOn: Binding(
                    get: { chosenCountries.contains(choice.code) },
                    set: { on in
                        if on { chosenCountries.insert(choice.code) }
                        else { chosenCountries.remove(choice.code) }
                    })) {
                    Text("\(choice.name) \u{2014} \(choice.count) server\(choice.count == 1 ? "" : "s")")
                }
                .toggleStyle(.checkbox)
                .accessibilityLabel(choice.name)
                .accessibilityValue("\(choice.count) servers")
            }
        }
    }

    // MARK: Progress

    /// Always in the layout, only sometimes visible. See the header: a row that
    /// appears and disappears would resize the sheet around a platform-backed view.
    private var progressRow: some View {
        HStack(spacing: 8) {
            if showsIndicator, let progress {
                if let fraction = progress.fraction {
                    ProgressView(value: fraction)
                        .frame(width: 120)
                } else {
                    // Indeterminate, because the server declared no length. Never a
                    // fabricated percentage.
                    ProgressView().controlSize(.small)
                }
                Text(progress.sentence(provider: provider))
                    .font(.caption).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }
            Spacer(minLength: 0)
        }
        .frame(height: 20)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(showsIndicator ? (progress?.spoken(provider: provider) ?? "") : "")
        .accessibilityHidden(!showsIndicator)
    }

    // MARK: Buttons

    private var buttons: some View {
        HStack {
            if task != nil {
                Button("Stop") { stop() }
                    .help("Stop the download. Nothing has been changed.")
            }
            Spacer()
            Button("Done") { dismiss() }
                .keyboardShortcut(.cancelAction)
            if provider.blocked == nil {
                Button(list == nil ? "Get Server List" : "Refresh") { begin() }
                    .disabled(task != nil || (refusal != nil && refusal != .needsConsent))
                    .buttonStyle(.glass)
            }
            if let list {
                let count = ProviderEndpointImport
                    .servers(from: list, countries: chosenCountries).count
                Button(ProviderPickerCopy.applyTitle(count: count)) { apply(list) }
                    .disabled(count == 0 || task != nil)
                    .buttonStyle(.glassProminent)
                    .help(count == 0 ? ProviderPickerCopy.nothingMatches : "")
            }
        }
    }

    // MARK: Actions

    /// The first press for a provider raises the consent sheet rather than fetching:
    /// the host is named BEFORE it is contacted, and one provider at a time.
    private func begin() {
        failure = nil
        if refusal == .needsConsent { consenting = true } else { start() }
    }

    private func start() {
        failure = nil
        progress = ProviderFetchProgress(stage: .contacting)
        showsIndicator = false
        let stored = store.list(provider.id)
        task = Task {
            // The delay lives here rather than in the view so there is exactly one
            // timer, and cancelling the fetch cancels it too.
            let reveal = Task {
                try? await Task.sleep(for: ProviderFetchProgress.indicatorDelay)
                if !Task.isCancelled { showsIndicator = true }
            }
            defer { reveal.cancel(); task = nil; showsIndicator = false }
            do {
                let fresh = try await ProviderListFetcher.shared.fetch(provider) { p in
                    progress = p
                }
                // RULE 3 AND 4: an update that moves an address or a key on a server
                // the user holds, or that loses a third of the list, is HELD. Nothing
                // is written here — the stored list stays exactly as it was, the
                // outcome says what is waiting, and the diff is handed to
                // `ProviderListUpdateSheet`, which is the only place in the app that
                // can pass `confirmed: true`. Declining that sheet leaves this state
                // exactly as this line found it.
                let diff = ProviderServerListDiff.between(stored: stored, incoming: fresh)
                guard !diff.needsConfirmation else {
                    announce(ProviderFetchOutcome
                        .needsConfirmation(moved: diff.moved.count, retired: diff.retired.count))
                    pendingUpdate = PendingProviderListUpdate(
                        provider: provider, diff: diff, stored: stored, incoming: fresh,
                        heldHostnames: Set(vpn.endpoints(for: profile.id).map(\.host)))
                    return
                }
                let applied = ProviderServerListUpdate.apply(diff, stored: stored,
                                                             incoming: fresh, confirmed: false)
                store.save(applied)
                list = applied
                announce(.ready(added: diff.added.count, unchanged: diff.unchangedCount,
                                total: applied.servers.count))
            } catch let failure as ProviderListFetcher.Failure {
                // Already in the user's words, and every one of them names the fix
                // and says nothing has been changed. A raw `URLError` shown here is
                // how somebody ends up reading "cancelled".
                announce(.failed(failure.sentence))
            } catch {
                announce(.failed(ProviderFetchOutcome.cancelled.sentence(provider: provider)))
            }
        }
    }

    private func stop() {
        task?.cancel()
        task = nil
        showsIndicator = false
        announce(.cancelled)
    }

    /// A user-initiated action ends with an IMMEDIATE announcement rather than the
    /// debounced event path — they pressed a button and are waiting for the answer
    /// (Docs/Accessibility.md).
    private func announce(_ outcome: ProviderFetchOutcome) {
        let sentence = outcome.sentence(provider: provider)
        if case .failed = outcome { failure = sentence }
        if case .needsConfirmation = outcome { failure = sentence }
        AccessibilityAnnouncer.sayNow(sentence)
    }

    /// The whole payoff: the provider's servers become ordinary endpoints on an
    /// ordinary profile, and every bit of sorting, probing and grouping that already
    /// exists starts applying to them without being built again.
    private func apply(_ list: ProviderServerList) {
        let servers = ProviderEndpointImport.servers(from: list, countries: chosenCountries)
        guard !servers.isEmpty else { return }
        let next = ProviderEndpointImport.applying(servers, from: provider.id,
                                                   to: vpn.endpointList(for: profile.id))
        Task {
            await vpn.setEndpointList(next, for: profile.id)
            AccessibilityAnnouncer.sayNow(ProviderPickerCopy.applied(
                count: servers.count, provider: provider, vpn: profile.name))
            dismiss()
        }
    }
}
