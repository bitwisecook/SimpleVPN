// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProviderListUpdateSheet.swift
//  THE MISSING HALF OF THE CONFIRMATION GATE. `ProviderServerListDiff` has always
//  been able to HOLD an update — a moved address, a moved peer key, a third of the
//  list gone — and the fetch has always honoured it. What did not exist was any way
//  to look at what is being held and say yes, so such an update could only ever be
//  declined by doing nothing. Fail-safe, and a dead end. This is the sheet.
//
//  FOUR RULES, and all four are refusals as much as they are features:
//
//   1. IT SAYS WHAT CHANGED, PER SERVER. A count is not enough for a
//      security-determining change: "12 servers changed" is the kind of sentence
//      somebody clicks through. Every server gets a line naming it and saying, in
//      words, what moved.
//   2. IT LEADS WITH THE DANGEROUS ONES. Not the alphabet —
//      `ProviderListUpdateReview` ranks a moved PUBLIC KEY on a server the user
//      HOLDS above everything, because WireGuard has no certificate behind it: the
//      key IS the authentication and it arrived in the same download as the address
//      it vouches for (Docs/ServiceBundles.md §3).
//   3. A REMOVAL IS A CHANGE, NOT A TIDY-UP. Vanished servers get their own rows and
//      say they will be kept and marked retired rather than deleted, and a list that
//      lost more than a third of itself says that is why the whole update is held.
//   4. ALL-OR-NOTHING. There is not one tick box on this sheet, and that absence is
//      the design: accepting the good rows beside a poisoned one is exactly what
//      `needsConfirmation` exists to prevent, and a UI that offered it would make
//      the gate decorative.
//
//  THE DEFAULT IS TO DO NOTHING. "Keep What I Have" carries `.cancelAction`, so
//  Escape is safe; the accepting button carries NO key equivalent at all, which is
//  the same treatment the WireGuard with-keys export consent already uses — Return
//  must not be able to apply a substitution.
//
//  WHAT THIS SHEET WILL NOT OFFER. It never appears for a fetch that failed
//  integrity. A payload that would not parse, that yielded nothing, that failed the
//  CA fingerprint or that came off the wrong host never produces a diff at all —
//  those are `ProviderListFetcher.Failure`s, the stored list is untouched and the
//  reason is shown. So there is no path here that turns a refusal into a prompt, and
//  none should ever be added: this sheet exists to let a HELD update proceed, not to
//  let a REFUSED one through.
//
//  THE LAYOUT-LOOP INVARIANT: fixed frame, no `ProgressView`, no `Toggle`, no
//  `TextField`, nothing animating a transform around a platform-backed view.
//

import SwiftUI

/// One held update, waiting to be looked at.
///
/// It carries the stored list and the incoming one alongside the diff because
/// `ProviderServerListUpdate.apply` needs all three — and because the sheet must not
/// be able to reconstruct what to write from the diff alone, which would be a second
/// implementation of the apply rules.
struct PendingProviderListUpdate: Identifiable {
    let provider: VPNServiceProvider
    let diff: ProviderServerListDiff
    let stored: ProviderServerList?
    let incoming: ProviderServerList
    /// The hostnames this VPN's Servers list actually holds, so "you have this one"
    /// is answered against what the user sees.
    let heldHostnames: Set<String>
    let id = UUID()
}

struct ProviderListUpdateSheet: View {

    let pending: PendingProviderListUpdate
    /// Called with the list to store when the user accepts. The caller does the
    /// writing; this view computes nothing about what to write.
    let accept: (ProviderServerList) -> Void

    @Environment(\.dismiss) private var dismiss

    private var provider: VPNServiceProvider { pending.provider }
    private var diff: ProviderServerListDiff { pending.diff }

    private var rows: [ProviderListUpdateReview.Row] {
        ProviderListUpdateReview.rows(diff, heldHostnames: pending.heldHostnames)
    }

    /// How many servers were stored before this update, for the "lost too many"
    /// sentence. Derived from the diff so it cannot disagree with `lostTooMany`.
    private var storedCount: Int {
        diff.unchangedCount + diff.moved.count + diff.retired.count
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    warnings
                    changeList
                    Text(ProviderListUpdateCopy.allOrNothing)
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.vertical, 2)
            }
            Divider()
            buttons
        }
        .padding(18)
        .frame(width: 540, height: 560)
        .task {
            // A held update is the answer to something the user pressed, so it is
            // announced immediately rather than through the debounced path.
            AccessibilityAnnouncer.sayNow(
                ProviderListUpdateCopy.title(provider) + ". "
                    + ProviderListUpdateCopy.summary(diff) + " "
                    + ProviderListUpdateCopy.nothingAppliedYet)
        }
    }

    // MARK: Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Text(ProviderListUpdateCopy.title(provider)).font(.headline)
                if let notice = provider.maturityNotice { MaturityBadge(notice: notice) }
            }
            Text(ProviderListUpdateCopy.summary(diff))
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text(ProviderListUpdateCopy.nothingAppliedYet)
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
    }

    // MARK: The warnings, above everything

    @ViewBuilder private var warnings: some View {
        if ProviderListUpdateReview.hasMovedKeyOnHeldServer(rows) {
            warning(ProviderListUpdateCopy.movedKeyWarning(provider), symbol: "key.slash")
        }
        if diff.lostTooMany {
            warning(ProviderListUpdateCopy.lostTooManyWarning(provider,
                                                              retired: diff.retired.count,
                                                              stored: storedCount),
                    symbol: "archivebox")
        }
    }

    /// A warning is CONTENT: a `Label` whose words carry it, never a tint carrying it
    /// alone, and its own element so VoiceOver reaches it before the list.
    private func warning(_ text: String, symbol: String) -> some View {
        Label {
            Text(text).fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: symbol)
        }
        .font(.callout)
        .foregroundStyle(.primary)
        .padding(10)
        .background(.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
        .accessibilityElement(children: .combine)
    }

    // MARK: The changes

    /// Grouped under headings in RANK order, so the list is a structure to move
    /// through rather than one long recitation, and the first heading a VoiceOver
    /// user meets is the one that matters most (Docs/Accessibility.md rule 6).
    private var changeList: some View {
        let grouped = groups(rows)
        return VStack(alignment: .leading, spacing: 12) {
            ForEach(grouped, id: \.heading) { group in
                VStack(alignment: .leading, spacing: 6) {
                    Text(group.heading)
                        .font(.callout.weight(.semibold))
                        .accessibilityAddTraits(.isHeader)
                    ForEach(group.rows) { row in
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Image(systemName: ProviderListUpdateCopy.symbol(row))
                                .foregroundStyle(row.isTheDangerousOne ? AnyShapeStyle(.orange)
                                                                       : AnyShapeStyle(.secondary))
                                .accessibilityHidden(true)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(ProviderListUpdateCopy.rowTitle(row))
                                    .font(.callout)
                                    .lineLimit(1).truncationMode(.middle)
                                Text(ProviderListUpdateCopy.sentence(row))
                                    .font(.caption).foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer(minLength: 0)
                        }
                        .accessibilityElement(children: .combine)
                        .accessibilityLabel(ProviderListUpdateCopy.rowTitle(row))
                        .accessibilityValue(ProviderListUpdateCopy.sentence(row))
                    }
                }
            }
        }
    }

    /// Runs of rows sharing a heading, in the order the ranking produced — never
    /// gathered or re-sorted, because gathering would undo the ranking.
    private func groups(_ rows: [ProviderListUpdateReview.Row])
        -> [(heading: String, rows: [ProviderListUpdateReview.Row])] {
        var out: [(heading: String, rows: [ProviderListUpdateReview.Row])] = []
        for row in rows {
            let heading = ProviderListUpdateCopy.heading(row)
            if out.last?.heading == heading { out[out.count - 1].rows.append(row) }
            else { out.append((heading: heading, rows: [row])) }
        }
        return out
    }

    // MARK: Buttons

    private var buttons: some View {
        HStack {
            Spacer()
            // THE SAFE ONE IS THE PROMINENT ONE, and it owns Escape. It is also what
            // happens if the sheet is dismissed any other way, because doing nothing
            // is the outcome of every path that is not the button on the right.
            Button(ProviderListUpdateCopy.keepTitle) { decline() }
                .buttonStyle(.glassProminent)
                .keyboardShortcut(.cancelAction)
                .help(ProviderListUpdateCopy.keepHelp(provider))
                .accessibilityValue(ProviderListUpdateCopy.keepHelp(provider))
            // NO KEY EQUIVALENT AT ALL, and deliberately not prominent: nothing on
            // this sheet carries `.defaultAction`, so Return cannot accept a moved
            // key. It has to be read and aimed at. Same treatment, same reasoning, as
            // the WireGuard with-keys export consent.
            Button(ProviderListUpdateCopy.acceptTitle(provider)) { approve() }
                .help(ProviderListUpdateCopy.acceptHelp(provider))
                .accessibilityValue(ProviderListUpdateCopy.acceptHelp(provider))
        }
    }

    // MARK: Actions

    /// The ONE place `confirmed: true` is passed anywhere in the app, and it is
    /// reached only by pressing the button above.
    private func approve() {
        let applied = ProviderServerListUpdate.apply(diff,
                                                     stored: pending.stored,
                                                     incoming: pending.incoming,
                                                     confirmed: true)
        accept(applied)
        AccessibilityAnnouncer.sayNow(
            ProviderListUpdateCopy.accepted(provider, total: applied.servers.count))
        dismiss()
    }

    private func decline() {
        AccessibilityAnnouncer.sayNow(ProviderListUpdateCopy.declined(provider))
        dismiss()
    }
}
