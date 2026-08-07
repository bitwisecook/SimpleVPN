// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProviderPickerSection.swift
//  THE FOUR ROWS — one component, used by both places a person meets them, so the
//  two entry points cannot drift into saying different things about the same company.
//
//  WHERE IT APPEARS:
//   • The no-VPNs page (`ConnectionView`'s `EmptyVPNsPrompt`), which is the "starting
//     journey" the request named. It sits UNDER the import actions, not above them,
//     because importing a configuration is still the thing most people arriving here
//     need to do first — for three of the four providers it is literally a
//     prerequisite.
//   • The Manage VPNs add flow, where it is a submenu of `+`.
//
//  PROTON'S ROW IS DISABLED AND SAYS WHY, and that is a design decision rather than
//  an oversight (`ConnectListing`'s standing rule: never hide a thing the user came
//  looking for; list it, disable it, say why). Their list needs an account token and
//  their terms bar automated access, so a button that tried would fail — and an
//  absent row is indistinguishable from a bug. It offers the thing that does work:
//  download the configuration from Proton and import it.
//
//  NO PROVIDER LOGOS, EVER (Docs/ServiceBundles.md §6). A globe glyph and the
//  company's own spelling of its name; nominative use, nothing borrowed.
//
//  THE LAYOUT-LOOP INVARIANT. There is deliberately NO `ProgressView` in this file.
//  A platform-backed view inside a transform-animated container caused a real crash
//  in this app, and the no-VPNs page cross-fades its whole content. Progress lives in
//  the SHEET, which is a stable container that never animates its own geometry.
//

import SwiftUI

/// The four rows. `onChoose` is handed the provider; the caller decides what a choice
/// opens, because the two entry points open different things (a sheet on an existing
/// VPN, or the import flow when there is no VPN yet).
struct ProviderPickerSection: View {

    var detail: String = ProviderPickerCopy.sectionDetail
    let action: (VPNServiceProvider) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(ProviderPickerCopy.sectionTitle)
                .font(.callout.weight(.semibold))
                .accessibilityAddTraits(.isHeader)
            Text(detail)
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(VPNServiceProviderCatalog.all) { provider in
                ProviderPickerRow(provider: provider) { action(provider) }
            }
        }
        // A container with its own name: the section used to be an unnamed AX group,
        // which is the shape the accessibility audit excuses as framework chrome.
        .accessibilityElement(children: .contain)
        .accessibilityLabel(ProviderPickerCopy.sectionTitle)
    }
}

/// One provider. The whole row is the button, because a row with a separate small
/// button in it is two targets for one idea.
struct ProviderPickerRow: View {

    let provider: VPNServiceProvider
    let action: () -> Void

    private var isBlocked: Bool { provider.blocked != nil }

    var body: some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: isBlocked ? "globe.badge.chevron.backward" : "globe")
                    .font(.title3)
                    .foregroundStyle(isBlocked ? AnyShapeStyle(.tertiary) : AnyShapeStyle(.tint))
                    .frame(width: 22)
                    .accessibilityHidden(true)      // its words ride the row's value
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(ProviderPickerCopy.title(provider))
                            .font(.callout.weight(.medium))
                        // The maturity claim rides here rather than in a footnote:
                        // Mullvad is the only one testable on this machine, and Nord
                        // and IPVanish ship untested with the feedback link.
                        if let notice = provider.maturityNotice {
                            MaturityBadge(notice: notice)
                        }
                    }
                    Text(ProviderPickerCopy.detail(provider))
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .multilineTextAlignment(.leading)
                    if let size = ProviderPickerCopy.downloadSize(provider) {
                        Text(size)
                            .font(.caption2).foregroundStyle(.tertiary)
                    }
                }
                Spacer(minLength: 0)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(isBlocked)
        .help(ProviderPickerCopy.detail(provider))
        // One element reading as a sentence: the company, what will happen, and the
        // caveat — so a listener never has to walk three labels to learn that
        // Mullvad still needs a configuration they have not downloaded.
        .accessibilityElement(children: .combine)
        .accessibilityLabel(ProviderPickerCopy.title(provider))
        .accessibilityValue(ProviderPickerCopy.detail(provider))
        .accessibilityHint(isBlocked ? "" : ProviderPickerCopy.actionTitle(provider))
    }
}
