// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProviderPickerSection.swift
//  THE FOUR ROWS — one component, used by both places a person meets them, so the
//  two entry points cannot drift into saying different things about the same company.
//
//  WHERE IT APPEARS:
//   • The no-VPNs page (`ConnectionView`'s `EmptyVPNsPrompt`), which is the "starting
//     journey" the request named. It shows four NAMES only; each opens the provider's
//     setup page, where the prerequisite configuration and later sign-in are
//     explained without turning the first page into four blocks of instructions.
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

enum ProviderPickerMetrics {
    /// 72 points is one inch in AppKit's coordinate system: approximately 2.5 cm.
    static let firstRunTileSide: CGFloat = 72
    static let firstRunColumnCount = 4
    static let firstRunSpacing: CGFloat = 12
}

/// The four rows. `action` is handed the provider; the caller decides what a choice
/// opens, because the two entry points open different things (a sheet on an existing
/// VPN, or a provider-specific instruction page when there is no VPN yet).
struct ProviderPickerSection: View {

    var title: String = ProviderPickerCopy.sectionTitle
    var detail: String = ProviderPickerCopy.sectionDetail
    /// First run is a choice of company names. The explanation belongs on the
    /// provider page that follows, where it has room to be actionable.
    var showsDetails = true
    /// A provider with no readable list is still a useful first-run choice: its
    /// second page explains the configuration-import path that does work.
    var allowsBlockedSelection = false
    let action: (VPNServiceProvider) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.callout.weight(.semibold))
                .accessibilityAddTraits(.isHeader)
            Text(detail)
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if showsDetails {
                ForEach(VPNServiceProviderCatalog.all) { provider in
                    ProviderPickerRow(provider: provider,
                                      showsDetails: true,
                                      allowsBlockedSelection: allowsBlockedSelection) {
                        action(provider)
                    }
                }
            } else {
                GlassEffectContainer(spacing: ProviderPickerMetrics.firstRunSpacing) {
                    LazyVGrid(columns: firstRunColumns,
                              alignment: .center,
                              spacing: ProviderPickerMetrics.firstRunSpacing) {
                        ForEach(VPNServiceProviderCatalog.all) { provider in
                            ProviderPickerTile(provider: provider) {
                                action(provider)
                            }
                        }
                    }
                    .frame(maxWidth: .infinity)
                    .accessibilityElement(children: .contain)
                    .accessibilityLabel("VPN provider choices")
                }
            }
        }
        // A container with its own name: the section used to be an unnamed AX group,
        // which is the shape the accessibility audit excuses as framework chrome.
        .accessibilityElement(children: .contain)
        .accessibilityLabel(title)
    }

    private var firstRunColumns: [GridItem] {
        Array(repeating: GridItem(.fixed(ProviderPickerMetrics.firstRunTileSide),
                                  spacing: ProviderPickerMetrics.firstRunSpacing),
              count: ProviderPickerMetrics.firstRunColumnCount)
    }
}

/// A first-run choice is intentionally just the company's name. The glass square
/// says "button" visually; its destination owns all explanation and caveats.
private struct ProviderPickerTile: View {
    let provider: VPNServiceProvider
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(ProviderPickerCopy.title(provider))
                .font(.callout.weight(.semibold))
                .multilineTextAlignment(.center)
                .lineLimit(2)
                .minimumScaleFactor(0.8)
                .frame(width: ProviderPickerMetrics.firstRunTileSide,
                       height: ProviderPickerMetrics.firstRunTileSide)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .glassEffect(.regular.interactive(),
                     in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .accessibilityLabel(ProviderPickerCopy.title(provider))
        .accessibilityHint(ProviderPickerCopy.firstRunActionTitle(provider))
    }
}

/// One provider. The whole row is the button, because a row with a separate small
/// button in it is two targets for one idea.
struct ProviderPickerRow: View {

    let provider: VPNServiceProvider
    var showsDetails = true
    var allowsBlockedSelection = false
    let action: () -> Void

    private var isBlocked: Bool { provider.blocked != nil }
    private var isDisabled: Bool { isBlocked && !allowsBlockedSelection }

    var body: some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: isDisabled ? "globe.badge.chevron.backward" : "globe")
                    .font(.title3)
                    .foregroundStyle(isDisabled ? AnyShapeStyle(.tertiary) : AnyShapeStyle(.tint))
                    .frame(width: 22)
                    .accessibilityHidden(true)      // its words ride the row's value
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(ProviderPickerCopy.title(provider))
                            .font(.callout.weight(.medium))
                        // The maturity claim rides here rather than in a footnote:
                        // Mullvad is the only one testable on this machine, and Nord
                        // and IPVanish ship untested with the feedback link.
                        if showsDetails, let notice = provider.maturityNotice {
                            MaturityBadge(notice: notice)
                        }
                    }
                    if showsDetails {
                        Text(ProviderPickerCopy.detail(provider))
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                            .multilineTextAlignment(.leading)
                        if let size = ProviderPickerCopy.downloadSize(provider) {
                            Text(size)
                                .font(.caption2).foregroundStyle(.tertiary)
                        }
                    }
                }
                Spacer(minLength: 0)
                if !isDisabled {
                    Image(systemName: "chevron.right")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.tertiary)
                        .accessibilityHidden(true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(isDisabled)
        .help(showsDetails
              ? ProviderPickerCopy.detail(provider)
              : ProviderPickerCopy.firstRunActionTitle(provider))
        // One element reading as a sentence: the company, what will happen, and the
        // caveat — so a listener never has to walk three labels to learn that
        // Mullvad still needs a configuration they have not downloaded.
        .accessibilityElement(children: .combine)
        .accessibilityLabel(ProviderPickerCopy.title(provider))
        .accessibilityValue(showsDetails ? ProviderPickerCopy.detail(provider) : "")
        .accessibilityHint(isDisabled
                           ? ""
                           : (showsDetails
                              ? ProviderPickerCopy.actionTitle(provider)
                              : ProviderPickerCopy.firstRunActionTitle(provider)))
    }
}
