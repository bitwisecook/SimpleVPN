// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// ProviderFirstRunView.swift
// One staged, vendor-owned first-run flow. The provider catalogue supplies the
// external destination; SimpleVPN supplies the one input it can act on.

import SwiftUI

struct ProviderFirstRunView: View {
    private enum Anchor: Hashable { case importConfiguration }
    private enum Metrics { static let contentWidth: CGFloat = 760 }

    let provider: VPNServiceProvider
    /// Driven by ConnectionView's window-wide drop handler. A drop anywhere on
    /// this page takes the same import path; the visible well reflects that state.
    let isDropTargeted: Bool
    let chooseConfiguration: () -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.liveVisualPolicy) private var liveVisuals
    @State private var showsImportCue = true

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    headerCard
                    setupCard
                }
                .frame(maxWidth: Metrics.contentWidth, alignment: .leading)
                .padding(.horizontal, 28)
                .padding(.vertical, 24)
                .frame(maxWidth: .infinity, alignment: .center)
            }
            // Guidance only: the ordinary scroll view remains fully usable with
            // trackpad, mouse, keyboard and assistive technologies.
            .safeAreaInset(edge: .bottom, spacing: 0) {
                if showsImportCue { scrollToImportButton(proxy) }
            }
        }
        .navigationTitle(provider.displayName)
    }

    private var headerCard: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: "globe")
                .font(.system(size: 30))
                .foregroundStyle(.tint)
                .frame(width: 38)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 7) {
                    Text(ProviderPickerCopy.firstRunTitle(provider))
                        .font(.title3.bold())
                    if let notice = provider.maturityNotice {
                        MaturityBadge(notice: notice, spokenElsewhere: false)
                    }
                }
                Text(ProviderPickerCopy.firstRunSummary(provider))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(18)
        .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
        .accessibilityElement(children: .contain)
    }

    private var setupCard: some View {
        let steps = ProviderPickerCopy.firstRunSteps(provider)
        return VStack(alignment: .leading, spacing: 16) {
            Text("Setup")
                .font(.headline)
                .accessibilityAddTraits(.isHeader)

            setupStep(number: 1, step: steps[0])
            Link(destination: provider.setupURL) {
                Label(ProviderPickerCopy.firstRunVendorLinkTitle(provider),
                      systemImage: "arrow.up.forward.square")
            }
            .buttonStyle(.bordered)
            .help("Opens \(provider.setupURL.host() ?? provider.displayName) in your browser")
            .accessibilityHint("Opens the provider’s configuration page in your browser.")

            Divider()

            // The input sits directly below the instruction that calls for it.
            // This is the same order for every vendor and both import methods.
            setupStep(number: 2, step: steps[1])
                .id(Anchor.importConfiguration)
            ConfigurationDropTarget(isTargeted: isDropTargeted, maximumWidth: nil)
                .frame(maxWidth: .infinity)
            Button(ProviderPickerCopy.firstRunImportTitle(provider), action: chooseConfiguration)
                .buttonStyle(.glassProminent)
                .controlSize(.large)
                .keyboardShortcut(.defaultAction)
                .accessibilityHint("Opens a file picker. You can also drag the configuration onto this window.")

            Divider()

            // A successful import creates a profile and the app swaps this empty
            // page for the normal VPN UI. Until then these stages are honestly
            // unavailable, using words and a lock as well as dimming.
            waitingStep(number: 3, step: steps[2])
            waitingStep(number: 4, step: steps[3])
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(18)
        .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Setup steps")
    }

    private func setupStep(number: Int, step: UserFacingError.Step) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 9) {
            Image(systemName: "\(number).circle.fill")
                .foregroundStyle(.tint)
                .accessibilityHidden(true)
            stepText(step)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Step \(number). \(step.text.replacingOccurrences(of: "**", with: ""))")
    }

    private func waitingStep(number: Int, step: UserFacingError.Step) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 9) {
            Image(systemName: "lock.circle")
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            stepText(step)
        }
        .opacity(0.52)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Step \(number), unavailable until you import a configuration. \(step.text.replacingOccurrences(of: "**", with: ""))")
    }

    private func stepText(_ step: UserFacingError.Step) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(LocalizedStringKey(step.text))
                .fixedSize(horizontal: false, vertical: true)
            if let note = step.note {
                Text(LocalizedStringKey(note))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .textSelection(.enabled)
    }

    private func scrollToImportButton(_ proxy: ScrollViewProxy) -> some View {
        Button {
            showsImportCue = false
            if reduceMotion {
                proxy.scrollTo(Anchor.importConfiguration, anchor: .top)
            } else {
                withAnimation(.easeInOut(duration: 0.28)) {
                    proxy.scrollTo(Anchor.importConfiguration, anchor: .top)
                }
            }
        } label: {
            Label("Continue to import configuration", systemImage: "chevron.down")
                .font(.callout.weight(.semibold))
                .symbolEffect(.bounce.down, options: .repeat(.periodic(delay: 1.8)),
                              isActive: liveVisuals.permitsContinuousAnimation(reduceMotion: reduceMotion))
        }
        .buttonStyle(.borderedProminent)
        .controlSize(.small)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity)
        .background(.bar)
        .accessibilityHint("Scrolls directly to the configuration import controls.")
    }
}
