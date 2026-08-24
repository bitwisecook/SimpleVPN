// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// BannerSurface.swift
//  The one structural treatment for an in-context notice: enough width to be
//  measured honestly by an NSSplitView, consistent padding and a rounded tint.

import SwiftUI

/// The geometry shared by informational, warning and recovery banners.
///
/// `NavigationSplitView` asks a detail subtree for its minimum size with an
/// effectively-zero width. A multiline banner that answers that query at one
/// word per line can make both split columns thousands of points tall. The
/// width floor is therefore a layout invariant, not a visual preference.
nonisolated enum BannerMetrics {
    static let minimumReadableWidth: CGFloat = 320
    static let padding: CGFloat = 12
    static let cornerRadius: CGFloat = 10
}

/// The narrowest detail column any editor is allowed to report. This is a layout
/// contract, not an aesthetic width: `NavigationSplitView` asks its detail for a
/// zero-width minimum-size proposal, and an editor with multiline content must
/// answer at a width it can actually be shown at. Keeping this beside
/// `BannerMetrics` makes the two halves of the same protection explicit:
/// banners protect their paragraphs, and the host protects every editor.
nonisolated enum EditorPaneMetrics {
    static let minimumReadableWidth: CGFloat = 520
}

/// The sizing contract for utility windows and sheets.  A fixed frame looks
/// tidy at its one authored size, but prevents a Mac user from making a long
/// diff, picker, or search result readable.  These are ideals, not locks.
nonisolated enum PanelMetrics {
    static let minimumWidth: CGFloat = 360
    static let minimumHeight: CGFloat = 280
}

private struct BannerSurface<Tint: ShapeStyle>: ViewModifier {
    let tint: Tint
    let opacity: Double

    func body(content: Content) -> some View {
        content
            // Banners frequently contain the exact wording a support request
            // needs. Make every banner's copy selectable at the shared surface
            // instead of relying on each individual banner author to remember.
            .textSelection(.enabled)
            .padding(BannerMetrics.padding)
            // Apply this OUTSIDE the content: the min-size pass must see the
            // floor before any multiline text decides its height.
            .frame(minWidth: BannerMetrics.minimumReadableWidth,
                   maxWidth: .infinity, alignment: .leading)
            .background(tint.opacity(opacity),
                        in: RoundedRectangle(cornerRadius: BannerMetrics.cornerRadius))
    }
}

extension View {
    /// Draw a user-facing banner. Use cards for richer, independent interaction
    /// structures; use this for an in-context notice, warning or recovery path.
    func bannerSurface<Tint: ShapeStyle>(tint: Tint, opacity: Double = 0.12) -> some View {
        modifier(BannerSurface(tint: tint, opacity: opacity))
    }

    /// Give an editor hosted in a split-view detail column its real minimum width.
    /// This is intentionally a single modifier rather than per-editor frames: an
    /// F5 editor is not the only place future multiline content can appear.
    func editorPaneWidthFloor() -> some View {
        frame(minWidth: EditorPaneMetrics.minimumReadableWidth,
              maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    /// Give a utility sheet a comfortable opening size without making that size
    /// its only size.  Content with a scroll view can now grow as the user
    /// resizes it, while the minimum stays usable on a small display.
    func resizablePanel(idealWidth: CGFloat, idealHeight: CGFloat,
                        minWidth: CGFloat = PanelMetrics.minimumWidth,
                        minHeight: CGFloat = PanelMetrics.minimumHeight) -> some View {
        frame(minWidth: minWidth, idealWidth: idealWidth, maxWidth: .infinity,
              minHeight: minHeight, idealHeight: idealHeight, maxHeight: .infinity,
              alignment: .topLeading)
    }
}

/// A non-blocking explanation for credentials that are deliberately collected at
/// first connect rather than treated as incomplete saved configuration.
///
/// All VPN editors use this one banner so a blank password, username, or
/// verification code never turns into a protocol-specific warning style.
struct FirstConnectSignInBanner: View {
    let need: ConnectNeed

    var body: some View {
        Label(message, systemImage: "info.circle")
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .bannerSurface(tint: Color.accentColor)
            .accessibilityLabel(message)
    }

    private var message: String {
        switch need.readiness {
        case .needsSignIn:
            "Sign-in details are empty. You can fill them in when connecting for the first time."
        case .needsCode:
            "A verification code is needed. Enter it when connecting; it is never saved."
        case .blocked, .ready:
            ""
        }
    }
}
