// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  EditorPaneHeightTests.swift
//  NO EDITOR MAY DEMAND MORE HEIGHT THAN ITS WINDOW HAS — measured, because this one
//  was misdiagnosed twice before anybody measured anything.
//
//  THE BUG. Selecting an F5 BIG-IP APM in Manage VPNs made the SIDEBAR go blank and
//  stop scrolling. Nothing was wrong with the sidebar, with `ConnectOrder`, or with
//  the arrangement — every row was still there, and AX said so. The DETAIL pane's
//  MINIMUM height was 4,627 points; `NSSplitView` gives both of its columns the same
//  height; and a 4,627pt column inside a 612pt window is laid out CENTRED, which put
//  the sidebar's rows about 1,800 points above the top of the window. AppKit then
//  persisted the split view's subview frames under the window's autosave name, so it
//  survived closing and reopening and the user could not recover without deleting a
//  defaults key.
//
//  THE SYMPTOM APPEARED IN A DIFFERENT COLUMN FROM THE CAUSE, which is why it was
//  chased twice in the wrong file. That is the general shape this pins.
//
//  WHERE THE HEIGHT CAME FROM. `MaturityBannerScaffold` mounts the "nobody has tested
//  this yet" banner ABOVE the editor's `TabView` — deliberately, so it is not one
//  more thing to scroll past — which makes it the one part of the pane that is not
//  inside a scroll container. Everything in a `Form` may be as tall as it likes,
//  because a `Form` scrolls; this may not. Its paragraph carried a bare
//  `.fixedSize(horizontal: false, vertical: true)`, and SwiftUI measures the two axes
//  independently: the minimum-height query arrives with a width proposal of nearly
//  nothing, so a paragraph never drawn narrower than 500pt answered with its height
//  at one word per line.
//
//  WHAT IS MEASURED HERE is `sizeThatFits(in:)` with a width proposal of ZERO, which
//  is exactly the query that blew up — an ordinary measurement at a sensible width
//  looked fine throughout, which is why nothing caught it.
//

import AppKit
import SwiftUI
import Testing
@testable import SimpleVPN

@MainActor
struct EditorPaneHeightTests {

    /// The shortest editor pane this app can produce: the `minHeight` on Manage VPNs'
    /// `NavigationSplitView`, less its toolbar. A pane whose MINIMUM exceeds this
    /// cannot be drawn in the window without overflowing it — and overflowing it takes
    /// the sidebar with it.
    private static let shortestPane: CGFloat = 560 - 52

    /// What this view would demand if it were squeezed as hard as the layout system
    /// can squeeze it. A width proposal of zero is not hypothetical: it is the
    /// proposal SwiftUI uses when it asks a subtree for its minimum size, which is
    /// what an `NSSplitView` column is ultimately sized against.
    private func minimumHeight<V: View>(of view: V) -> CGFloat {
        NSHostingController(rootView: view).sizeThatFits(in: .zero).height
    }

    /// EVERY MATURITY BANNER FITS IN THE SHORTEST WINDOW. One per kind that has a
    /// notice, because the paragraph is written per-kind and the longest one breaks
    /// first — the F5's was the one the user hit, and it was not the longest.
    @Test func noMaturityBannerCanOutgrowTheWindow() {
        for kind in VPNKind.allCases {
            guard let notice = kind.maturityNotice else { continue }
            let height = minimumHeight(of: MaturityBanner(
                notice: notice,
                request: .init(kind: kind, profileID: "test", reason: .untestedKind)))
            #expect(height <= Self.shortestPane, """
                \(kind.displayName)'s maturity banner demands \(height)pt at its minimum \
                width. It is mounted above the editor's TabView, outside every scroll \
                container, so that is the minimum height of the whole detail pane — and \
                NavigationSplitView gives the sidebar the same height, which is how a \
                tall banner empties the sidebar of a window that is far shorter
                """)
        }
    }

    /// THE SAME FOR THE OTHER BANNER IN THAT FILE. `FeatureRequestBanner` is built to
    /// the same pattern, is shown in the same places, and had the same paragraph — so
    /// stating it only for the maturity one would leave the identical fault live.
    @Test func noFeatureRequestBannerCanOutgrowTheWindow() {
        for notice in FeatureRequestNotice.all {
            let height = minimumHeight(of: FeatureRequestBanner(notice: notice))
            #expect(height <= Self.shortestPane,
                    "the \(notice.subject) feature-request banner demands \(height)pt at its minimum width")
        }
    }

    /// AND THE SCAFFOLD THAT MOUNTS IT, which is what an editor actually gets. A
    /// banner that is fine on its own but is mounted in a container that adds an
    /// unbounded paragraph of its own would pass the test above and still empty the
    /// sidebar.
    @Test func theBannerScaffoldAddsNoUnboundedHeightToAnEditor() {
        let content: CGFloat = 200
        for kind in VPNKind.allCases where kind.maturityNotice != nil {
            let scaffolded = Color.clear
                .frame(width: 400, height: content)
                .modifier(MaturityBannerScaffold(kind: kind, profileID: "test"))
            let height = minimumHeight(of: scaffolded)
            #expect(height <= Self.shortestPane + content, """
                \(kind.displayName): the editor scaffold's minimum height is \(height)pt \
                around \(content)pt of content — the banner above it is demanding the \
                rest, and that demand reaches the split view
                """)
        }
    }

    /// THE PARAGRAPH IS THE PART THAT BREAKS, and it breaks by being measured at a
    /// width nobody will ever draw it at. Stated on its own so that a future edit
    /// reintroducing a bare `.fixedSize(horizontal: false, vertical: true)` on a long
    /// explanatory paragraph fails HERE, with the reason, rather than three views up
    /// as an arithmetic mystery about a sidebar.
    @Test func aNoticeParagraphIsNeverMeasuredOneWordWide() throws {
        let notice = try #require(VPNKind.f5apm.maturityNotice)
        let controller = NSHostingController(rootView: NoticeParagraph(text: notice.detail))
        let squeezed = controller.sizeThatFits(in: .zero)
        #expect(squeezed.width >= NoticeParagraph.minimumWidth, """
            the paragraph reports a minimum width of \(squeezed.width)pt, so its minimum \
            HEIGHT is measured at roughly one word per line — which is where 4,527 \
            points came from
            """)
        #expect(squeezed.height <= 320, "minimum height \(squeezed.height)pt")

        // …and the floor changes NOTHING at a width anyone will ever see, which is the
        // claim that makes it safe. The narrowest real pane is a 760pt window less a
        // 200pt sidebar.
        let unbounded = CGFloat.greatestFiniteMagnitude
        let real = controller.sizeThatFits(in: CGSize(width: 560, height: unbounded))
        #expect(real.width <= 560)
        #expect(real.height <= 160, "at a real width the paragraph is \(real.height) points")
    }
}
