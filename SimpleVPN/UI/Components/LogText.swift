// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  LogText.swift
//  A read-only, syntax-highlighted, fully selectable log viewer.
//
//  Backed by NSTextView, not a stack of SwiftUI Text views. The first version drew one
//  Text per line — which highlighted beautifully and broke the only thing this text is
//  for: ⌘A selected a single line, and a drag couldn't cross a line boundary. Since the
//  whole purpose of showing a log here is that the user copies it into a bug report,
//  selection is the feature and colouring is the garnish.
//
//  NSTextView is also simply the right tool: TextKit handles hundreds of KB of text
//  without complaint, and ⌘F (find) comes free — genuinely useful when you're checking a
//  diagnostics bundle for your own hostname before sharing it.
//

import SwiftUI
import AppKit

struct LogText: NSViewRepresentable {
    let text: String
    /// Point size; callers use the same scale as the surrounding UI.
    var fontSize: CGFloat = 11
    @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor

    final class Coordinator {
        /// What we last pushed into the view, so a SwiftUI re-render doesn't rebuild the
        /// attributed string and wipe the user's selection mid-drag.
        var rendered: String?
        var renderedSize: CGFloat = 0
        var renderedDWC = false
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeNSView(context: Context) -> NSScrollView {
        let textView = NSTextView()
        textView.isEditable = false
        textView.isSelectable = true
        textView.drawsBackground = false
        textView.textContainerInset = NSSize(width: 4, height: 6)
        // It's a log: substitutions would corrupt what the user copies out.
        textView.isAutomaticQuoteSubstitutionEnabled = false
        textView.isAutomaticDashSubstitutionEnabled = false
        textView.isAutomaticSpellingCorrectionEnabled = false
        textView.isAutomaticTextReplacementEnabled = false
        textView.usesFindBar = true
        textView.isIncrementalSearchingEnabled = true
        textView.allowsUndo = false

        // Wrap to the view's width and grow vertically.
        textView.minSize = NSSize(width: 0, height: 0)
        textView.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude,
                                  height: CGFloat.greatestFiniteMagnitude)
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.autoresizingMask = [.width]
        textView.textContainer?.widthTracksTextView = true
        textView.textContainer?.containerSize = NSSize(width: 0,
                                                      height: CGFloat.greatestFiniteMagnitude)

        // Without a name VoiceOver introduces this as a bare "text" — say what
        // it holds (the content itself is readable/selectable as usual).
        textView.setAccessibilityLabel("Log")

        let scroll = NSScrollView()
        scroll.documentView = textView
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.drawsBackground = false
        // The find bar needs the scroll view to own it.
        scroll.findBarPosition = .aboveContent
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let textView = scroll.documentView as? NSTextView else { return }
        let coordinator = context.coordinator
        guard coordinator.rendered != text || coordinator.renderedSize != fontSize
                || coordinator.renderedDWC != differentiateWithoutColor else { return }
        coordinator.rendered = text
        coordinator.renderedSize = fontSize
        coordinator.renderedDWC = differentiateWithoutColor
        let font = NSFont.monospacedSystemFont(ofSize: fontSize, weight: .regular)
        textView.textStorage?.setAttributedString(
            LogHighlighter.nsAttributed(text, font: font,
                                        differentiateWithoutColor: differentiateWithoutColor))
    }
}

/// Copy the whole log in one click. Selection works properly now, but for a few hundred
/// lines "copy everything" is what people actually want, and it shouldn't require a
/// scroll-and-drag.
struct CopyLogButton: View {
    let text: String
    @State private var copied = false

    var body: some View {
        Button {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
            copied = true
            // The label morphing to "Copied" is silent for VoiceOver.
            AccessibilityAnnouncer.sayNow("Log copied")
        } label: {
            Label(copied ? "Copied" : "Copy All",
                  systemImage: copied ? "checkmark" : "doc.on.doc")
                .contentTransition(.symbolEffect(.replace))
        }
        .controlSize(.small)
        .help("Copy the whole text to the clipboard (⌘A then ⌘C also works)")
    }
}
