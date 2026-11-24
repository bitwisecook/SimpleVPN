// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit
import SwiftUI

extension ConfigSyntax.Kind {
    var sourceColor: NSColor {
        switch self {
        case .keyword: ConfigSyntaxColors.keyword
        case .section: ConfigSyntaxColors.section
        case .string: ConfigSyntaxColors.string
        case .number: ConfigSyntaxColors.number
        case .comment, .punctuation: ConfigSyntaxColors.secondary
        case .literal: .labelColor
        }
    }
}

/// Short directives embedded in prose or table rows retain the caller's text style.
struct ConfigSourceLabel: View {
    let text: String
    let format: ConfigSyntax.Format

    var body: some View {
        var source = AttributedString(text)
        for span in ConfigSyntax.spans(in: text, format: format) {
            if let utfRange = Range(span.range, in: text),
               let range = Range(utfRange, in: source) {
                source[range].foregroundColor = Color(nsColor: span.kind.sourceColor)
            }
        }
        return Text(source)
    }
}

struct ConfigurationSourceText: NSViewRepresentable {
    @Binding var text: String
    let format: ConfigSyntax.Format
    let accessibilityLabel: String
    var initialFocus = false
    var languageDocument: RoutingEditorDocument?
    @Environment(\.isEnabled) private var enabled
    @Environment(\.settingCommit) private var commit

    init(text: Binding<String>, format: ConfigSyntax.Format, accessibilityLabel: String,
         initialFocus: Bool = false, languageDocument: RoutingEditorDocument? = nil) {
        _text = text
        self.format = format
        self.accessibilityLabel = accessibilityLabel
        self.initialFocus = initialFocus
        self.languageDocument = languageDocument
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeNSView(context: Context) -> NSScrollView {
        let editor = SourceTextView(usingTextLayoutManager: false)
        editor.focusOnAttach = initialFocus
        editor.languageDocument = languageDocument
        editor.delegate = context.coordinator
        editor.isRichText = false
        editor.importsGraphics = false
        editor.allowsUndo = true
        editor.isSelectable = true
        editor.drawsBackground = false
        editor.usesFindBar = true
        editor.isAutomaticQuoteSubstitutionEnabled = false
        editor.isAutomaticDashSubstitutionEnabled = false
        editor.isAutomaticTextReplacementEnabled = false
        editor.isAutomaticTextCompletionEnabled = false
        editor.isAutomaticSpellingCorrectionEnabled = false
        editor.isContinuousSpellCheckingEnabled = false
        editor.isAutomaticLinkDetectionEnabled = false
        editor.smartInsertDeleteEnabled = false
        editor.font = .monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        editor.textColor = .textColor
        editor.textContainerInset = NSSize(width: 4, height: 5)
        editor.isVerticallyResizable = true
        editor.isHorizontallyResizable = false
        editor.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        editor.autoresizingMask = [.width]
        editor.textContainer?.widthTracksTextView = true
        editor.textContainer?.containerSize = NSSize(width: 0, height: CGFloat.greatestFiniteMagnitude)

        let scroll = NSScrollView()
        scroll.drawsBackground = false
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.findBarPosition = .aboveContent
        scroll.documentView = editor
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let editor = scroll.documentView as? NSTextView else { return }
        languageDocument?.attach(editor)
        editor.isEditable = enabled
        editor.setAccessibilityLabel(accessibilityLabel)
        context.coordinator.update(editor, text: $text, format: format, commit: commit)
    }

    static func dismantleNSView(_ scroll: NSScrollView, coordinator: Coordinator) {
        (scroll.documentView as? NSTextView)?.delegate = nil
        coordinator.stop()
    }

    private final class SourceTextView: NSTextView {
        var focusOnAttach = false
        weak var languageDocument: RoutingEditorDocument?
        private var hoverArea: NSTrackingArea?
        private var hoverTask: Task<Void, Never>?
        private var hoverRevision = 0

        override func updateTrackingAreas() {
            super.updateTrackingAreas()
            if let hoverArea { removeTrackingArea(hoverArea); self.hoverArea = nil }
            guard languageDocument != nil else { return }
            let area = NSTrackingArea(rect: .zero, options: [.activeInKeyWindow, .inVisibleRect, .mouseMoved, .mouseEnteredAndExited], owner: self, userInfo: nil)
            addTrackingArea(area)
            hoverArea = area
        }

        override func mouseMoved(with event: NSEvent) {
            super.mouseMoved(with: event)
            guard let languageDocument else { return }
            resetHover()
            let revision = hoverRevision
            let point = convert(event.locationInWindow, from: nil)
            let offset = characterIndexForInsertion(at: point)
            hoverTask = Task { [weak self, weak languageDocument] in
                do { try await Task.sleep(for: .milliseconds(450)) } catch { return }
                guard let self, let languageDocument, window != nil, hoverRevision == revision else { return }
                languageDocument.hover(at: offset) { [weak self] text in
                    guard let self, hoverRevision == revision else { return }
                    toolTip = text
                }
            }
        }

        override func mouseExited(with event: NSEvent) {
            super.mouseExited(with: event)
            resetHover()
        }

        private func resetHover() {
            hoverTask?.cancel()
            hoverRevision &+= 1
            if toolTip != nil { toolTip = nil }
        }


        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if window == nil { resetHover() }
            guard focusOnAttach, let window else { return }
            DispatchQueue.main.async { [weak self, weak window] in
                guard let self, let window, self.window === window, isEditable else { return }
                focusOnAttach = false
                window.makeFirstResponder(self)
            }
        }

        override func unmarkText() {
            super.unmarkText()
            (delegate as? Coordinator)?.didEdit(self)
        }
    }

    final class Coordinator: NSObject, NSTextViewDelegate {
        private var model: Binding<String>?
        private var lastSource: String?
        private var format: ConfigSyntax.Format?
        private var commit = SettingCommit()
        private var edited = false
        private var externalChangeWhileComposing = false
        private let history = UndoManager()
        private var highlight: Task<Void, Never>?

        func update(_ editor: NSTextView, text: Binding<String>, format: ConfigSyntax.Format,
                    commit: SettingCommit) {
            model = text
            self.commit = commit
            let formatChanged = self.format != format
            self.format = format
            let newSource = text.wrappedValue
            // Configurations can contain canonically equivalent but byte-distinct
            // strings. A programmatic replacement must preserve the supplied bytes.
            let sourceChanged = lastSource?.utf8.elementsEqual(newSource.utf8) != true
            if editor.hasMarkedText() {
                externalChangeWhileComposing = sourceChanged
                return
            }
            if sourceChanged { replaceSource(in: editor, with: newSource) }
            if sourceChanged || formatChanged { scheduleHighlight(in: editor) }
        }

        private func replaceSource(in editor: NSTextView, with source: String) {
            let selection = editor.selectedRanges
            let origin = editor.enclosingScrollView?.contentView.bounds.origin
            lastSource = source
            edited = false
            editor.string = source
            history.removeAllActions()
            let length = (source as NSString).length
            editor.selectedRanges = selection.map { value in
                let range = value.rangeValue
                let start = min(range.location, length)
                let end = min(NSMaxRange(range), length)
                return NSValue(range: NSRange(location: start, length: end - start))
            }
            if let origin, let clip = editor.enclosingScrollView?.contentView {
                let proposed = NSRect(origin: origin, size: clip.bounds.size)
                clip.scroll(to: clip.constrainBoundsRect(proposed).origin)
            }
        }

        func undoManager(for view: NSTextView) -> UndoManager? { history }

        func textDidChange(_ notification: Notification) {
            guard let editor = notification.object as? NSTextView else { return }
            didEdit(editor)
        }

        fileprivate func didEdit(_ editor: NSTextView) {
            guard !editor.hasMarkedText(), let model else { return }
            if externalChangeWhileComposing {
                externalChangeWhileComposing = false
                replaceSource(in: editor, with: model.wrappedValue)
            } else {
                let value = editor.string
                guard lastSource?.utf8.elementsEqual(value.utf8) != true else { return }
                lastSource = value
                edited = true
                model.wrappedValue = value
            }
            scheduleHighlight(in: editor)
        }

        func textDidEndEditing(_ notification: Notification) {
            guard edited else { return }
            edited = false
            commit()
        }

        func stop() {
            highlight?.cancel()
            highlight = nil
            model = nil
            lastSource = nil
            commit = SettingCommit()
            history.removeAllActions()
        }

        private func scheduleHighlight(in editor: NSTextView) {
            highlight?.cancel()
            guard let source = lastSource, let format, !source.isEmpty else {
                highlight = nil
                return
            }
            highlight = Task { [weak editor] in
                try? await Task.sleep(for: .milliseconds(100))
                guard !Task.isCancelled else { return }
                let spans = await Self.scan(source, format: format)
                guard !Task.isCancelled, let editor, !editor.hasMarkedText(),
                      let layout = editor.layoutManager, let storage = editor.textStorage else { return }
                layout.removeTemporaryAttribute(.foregroundColor,
                                                forCharacterRange: NSRange(location: 0, length: storage.length))
                for span in spans {
                    layout.addTemporaryAttribute(.foregroundColor, value: span.kind.sourceColor,
                                                 forCharacterRange: span.range)
                }
            }
        }

        @concurrent
        private static func scan(_ source: String, format: ConfigSyntax.Format) async -> [ConfigSyntax.Span] {
            ConfigSyntax.spans(in: source, format: format)
        }
    }
}
