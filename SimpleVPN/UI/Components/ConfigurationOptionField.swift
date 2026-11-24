// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit
import SwiftUI

/// One SSH directive or OpenConnect argument. AppKit owns the normal single-line
/// field editor, its selection, native text entry, and its plain-text pasteboard.
struct ConfigurationOptionField: NSViewRepresentable {
    @Binding var text: String
    let format: ConfigSyntax.Format
    let prompt: String
    let accessibilityLabel: String
    var onSubmit: (() -> Void)? = nil
    @Environment(\.isEnabled) private var isEnabled
    @Environment(\.settingCommit) private var commit

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSTextField {
        let field = OptionTextField(string: "")
        field.didSubmit = { [weak coordinator = context.coordinator] field in
            coordinator?.restoreAppearanceAfterSubmit(field)
        }
        field.isEditable = true
        field.isSelectable = true
        field.bezelStyle = .roundedBezel
        field.usesSingleLineMode = true
        field.allowsEditingTextAttributes = false
        field.font = .monospacedSystemFont(ofSize: NSFont.systemFontSize(for: .small), weight: .regular)
        field.delegate = context.coordinator
        field.setContentHuggingPriority(.defaultLow, for: .horizontal)
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        return field
    }

    func updateNSView(_ field: NSTextField, context: Context) {
        context.coordinator.parent = self
        field.placeholderString = prompt
        field.setAccessibilityLabel(accessibilityLabel)
        field.isEnabled = isEnabled
        if let editor = field.currentEditor() as? NSTextView {
            guard !editor.hasMarkedText(), !editor.string.utf8.elementsEqual(text.utf8) else { return }
            let selected = editor.selectedRange()
            editor.string = text
            editor.setSelectedRange(NSRange(location: min(selected.location, (text as NSString).length), length: 0))
            context.coordinator.paint(editor)
        } else {
            context.coordinator.display(text, in: field)
        }
    }

    static func dismantleNSView(_ field: NSTextField, coordinator: Coordinator) {
        coordinator.clearEditor()
        field.delegate = nil
    }

    @MainActor final class Coordinator: NSObject, NSTextFieldDelegate {
        fileprivate var parent: ConfigurationOptionField
        private weak var activeEditor: NSTextView?
        // The window reuses this editor for ordinary prose fields. Restore its
        // user's typing preferences as soon as the configuration field loses it.
        private var typingSettings: [(ReferenceWritableKeyPath<NSTextView, Bool>, Bool)] = []
        private static let proseSettings: [ReferenceWritableKeyPath<NSTextView, Bool>] = [
            \.isAutomaticQuoteSubstitutionEnabled, \.isAutomaticDashSubstitutionEnabled,
            \.isAutomaticTextReplacementEnabled, \.isAutomaticSpellingCorrectionEnabled,
            \.isContinuousSpellCheckingEnabled, \.isGrammarCheckingEnabled,
            \.isAutomaticTextCompletionEnabled
        ]
        private var displayed: (text: String, format: ConfigSyntax.Format, enabled: Bool)?

        init(_ parent: ConfigurationOptionField) { self.parent = parent }

        func controlTextDidBeginEditing(_ notification: Notification) {
            guard let editor = (notification.object as? NSTextField)?.currentEditor() as? NSTextView else { return }
            beginEditing(editor)
        }

        fileprivate func restoreAppearanceAfterSubmit(_ field: NSTextField) {
            // AppKit can reselect the same field after Return and initialize
            // its shared editor after the delegate's end-editing notification.
            if let editor = field.currentEditor() as? NSTextView {
                beginEditing(editor)
            } else {
                displayed = nil
                display(parent.text, in: field)
            }
        }

        private func beginEditing(_ editor: NSTextView) {
            if activeEditor === editor { paint(editor); return }
            clearEditor()
            activeEditor = editor
            typingSettings = Self.proseSettings.map { ($0, editor[keyPath: $0]) }
            for setting in Self.proseSettings { editor[keyPath: setting] = false }
            displayed = nil
            paint(editor)
        }

        func controlTextDidChange(_ notification: Notification) {
            guard let editor = (notification.object as? NSTextField)?.currentEditor() as? NSTextView else { return }
            guard !editor.hasMarkedText() else { return }
            parent.text = editor.string
            paint(editor)
        }

        func controlTextDidEndEditing(_ notification: Notification) {
            guard let field = notification.object as? NSTextField else { return }
            clearEditor()
            // Changes already reached the binding while the row was active.
            // An indexed list may have moved another option here during removal.
            display(parent.text, in: field)
            if notification.userInfo?["NSTextMovement"] as? Int == NSTextMovement.return.rawValue {
                parent.onSubmit?()
            }
            parent.commit()
        }

        fileprivate func clearEditor() {
            if let editor = activeEditor {
                for (setting, previous) in typingSettings { editor[keyPath: setting] = previous }
                editor.layoutManager?.removeTemporaryAttribute(.foregroundColor,
                    forCharacterRange: NSRange(location: 0, length: (editor.string as NSString).length))
            }
            activeEditor = nil
            typingSettings.removeAll(keepingCapacity: true)
        }

        fileprivate func paint(_ editor: NSTextView) {
            guard let layout = editor.layoutManager else { return }
            let source = editor.string
            let range = NSRange(location: 0, length: (source as NSString).length)
            layout.addTemporaryAttribute(.foregroundColor, value: NSColor.textColor, forCharacterRange: range)
            for span in ConfigSyntax.spans(in: source, format: parent.format) {
                layout.addTemporaryAttribute(.foregroundColor, value: span.kind.sourceColor, forCharacterRange: span.range)
            }
        }

        fileprivate func display(_ source: String, in field: NSTextField) {
            if let displayed, displayed.text.utf8.elementsEqual(source.utf8), displayed.format == parent.format,
               displayed.enabled == field.isEnabled { return }
            let shown = NSMutableAttributedString(string: source, attributes: [
                .font: field.font ?? NSFont.systemFont(ofSize: NSFont.systemFontSize),
                .foregroundColor: field.isEnabled ? NSColor.textColor : .disabledControlTextColor
            ])
            if field.isEnabled {
                for span in ConfigSyntax.spans(in: source, format: parent.format) {
                    shown.addAttribute(.foregroundColor, value: span.kind.sourceColor, range: span.range)
                }
            }
            field.attributedStringValue = shown
            displayed = (source, parent.format, field.isEnabled)
        }
    }
}


private final class OptionTextField: NSTextField {
    var didSubmit: ((NSTextField) -> Void)?

    override func textDidEndEditing(_ notification: Notification) {
        super.textDidEndEditing(notification)
        if notification.userInfo?["NSTextMovement"] as? Int == NSTextMovement.return.rawValue {
            didSubmit?(self)
        }
    }
}
