// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit

private struct Token: Decodable {
    let offset: Int
    let length: Int
    let kind: String
}

private struct Decision: Decodable {
    struct Rule: Decodable {
        struct Action: Decodable { let kind: String; let vpn: String? }
        let id: String
        let line: Int
        let prefix: String?
        let source: String?
        let action: Action
    }
    let destination: String
    let rule: Rule

    var explanation: String {
        let outcome: String
        switch rule.action.kind {
        case "drop": outcome = "would be dropped"
        case "via": outcome = "would go through " + (rule.action.vpn ?? "an unspecified VPN")
        default: outcome = "has an unsupported action (" + rule.action.kind + ")"
        }
        let match: String
        if let source = rule.source, let prefix = rule.prefix { match = "matches source " + source + " and " + prefix }
        else if let source = rule.source { match = "matches source " + source }
        else { match = rule.prefix.map { "matches " + $0 } ?? "uses the default" }
        return "\(destination) \(match) and \(outcome). Rule \(rule.id), line \(rule.line)."
    }
}

@MainActor
private final class Editor: NSObject, NSApplicationDelegate, NSTextViewDelegate, NSTextFieldDelegate {
    private let checker: URL
    private let sample: String
    private let editor = NSTextView(usingTextLayoutManager: false)
    private let address = NSTextField(string: "10.42.8.19")
    private let sourceKind = NSPopUpButton()
    private let sourceAlias = NSTextField(string: "")
    private let result = NSTextField(wrappingLabelWithString: "Test an address against this draft.")
    private var window: NSWindow?
    private var highlightTask: Task<Void, Never>?
    private var highlightProcess: Process?
    private var testProcess: Process?
    private var sourceRevision = 0
    private var testRevision = 0
    private static let sourceLimit = 256 * 1024

    init(checker: URL, sample: String) {
        self.checker = checker
        self.sample = sample
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        installMenus()
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 800, height: 520),
                              styleMask: [.titled, .closable, .miniaturizable, .resizable],
                              backing: .buffered, defer: false)
        self.window = window
        window.title = "Offline Routing Editor"
        window.isReleasedWhenClosed = false
        window.minSize = NSSize(width: 480, height: 330)
        let content = NSView()
        window.contentView = content

        let label = NSTextField(labelWithString: "Routing policy")
        label.font = .preferredFont(forTextStyle: .headline)
        editor.setAccessibilityLabel("Routing policy source")
        editor.setAccessibilityHelp("Edits stay in memory. Use Command-Return to test a destination.")
        editor.isRichText = false
        editor.allowsUndo = true
        editor.isAutomaticQuoteSubstitutionEnabled = false
        editor.isAutomaticDashSubstitutionEnabled = false
        editor.isAutomaticTextReplacementEnabled = false
        editor.isContinuousSpellCheckingEnabled = false
        editor.font = .monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        editor.textColor = .textColor
        editor.textContainerInset = NSSize(width: 8, height: 8)
        editor.isVerticallyResizable = true
        editor.isHorizontallyResizable = false
        editor.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        editor.autoresizingMask = [.width]
        editor.textContainer?.widthTracksTextView = true
        editor.string = sample
        editor.delegate = self
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        scroll.documentView = editor

        address.setAccessibilityLabel("Destination IP address")
        address.placeholderString = "IPv4 or IPv6 address"
        address.delegate = self
        address.target = self
        address.action = #selector(test)
        sourceKind.addItems(withTitles: ["Unknown", "Signed app", "Running process"])
        sourceKind.setAccessibilityLabel("Test source")
        sourceKind.target = self
        sourceKind.action = #selector(changeSource)
        sourceAlias.placeholderString = "Source alias in the policy"
        sourceAlias.setAccessibilityLabel("Source alias in the policy")
        sourceAlias.delegate = self
        sourceAlias.target = self
        sourceAlias.action = #selector(test)
        sourceAlias.isHidden = true
        let sourceControls = NSStackView(views: [NSTextField(labelWithString: "Source"), sourceKind, sourceAlias])
        sourceControls.spacing = 8
        let testButton = NSButton(title: "Test Destination", target: self, action: #selector(test))
        let controls = NSStackView(views: [NSTextField(labelWithString: "Destination"), address, testButton])
        controls.spacing = 8
        result.isSelectable = true
        result.setAccessibilityLabel("Offline test result")
        let stack = NSStackView(views: [label, scroll, sourceControls, controls, result])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        stack.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 16),
            stack.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -16),
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            scroll.widthAnchor.constraint(equalTo: stack.widthAnchor),
            sourceAlias.widthAnchor.constraint(greaterThanOrEqualToConstant: 180),
            controls.widthAnchor.constraint(equalTo: stack.widthAnchor),
            result.widthAnchor.constraint(equalTo: stack.widthAnchor),
            scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 110),
        ])
        window.center()
        window.makeKeyAndOrderFront(nil)
        window.makeFirstResponder(editor)
        NSApp.activate()
        scheduleHighlight()
    }

    private func installMenus() {
        let bar = NSMenu()
        func menu(_ title: String) -> NSMenu {
            let item = NSMenuItem()
            let menu = NSMenu(title: title)
            item.submenu = menu
            bar.addItem(item)
            return menu
        }
        let app = menu("Routing Editor")
        app.addItem(withTitle: "Quit Routing Editor", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        let file = menu("File")
        let run = file.addItem(withTitle: "Test Destination", action: #selector(test), keyEquivalent: "\r")
        run.target = self
        file.addItem(withTitle: "Close Window", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        let edit = menu("Edit")
        for (title, action, key) in [("Undo", "undo:", "z"), ("Redo", "redo:", "Z"),
                                     ("Cut", "cut:", "x"), ("Copy", "copy:", "c"),
                                     ("Paste", "paste:", "v"), ("Select All", "selectAll:", "a")] {
            edit.addItem(withTitle: title, action: Selector(action), keyEquivalent: key)
        }
        NSApp.mainMenu = bar
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationWillTerminate(_ notification: Notification) {
        highlightTask?.cancel()
        cancel(&highlightProcess)
        cancel(&testProcess)
    }

    func textDidChange(_ notification: Notification) {
        invalidateTest()
        scheduleHighlight()
    }

    func controlTextDidChange(_ notification: Notification) { invalidateTest() }

    private func cancel(_ process: inout Process?) {
        if let running = process, running.isRunning { running.terminate() }
        process = nil
    }

    private func invalidateTest() {
        testRevision += 1
        cancel(&testProcess)
        result.stringValue = "Test an address against this draft."
    }

    private func scheduleHighlight() {
        sourceRevision += 1
        let revision = sourceRevision
        highlightTask?.cancel()
        cancel(&highlightProcess)
        highlightTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(200))
            guard !Task.isCancelled, let self else { return }
            let source = editor.string
            guard source.utf8.count <= Self.sourceLimit else {
                clearHighlight()
                result.stringValue = "The draft exceeds the 256 KiB source limit."
                return
            }
            highlightProcess = check(["--tokens", "-"], source: source) { [weak self] data, error in
                guard let self, sourceRevision == revision else { return }
                highlightProcess = nil
                clearHighlight()
                guard let data, let tokens = try? JSONDecoder().decode([Token].self, from: data) else {
                    result.stringValue = error ?? "Could not read highlighting from routecheck."
                    return
                }
                apply(tokens, to: source)
            }
        }
    }

    private func clearHighlight() {
        guard let layout = editor.layoutManager else { return }
        let range = NSRange(location: 0, length: (editor.string as NSString).length)
        layout.removeTemporaryAttribute(.foregroundColor, forCharacterRange: range)
        layout.removeTemporaryAttribute(.underlineStyle, forCharacterRange: range)
    }

    private func apply(_ tokens: [Token], to source: String) {
        guard let layout = editor.layoutManager else { return }
        let bytes = Array(source.utf8)
        var cursor = 0
        var position = 0
        for token in tokens {
            guard token.offset >= cursor, token.offset <= bytes.count, token.length > 0,
                  token.length <= bytes.count - token.offset else { continue }
            let end = token.offset + token.length
            position += String(decoding: bytes[cursor..<token.offset], as: UTF8.self).utf16.count
            let length = String(decoding: bytes[token.offset..<end], as: UTF8.self).utf16.count
            let range = NSRange(location: position, length: length)
            let color: NSColor
            switch token.kind {
            case "keyword": color = ConfigSyntaxColors.keyword
            case "number", "network": color = ConfigSyntaxColors.number
            case "rule": color = .labelColor
            case "vpn", "source": color = ConfigSyntaxColors.string
            case "comment": color = ConfigSyntaxColors.secondary
            case "error":
                color = ConfigSyntaxColors.error
                layout.addTemporaryAttribute(.underlineStyle, value: NSUnderlineStyle.single.rawValue, forCharacterRange: range)
            default: color = .textColor
            }
            layout.addTemporaryAttribute(.foregroundColor, value: color, forCharacterRange: range)
            position += length
            cursor = end
        }
    }

    @objc private func changeSource() {
        sourceAlias.isHidden = sourceKind.indexOfSelectedItem == 0
        invalidateTest()
    }

    @objc private func test() {
        invalidateTest()
        let destination = address.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !destination.isEmpty else { report("Enter a destination IP address."); return }
        let revision = testRevision
        result.stringValue = "Testing…"
        var arguments: [String] = []
        if sourceKind.indexOfSelectedItem > 0 {
            let alias = sourceAlias.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !alias.isEmpty else { report("Enter the source alias from the policy."); return }
            arguments = [sourceKind.indexOfSelectedItem == 1 ? "--app" : "--process", alias]
        }
        arguments += ["-", destination]
        testProcess = check(arguments, source: editor.string) { [weak self] data, error in
            guard let self, revision == testRevision else { return }
            testProcess = nil
            if let data, let decision = try? JSONDecoder().decode(Decision.self, from: data) {
                report(decision.explanation)
            } else {
                report(error ?? "Could not read a decision from routecheck.")
            }
        }
    }

    private func report(_ text: String) {
        result.stringValue = text
        NSAccessibility.post(element: result, notification: .announcementRequested, userInfo: [
            .announcement: text, .priority: NSAccessibilityPriorityLevel.medium.rawValue,
        ])
    }

    // The child gets only the current draft on stdin. Draining output concurrently
    // with the write keeps long token streams from filling either pipe and hanging.
    private func check(_ arguments: [String], source: String,
                       completion: @escaping @MainActor (Data?, String?) -> Void) -> Process? {
        guard source.utf8.count <= Self.sourceLimit else {
            completion(nil, "The draft exceeds the 256 KiB source limit.")
            return nil
        }
        let child = Process()
        let input = Pipe(), output = Pipe()
        child.executableURL = checker
        child.arguments = arguments
        child.standardInput = input
        child.standardOutput = output
        child.standardError = output
        let writer = input.fileHandleForWriting
        _ = fcntl(writer.fileDescriptor, F_SETNOSIGPIPE, 1)
        do { try child.run() } catch { completion(nil, error.localizedDescription); return nil }
        DispatchQueue.global(qos: .userInitiated).async {
            try? writer.write(contentsOf: Data(source.utf8))
            try? writer.close()
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let reader = output.fileHandleForReading
            let data = (try? reader.readToEnd()) ?? Data()
            try? reader.close()
            child.waitUntilExit()
            let ok = child.terminationReason == .exit && child.terminationStatus == 0
            if ok {
                DispatchQueue.main.async { completion(data, nil) }
            } else {
                let message = String(decoding: data.prefix(4096), as: UTF8.self)
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                DispatchQueue.main.async {
                    completion(nil, message.isEmpty ? "routecheck exited with status \(child.terminationStatus)." : message)
                }
            }
        }
        return child
    }
}

let checkerURL: URL
let sampleURL: URL
if CommandLine.arguments.count == 3 {
    checkerURL = URL(fileURLWithPath: CommandLine.arguments[1]).standardizedFileURL
    sampleURL = URL(fileURLWithPath: CommandLine.arguments[2]).standardizedFileURL
} else if CommandLine.arguments.count == 1,
          let sample = Bundle.main.url(forResource: "two-vpns", withExtension: "route") {
    checkerURL = Bundle.main.bundleURL.appending(path: "Contents/Helpers/routecheck")
    sampleURL = sample
} else {
    FileHandle.standardError.write(Data("Usage: RoutingEditor ROUTECHECK SAMPLE.route\n".utf8))
    exit(2)
}
guard FileManager.default.isExecutableFile(atPath: checkerURL.path) else {
    FileHandle.standardError.write(Data("Cannot execute routecheck at \(checkerURL.path).\n".utf8))
    exit(2)
}
let sample = try String(contentsOf: sampleURL, encoding: .utf8)
private let delegate = Editor(checker: checkerURL, sample: sample)
let app = NSApplication.shared
app.setActivationPolicy(.regular)
app.delegate = delegate
app.run()
