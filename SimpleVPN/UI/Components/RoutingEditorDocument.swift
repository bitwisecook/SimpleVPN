// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit
import Observation

nonisolated struct RoutingLSPPosition: Codable, Equatable {
    let line, character: Int
    var object: [String: Int] { ["line": line, "character": character] }

    static func at(_ offset: Int, in text: String) -> Self {
        let source = text as NSString
        let prefix = source.substring(to: min(max(0,offset),source.length)) as NSString
        let lines = (prefix as String).components(separatedBy: "\n")
        return Self(line: lines.count - 1, character: (lines.last ?? "").utf16.count)
    }

    func offset(in lines: [String]) -> Int? {
        guard line >= 0, line < lines.count, character >= 0 else { return nil }
        let current = lines[line] as NSString
        let width = current.hasSuffix("\r") ? current.length - 1 : current.length
        guard character <= width else { return nil }
        return lines.prefix(line).reduce(0) { $0 + $1.utf16.count + 1 } + character
    }
}

nonisolated struct RoutingLSPRange: Codable, Equatable {
    let start, end: RoutingLSPPosition
    func range(in lines: [String]) -> NSRange? {
        guard let a = start.offset(in: lines), let b = end.offset(in: lines), a <= b else { return nil }
        return NSRange(location: a, length: b-a)
    }
}

nonisolated struct RoutingIssue: Decodable {
    let message: String
    let range: RoutingLSPRange
}

nonisolated struct RoutingSuggestion: Decodable, Identifiable {
    struct Edit: Decodable { let range: RoutingLSPRange; let newText: String }
    let label, detail: String
    let textEdit: Edit
    var id: String { label }
}

nonisolated struct RoutingTreeNode: Decodable, Identifiable {
    let kind: String
    let name, event: String?
    let selectionRange: RoutingLSPRange
    let children: [RoutingTreeNode]
    var id: String { "\(kind)-\(selectionRange.start.line)-\(selectionRange.start.character)" }
    var branches: [RoutingTreeNode]? { children.isEmpty ? nil : children }
    var title: String { [name ?? kind,event].compactMap { $0 }.joined(separator: " · ") }
}

nonisolated struct RoutingDiagramEvent: Decodable, Identifiable {
    struct Handler: Decodable, Identifiable { let name:String; let range:RoutingLSPRange; var id: String {name} }
    let event:String
    let handlers:[Handler]
    var id:String { event }
    var layer: String {
        switch event.split(separator: ".").first {
        case "ip","ipv4","ipv6": "IP packet"
        case "tcp","udp","icmp","icmpv6": "Transport and control"
        case "tls","quic","dns": "Protocol observation"
        case "ssh": "SSH forwarding"
        default: "Adapter events"
        }
    }
}

@MainActor @Observable
final class RoutingEditorDocument {
    enum Panel: String, Identifiable { case completions, help, tree, events; var id: Self { self } }
    let uri = "simplevpn-routing://editor/" + UUID().uuidString
    let adapter: String
    private(set) var version = 0
    private(set) var source = ""
    private(set) var issues: [RoutingIssue] = []
    private(set) var notice: String?
    private(set) var suggestions: [RoutingSuggestion] = []
    private(set) var events: [RoutingDiagramEvent] = []
    private(set) var nodes: [RoutingTreeNode] = []
    private(set) var detail = ""
    private(set) var truncated = false
    private(set) var railroad: RoutingBlockSnapshot?
    private(set) var railroadSource = ""
    private(set) var railroadError: String?
    var panel: Panel?
    private(set) var loading = false
    @ObservationIgnored private weak var editor: NSTextView?
    @ObservationIgnored private var pending: Task<Void, Never>?
    @ObservationIgnored private var visible = false
    @ObservationIgnored private var ready = false
    @ObservationIgnored private var sent = -1
    @ObservationIgnored private var query = 0
    @ObservationIgnored private var showsRailroad = false
    private var client: RoutingLanguageClient { .shared }

    init(adapter: String) { self.adapter = adapter }

    func attach(_ editor: NSTextView) { self.editor = editor }

    func appear(source: String) {
        guard !visible else { return }
        visible = true
        self.source = source
        if fits { client.open(self) } else { notice = Self.tooLarge }
    }
    private static let tooLarge = "Language tools support up to 32 KiB of source."
    private var fits: Bool { source.utf8.count <= 32768 }
    func changed(_ next: String) {
        guard visible, !source.utf8.elementsEqual(next.utf8) else { return }
        source = next
        version += 1
        issues = []
        railroadError = nil
        loading = false
        clearMarks()
        panel = nil
        query += 1
        pending?.cancel()
        guard fits else {
            client.close(self)
            ready = false
            railroad = nil
            railroadSource = ""
            notice = Self.tooLarge
            return
        }
        if notice == Self.tooLarge { notice = nil; client.open(self); return }
        pending = Task { [weak self] in
            do { try await Task.sleep(for: .milliseconds(180)) } catch { return }
            self?.flush()
        }
    }
    func opened() { ready = true; sent = version; notice = nil; refreshRailroad() }
    func unavailable() {
        ready = false
        loading = false
        railroad = nil
        railroadSource = ""
        notice = "Language tools are unavailable. You can still edit and save the rules."
    }
    func retry() { guard visible, fits else { return }; client.open(self) }
    func close() {
        pending?.cancel()
        query += 1
        client.close(self)
        clearMarks()
        editor = nil
        visible = false
        ready = false
        source = ""
        issues = []
        suggestions = []
        nodes = []
        railroad = nil
        railroadSource = ""
        railroadError = nil
        panel = nil
    }
    private func flush() {
        if ready, sent != version, fits {
            client.change(self)
            sent = version
            refreshRailroad()
        }
    }

    func showRailroad(_ show: Bool) {
        showsRailroad = show
        if show {
            if sent != version { flush() }
            else { refreshRailroad() }
        }
    }

    private func refreshRailroad() {
        guard showsRailroad, ready, fits else { return }
        let revision = version
        client.request("simplevpn/railroad", params: ["textDocument": ["uri": uri]], uri: uri) { [weak self] reply in
            guard let self, visible, version == revision else { return }
            if let next = decode(reply, as: RoutingBlockSnapshot.self), next.version == revision {
                railroadSource = source
                railroad = next
                railroadError = nil
            } else {
                railroadError = "The routing diagram is unavailable."
            }
        }
    }

    var canUndo: Bool { editor?.undoManager?.canUndo == true }
    var canRedo: Bool { editor?.undoManager?.canRedo == true }

    func undoRailroad(redo: Bool = false) {
        guard let editor, editor.isEditable, !editor.hasMarkedText() else { return }
        if redo { editor.undoManager?.redo() } else { editor.undoManager?.undo() }
        changed(editor.string)
        flush()
    }

    @discardableResult
    func editRailroad(_ edit: RoutingBlockSource.Edit, version revision: Int, action: String) -> Bool {
        guard let editor, editor.isEditable, !editor.hasMarkedText(), revision == version,
              railroad?.version == revision, railroad?.complete == true, railroad?.limited == false,
              editor.string.utf8.elementsEqual(source.utf8),
              let range = Range(edit.range, in: source) else { return false }
        var next = source
        next.replaceSubrange(range, with: edit.replacement)
        guard next.utf8.count <= 32768 else {
            railroadError = "This edit would exceed the 32 KiB source limit."
            return false
        }
        editor.breakUndoCoalescing()
        editor.insertText(edit.replacement, replacementRange: edit.range)
        editor.breakUndoCoalescing()
        guard editor.string.utf8.elementsEqual(next.utf8) else { return false }
        editor.undoManager?.setActionName(action)
        changed(editor.string)
        flush()
        return true
    }
    private func decode<T: Decodable>(_ object: Any?, as: T.Type) -> T? {
        guard let object, JSONSerialization.isValidJSONObject(object),
              let data = try? JSONSerialization.data(withJSONObject: object) else { return nil }
        return try? JSONDecoder().decode(T.self, from: data)
    }
    private func clearMarks() {
        guard let editor, let storage = editor.textStorage, let layout = editor.layoutManager else { return }
        let range = NSRange(location: 0,length: storage.length)
        layout.removeTemporaryAttribute(.underlineStyle, forCharacterRange: range)
        layout.removeTemporaryAttribute(.underlineColor, forCharacterRange: range)
    }
    func publish(_ params: [String: Any]) {
        guard params["version"] as? Int == version,
              let parsed = decode(params["diagnostics"], as: [RoutingIssue].self) else { return }
        issues = parsed
        clearMarks()
        guard let editor, editor.string.utf8.elementsEqual(source.utf8), !editor.hasMarkedText(), let layout = editor.layoutManager else { return }
        let lines = source.components(separatedBy: "\n")
        for issue in issues {
            guard let range = issue.range.range(in: lines) else { continue }
            layout.addTemporaryAttributes([.underlineColor:NSColor.systemRed,.underlineStyle:NSUnderlineStyle.patternDot.rawValue | NSUnderlineStyle.single.rawValue],forCharacterRange:range)
        }
    }

    func reveal(_ range: RoutingLSPRange) {
        guard let editor, editor.string.utf8.elementsEqual(source.utf8), let r = range.range(in: source.components(separatedBy: "\n")) else { return }
        panel = nil
        editor.window?.makeFirstResponder(editor)
        editor.setSelectedRange(r)
        editor.scrollRangeToVisible(r)
    }

    func insert(_ suggestion: RoutingSuggestion) {
        guard let editor, editor.isEditable, !editor.hasMarkedText(), editor.string.utf8.elementsEqual(source.utf8),
              let r = suggestion.textEdit.range.range(in: source.components(separatedBy: "\n")) else { return }
        panel = nil
        editor.window?.makeFirstResponder(editor)
        editor.insertText(suggestion.textEdit.newText, replacementRange: r)
    }

    func addHandler(for event: String, revealSource: Bool = true, added: ((String) -> Void)? = nil) {
        guard let editor, editor.isEditable, !editor.hasMarkedText(), ready, !loading else { return }
        flush()
        let revision = version
        loading = true
        client.request("simplevpn/addHandler", params: ["textDocument":["uri":uri],"event":event,"version":revision],uri:uri) { [weak self,weak editor] reply in
            guard let self, let editor, version == revision, editor.string.utf8.elementsEqual(source.utf8) else { return }
            loading = false
            guard let r = reply as? [String: Any],
                  let edit = decode(r["edit"], as: RoutingSuggestion.Edit.self),
                  let range = edit.range.range(in: source.components(separatedBy: "\n")),
                  let location = decode(r["selectionRange"],as: RoutingLSPRange.self) else {
                let message = (reply as? [String: Any])?["message"] as? String ?? "This handler could not be added to the current source."
                if revealSource { detail = message } else { railroadError = message }
                return
            }
            panel = nil
            editor.breakUndoCoalescing()
            editor.insertText(edit.newText,replacementRange: range)
            editor.breakUndoCoalescing()
            editor.undoManager?.setActionName("Add Handler")
            changed(editor.string)
            flush()
            if revealSource { reveal(location) }
            if let name = r["name"] as? String { added?(name) }
        }
    }

    func hover(at offset: Int, reply: @escaping (String?) -> Void) {
        guard ready, let editor, !editor.hasMarkedText(), editor.string.utf8.elementsEqual(source.utf8) else { return }
        flush()
        let revision = version
        let pos = RoutingLSPPosition.at(offset, in: source)
        client.request("textDocument/hover", params: ["textDocument":["uri":uri],"position":["line":pos.line,"character":pos.character]], uri:uri) { [weak self] value in
            guard let self, version == revision else { return }
            let contents = (value as? [String: Any])?["contents"] as? [String: Any]
            reply(contents?["value"] as? String)
        }
    }

    func inspect(_ choice: Panel) {
        guard let editor, ready, !editor.hasMarkedText() else { return }
        flush()
        panel = choice
        loading = true
        detail = ""; nodes = []; suggestions = []; truncated = false
        query += 1
        let token = query, revision = version
        var params: [String: Any] = ["textDocument":["uri":uri]]
        let method: String
        switch choice {
        case .tree: method = "simplevpn/syntaxTree"
        case .events: method = "simplevpn/eventDiagram"
        case .help, .completions:
            method = choice == .help ? "textDocument/hover" : "textDocument/completion"
            params["position"] = RoutingLSPPosition.at(editor.selectedRange().location, in: source).object
        }
        client.request(method, params: params, uri: uri) { [weak self] reply in
            guard let self, token == query, version == revision else { return }
            loading = false
            let result = reply as? [String: Any]
            switch choice {
            case .events:
                events = decode(result?["events"], as: [RoutingDiagramEvent].self) ?? []
            case .tree:
                nodes = decode(result?["nodes"], as: [RoutingTreeNode].self) ?? []
                truncated = result?["truncated"] as? Bool == true
            case .help:
                detail = (result?["contents"] as? [String: Any])?["value"] as? String ?? "Place the insertion point on an event, field, action or declaration."
            case .completions:
                suggestions = decode(result?["items"], as: [RoutingSuggestion].self) ?? []
            }
        }
    }
}
