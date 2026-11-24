// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit
import SwiftUI
import Testing
@testable import SimpleVPN

@MainActor
struct RoutingLanguageEditorTests {
    @Test func lspRangesUseUTF16Columns() {
        let source = "💡 rules\r\n雪"
        #expect(RoutingLSPPosition.at(2, in: source) == .init(line: 0, character: 2))
        let lines = source.components(separatedBy: "\n")
        #expect(RoutingLSPRange(start: .init(line: 1, character: 0), end: .init(line: 1, character: 1)).range(in: lines) == NSRange(location: 10,length: 1))
    }

    @Test func embeddedPeerServesSourceAndDiagnostics() async throws {
        let code = "# 💡\non allow: ip.packet { count(); }\n"
        let view = NSTextView()
        view.string = code
        let doc = RoutingEditorDocument(adapter: "wireguard")
        doc.attach(view)
        doc.appear(source: code)
        defer { doc.close() }

        let clock = ContinuousClock()
        let limit = clock.now + .seconds(5)
        while doc.panel == nil && clock.now < limit && doc.notice == nil {
            doc.inspect(.tree)
            try await Task.sleep(for: .milliseconds(20))
        }
        while doc.loading && clock.now < limit { try await Task.sleep(for: .milliseconds(20)) }
        #expect(doc.notice == nil)
        #expect(doc.nodes.first?.event == "ip.packet")
        #expect(doc.nodes.first?.name == "allow")

        doc.inspect(.events)
        while doc.loading && clock.now < limit { try await Task.sleep(for: .milliseconds(20)) }
        #expect(doc.events.first { $0.event == "ip.packet" }?.handlers.first?.name == "allow")
        #expect(!doc.events.contains { $0.event == "ssh.forward_open" })
        doc.addHandler(for: "ip.packet")
        while doc.loading && clock.now < limit { try await Task.sleep(for: .milliseconds(20)) }
        #expect((view.string as NSString).substring(with: view.selectedRange()) == "handle_ip_packet")
        doc.addHandler(for: "ip.packet")
        while doc.loading && clock.now < limit { try await Task.sleep(for: .milliseconds(20)) }
        #expect((view.string as NSString).substring(with: view.selectedRange()) == "handle_ip_packet_2")
        #expect(view.string.contains("on handle_ip_packet_2: ip.packet"))

        let invalid = "on invalid: ip.packet { abc.unknown = 1; }"
        view.string = invalid
        doc.changed(invalid)
        while doc.issues.isEmpty && clock.now < limit { try await Task.sleep(for: .milliseconds(20)) }
        #expect(!doc.issues.isEmpty)
    }

    @Test func movingARailroadBlockUpdatesSourceAndUndoRestoresItsBytes() async throws {
        let original = """
        # café 💡
        on observe: ip.packet {
            count(); # keep with count
            if ip.dscp >= 40 {} else {
                drop();
            }
        }
        """.replacingOccurrences(of: "\n", with: "\r\n")
        var draft = original
        let document = RoutingEditorDocument(adapter: "wireguard")
        let view = NSTextView()
        let coordinator = ConfigurationSourceText.Coordinator()
        view.delegate = coordinator
        view.allowsUndo = true
        coordinator.update(view, text: Binding(get: { draft }, set: {
            draft = $0
            document.changed($0)
        }), format: .routingEvents, commit: SettingCommit())
        document.attach(view)
        document.showRailroad(true)
        document.appear(source: draft)
        defer { document.close(); coordinator.stop() }

        let clock = ContinuousClock()
        let limit = clock.now + .seconds(8)
        while document.railroad == nil && document.notice == nil && clock.now < limit {
            try await Task.sleep(for: .milliseconds(20))
        }
        let snapshot = try #require(document.railroad)
        let root = try #require(snapshot.declarations.first)
        let count = try #require(root.children.first)
        let condition = try #require(root.children.first { $0.kind == "if" })
        let alternative = try #require(root.children.first { $0.kind == "else" })
        let drop = try #require(alternative.children.first)
        let model = RoutingBlockSource(root: root, source: draft)
        let drawing = RoutingBlockDiagram(model: model, selected: nil, destination: nil, canEdit: true,
            payload: { .init(document: document.uri, version: snapshot.version, block: $0) },
            select: { _ in }, selectSlot: { _ in }, drop: { _, _ in }).drawing(headerHeight: 28)
        #expect(drawing.tracks.contains { $0.label == "Otherwise" })
        #expect(drawing.tracks.contains { $0.label == "Then" && $0.slot?.scope == condition.id })
        #expect(drawing.rows[String(condition.id)] == [
            .init(label: "Field", value: "ip.dscp"),
            .init(label: "Operator", value: "At least", operation: ">="),
            .init(label: "Value", value: "40"),
        ])
        #expect(drawing.rows[String(count.id)] == [.init(label: "Function", value: "count")])
        let move = try #require(model.moving(count.id, to: .init(scope: alternative.id, before: drop.id)))
        #expect(model.moving(condition.id, to: .init(scope: alternative.id, before: drop.id)) == nil)
        #expect(document.editRailroad(move, version: snapshot.version, action: "Move Block"))
        #expect(draft.contains("else {\r\n        count(); # keep with count\r\n        drop();"))
        #expect(!draft.contains("count(); # keep with count\r\n    if"))
        #expect(!document.editRailroad(move, version: snapshot.version, action: "Move Block"))

        while document.railroad?.version != document.version && clock.now < limit {
            try await Task.sleep(for: .milliseconds(20))
        }
        let updated = try #require(document.railroad?.declarations.first)
        #expect(updated.children.first?.kind == "if")
        #expect(updated.children.first { $0.kind == "else" }?.children.count == 2)
        document.undoRailroad()
        #expect(draft.utf8.elementsEqual(original.utf8))

        let compound = "ip.dscp > 0 && ip.dscp < 40"
        view.insertText(compound, replacementRange: (view.string as NSString).range(of: "ip.dscp >= 40"))
        while document.railroad?.version != document.version && clock.now < limit {
            try await Task.sleep(for: .milliseconds(20))
        }
        let typedRoot = try #require(document.railroad?.declarations.first)
        let typedCondition = try #require(typedRoot.children.first { $0.kind == "if" })
        let typedModel = RoutingBlockSource(root: typedRoot, source: draft)
        #expect(typedModel.field(for: typedCondition)?.source == compound)
        #expect(typedModel.rows(for: typedCondition) == [.init(label: "Expression", value: compound, wraps: true)])
    }
}
