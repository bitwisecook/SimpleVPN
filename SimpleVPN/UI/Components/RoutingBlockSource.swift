// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

nonisolated struct RoutingBlockSnapshot: Decodable {
    let version: Int
    let declarations: [RoutingBlock]
    let events: [String]
    let complete, limited: Bool
}

nonisolated struct RoutingBlock: Decodable, Identifiable {
    struct Expression: Decodable {
        struct Operand: Decodable {
            let kind: String
            let range: RoutingLSPRange
        }

        let kind: String
        let name: String?
        let range: RoutingLSPRange
        let operands: [Operand]
    }

    let id: Int
    let kind: String
    let name, event: String?
    let range, header: RoutingLSPRange
    let body: RoutingLSPRange?
    let condition: RoutingLSPRange?
    let expression: Expression?
    let children: [RoutingBlock]
    let call: Bool

    var title: String {
        switch kind {
        case "handler": "Handler"
        case "if", "elseIf", "predicate": "Condition"
        case "else": "Otherwise"
        case "for": "Loop"
        case "match": "Lookup"
        case "found": "Found"
        case "missing": "Missing"
        case "binding": "Variable"
        case "assignment": "Assignment"
        case "return": "Return"
        case "action": "Action"
        case "expression": call ? "Action" : "Expression"
        case "function": "Function"
        case "table": "Table"
        default: "Source"
        }
    }

    func block(_ id: Int) -> Self? {
        if self.id == id { return self }
        for child in children {
            if let match = child.block(id) { return match }
        }
        return nil
    }

    func parent(of id: Int) -> Self? {
        if children.contains(where: { $0.id == id }) { return self }
        for child in children {
            if let match = child.parent(of: id) { return match }
        }
        return nil
    }

    var isAlternative: Bool { kind == "elseIf" || kind == "else" }

    var acceptsBlocks: Bool {
        body != nil && ["handler", "if", "elseIf", "else", "for", "found", "missing"].contains(kind)
    }
}

nonisolated struct RoutingBlockRow: Equatable {
    let label: String
    let value: String
    var operation: String? = nil
    var wraps = false
}

nonisolated struct RoutingBlockSlot: Hashable {
    let scope: Int
    let before: Int?
}

nonisolated enum RoutingBlockTemplate: String, CaseIterable, Codable, Sendable {
    case count, drop, condition

    var title: String {
        switch self {
        case .count: "Count"
        case .drop: "Drop"
        case .condition: "If"
        }
    }

    var symbol: String {
        switch self {
        case .count: "number"
        case .drop: "hand.raised"
        case .condition: "arrow.triangle.branch"
        }
    }

    var source: String {
        switch self {
        case .count: "count();"
        case .drop: "drop();"
        case .condition: "if true {} else {}"
        }
    }
}

/// The Rust syntax tree supplies the ranges. Source stays authoritative, with a
/// single contiguous replacement so a move has one native Undo step.
nonisolated struct RoutingBlockSource {
    struct Edit {
        let range: NSRange
        let replacement: String
    }

    struct Field {
        let title: String
        let source: String
        let range: NSRange
    }

    let root: RoutingBlock
    let source: String
    private let lines: [String]
    private let buffer: NSString

    init(root: RoutingBlock, source: String) {
        self.root = root
        self.source = source
        buffer = source as NSString
        lines = buffer.components(separatedBy: "\n")
    }

    func header(of block: RoutingBlock) -> String {
        text(in: block.header) ?? ""
    }

    private func text(in span: RoutingLSPRange) -> String? {
        guard let range = span.range(in: lines) else { return nil }
        return buffer.substring(with: range).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func rows(for block: RoutingBlock) -> [RoutingBlockRow] {
        let value = block.expression.flatMap { text(in: $0.range) }
        switch block.kind {
        case "handler":
            if let event = block.event { return [.init(label: "Event", value: event)] }
        case "if", "elseIf":
            if let comparison = block.expression, comparison.kind == "binary",
               let symbol = comparison.name, let name = Self.comparisons[symbol],
               comparison.operands.count == 2,
               let lhs = text(in: comparison.operands[0].range),
               let rhs = text(in: comparison.operands[1].range) {
                let label = comparison.operands[0].kind == "reference" && lhs.contains(".") ? "Field" : "Left side"
                return [.init(label: label, value: lhs),
                        .init(label: "Operator", value: name, operation: symbol),
                        .init(label: "Value", value: rhs)]
            }
            if let predicate = value ?? block.condition.flatMap(text(in:)) {
                return [.init(label: "Expression", value: predicate, wraps: true)]
            }
        case "assignment", "binding":
            if let name = block.name, let value {
                return [.init(label: block.kind == "assignment" ? "Field" : "Variable", value: name),
                        .init(label: "Value", value: value)]
            }
        case "expression":
            if let call = block.expression, call.kind == "call", let name = call.name {
                let arguments = call.operands.compactMap { text(in: $0.range) }
                let summary: [RoutingBlockRow] = [.init(label: "Function", value: name)]
                if arguments.count > 2 {
                    return summary + [.init(label: "Arguments", value: arguments.prefix(2).joined(separator: ", ") + ", …", wraps: true)]
                }
                return summary + arguments.enumerated().map { index, argument in
                    .init(label: arguments.count == 1 ? "Argument" : "Argument \(index + 1)", value: argument)
                }
            }
        case "for":
            if let name = block.name, let value {
                return [.init(label: "Item", value: name), .init(label: "Collection", value: value)]
            }
        case "return", "match":
            if let value {
                return [.init(label: block.kind == "return" ? "Result" : "Lookup", value: value, wraps: true)]
            }
        case "else":
            return []
        default:
            break
        }
        let source = header(of: block)
        return source.isEmpty ? [] : [.init(label: "Source", value: source, wraps: true)]
    }

    private static let comparisons = [
        "==": "Equals", "!=": "Does not equal", "<": "Less than", "<=": "At most",
        ">": "Greater than", ">=": "At least", "in": "Is in",
    ]

    func field(for block: RoutingBlock) -> Field? {
        guard root.kind == "handler", block.id != root.id else { return nil }
        if let range = block.condition?.range(in: lines) {
            return Field(title: "Condition", source: buffer.substring(with: range), range: range)
        }
        if block.call, let range = block.header.range(in: lines) {
            return Field(title: "Action", source: buffer.substring(with: range), range: range)
        }
        return nil
    }

    func offset(for slot: RoutingBlockSlot) -> Int? {
        guard root.kind == "handler", let scope = root.block(slot.scope),
              scope.acceptsBlocks, let body = scope.body else { return nil }
        if let id = slot.before {
            guard let block = scope.children.first(where: { $0.id == id }), !block.isAlternative else { return nil }
            return block.range.start.offset(in: lines)
        }
        return body.end.offset(in: lines)
    }

    func moveRange(for id: Int) -> NSRange? {
        guard root.kind == "handler", let parent = root.parent(of: id), parent.acceptsBlocks,
              let index = parent.children.firstIndex(where: { $0.id == id }) else { return nil }
        let block = parent.children[index]
        let end: RoutingLSPPosition
        if block.kind == "if" && block.body != nil {
            let alternatives = parent.children.dropFirst(index + 1).prefix(while: \.isAlternative)
            guard alternatives.allSatisfy({ $0.body != nil }) else { return nil }
            end = alternatives.last?.range.end ?? block.range.end
        } else if (["for", "match"].contains(block.kind) && block.body != nil)
                    || (["assignment", "binding", "expression", "return"].contains(block.kind)
                        && header(of: block).hasSuffix(";")) {
            end = block.range.end
        } else {
            return nil
        }
        guard let range = RoutingLSPRange(start: block.range.start, end: end).range(in: lines) else { return nil }
        // A trailing line comment travels with its block. Leading comments and
        // all other text outside the moved range stay where they were written.
        let tail = String((lines[end.line] as NSString).substring(from: end.character))
        let comment = tail.trimmingCharacters(in: .whitespaces)
        if comment.hasPrefix("#") || comment.hasPrefix("//") {
            let length = tail.hasSuffix("\r") ? tail.utf16.count - 1 : tail.utf16.count
            return NSRange(location: range.location, length: range.length + length)
        }
        return range
    }

    func canMove(_ id: Int, to slot: RoutingBlockSlot) -> Bool {
        guard let range = moveRange(for: id), let destination = offset(for: slot),
              destination < range.location || destination > NSMaxRange(range) else { return false }
        // The connector immediately after this block already leads to that slot.
        let start = NSMaxRange(range)
        if destination > start,
           buffer.substring(with: NSRange(location: start, length: destination - start))
            .trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return false }
        return true
    }

    func moving(_ id: Int, to slot: RoutingBlockSlot) -> Edit? {
        guard canMove(id, to: slot), let range = moveRange(for: id),
              let destination = offset(for: slot) else { return nil }
        let insertion = insertionText(buffer.substring(with: range), at: destination, slot: slot)
        if destination < range.location {
            let between = NSRange(location: destination, length: range.location - destination)
            return Edit(range: NSUnionRange(between, range),
                        replacement: insertion + buffer.substring(with: between))
        }
        let between = NSRange(location: NSMaxRange(range), length: destination - NSMaxRange(range))
        return Edit(range: NSUnionRange(range, between),
                    replacement: buffer.substring(with: between) + insertion)
    }

    func inserting(_ template: RoutingBlockTemplate, at slot: RoutingBlockSlot) -> Edit? {
        guard let destination = offset(for: slot) else { return nil }
        return Edit(range: NSRange(location: destination, length: 0),
                    replacement: insertionText(template.source, at: destination, slot: slot))
    }

    func deleting(_ id: Int) -> Edit? {
        moveRange(for: id).map { Edit(range: $0, replacement: "") }
    }

    private func insertionText(_ statement: String, at offset: Int, slot: RoutingBlockSlot) -> String {
        let line = RoutingLSPPosition.at(offset, in: source).line
        let column = offset - (RoutingLSPPosition(line: line, character: 0).offset(in: lines) ?? offset)
        let prefix = (lines[line] as NSString).substring(to: column)
        let indentation = String(prefix.prefix { $0 == " " || $0 == "\t" })
        let newline = lines.first(where: { !$0.isEmpty })?.hasSuffix("\r") == true ? "\r\n" : "\n"
        // Before a closing brace, indent one level inside the containing block.
        // Inline destinations also need a line break before the inserted text.
        if slot.before == nil {
            let scopeLine = root.block(slot.scope)?.range.start.line ?? line
            let scopeIndent = String(lines[scopeLine].prefix { $0 == " " || $0 == "\t" })
            let childLine = root.block(slot.scope)?.children.first?.range.start.line
            let childIndent = childLine.flatMap { $0 == scopeLine ? nil : String(lines[$0].prefix { $0 == " " || $0 == "\t" }) }
            let inner = childIndent ?? (scopeIndent + "    ")
            if prefix == indentation, inner.hasPrefix(indentation) {
                return String(inner.dropFirst(indentation.count)) + statement + newline + indentation
            }
            return newline + inner + statement + newline + scopeIndent
        }
        let start = prefix == indentation ? "" : newline + indentation + "    "
        return start + statement + newline + (prefix == indentation ? indentation : indentation + "    ")
    }
}
