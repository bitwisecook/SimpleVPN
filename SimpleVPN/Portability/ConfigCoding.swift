// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConfigCoding.swift
//  The two encoders and the two decoders over `ConfigValue` — JSON and YAML, one
//  model (see ConfigValue.swift's header for why that is the whole point).
//
//  BOTH WRITERS ARE HAND-ROLLED, and JSON's is hand-rolled deliberately:
//  `JSONSerialization` cannot be asked to preserve key order, and the import
//  confirmation shows a DIFF of a file against what is installed. A file whose
//  keys shuffle between two exports of the same configuration produces a diff
//  that is all noise, which is the same as having no diff at all.
//
//  THE YAML SUBSET is exactly what the writer emits and nothing more: block maps,
//  block sequences, `|-` block scalars, double-quoted scalars, `{}`/`[]` for
//  empty, and `#` comments. Anchors, aliases, tags, flow collections with content,
//  multi-document streams and directives are NOT accepted. That is a security
//  posture, not laziness — an imported document is a file from outside every
//  protection the app has, and the smaller the grammar the fewer the surprises. A
//  file using anything else is REFUSED with the line number, never guessed at.
//

import Foundation

// MARK: - Errors

nonisolated enum ConfigCodingError: Error, Equatable, CustomStringConvertible {
    case notUTF8
    case empty
    case notAMap
    case badJSON(String)
    /// A YAML construct outside the accepted subset, with the 1-based line.
    case unsupportedYAML(line: Int, what: String)
    case badIndent(line: Int)

    var description: String {
        switch self {
        case .notUTF8: "The file isn\u{2019}t text SimpleVPN can read (it isn\u{2019}t UTF-8)."
        case .empty: "The file is empty."
        case .notAMap: "The file doesn\u{2019}t look like a SimpleVPN settings file \u{2014} its top level isn\u{2019}t a list of named sections."
        case .badJSON(let why): "The file isn\u{2019}t valid JSON: \(why)"
        case .unsupportedYAML(let line, let what):
            "Line \(line) uses YAML SimpleVPN doesn\u{2019}t accept (\(what)). Settings files use plain names, values, lists and blocks of text."
        case .badIndent(let line): "Line \(line) is indented in a way SimpleVPN can\u{2019}t read."
        }
    }
}

// MARK: - JSON

nonisolated enum ConfigJSON {

    /// Pretty, stable, two-space JSON. `leadingComments` become a `"_readme"`
    /// array as the first member — JSON has no comments, and the file must still
    /// be able to say what it left out and why (the `.ovpn` exporter's header
    /// comment is the precedent this follows).
    static func encode(_ root: ConfigMap, leadingComments: [String] = []) -> String {
        var root = root
        if !leadingComments.isEmpty {
            var withReadme = ConfigMap()
            withReadme.put(ConfigDocumentKeys.readme, .strings(leadingComments))
            withReadme.entries.append(contentsOf: root.entries)
            root = withReadme
        }
        var out = ""
        write(.map(root), indent: 0, into: &out)
        return out + "\n"
    }

    private static func write(_ value: ConfigValue, indent: Int, into out: inout String) {
        let pad = String(repeating: " ", count: indent * 2)
        let inner = String(repeating: " ", count: (indent + 1) * 2)
        switch value {
        case .bool(let b): out += b ? "true" : "false"
        case .int(let i): out += String(i)
        case .double(let d): out += jsonNumber(d)
        case .string(let s), .text(let s): out += quote(s)
        case .list(let items):
            guard !items.isEmpty else { out += "[]"; return }
            out += "[\n"
            for (i, item) in items.enumerated() {
                out += inner
                write(item, indent: indent + 1, into: &out)
                out += i == items.count - 1 ? "\n" : ",\n"
            }
            out += pad + "]"
        case .map(let m):
            guard !m.isEmpty else { out += "{}"; return }
            out += "{\n"
            for (i, e) in m.entries.enumerated() {
                out += inner + quote(e.key) + ": "
                write(e.value, indent: indent + 1, into: &out)
                out += i == m.entries.count - 1 ? "\n" : ",\n"
            }
            out += pad + "}"
        }
    }

    /// A finite double, written so it reads back as the same value; a
    /// non-finite one has no JSON spelling and becomes 0 (no configuration
    /// value in this app is ever infinite).
    private static func jsonNumber(_ d: Double) -> String {
        guard d.isFinite else { return "0" }
        if d == d.rounded(), abs(d) < 1e15 { return String(format: "%.1f", d) }
        return String(d)
    }

    private static func quote(_ s: String) -> String {
        var out = "\""
        for ch in s.unicodeScalars {
            switch ch {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if ch.value < 0x20 {
                    out += String(format: "\\u%04x", ch.value)
                } else {
                    out.unicodeScalars.append(ch)
                }
            }
        }
        return out + "\""
    }

    /// Read JSON. Order is irrelevant on the way IN (the diff is computed against
    /// the app's own ordering), so `JSONSerialization` is fine here — and it is
    /// the hardened parser Apple ships, which is exactly what a file from outside
    /// should meet first.
    static func decode(_ text: String) throws -> ConfigMap {
        guard let data = text.data(using: .utf8) else { throw ConfigCodingError.notUTF8 }
        let any: Any
        do {
            any = try JSONSerialization.jsonObject(with: data, options: [])
        } catch {
            throw ConfigCodingError.badJSON(error.localizedDescription)
        }
        guard let dict = any as? [String: Any] else { throw ConfigCodingError.notAMap }
        guard case .map(let m) = convert(dict) else { throw ConfigCodingError.notAMap }
        return m
    }

    /// A `JSONSerialization` object graph as a `ConfigValue`. Internal because the
    /// document builder reaches for it too: every config struct in the app is
    /// already `Codable`, so its JSON form is the shortest honest route into this
    /// tree — and reusing the app's own encoding is what stops the export from
    /// becoming a second, drifting description of the same settings.
    static func value(_ any: Any) -> ConfigValue { convert(any) }

    private static func convert(_ any: Any) -> ConfigValue {
        switch any {
        case let s as String: return .document(s)
        // NSNumber BEFORE Bool, and it is load-bearing: `1 as Any as? Bool` is
        // `true` in Swift, so a leading `as? Bool` case turns every 1 and 0 in the
        // file into a boolean — which is how `format: 1` came back as `true`.
        // CFBoolean is an NSNumber too, so the real question is asked here instead.
        case let n as NSNumber:
            if CFGetTypeID(n) == CFBooleanGetTypeID() { return .bool(n.boolValue) }
            let d = n.doubleValue
            if d == d.rounded(), abs(d) <= Double(Int.max) { return .int(n.intValue) }
            return .double(d)
        case let a as [Any]: return .list(a.map(convert))
        case let d as [String: Any]:
            // Sorted, so a JSON file re-exported as YAML is at least STABLE even
            // though JSON gave us no order to preserve.
            var m = ConfigMap()
            for key in d.keys.sorted() { m[key] = convert(d[key]!) }
            return .map(m)
        default: return .string("")
        }
    }
}

// MARK: - YAML

nonisolated enum ConfigYAML {

    // MARK: Writing

    static func encode(_ root: ConfigMap, leadingComments: [String] = []) -> String {
        var out = ""
        for line in leadingComments {
            out += line.isEmpty ? "#\n" : "# \(line)\n"
        }
        if !leadingComments.isEmpty { out += "\n" }
        writeMap(root, indent: 0, into: &out)
        return out
    }

    private static func writeMap(_ m: ConfigMap, indent: Int, into out: inout String) {
        let pad = String(repeating: " ", count: indent)
        for e in m.entries {
            switch e.value {
            case .map(let child):
                if child.isEmpty {
                    out += "\(pad)\(key(e.key)): {}\n"
                } else {
                    out += "\(pad)\(key(e.key)):\n"
                    writeMap(child, indent: indent + 2, into: &out)
                }
            case .list(let items):
                if items.isEmpty {
                    out += "\(pad)\(key(e.key)): []\n"
                } else {
                    out += "\(pad)\(key(e.key)):\n"
                    writeList(items, indent: indent + 2, into: &out)
                }
            case .text(let s) where blockScalarSafe(s):
                out += "\(pad)\(key(e.key)): |-\n"
                for line in s.components(separatedBy: "\n") {
                    out += line.isEmpty ? "\n" : "\(pad)  \(line)\n"
                }
            default:
                out += "\(pad)\(key(e.key)): \(scalar(e.value))\n"
            }
        }
    }

    private static func writeList(_ items: [ConfigValue], indent: Int, into out: inout String) {
        let pad = String(repeating: " ", count: indent)
        for item in items {
            switch item {
            case .map(let m) where !m.isEmpty:
                // "- " then the first key on the same line, the rest aligned under
                // it: the shape every hand-written YAML list of records has.
                var block = ""
                writeMap(m, indent: indent + 2, into: &block)
                var lines = block.components(separatedBy: "\n")
                if lines.last == "" { lines.removeLast() }
                for (i, line) in lines.enumerated() {
                    if i == 0 {
                        out += "\(pad)- \(line.dropFirst(indent + 2))\n"
                    } else {
                        out += "\(line)\n"
                    }
                }
            case .list(let nested) where !nested.isEmpty:
                out += "\(pad)-\n"
                writeList(nested, indent: indent + 2, into: &out)
            case .map(let m) where m.isEmpty:
                out += "\(pad)- {}\n"
            case .list: out += "\(pad)- []\n"
            default:
                out += "\(pad)- \(scalar(item))\n"
            }
        }
    }

    /// A key is always a plain scalar here — every key in this format is a setting
    /// id or a section name, i.e. `[a-z0-9.-]`. Quoted anyway if it somehow isn't,
    /// so a key can never break the file.
    /// A key is always a plain scalar here. Setting ids are `[a-z0-9.-]`; the
    /// structural sections' keys are the app's own camel-case field names
    /// (`requiresOTP`), so LETTERS OF EITHER CASE are plain too — quoting those
    /// would produce `"requiresOTP": true`, and a quoted key is outside the grammar
    /// the reader accepts. Anything else is quoted, so a key can never break the
    /// file.
    private static func key(_ s: String) -> String {
        !s.isEmpty && s.allSatisfy { $0.isLetter && $0.isASCII || $0.isNumber || $0 == "." || $0 == "-" || $0 == "_" }
            ? s : quoted(s)
    }

    private static func scalar(_ v: ConfigValue) -> String {
        switch v {
        case .bool(let b): return b ? "true" : "false"
        case .int(let i): return String(i)
        case .double(let d): return d.isFinite ? (d == d.rounded() && abs(d) < 1e15 ? String(format: "%.1f", d) : String(d)) : "0"
        case .string(let s), .text(let s): return plainSafe(s) ? s : quoted(s)
        case .list, .map: return "" // handled by the callers
        }
    }

    /// YAML scalars that must be quoted or they change meaning. `no` is the one
    /// that matters most in this app: `openvpn.compression: no` would read back as
    /// the boolean false rather than OpenVPN's own `no` token.
    private static let reservedPlain: Set<String> = [
        "y", "Y", "yes", "Yes", "YES", "n", "N", "no", "No", "NO",
        "true", "True", "TRUE", "false", "False", "FALSE",
        "on", "On", "ON", "off", "Off", "OFF",
        "null", "Null", "NULL", "~", "-", "?", ":",
    ]

    private static func plainSafe(_ s: String) -> Bool {
        guard !s.isEmpty, !reservedPlain.contains(s) else { return false }
        guard Double(s) == nil, Int(s) == nil else { return false }   // keep numbers typed
        guard let first = s.first, let last = s.last else { return false }
        guard !first.isWhitespace, !last.isWhitespace else { return false }
        guard !"-?:,[]{}#&*!|>'\"%@`".contains(first) else { return false }
        let chars = Array(s)
        for (i, ch) in chars.enumerated() {
            // `isNewline`, not `ch == "\n"`: Swift treats CRLF as ONE Character, so a
            // CRLF-terminated .ovpn (which is most of them from Windows) slipped past
            // an equality check and was written as a plain scalar spanning two lines.
            if ch.isNewline || ch == "\t" { return false }
            if ch.unicodeScalars.contains(where: { $0.value < 0x20 }) { return false }
            // ": " (or a trailing colon) would end the scalar and start a mapping.
            if ch == ":", i == chars.count - 1 || chars[i + 1] == " " { return false }
            // " #" would start a comment.
            if ch == "#", i > 0, chars[i - 1] == " " { return false }
        }
        return true
    }

    private static func quoted(_ s: String) -> String {
        var out = "\""
        for ch in s.unicodeScalars {
            switch ch {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if ch.value < 0x20 { out += String(format: "\\x%02x", ch.value) }
                else { out.unicodeScalars.append(ch) }
            }
        }
        return out + "\""
    }

    /// Can this text ride in a `|-` block? Not if a line starts with whitespace
    /// (that needs an explicit indentation indicator, which is exactly the kind of
    /// YAML nobody should have to read) or carries a carriage return. Anything
    /// else falls back to a quoted string with `\n` escapes — uglier, still exact.
    private static func blockScalarSafe(_ s: String) -> Bool {
        // Scalar-level, for the CRLF-is-one-Character reason above.
        guard !s.isEmpty, !s.unicodeScalars.contains("\r") else { return false }
        for line in s.components(separatedBy: "\n") {
            if let f = line.first, f == " " || f == "\t" { return false }
            if line.hasSuffix(" ") || line.hasSuffix("\t") { return false }
        }
        return true
    }

    // MARK: Reading

    private struct Line {
        let number: Int      // 1-based
        let indent: Int
        let content: String
    }

    static func decode(_ text: String) throws -> ConfigMap {
        let lines = try fold(text)
        guard !lines.isEmpty else { throw ConfigCodingError.empty }
        guard lines[0].indent == 0 else { throw ConfigCodingError.badIndent(line: lines[0].number) }
        var index = 0
        let root = try parseMap(lines, &index, indent: 0)
        guard index == lines.count else { throw ConfigCodingError.badIndent(line: lines[index].number) }
        return root
    }

    /// PASS ONE: drop comments and blank lines, refuse the YAML we don't accept,
    /// and fold each `|-` block into ONE synthetic line whose value is prefixed
    /// with U+0001 — so the structural parser below never has to know block
    /// scalars exist, and no typed text can be mistaken for one.
    ///
    /// Comments are dropped only OUTSIDE a block: a `#` line inside an embedded
    /// .ovpn is a comment in THAT file and must survive verbatim.
    private static func fold(_ text: String) throws -> [Line] {
        var out: [Line] = []
        // The open block scalar: the column its "key:" sat in, the text to re-emit
        // in front of the folded value (which carries the "- " of a list record
        // when the block is a record's first field), and its collected lines.
        var open: (indent: Int, prefix: String, startedAt: Int)? = nil
        var body: [String] = []
        var bodyIndent: Int? = nil

        func closeBlock(at number: Int) {
            guard let block = open else { return }
            var kept = body
            while kept.last == "" { kept.removeLast() }
            out.append(Line(number: block.startedAt, indent: block.indent,
                            content: "\(block.prefix): \u{1}\(kept.joined(separator: "\n"))"))
            open = nil
            body = []
            bodyIndent = nil
        }

        let rawLines = text.components(separatedBy: "\n")
        for (i, raw) in rawLines.enumerated() {
            let number = i + 1
            let leading = raw.prefix { $0 == " " || $0 == "\t" }
            if leading.contains("\t") {
                throw ConfigCodingError.unsupportedYAML(line: number, what: "a tab used for indentation")
            }
            let indent = leading.count
            let trimmed = String(raw.reversed().drop { $0 == " " || $0 == "\t" }.reversed())

            if let block = open {
                if trimmed.isEmpty { body.append(""); continue }
                if indent > block.indent {
                    if bodyIndent == nil { bodyIndent = indent }
                    body.append(String(trimmed.dropFirst(min(bodyIndent ?? indent, indent))))
                    continue
                }
                closeBlock(at: number)
            }

            if trimmed.isEmpty { continue }
            var content = String(trimmed.dropFirst(indent))
            if content.hasPrefix("#") { continue }
            if content.hasPrefix("---") || content.hasPrefix("...") || content.hasPrefix("%") {
                throw ConfigCodingError.unsupportedYAML(line: number, what: "a document marker or directive")
            }
            if content.hasPrefix("&") || content.hasPrefix("*") || content.hasPrefix("!") {
                throw ConfigCodingError.unsupportedYAML(line: number, what: "an anchor, alias or tag")
            }

            // A list record's first field can itself open a block, so look past a
            // leading "- " and put it back on the folded line.
            var dash = ""
            if content.hasPrefix("- ") {
                dash = "- "
                content = String(content.dropFirst(2))
            }
            if let split = splitKey(content), let indicator = split.value.first,
               indicator == "|" || indicator == ">" {
                if indicator == ">" {
                    throw ConfigCodingError.unsupportedYAML(line: number, what: "a folded (>) block")
                }
                let rest = split.value.dropFirst()
                if rest.contains(where: \.isNumber) {
                    throw ConfigCodingError.unsupportedYAML(
                        line: number, what: "a block with an explicit indentation indicator")
                }
                // `|`, `|-` and `|+` all land in the same place: ConfigValue.document
                // drops trailing newlines anyway, so the chomping indicator changes
                // nothing here and is accepted rather than refused.
                open = (indent: indent, prefix: "\(dash)\(split.key)", startedAt: number)
                continue
            }
            out.append(Line(number: number, indent: indent, content: "\(dash)\(content)"))
        }
        closeBlock(at: rawLines.count)
        return out
    }

    /// Split "key: value" the way YAML does: the key ends at the first colon that
    /// is followed by a SPACE or ends the line. Without that rule
    /// `- vpn.example.com:1194` in a list of servers would parse as a record with a
    /// key of "vpn.example.com".
    ///
    /// Plain keys only. A quoted key is legal YAML, is never emitted here, and
    /// accepting it would mean a second scalar parser for keys.
    private static func splitKey(_ body: String) -> (key: String, value: String)? {
        let chars = Array(body)
        for (i, ch) in chars.enumerated() where ch == ":" {
            guard i == chars.count - 1 || chars[i + 1] == " " else { continue }
            let key = String(chars[0..<i]).trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty, !key.contains(" "), !key.contains("\""), !key.contains("'") else { return nil }
            let value = String(chars[(i + 1)...]).trimmingCharacters(in: .whitespaces)
            return (key, value)
        }
        return nil
    }

    private static func parseMap(_ lines: [Line], _ i: inout Int, indent: Int) throws -> ConfigMap {
        var m = ConfigMap()
        while i < lines.count {
            let line = lines[i]
            if line.indent < indent { break }
            if line.indent > indent { throw ConfigCodingError.badIndent(line: line.number) }
            if line.content.hasPrefix("- ") || line.content == "-" {
                throw ConfigCodingError.unsupportedYAML(line: line.number,
                                                        what: "a list where named settings were expected")
            }
            guard let (key, rawValue) = splitKey(line.content) else {
                throw ConfigCodingError.unsupportedYAML(line: line.number, what: "a line with no “name:”")
            }
            i += 1
            if rawValue.isEmpty {
                // A nested block: either a map or a sequence, decided by the next line.
                guard i < lines.count, lines[i].indent > indent else {
                    m[key] = .map(ConfigMap())          // "key:" with nothing under it
                    continue
                }
                let childIndent = lines[i].indent
                if lines[i].content.hasPrefix("- ") || lines[i].content == "-" {
                    m[key] = .list(try parseList(lines, &i, indent: childIndent))
                } else {
                    m[key] = .map(try parseMap(lines, &i, indent: childIndent))
                }
            } else {
                m[key] = try parseScalar(rawValue, line: line.number)
            }
        }
        return m
    }

    private static func parseList(_ lines: [Line], _ i: inout Int, indent: Int) throws -> [ConfigValue] {
        var out: [ConfigValue] = []
        while i < lines.count {
            let line = lines[i]
            if line.indent < indent { break }
            if line.indent > indent { throw ConfigCodingError.badIndent(line: line.number) }
            guard line.content.hasPrefix("- ") || line.content == "-" else { break }
            let item = line.content == "-" ? "" : String(line.content.dropFirst(2))
            if item.isEmpty {
                i += 1
                guard i < lines.count, lines[i].indent > indent else { out.append(.string("")); continue }
                if lines[i].content.hasPrefix("- ") {
                    out.append(.list(try parseList(lines, &i, indent: lines[i].indent)))
                } else {
                    out.append(.map(try parseMap(lines, &i, indent: lines[i].indent)))
                }
                continue
            }
            if item == "{}" { out.append(.map(ConfigMap())); i += 1; continue }
            if item == "[]" { out.append(.list([])); i += 1; continue }
            if let (key, rawValue) = splitKey(item), !item.hasPrefix("\"") {
                // "- key: value" — a record. Its remaining keys sit at the column
                // the first key starts in, which is two past the dash.
                let recordIndent = indent + 2
                var record = ConfigMap()
                if rawValue.isEmpty {
                    i += 1
                    if i < lines.count, lines[i].indent > recordIndent {
                        if lines[i].content.hasPrefix("- ") || lines[i].content == "-" {
                            record[key] = .list(try parseList(lines, &i, indent: lines[i].indent))
                        } else {
                            record[key] = .map(try parseMap(lines, &i, indent: lines[i].indent))
                        }
                    } else {
                        record[key] = .map(ConfigMap())
                    }
                } else {
                    record[key] = try parseScalar(rawValue, line: line.number)
                    i += 1
                }
                if i < lines.count, lines[i].indent == recordIndent {
                    let rest = try parseMap(lines, &i, indent: recordIndent)
                    record.entries.append(contentsOf: rest.entries)
                }
                out.append(.map(record))
                continue
            }
            out.append(try parseScalar(item, line: line.number))
            i += 1
        }
        return out
    }

    private static func parseScalar(_ raw: String, line: Int) throws -> ConfigValue {
        // A folded block scalar arrives from pass one already assembled, marked
        // with U+0001 so it can never be confused with anything typed.
        if raw.hasPrefix("\u{1}") { return .document(String(raw.dropFirst())) }
        if raw == "{}" { return .map(ConfigMap()) }
        if raw == "[]" { return .list([]) }
        if raw.hasPrefix("[") || raw.hasPrefix("{") {
            throw ConfigCodingError.unsupportedYAML(line: line, what: "a flow list or map with contents")
        }
        // A tag, an anchor or an alias in the VALUE position — the same refusal as at
        // the start of a line, and the one that actually matters: `!!binary`,
        // `!!python/object` and friends live here.
        if raw.hasPrefix("!") || raw.hasPrefix("&") || raw.hasPrefix("*") {
            throw ConfigCodingError.unsupportedYAML(line: line, what: "an anchor, alias or tag")
        }
        if raw.hasPrefix("\"") {
            return .document(try unquoteDouble(raw, line: line))
        }
        if raw.hasPrefix("'") {
            return .document(try unquoteSingle(raw, line: line))
        }
        // Strip a trailing comment from a plain scalar (" # like this").
        var body = raw
        if let hash = body.range(of: " #") { body = String(body[body.startIndex..<hash.lowerBound]) }
        body = body.trimmingCharacters(in: .whitespaces)
        switch body.lowercased() {
        case "true", "yes", "on": return .bool(true)
        case "false", "no", "off": return .bool(false)
        case "null", "~", "": return .string("")
        default: break
        }
        if let i = Int(body) { return .int(i) }
        if let d = Double(body), body.contains(".") || body.lowercased().contains("e") { return .double(d) }
        return .string(body)
    }

    private static func unquoteDouble(_ raw: String, line: Int) throws -> String {
        var out = ""
        var it = raw.dropFirst().makeIterator()
        while let ch = it.next() {
            if ch == "\"" { return out }
            guard ch == "\\" else { out.append(ch); continue }
            guard let esc = it.next() else { break }
            switch esc {
            case "n": out.append("\n")
            case "r": out.append("\r")
            case "t": out.append("\t")
            case "\"": out.append("\"")
            case "\\": out.append("\\")
            case "0": out.append("\0")
            case "x":
                var hex = ""
                for _ in 0..<2 { if let h = it.next() { hex.append(h) } }
                guard let v = UInt32(hex, radix: 16), let s = Unicode.Scalar(v) else {
                    throw ConfigCodingError.unsupportedYAML(line: line, what: "a bad \\x escape")
                }
                out.unicodeScalars.append(s)
            case "u":
                var hex = ""
                for _ in 0..<4 { if let h = it.next() { hex.append(h) } }
                guard let v = UInt32(hex, radix: 16), let s = Unicode.Scalar(v) else {
                    throw ConfigCodingError.unsupportedYAML(line: line, what: "a bad \\u escape")
                }
                out.unicodeScalars.append(s)
            default:
                throw ConfigCodingError.unsupportedYAML(line: line, what: "an unknown \\ escape")
            }
        }
        throw ConfigCodingError.unsupportedYAML(line: line, what: "a quoted value with no closing quote")
    }

    private static func unquoteSingle(_ raw: String, line: Int) throws -> String {
        var out = ""
        let chars = Array(raw.dropFirst())
        var i = 0
        while i < chars.count {
            if chars[i] == "'" {
                if i + 1 < chars.count, chars[i + 1] == "'" { out.append("'"); i += 2; continue }
                return out
            }
            out.append(chars[i])
            i += 1
        }
        throw ConfigCodingError.unsupportedYAML(line: line, what: "a quoted value with no closing quote")
    }
}
