// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

/// Lexical styles for editable source. Ranges address the unmodified NSTextStorage
/// in UTF-16. Incomplete documents are ordinary input while typing.
nonisolated enum ConfigSyntax {
    enum Format: Sendable {
        case automatic, openVPN, wireGuard, ssh, ini, json, yaml, xml, shell, routingEvents
    }

    enum Kind: Sendable {
        case keyword, section, string, number, comment, punctuation, literal
    }

    struct Span: Equatable, Sendable {
        let range: NSRange
        let kind: Kind
    }

    // Bound the work and attributed-string mutations on a large paste. Text
    // beyond the budget remains editable and uses the editor's base style.
    static let maximumUnits = 256 * 1024
    static let maximumSpans = 16_384

    static func spans(in text: String, format: Format) -> [Span] {
        guard !Task.isCancelled, !text.isEmpty else { return [] }
        guard let selected = format == .automatic ? Lexer.detect(text) : format else { return [] }
        var lexer = Lexer(text)
        return lexer.scan(selected)
    }

    private struct Lexer {
        let units: [UInt16]
        var spans: [Span] = []
        var opaqueTag: String?
        var pem = false
        var blockIndent: Int?
        var shellQuote: UInt16?

        init(_ text: String) {
            var prefix = Array(text.utf16.prefix(maximumUnits))
            if let last = prefix.last, (0xD800...0xDBFF).contains(last) { prefix.removeLast() }
            units = prefix
        }

        static func detect(_ text: String) -> Format? {
            // This selects a highlighting grammar only. The importer owns
            // profile recognition and validation, and may accept unfinished input differently.
            let sample = String(decoding: text.utf16.prefix(4096), as: UTF16.self)
            var yamlKeys = 0
            var iniKeys = 0
            for raw in sample.split(whereSeparator: \.isNewline) {
                let line = raw.trimmingCharacters(in: .whitespaces.union(CharacterSet(charactersIn: "\u{FEFF}"))).lowercased()
                if line.isEmpty { continue }
                if line.hasPrefix("#!") { return .shell }
                if line.hasPrefix("#") || line.hasPrefix(";") { continue }
                if line == "[interface]" || line == "[peer]" { return .wireGuard }
                if line == "[main]" { return .ini }
                if line.hasPrefix("{") { return .json }
                if line.hasPrefix("[") {
                    let inner = line.dropFirst().prefix { $0 != "]" }
                    let section = line.hasSuffix("]") && inner.first?.isLetter == true
                        && !["true", "false", "null"].contains(inner)
                    return section ? .ini : .json
                }
                if line.hasPrefix("-----begin ") { return .openVPN }
                if line.hasPrefix("<") {
                    let tag = line.trimmingCharacters(in: CharacterSet(charactersIn: "</>"))
                    if Self.inlineTags.contains(tag) || tag == "connection" { return .openVPN }
                    if line.hasPrefix("<?xml") || line.hasPrefix("<!--") || line.hasPrefix("<!doctype") { return .xml }
                    let element = line.dropFirst().prefix { $0.isLetter || $0.isNumber || "._:-".contains($0) }
                    if element.first?.isLetter == true, !element.hasSuffix(":") { return .xml }
                    continue
                }
                if line == "---" { return .yaml }
                let mapping = line.hasPrefix("- ") ? line.dropFirst(2) : line[...]
                if let colon = mapping.firstIndex(of: ":"),
                   mapping.index(after: colon) == mapping.endIndex || mapping[mapping.index(after: colon)].isWhitespace,
                   Self.plausibleKey(mapping[..<colon]) {
                    yamlKeys += 1
                    if yamlKeys >= 2 || ["vpns", "app-settings", "openvpn-configuration"].contains(mapping[..<colon]) {
                        return .yaml
                    }
                }
                let first = line.prefix { !$0.isWhitespace && $0 != "=" }
                switch first {
                case "host", "match", "hostname", "identityfile", "proxyjump", "localforward", "remoteforward", "dynamicforward": return .ssh
                case "client", "remote", "dev", "proto", "port", "tls-client", "auth-user-pass", "verb", "route", "cipher", "setenv", "persist-key", "nobind": return .openVPN
                case "ssh", "sudo", "export", "openconnect", "openvpn", "wg", "wg-quick", "tailscale", "simplevpn": return .shell
                default: break
                }
                if let equals = line.firstIndex(of: "="), Self.plausibleKey(line[..<equals]) {
                    iniKeys += 1
                    if iniKeys >= 2 { return .ini }
                }
            }
            return nil
        }

        static func plausibleKey(_ key: Substring) -> Bool {
            let trimmed = key.trimmingCharacters(in: .whitespaces)
            return trimmed.first?.isLetter == true && trimmed.allSatisfy { $0.isLetter || $0.isNumber || "._-".contains($0) }
        }

        static let inlineTags = Set(OVPNSecretMaterial.secretTags + OVPNSecretMaterial.publicTags + ["peer-fingerprint"])

        // Delimiters are ASCII. Non-ASCII units travel together inside values;
        // scanning never converts a UTF-16 offset through String.Index.
        func char(_ index: Int) -> Unicode.Scalar? {
            index < units.count ? Unicode.Scalar(units[index]) : nil
        }

        func matches(_ token: StaticString, at start: Int, end: Int) -> Bool {
            let length = token.utf8CodeUnitCount
            guard length <= end - start else { return false }
            for n in 0..<length where units[start + n] != UInt16(token.utf8Start[n]) { return false }
            return true
        }

        func whitespace(_ i: Int) -> Bool {
            switch units[i] { case 9...13, 32, 0xFEFF: true; default: false }
        }

        func skipSpace(_ start: Int, _ end: Int) -> Int {
            var i = start
            while i < end, whitespace(i) { i += 1 }
            return i
        }

        func string(_ start: Int, _ end: Int) -> String {
            String(decoding: units[start..<end], as: UTF16.self)
        }

        mutating func add(_ kind: Kind, _ start: Int, _ end: Int) {
            guard start < end, spans.count < maximumSpans else { return }
            spans.append(Span(range: NSRange(location: start, length: end - start), kind: kind))
        }

        func afterQuote(from content: Int, to end: Int, quote: UInt16, escapes: Bool = true,
                        doubled: Bool = false) -> (index: Int, closed: Bool) {
            var i = content
            while i < end {
                if units[i] == quote {
                    if doubled, i + 1 < end, units[i + 1] == quote { i += 2; continue }
                    return (i + 1, true)
                }
                if escapes, char(i) == "\\" { i = min(i + 2, end) } else { i += 1 }
            }
            return (end, false)
        }

        func valueKind(_ start: Int, _ end: Int, bare: Kind) -> Kind {
            guard end - start <= 64 else { return bare }
            if (48...57).contains(units[start]) || char(start) == "-" || char(start) == "+" {
                return Double(string(start, end))?.isFinite == true ? .number : bare
            }
            switch char(start) {
            case "t", "f", "n", "y", "o", "T", "F", "N", "Y", "O":
                if ["true", "false", "null", "yes", "no", "on", "off"].contains(string(start, end).lowercased()) { return .literal }
            default: break
            }
            return bare
        }

        mutating func scan(_ format: Format) -> [Span] {
            if Task.isCancelled { return [] }
            if format == .xml { xml(); return spans }
            if format == .json { line(0, units.count, format); return spans }
            var start = 0
            while start < units.count, spans.count < maximumSpans, !Task.isCancelled {
                var end = start
                while end < units.count, units[end] != 10, units[end] != 13 { end += 1 }
                line(start, end, format)
                start = end + 1
                if end < units.count, units[end] == 13, char(start) == "\n" { start += 1 }
            }
            return spans
        }

        mutating func line(_ start: Int, _ end: Int, _ format: Format) {
            var i = start
            if format == .routingEvents { routingLine(start, end); return }
            if format == .shell, let quote = shellQuote {
                let continuation = afterQuote(from: start, to: end, quote: quote, escapes: quote == 34)
                add(.string, start, continuation.index)
                guard continuation.closed else { return }
                shellQuote = nil
                i = continuation.index
            }
            i = skipSpace(i, end)
            guard i < end else { return }
            if format == .yaml, let indent = blockIndent {
                if i - start > indent { add(.literal, i, end); return }
                blockIndent = nil
            }
            if format == .openVPN {
                if matches("-----BEGIN ", at: i, end: end) { pem = true; add(.section, i, end); return }
                if matches("-----END ", at: i, end: end) { pem = false; add(.section, i, end); return }
                if char(i) == "<", let close = units[i..<min(i + 72, end)].firstIndex(of: 62) {
                    let tag = string(i + 1, close).lowercased()
                    if opaqueTag == nil || tag == "/" + (opaqueTag ?? "") {
                        add(.section, i, close + 1)
                        if tag.hasPrefix("/") { opaqueTag = nil; pem = false }
                        else if Self.inlineTags.contains(tag) { opaqueTag = tag }
                        i = skipSpace(close + 1, end)
                        if i < end, char(i) == "#" || char(i) == ";" { add(.comment, i, end) }
                        return
                    }
                }
                if opaqueTag != nil || pem { add(.literal, i, end); return }
            }
            let assignment = format == .wireGuard || format == .ini || format == .ssh || format == .shell
            if (format == .wireGuard || format == .ini), char(i) == "[" {
                let close = units[i..<end].firstIndex(of: 93).map { $0 + 1 } ?? end
                add(.section, i, close)
                i = close
            }
            var first = i == skipSpace(start, end)
            var afterKey = false
            while i < end, spans.count < maximumSpans, !Task.isCancelled {
                if whitespace(i) { i += 1; continue }
                let c = char(i)
                let wordStart = i
                if comment(at: i, start: start, format: format) { add(.comment, i, end); return }
                if c == "\"" || (c == "'" && format != .json) {
                    let token = afterQuote(from: i + 1, to: end, quote: units[i],
                                           escapes: !(c == "'" && (format == .shell || format == .yaml)),
                                           doubled: c == "'" && format == .yaml)
                    if format == .shell, !token.closed { shellQuote = units[i] }
                    i = token.index
                    let next = skipSpace(i, end)
                    let key = (format == .json || format == .yaml) && next < end && char(next) == ":"
                    add(key ? .keyword : .string, wordStart, i)
                } else if structural(i, end, format) || (c == "=" && afterKey && assignment) {
                    i += 1; add(.punctuation, wordStart, i)
                } else {
                    // An escape consumes its following character even if that
                    // character would otherwise begin a comment or end a word.
                    while i < end, !whitespace(i), !structural(i, end, format),
                          !comment(at: i, start: start, format: format),
                          !(assignment && first && char(i) == "="),
                          char(i) != "\"", char(i) != "'" || format == .json {
                        if char(i) == "\\", format != .json { i = min(i + 2, end) } else { i += 1 }
                    }
                    if i == wordStart { i += 1 }
                    let next = skipSpace(i, end)
                    let mappingKey = (format == .json || format == .yaml) && next < end && char(next) == ":"
                    let directive = first && format != .json && format != .yaml
                    var kind = mappingKey || directive ? Kind.keyword : valueKind(wordStart, i, bare: .string)
                    if format == .yaml, ["|", "|-", "|+", ">", ">-", ">+"].contains(i - wordStart <= 2 ? string(wordStart, i) : "") {
                        kind = .punctuation
                        let lineHead = skipSpace(start, end)
                        let keyHead = matches("- ", at: lineHead, end: end) ? skipSpace(lineHead + 1, end) : lineHead
                        blockIndent = keyHead - start
                    }
                    add(kind, wordStart, i)
                }
                afterKey = first
                first = format == .shell && (c == ";" || c == "|" || c == "&")
            }
        }

        /// Legacy rules use whitespace-separated fields, including IPv6 prefixes
        /// and hyphenated action names. In a typed handler the ID precedes a colon.
        func simpleRoutingHeader(_ start: Int, _ end: Int) -> Bool {
            let head = skipSpace(start, end)
            guard matches("on", at: head, end: end), head + 2 < end, whitespace(head + 2) else { return false }
            var p = skipSpace(head + 2, end)
            while p < end, !whitespace(p), char(p) != ":" { p += 1 }
            p = skipSpace(p, end)
            return p < end && char(p) != ":"
        }

        mutating func routingLine(_ start: Int, _ end: Int) {
            let simple = simpleRoutingHeader(start, end)
            var i = start
            while i < end, spans.count < maximumSpans, !Task.isCancelled {
                i = skipSpace(i, end)
                guard i < end else { return }
                if char(i) == "#" || (!simple && matches("//", at: i, end: end)) {
                    add(.comment, i, end)
                    return
                }
                let first = i
                if simple {
                    while i < end, !whitespace(i), char(i) != "#" { i += 1 }
                    let word = string(first, i)
                    let kind: Kind = switch word {
                    case "on", "=>", "port", "dst", "name", "source", "count", "drop", "mark-dscp", "clamp-mss", "set-dns-rd": .keyword
                    case "tcp.syn", "udp.open", "tls.hello", "dns.query", "quic.initial": .section
                    default: UInt16(word) == nil ? .string : .number
                    }
                    add(kind, first, i)
                } else if char(i) == "\"" {
                    i = afterQuote(from: i + 1, to: end, quote: 34).index
                    add(.string, first, i)
                } else if routingIdentifierStart(units[i]) {
                    i += 1
                    var dotted = false
                    while i < end {
                        let unit = units[i]
                        if unit == 46 { dotted = true }
                        else if !routingIdentifierStart(unit) && !(48...57).contains(unit) { break }
                        i += 1
                    }
                    let next = skipSpace(i, end)
                    let word = string(first, i)
                    let kind: Kind = switch word {
                    case "on", "fn", "table", "external", "if", "else", "for", "in", "let", "var", "return", "match", "found", "missing",
                         "bool", "int", "string", "dns", "addr", "prefix", "bytes": .keyword
                    case "true", "false": .literal
                    default: next < end && char(next) == "(" ? .keyword : dotted ? .section : .string
                    }
                    add(kind, first, i)
                } else if (48...57).contains(units[i]) {
                    while i < end, (48...57).contains(units[i]) { i += 1 }
                    if i < end, units[i] == 46 {
                        // An unquoted IPv4 address or prefix. In an integer
                        // expression the slash still belongs to division.
                        while i < end, (48...57).contains(units[i]) || units[i] == 46 || units[i] == 47 { i += 1 }
                    }
                    add(.number, first, i)
                } else {
                    let symbol = char(i)
                    i += 1
                    switch symbol {
                    case "!", "%", "&", "(", ")", "*", "+", ",", "-", "/", ":", ";", "<", "=", ">",
                         "[", "]", "{", "|", "}":
                        switch (symbol, i < end ? char(i) : nil) {
                        case ("-", ">"), ("!", "="), ("<", "="), ("=", "="), (">", "="), ("&", "&"), ("|", "|"): i += 1
                        default: break
                        }
                        add(.punctuation, first, i)
                    default: break
                    }
                }
            }
        }

        func routingIdentifierStart(_ unit: UInt16) -> Bool {
            unit == 95 || (65...90).contains(unit) || (97...122).contains(unit)
        }

        func structural(_ i: Int, _ end: Int, _ format: Format) -> Bool {
            switch (format, char(i)) {
            case (.json, "{"), (.json, "}"), (.json, "["), (.json, "]"), (.json, ":"), (.json, ","): true
            case (.yaml, "{"), (.yaml, "}"), (.yaml, "["), (.yaml, "]"): true
            case (.yaml, ":"), (.yaml, "-"): i + 1 == end || whitespace(i + 1)
            case (.shell, ";"), (.shell, "|"), (.shell, "&"), (.shell, "<"), (.shell, ">"): true
            default: false
            }
        }

        func comment(at i: Int, start: Int, format: Format) -> Bool {
            let c = char(i)
            if format == .wireGuard { return c == "#" }
            if format == .json { return false }
            guard c == "#" || (c == ";" && (format == .openVPN || format == .ini)) else { return false }
            return i == start || whitespace(i - 1)
        }

        mutating func xml() {
            var i = 0
            var inTag = false
            var awaitingName = false
            while i < units.count, spans.count < maximumSpans, !Task.isCancelled {
                let start = i
                if !inTag, matches("<!--", at: i, end: units.count) || matches("<![CDATA[", at: i, end: units.count) {
                    let comment = char(i + 2) == "-"
                    let close: StaticString = comment ? "-->" : "]]>"
                    i += comment ? 4 : 9
                    while i < units.count, !matches(close, at: i, end: units.count) { i += 1 }
                    i = min(i + close.utf8CodeUnitCount, units.count)
                    add(comment ? .comment : .literal, start, i)
                } else if char(i) == "<" {
                    i += 1
                    if char(i) == "/" || char(i) == "?" || char(i) == "!" { i += 1 }
                    add(.punctuation, start, i); inTag = true; awaitingName = true
                } else if inTag {
                    switch char(i) {
                    case ">", "/", "?", "=":
                        if char(i) == ">" { inTag = false }
                        i += 1; add(.punctuation, start, i)
                    case "\"", "'":
                        i = afterQuote(from: i + 1, to: units.count, quote: units[i], escapes: false).index
                        add(.string, start, i)
                    default:
                        if whitespace(i) { i += 1; continue }
                        while i < units.count, !whitespace(i), ![">", "/", "?", "=", "\"", "'", "<"].contains(char(i)) { i += 1 }
                        if start == i { i += 1 }
                        add(awaitingName ? .section : .keyword, start, i); awaitingName = false
                    }
                } else {
                    while i < units.count, char(i) != "<" { i += 1 }
                    if skipSpace(start, i) < i { add(.string, start, i) }
                }
            }
        }
    }
}
