// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConfigValue.swift
//  ONE model, TWO encoders. The whole-configuration export/import file (see
//  Docs/SecretsAndSync.md §3, §5 step 1) is offered as JSON and as YAML, and the
//  single mistake that would matter most here is writing it twice: two emitters
//  over two models drift, and the drift shows up as "the YAML import lost my
//  routes". So there is exactly one in-memory shape — this tree — and JSON and
//  YAML are a writer and a reader each over it.
//
//  WHY NOT Codable + JSONEncoder? Two reasons, both about the file being read by
//  a person:
//   • KEY ORDER. A dictionary's encoding order is unspecified, and a config file
//     whose keys shuffle between exports cannot be diffed — and a diff is how the
//     import confirmation shows what a file would change. The map here is an
//     ORDERED list of entries, and both writers preserve it.
//   • BLOCK TEXT. An .ovpn is a multi-line document. As a JSON string it is one
//     enormous "\n"-riddled line; as a YAML block scalar it is the file, readable.
//     `.text` is that distinction, carried in the model rather than guessed at by
//     the emitter.
//
//  It is deliberately a SMALL value language — bool, int, double, string, text,
//  list, map. Nothing else can appear in a configuration, and a format that
//  cannot express more than it needs is a format with fewer ways to be attacked.
//

import Foundation

// MARK: - The tree

/// A configuration document's values. `.string` is a one-line scalar, `.text` is
/// a multi-line document (an .ovpn, a wg-quick file) — the two differ only in how
/// they are WRITTEN, never in what they mean, so a JSON→YAML round trip through
/// this type is lossless.
nonisolated indirect enum ConfigValue: Equatable, Sendable {
    case bool(Bool)
    case int(Int)
    case double(Double)
    case string(String)
    case text(String)
    case list([ConfigValue])
    case map(ConfigMap)

    /// Multi-line text, normalised. Trailing newlines are dropped because a YAML
    /// block scalar cannot preserve them faithfully without an indicator nobody
    /// reads — so they are dropped HERE, once, and the round trip is exact for
    /// every value the writers can produce. A single-line string is stored as
    /// `.string`, so `.text` always means "expect several lines".
    static func document(_ s: String) -> ConfigValue {
        var t = s
        while t.hasSuffix("\n") || t.hasSuffix("\r") { t.removeLast() }
        return t.contains("\n") ? .text(t) : .string(t)
    }

    static func strings(_ list: [String]) -> ConfigValue { .list(list.map { .string($0) }) }

    // MARK: Readers (import side — every one of them TOLERANT)
    //
    // A document from outside the app is not trusted, so nothing here throws on a
    // type mismatch: the caller asks for what it expects and gets nil, and the
    // import plan reports the field as unreadable rather than failing the file.

    var boolValue: Bool? {
        switch self {
        case .bool(let b): b
        // A hand-edited file says `true`/`yes`/`1`; refusing those would be pedantry
        // about a format meant to be typed by a person.
        case .string(let s), .text(let s):
            switch s.lowercased() {
            case "true", "yes", "on": true
            case "false", "no", "off": false
            default: nil
            }
        case .int(let i): i == 0 ? false : (i == 1 ? true : nil)
        default: nil
        }
    }

    var intValue: Int? {
        switch self {
        case .int(let i): i
        case .double(let d): d == d.rounded() ? Int(d) : nil
        case .string(let s), .text(let s): Int(s.trimmingCharacters(in: .whitespaces))
        default: nil
        }
    }

    var doubleValue: Double? {
        switch self {
        case .double(let d): d
        case .int(let i): Double(i)
        case .string(let s), .text(let s): Double(s.trimmingCharacters(in: .whitespaces))
        default: nil
        }
    }

    var stringValue: String? {
        switch self {
        case .string(let s), .text(let s): s
        case .bool(let b): b ? "true" : "false"
        case .int(let i): String(i)
        case .double(let d): String(d)
        default: nil
        }
    }

    var listValue: [ConfigValue]? {
        if case .list(let l) = self { return l }
        return nil
    }

    var stringList: [String]? { listValue?.compactMap(\.stringValue) }

    var mapValue: ConfigMap? {
        if case .map(let m) = self { return m }
        return nil
    }

    /// The `JSONSerialization`-shaped object graph, so an imported value can be
    /// handed straight back to the app's own `Codable` decoders. The import side
    /// deliberately never hand-decodes a config struct: the struct's own
    /// (lenient, version-tolerant) decoder is the one that has to accept the
    /// value, so it is the one that gets to judge it.
    var jsonObject: Any {
        switch self {
        case .bool(let b): return b
        case .int(let i): return i
        case .double(let d): return d
        case .string(let s), .text(let s): return s
        case .list(let l): return l.map(\.jsonObject)
        case .map(let m):
            return Dictionary(m.entries.map { ($0.key, $0.value.jsonObject) },
                              uniquingKeysWith: { _, last in last })
        }
    }

    /// What a diff line calls this value. Never a secret — nothing secret reaches
    /// this tree (see ConfigSecrets) — and never more than one line.
    var displayText: String {
        switch self {
        case .bool(let b): return b ? "on" : "off"
        case .int(let i): return String(i)
        case .double(let d): return String(d)
        case .string(let s): return s.isEmpty ? "(empty)" : s
        case .text(let s):
            let lines = s.components(separatedBy: "\n").count
            return "\(lines) line\(lines == 1 ? "" : "s") of text"
        case .list(let l):
            return l.isEmpty ? "(none)" : l.compactMap(\.stringValue).joined(separator: ", ")
        case .map(let m):
            return m.entries.isEmpty ? "(none)" : "\(m.entries.count) setting\(m.entries.count == 1 ? "" : "s")"
        }
    }
}

/// An ORDER-PRESERVING map. Order is not cosmetic: the import confirmation shows
/// a diff of the file against what is installed, and a diff of two shuffled key
/// lists is unreadable.
nonisolated struct ConfigMap: Equatable, Sendable {

    nonisolated struct Entry: Equatable, Sendable {
        let key: String
        var value: ConfigValue
    }

    var entries: [Entry] = []

    init() {}
    init(_ entries: [Entry]) { self.entries = entries }

    var isEmpty: Bool { entries.isEmpty }
    var keys: [String] { entries.map(\.key) }

    subscript(_ key: String) -> ConfigValue? {
        get { entries.first { $0.key == key }?.value }
        set {
            guard let newValue else {
                entries.removeAll { $0.key == key }
                return
            }
            if let i = entries.firstIndex(where: { $0.key == key }) { entries[i].value = newValue }
            else { entries.append(Entry(key: key, value: newValue)) }
        }
    }

    /// Append only when there is something to say. Used everywhere on the export
    /// side so an untouched setting leaves no line at all — the same rule
    /// `OpenVPNOverrides` follows for `providerConfiguration`, for the same reason:
    /// a file full of defaults hides the two lines that matter.
    mutating func put(_ key: String, _ value: ConfigValue?) {
        guard let value else { return }
        self[key] = value
    }

    mutating func put(_ key: String, ifNotEmpty s: String?) {
        guard let s, !s.isEmpty else { return }
        put(key, .document(s))
    }

    mutating func put(_ key: String, ifNotEmpty list: [String]?) {
        guard let list, !list.isEmpty else { return }
        put(key, .strings(list))
    }

    mutating func put(_ key: String, ifNotEmpty map: ConfigMap?) {
        guard let map, !map.isEmpty else { return }
        put(key, .map(map))
    }

    mutating func put(_ key: String, ifNotEmpty list: [ConfigMap]?) {
        guard let list, !list.isEmpty else { return }
        put(key, .list(list.map { .map($0) }))
    }
}
