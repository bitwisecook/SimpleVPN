// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  LogHighlighter.swift
//  Syntax highlighting and severity tinting for log text.
//
//  This is not decoration. The user is asked to READ a diagnostics bundle before sharing
//  it — to check for a hostname or username they'd rather not publish — and a wall of
//  identical grey monospace makes that review impossible to do properly. Colouring
//  exactly the categories that matter (addresses, hostnames, users, versions) turns
//  "scroll past it and hope" into a review you can actually perform. The same reason
//  applies to spotting the one error line in 400 lines of chatter.
//
//  Highlighting is presentation only: the text that gets shared is always the original.
//

import SwiftUI

nonisolated enum LogHighlighter {

    // MARK: Line severity

    enum Severity: Sendable {
        case fault, error, warning, notice, debug, plain, heading, note

        /// Row background. Deliberately faint — this has to survive being read for
        /// minutes, and a saturated block behind body text is exhausting. Dark mode
        /// needs slightly more alpha to register against a dark surface.
        func tint(dark: Bool) -> Color? {
            switch self {
            case .fault:   return .red.opacity(dark ? 0.30 : 0.17)
            case .error:   return .red.opacity(dark ? 0.18 : 0.10)
            case .warning: return .yellow.opacity(dark ? 0.18 : 0.16)
            case .heading: return .gray.opacity(dark ? 0.22 : 0.12)
            case .note:    return .teal.opacity(dark ? 0.16 : 0.10)
            case .notice, .debug, .plain: return nil
            }
        }

        var isDim: Bool { self == .debug }
        /// AppKit counterpart of `tint(dark:)`, resolved per appearance so the same
        /// string works in light and dark without being rebuilt.
        func nsTint() -> NSColor? {
            func dynamic(_ base: NSColor, dark: CGFloat, light: CGFloat) -> NSColor {
                NSColor(name: nil) { appearance in
                    let isDark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
                    return base.withAlphaComponent(isDark ? dark : light)
                }
            }
            switch self {
            case .fault:   return dynamic(.systemRed, dark: 0.30, light: 0.17)
            case .error:   return dynamic(.systemRed, dark: 0.18, light: 0.10)
            case .warning: return dynamic(.systemYellow, dark: 0.18, light: 0.16)
            case .heading: return dynamic(.systemGray, dark: 0.22, light: 0.12)
            case .note:    return dynamic(.systemTeal, dark: 0.16, light: 0.10)
            case .notice, .debug, .plain: return nil
            }
        }

    }

    /// `log show --style compact` type column. Verified against real output on macOS 26:
    /// Df, I, A, E, Sd, Db, F, Ts.
    private static func severity(forType type: String) -> Severity {
        switch type {
        case "F", "Fa": return .fault
        case "E", "Er": return .error
        case "Db", "Dg", "D": return .debug
        case "A", "Sd", "Ts": return .debug      // activity/signpost/timesync: structural noise
        case "I", "In": return .notice
        default: return .plain                    // Df and anything unrecognised
        }
    }

    /// Words that mean trouble in a line the OS didn't classify as an error. Unified
    /// logging has no "warning" level at all, so this heuristic is the only way to
    /// surface "TLS handshake failed" when it was logged at default level — which is
    /// where openvpn3 and openconnect put most of what goes wrong.
    private static let warningWords: Set<String> = [
        "warn", "warning", "fail", "failed", "failure", "timeout", "timed",
        "retry", "retrying", "refused", "unreachable", "denied", "invalid",
        "cannot", "couldn't", "unable", "dropped", "stall", "stalled",
        "mismatch", "expired", "rejected", "abort", "aborted", "error",
    ]

    private static func looksLikeWarning(_ text: String) -> Bool {
        for word in text.lowercased().split(whereSeparator: { !$0.isLetter && $0 != "'" }) {
            if warningWords.contains(String(word)) { return true }
        }
        return false
    }

    // MARK: Structure

    /// One display line: what to draw, and how to tint the row behind it.
    struct Line: Identifiable, Sendable {
        let id: Int
        let text: String
        let severity: Severity
        /// The part before the message (timestamp/type/process/subsystem), if this parsed
        /// as a log line. Drawn dimmed so the eye goes to the message.
        let prefixLength: Int
    }

    /// Split and classify. Cheap — no token regexes here, so a 5000-line bundle can be
    /// prepared up front while the per-line colouring stays lazy.
    static func lines(_ text: String) -> [Line] {
        text.split(separator: "\n", omittingEmptySubsequences: false)
            .enumerated()
            .map { index, raw in classify(String(raw), id: index) }
    }

    private static func classify(_ raw: String, id: Int) -> Line {
        // Markdown scaffolding from DiagnosticBundle.
        if raw.hasPrefix("#") { return Line(id: id, text: raw, severity: .heading, prefixLength: 0) }
        if raw.hasPrefix(">") { return Line(id: id, text: raw, severity: .note, prefixLength: 0) }
        if raw.hasPrefix("```") { return Line(id: id, text: raw, severity: .debug, prefixLength: 0) }

        // Compact log line: "2026-07-30 12:20:14.426 Df SimpleVPN[385:230] [sub:cat] msg"
        if let parsed = parseCompactLogLine(raw) {
            var sev = severity(forType: parsed.type)
            if sev == .plain || sev == .notice, looksLikeWarning(parsed.message) { sev = .warning }
            return Line(id: id, text: raw, severity: sev, prefixLength: parsed.prefixLength)
        }

        // Not a log line (netstat/ifconfig output, our own markdown tables).
        return Line(id: id, text: raw, severity: .plain, prefixLength: 0)
    }

    private struct ParsedLine { let type: String; let message: String; let prefixLength: Int }

    /// Hand-rolled rather than a regex: it runs on every line of every bundle, and the
    /// shape is rigidly positional.
    private static func parseCompactLogLine(_ line: String) -> ParsedLine? {
        // Needs at least "yyyy-mm-dd hh:mm:ss.mmm T ".
        guard line.count > 26 else { return nil }
        let chars = Array(line)
        guard chars[4] == "-", chars[7] == "-", chars[10] == " ",
              chars[13] == ":", chars[16] == ":" else { return nil }

        var idx = line.index(line.startIndex, offsetBy: 23)
        // Skip to the type column.
        while idx < line.endIndex, line[idx] == " " { idx = line.index(after: idx) }
        var typeEnd = idx
        while typeEnd < line.endIndex, line[typeEnd] != " " { typeEnd = line.index(after: typeEnd) }
        let type = String(line[idx..<typeEnd])
        guard !type.isEmpty, type.count <= 3 else { return nil }

        // The prefix ends after the "[subsystem:category]" bracket when there is one,
        // else after "process[pid:tid]".
        var cursor = typeEnd
        var prefixEnd = typeEnd
        var seenBrackets = 0
        while cursor < line.endIndex, seenBrackets < 2 {
            if line[cursor] == "]" {
                seenBrackets += 1
                prefixEnd = line.index(after: cursor)
            }
            cursor = line.index(after: cursor)
        }
        let message = prefixEnd < line.endIndex ? String(line[prefixEnd...]) : ""
        return ParsedLine(type: type, message: message,
                          prefixLength: line.distance(from: line.startIndex, to: prefixEnd))
    }

    // MARK: Token highlighting

    /// What a token is, which decides its colour. Kept small on purpose: more colours
    /// than this stops being a signal and starts being confetti.
    enum Token: CaseIterable {
        case placeholder    // <ip4-private:ab12> — a scrubbed value
        case uuid
        case mac
        case ipv6
        case cidr
        case ipv4
        case url
        case email
        case path
        case version
        case bundleID
        case host
        case interface
        case key            // foo= in foo=bar
        case quoted

        /// Priority order. Most specific first, because a claimed range is never
        /// re-claimed — this is what stops the host pattern eating an IP address, or a
        /// version number being read as a hostname.
        static var byPriority: [Token] {
            [.placeholder, .uuid, .mac, .ipv6, .cidr, .ipv4, .url, .email,
             .path, .version, .bundleID, .host, .interface, .key, .quoted]
        }

        var color: Color {
            switch self {
            // Scrubbed values get the strongest signal: in a scrubbed bundle these mark
            // every place something WAS removed, which is what a reviewer wants to see.
            case .placeholder: return .mint
            case .ipv4, .ipv6, .cidr: return .cyan
            case .mac: return .teal
            case .host, .url: return .blue
            case .email: return .pink        // the closest thing to a username in a log
            case .path: return .indigo
            case .version: return .purple
            case .bundleID: return .brown
            case .uuid: return .gray
            case .interface: return .orange
            case .key: return .secondary
            case .quoted: return .green
            }
        }

        var nsColor: NSColor {
            switch self {
            case .placeholder: return .systemMint
            case .ipv4, .ipv6, .cidr: return .systemCyan
            case .mac: return .systemTeal
            case .host, .url: return .systemBlue
            case .email: return .systemPink
            case .path: return .systemIndigo
            case .version: return .systemPurple
            case .bundleID: return .systemBrown
            case .uuid: return .systemGray
            case .interface: return .systemOrange
            case .key: return .secondaryLabelColor
            case .quoted: return .systemGreen
            }
        }

        var pattern: String {
            switch self {
            case .placeholder: return #"<[a-z0-9]+(?:-[a-z0-9]+)*:[0-9a-f]+>"#
            case .uuid:        return #"\b[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\b"#
            case .mac:         return #"\b(?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}\b"#
            // Require >= 3 colon groups or a "::" so clock times can't match.
            case .ipv6:        return #"(?:\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}(?:/\d{1,3})?\b)|(?:\b[0-9a-fA-F]{0,4}::[0-9a-fA-F:.]*(?:/\d{1,3})?)"#
            case .cidr:        return #"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b"#
            case .ipv4:        return #"\b(?:\d{1,3}\.){3}\d{1,3}\b"#
            case .url:         return #"\bhttps?://[^\s<>"')\]]+"#
            case .email:       return #"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"#
            case .path:        return #"(?:/Users/[^\s:,)\]]+|/(?:private|var|tmp|Applications|Library|etc|usr|opt|System)/[^\s:,)\]]*)"#
            // Versions before hosts, so "0.1" and "3.6.3" aren't read as domain names.
            case .version:     return #"(?:\b(?:OpenSSH|OpenSSL|LibreSSL|OpenVPN|dropbear|libssh2)[-_/ ]?\d[0-9A-Za-z._+-]*)|(?:\bbuild \d+\b)|(?:\bv?\d+\.\d+(?:\.\d+){0,2}(?:[-_+][0-9A-Za-z.]+)?\b)"#
            case .bundleID:    return #"\b(?:com|org|net|io|uk)\.[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+\b"#
            case .host:        return #"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"#
            case .interface:   return #"\b(?:en|utun|awdl|llw|bridge|gif|stf|anpi|ap)\d+\b|\blo0\b"#
            case .key:         return #"\b[a-zA-Z][a-zA-Z0-9_.\-]*(?==)"#
            case .quoted:      return #""[^"\n]{0,200}"|'[^'\n]{0,200}'"#
            }
        }
    }

    /// Compiled once. A bad pattern here is a programmer error, and
    /// LogHighlighterTests constructs every one of them so it can't ship broken.
    private static let compiled: [(Token, NSRegularExpression)] = Token.byPriority.compactMap {
        guard let re = try? NSRegularExpression(pattern: $0.pattern) else { return nil }
        return ($0, re)
    }

    /// The coloured spans in one line, in priority order with no overlaps. Extracted
    /// so the renderer and the tests share exactly one implementation of the ordering
    /// rule that keeps an IP address from being read as a hostname.
    static func spans(in line: Line) -> [(range: NSRange, token: Token)] {
        let ns = line.text as NSString
        guard ns.length > 0 else { return [] }
        var claimed: [NSRange] = []
        // The prefix is dimmed wholesale, so nothing inside it should be re-coloured.
        if line.prefixLength > 0 {
            claimed.append(NSRange(location: 0, length: min(line.prefixLength, ns.length)))
        }
        var found: [(range: NSRange, token: Token)] = []
        let full = NSRange(location: 0, length: ns.length)
        for (token, re) in compiled {
            for match in re.matches(in: line.text, options: [], range: full) {
                let r = match.range
                guard r.length > 0,
                      !claimed.contains(where: { NSIntersectionRange($0, r).length > 0 })
                else { continue }
                claimed.append(r)
                found.append((r, token))
            }
        }
        return found
    }

    /// The whole document as one attributed string, for the NSTextView-backed viewer.
    ///
    /// One string rather than a view per line is what makes ⌘A, click-drag across lines
    /// and ⌘F work — which matters more than anything else here, because the entire
    /// point of this text is that the user copies it into a bug report.
    static func nsAttributed(_ text: String, font: NSFont,
                             differentiateWithoutColor: Bool = false) -> NSAttributedString {
        let out = NSMutableAttributedString(string: text, attributes: [
            .font: font,
            .foregroundColor: NSColor.labelColor,
        ])
        var lineStart = 0
        let whole = text as NSString
        for line in lines(text) {
            let lineLength = (line.text as NSString).length
            // Include the newline in the background range: in TextKit that stretches the
            // tint to the end of the line box, so severities read as bands rather than
            // ragged word-shaped blobs.
            let bgLength = min(lineLength + 1, max(0, whole.length - lineStart))
            if bgLength > 0, let tint = line.severity.nsTint() {
                out.addAttribute(.backgroundColor, value: tint,
                                 range: NSRange(location: lineStart, length: bgLength))
            }
            // Differentiate Without Color: the red/orange bands gain an
            // underline channel — thick for fault/error, single for warning —
            // so severity survives without hue.
            if differentiateWithoutColor, lineLength > 0 {
                let style: NSUnderlineStyle? = switch line.severity {
                case .fault, .error: .thick
                case .warning: .single
                default: nil
                }
                if let style {
                    out.addAttribute(.underlineStyle, value: style.rawValue,
                                     range: NSRange(location: lineStart, length: lineLength))
                }
            }
            if line.severity == .heading, lineLength > 0 {
                out.addAttributes([.font: NSFont.monospacedSystemFont(ofSize: font.pointSize,
                                                                     weight: .bold)],
                                  range: NSRange(location: lineStart, length: lineLength))
            }
            if line.severity.isDim, lineLength > 0 {
                out.addAttribute(.foregroundColor, value: NSColor.secondaryLabelColor,
                                 range: NSRange(location: lineStart, length: lineLength))
            }
            // Dim the repeated timestamp/process/subsystem prefix — identical on every
            // line, so it's noise once seen, and dimming it makes the message pop.
            if line.prefixLength > 0 {
                out.addAttribute(.foregroundColor, value: NSColor.secondaryLabelColor,
                                 range: NSRange(location: lineStart,
                                                length: min(line.prefixLength, lineLength)))
            }
            for span in spans(in: line) {
                out.addAttribute(.foregroundColor, value: span.token.nsColor,
                                 range: NSRange(location: lineStart + span.range.location,
                                                length: span.range.length))
            }
            lineStart += lineLength + 1
        }
        return out
    }
}
