// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  LogHighlighterTests.swift
//  The highlighter is built on hand-written patterns and a positional parse of
//  `log show --style compact`. Both are the kind of thing that rots silently, and the
//  cost of rot is a diagnostics review the user can't actually perform. So: assert the
//  real formats, and assert the priority order that stops an IP being read as a hostname.
//

import Testing
@testable import SimpleVPN

struct LogHighlighterTests {

    // Real lines, copied from `log show --style compact` output on macOS 26.
    private let activated = "2026-07-30 12:20:14.480 Df SimpleVPN[38512:230779] [com.bragi0.SimpleVPN:sysext] system extension activated: result=0 bundled=v0.1 (build 47)"
    private let failed = "2026-07-30 12:43:36.848 E  SimpleVPN[41014:239f7f] [com.bragi0.SimpleVPN:sysext] system extension failed: App must be in /Applications"

    @Test func compactLogLinesAreRecognisedAndTyped() {
        let lines = LogHighlighter.lines("\(activated)\n\(failed)")
        #expect(lines.count == 2)
        // Df with nothing alarming in it ⇒ no tint.
        #expect(lines[0].severity == .plain)
        // The E type column ⇒ error.
        #expect(lines[1].severity == .error)
        // The prefix (timestamp…subsystem) is identified so it can be dimmed, and it
        // must stop at the subsystem bracket, not swallow the message.
        #expect(lines[0].prefixLength > 0)
        let prefix = String(activated.prefix(lines[0].prefixLength))
        #expect(prefix.hasSuffix("]"))
        #expect(!prefix.contains("system extension activated"))
    }

    @Test func defaultLevelFailuresAreRaisedToWarning() {
        // Unified logging has no warning level, and openvpn3/openconnect log most of
        // what goes wrong at default. Without this heuristic those lines are invisible.
        let line = "2026-07-30 12:20:14.480 Df SimpleVPN[1:2] [com.bragi0.SimpleVPN:vpn] TLS handshake timed out, retrying"
        #expect(LogHighlighter.lines(line)[0].severity == .warning)
    }

    @Test func markdownScaffoldingIsClassified() {
        let text = "## Routing table\n```\n> Scrubbed capture: addresses replaced.\n"
        let lines = LogHighlighter.lines(text)
        #expect(lines[0].severity == .heading)
        #expect(lines[1].severity == .debug)   // fence: structural, dimmed
        #expect(lines[2].severity == .note)
    }

    @Test func nonLogTextIsLeftAlone() {
        // netstat -rn output must not be mistaken for a log line.
        let route = "default            192.168.87.10      UGScg            en0"
        let line = LogHighlighter.lines(route)[0]
        #expect(line.severity == .plain)
        #expect(line.prefixLength == 0)
    }

    @Test func clockTimesAreNotMistakenForIPv6() {
        // The timestamp holds "12:20:14", which a loose IPv6 pattern would claim.
        // Colouring a clock as an address would actively mislead a privacy review.
        let line = LogHighlighter.lines(activated)[0]
        let ipish = LogHighlighter.spans(in: line).filter {
            [.ipv6, .ipv4, .cidr, .mac].contains($0.token)
        }
        #expect(ipish.isEmpty)
    }

    @Test func addressesWinOverHostnamesAndVersionsOverDomains() {
        // The priority order is the whole correctness story: an IP must not be claimed as
        // a hostname, and "3.6.3" must not be claimed as a domain name.
        let text = "connect 192.168.87.10 v0.1 tig-vpn.grlab.co.uk build 47 en0 3.6.3"
        let line = LogHighlighter.lines(text)[0]
        let byText = Dictionary(
            LogHighlighter.spans(in: line).map {
                ((text as NSString).substring(with: $0.range), $0.token)
            }, uniquingKeysWith: { a, _ in a })
        #expect(byText["192.168.87.10"] == .ipv4)
        #expect(byText["tig-vpn.grlab.co.uk"] == .host)
        #expect(byText["3.6.3"] == .version)
        #expect(byText["v0.1"] == .version)
        #expect(byText["en0"] == .interface)
    }

    @Test func everyPatternCompilesAndMatches() {
        // A pattern that fails to compile is skipped silently, so a typo would just
        // quietly stop highlighting one category rather than failing loudly.
        let sample = "192.168.87.10/24 aa:bb:cc:dd:ee:ff host.example.com v1.2.3 en0 <ip4-private:ab12ef> /Users/x a=b"
        let kinds = Set(LogHighlighter.spans(in: LogHighlighter.lines(sample)[0]).map(\.token))
        #expect(kinds.contains(.cidr))
        #expect(kinds.contains(.mac))
        #expect(kinds.contains(.host))
        #expect(kinds.contains(.version))
        #expect(kinds.contains(.interface))
        #expect(kinds.contains(.placeholder))
        #expect(kinds.contains(.path))
    }

    @Test func wholeDocumentRendersAsOneSelectableString() {
        // One attributed string (not a view per line) is what makes ⌘A and cross-line
        // drag selection work — the thing this text exists for.
        let text = "\(activated)\n\(failed)\n"
        let out = LogHighlighter.nsAttributed(text, font: .monospacedSystemFont(ofSize: 11, weight: .regular))
        #expect(out.string == text)
        // The error line must carry a background tint; the plain one must not.
        var range = NSRange()
        let errorOffset = (("\(activated)\n") as NSString).length + 5
        let bg = out.attribute(.backgroundColor, at: errorOffset, effectiveRange: &range)
        #expect(bg != nil)
    }
}
