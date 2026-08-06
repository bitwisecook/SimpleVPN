// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DiagnosticReportLog.swift
//  The ONLY path by which anything resembling a log line reaches a diagnostic
//  report — and it is an allow-list of EVENT TYPES, not a filter over text.
//
//  WHY IT IS BUILT THIS WAY. The debug bundle collects `log show` output and
//  scrubs it; that is a blacklist, it is shown to the user before it can leave,
//  and it is honest about being best-effort. A report offered from a banner is
//  different: people will accept it without reading every line, so a blacklist is
//  the wrong primary control.
//
//  So a line is admitted only if:
//   1. its subsystem is ours,
//   2. its CATEGORY is one of ours (a closed set — `Logger(category:)` values),
//   3. its message matches one of the `EventType` patterns below, and
//   4. the emitted text is REBUILT from that event type's own compile-time
//      template plus its captures, each capture rendered as a typed
//      `ReportValue`. Nothing outside a capture group survives, so a secret
//      appended to a known message cannot ride along inside a matched line.
//
//  Anything that does not match is counted and reported as a number. "47 further
//  log events were not of a recognised type and were left out" is a true, useful
//  sentence; pasting those 47 lines in would not be.
//
//  ONE event type deliberately admits free text: a tunnel-start failure's
//  underlying error description. It is the single most useful string in a failure
//  report, it is bounded, and it goes through the scrubber — which is exactly the
//  "defence in depth, not the primary control" case the design allows.
//

import Foundation

nonisolated enum DiagnosticReportLog {

    // MARK: How a capture is typed

    /// What a capture group IS, which decides how it is rendered and therefore
    /// what it is capable of carrying.
    nonisolated enum Capture: Sendable, Equatable {
        /// An enum name / state word.
        case state
        /// A number.
        case count
        /// A version string.
        case version
        /// A profile identifier. Rendered as a stable per-report token: it keeps
        /// "the same VPN again" readable without publishing the identifier.
        case opaqueID
        /// Prose we generate ourselves (a refusal reason).
        case words
        /// An underlying error description — the one free-text capture. Bounded
        /// and scrubbed.
        case errorText
        /// Matched so the pattern can anchor, then thrown away. Used for a
        /// captive-portal sign-in address: knowing a portal was in the way is
        /// useful, knowing which hotel you were in is not.
        case discarded

        func value(_ raw: String, scrubber: SecretScrubber) -> ReportValue? {
            switch self {
            case .state: .state(raw)
            case .count: Int(raw).map { ReportValue.count($0) } ?? .state(raw)
            case .version: .version(raw)
            case .opaqueID: .words(scrubber.token("profile", raw))
            case .words: .words(raw)
            case .errorText: .words(String(raw.prefix(200)))
            case .discarded: nil
            }
        }
    }

    /// One recognised kind of event.
    nonisolated struct EventType: Sendable, Equatable, Identifiable {
        var id: String
        /// The categories this event can come from. Narrow on purpose.
        var categories: Set<String>
        /// Anchored at both ends: a pattern that can match a fragment can be
        /// prefixed with anything at all.
        var pattern: String
        /// The sentence, with `{0}`, `{1}`… replaced by rendered captures. The
        /// wording is OURS, so the emitted line cannot inherit anything from the
        /// log message beyond the captures.
        var template: String
        var captures: [Capture]
    }

    /// The categories any admitted line may come from. Closed set, taken from the
    /// `Logger(category:)` values in this app.
    static let allowedCategories: Set<String> = [
        "vpn", "tunnel", "sysext", "native", "subprocess", "ssh-engine", "sshnet",
        "wireguard", "tailscale", "proxytunnel", "openconnect-ne",
        "route-mediator", "dns-mediator", "proxy-mediator",
        "sign-in-sources", "tool-discovery", "local-tool", "security-key",
        "extdoctor", "crash",
    ]

    /// Every event type. Adding one is a row here; there is no other way in.
    static let eventTypes: [EventType] = [
        // --- Connection lifecycle -----------------------------------------
        EventType(id: "status", categories: ["vpn"],
                  pattern: #"^status\[(.+)\] → (.+)$"#,
                  template: "connection status of {0} \u{2192} {1}",
                  captures: [.opaqueID, .state]),
        EventType(id: "connect-requested", categories: ["vpn"],
                  pattern: #"^connect: (\S+) source=(\S+)$"#,
                  template: "connect requested for {0}, credential source {1}",
                  captures: [.opaqueID, .state]),
        EventType(id: "credential-source", categories: ["vpn"],
                  pattern: #"^credential source for (\S+): (\S+)$"#,
                  template: "credential source for {0} is {1}",
                  captures: [.opaqueID, .state]),
        EventType(id: "start-dispatched", categories: ["vpn"],
                  pattern: #"^startTunnel dispatched for (\S+) \(status now (.+)\)$"#,
                  template: "tunnel start dispatched for {0}, status now {1}",
                  captures: [.opaqueID, .state]),
        EventType(id: "start-dispatched-engine", categories: ["vpn"],
                  pattern: #"^(tailscale|wireguard|proxy tunnel|ssh network tunnel) startTunnel dispatched for (\S+)$"#,
                  template: "{0} tunnel start dispatched for {1}",
                  captures: [.state, .opaqueID]),
        EventType(id: "start-failed", categories: ["vpn"],
                  pattern: #"^startTunnel failed for (\S+): (.+)$"#,
                  template: "tunnel start FAILED for {0}: {1}",
                  captures: [.opaqueID, .errorText]),
        EventType(id: "no-session", categories: ["vpn"],
                  pattern: #"^connect: no NETunnelProviderSession for (\S+)$"#,
                  template: "no tunnel session existed for {0}",
                  captures: [.opaqueID]),
        EventType(id: "watchdog", categories: ["vpn"],
                  pattern: #"^connect watchdog fired for (\S+) — giving up$"#,
                  template: "the connect watchdog gave up on {0}",
                  captures: [.opaqueID]),
        EventType(id: "retry-failed", categories: ["vpn"],
                  pattern: #"^retry failed for (\S+): (.+)$"#,
                  template: "a retry failed for {0}: {1}",
                  captures: [.opaqueID, .errorText]),
        EventType(id: "paused", categories: ["vpn"],
                  pattern: #"^paused (\S+)$"#,
                  template: "{0} was paused",
                  captures: [.opaqueID]),
        EventType(id: "resumed", categories: ["vpn"],
                  pattern: #"^resumed (\S+)$"#,
                  template: "{0} was resumed",
                  captures: [.opaqueID]),
        EventType(id: "auth-config", categories: ["vpn"],
                  pattern: #"^auth config saved for (\S+): requiresOTP=(true|false)$"#,
                  template: "sign-in settings saved for {0}, needs a verification code: {1}",
                  captures: [.opaqueID, .state]),

        // --- Facts about the build and the plan ---------------------------
        EventType(id: "profiles-loaded", categories: ["vpn"],
                  pattern: #"^loadAll: (\d+) profile\(s\)$"#,
                  template: "{0} VPN profile(s) loaded",
                  captures: [.count]),
        EventType(id: "extension-version", categories: ["vpn"],
                  pattern: #"^running extension version: (.+)$"#,
                  template: "the running system extension reports version {0}",
                  captures: [.version]),
        EventType(id: "packet-tunnel-start", categories: ["tunnel"],
                  pattern: #"^startTunnel — PacketTunnel v(.+)$"#,
                  template: "the packet tunnel started, version {0}",
                  captures: [.version]),
        EventType(id: "divert-plan", categories: ["tunnel"],
                  pattern: #"^divert plan: (\d+) destination\(s\) around this VPN, (\d+) routed into it \(kind (\S+)\)$"#,
                  template: "routing plan: {0} destination(s) around this VPN, {1} routed into it, kind {2}",
                  captures: [.count, .count, .state]),

        // --- Things that got in the way -----------------------------------
        EventType(id: "captive-portal", categories: ["vpn"],
                  pattern: #"^captive portal detected, sign-in at (.+)$"#,
                  template: "a captive portal was detected (its sign-in address is deliberately left out)",
                  captures: [.discarded]),
        EventType(id: "control-denied", categories: ["vpn"],
                  pattern: #"^control: (\S+) denied — (.+)$"#,
                  template: "the command {0} was refused: {1}",
                  captures: [.state, .words]),
    ]

    // MARK: Admitting one event

    /// One parsed `log show` record, before any decision is taken about it.
    nonisolated struct Record: Sendable, Equatable {
        var timeOfDay: String
        var category: String
        var messageType: String
        var message: String
    }

    /// The result of a collection: what got in, and how much did not.
    nonisolated struct Admitted: Sendable, Equatable {
        var fields: [DiagnosticReportField] = []
        /// Lines of ours that matched no event type.
        var unrecognised = 0
        /// Lines whose category is not on the allow-list.
        var outsideAllowedCategories = 0
        /// Non-nil when the log could not be read at all.
        var failure: String?
    }

    /// Turn a record into a report field, or refuse it. PURE — the whole
    /// allow-list decision is testable with no `log show` and no filesystem.
    static func admit(_ record: Record, scrubber: SecretScrubber) -> DiagnosticReportField? {
        guard allowedCategories.contains(record.category) else { return nil }
        for type in eventTypes {
            guard type.categories.contains(record.category) else { continue }
            guard let re = try? NSRegularExpression(pattern: type.pattern, options: []) else { continue }
            let ns = record.message as NSString
            guard let m = re.firstMatch(in: record.message,
                                        options: [.anchored],
                                        range: NSRange(location: 0, length: ns.length)),
                  m.range.length == ns.length
            else { continue }
            var rendered = type.template
            for (index, capture) in type.captures.enumerated() {
                let group = index + 1
                let placeholder = "{\(index)}"
                guard group < m.numberOfRanges, m.range(at: group).location != NSNotFound else {
                    rendered = rendered.replacingOccurrences(of: placeholder, with: "\u{2014}")
                    continue
                }
                let raw = ns.substring(with: m.range(at: group))
                let value = capture.value(raw, scrubber: scrubber)
                rendered = rendered.replacingOccurrences(
                    of: placeholder, with: value?.rendered(with: scrubber) ?? "\u{2014}")
            }
            return DiagnosticReportField(
                label: "\(record.timeOfDay) \u{00B7} \(record.category) \u{00B7} \(level(record.messageType))",
                value: .words(rendered))
        }
        return nil
    }

    /// Plain words for a log level. "Df"/"Default" is jargon.
    static func level(_ messageType: String) -> String {
        switch messageType.lowercased() {
        case "error": "error"
        case "fault": "fault"
        case "info": "info"
        case "debug": "debug"
        default: "normal"
        }
    }

    // MARK: Reading the log

    /// Collect recent events. Reads `log show` for OUR subsystem only, in
    /// `ndjson` so each record arrives with its subsystem, category, level and
    /// message as separate fields — parsing a formatted line would mean guessing
    /// at a format Apple can change, and guessing wrong would fail OPEN.
    static func collect(window: TimeInterval = 20 * 60,
                        limit: Int = 120,
                        scrubber: SecretScrubber) async -> Admitted {
        let minutes = max(1, Int(window / 60))
        let raw = await DiagnosticBundle.run(
            "/usr/bin/log",
            ["show", "--style", "ndjson", "--info", "--last", "\(minutes)m",
             "--predicate", #"subsystem BEGINSWITH "com.bragi0.SimpleVPN""#])
        return admitAll(ndjson: raw, limit: limit, scrubber: scrubber)
    }

    /// Split from `collect` so the whole admission pipeline can be tested against
    /// fixture `ndjson` with no subprocess at all.
    static func admitAll(ndjson: String, limit: Int, scrubber: SecretScrubber) -> Admitted {
        var out = Admitted()
        var records: [Record] = []
        var sawAnyRecord = false
        for line in ndjson.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("{") else { continue }
            guard let data = trimmed.data(using: .utf8),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let subsystem = object["subsystem"] as? String,
                  subsystem.hasPrefix("com.bragi0.SimpleVPN"),
                  let message = object["eventMessage"] as? String
            else { continue }
            sawAnyRecord = true
            let category = object["category"] as? String ?? ""
            guard allowedCategories.contains(category) else {
                out.outsideAllowedCategories += 1
                continue
            }
            records.append(Record(
                timeOfDay: timeOfDay(object["timestamp"] as? String ?? ""),
                category: category,
                messageType: object["messageType"] as? String ?? "",
                message: message))
        }
        if !sawAnyRecord,
           !ndjson.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
           !ndjson.contains("{") {
            // `log show` printed something that is not ndjson at all — an error,
            // or a macOS that has changed the format. Say so rather than
            // reporting "no events", which would read as "nothing happened".
            out.failure = "SimpleVPN couldn\u{2019}t read the system log, so no events are included."
            return out
        }
        // Newest last, and only the last `limit`, so a chatty session doesn't
        // produce a report nobody will read.
        var admitted: [DiagnosticReportField] = []
        for record in records {
            if let field = admit(record, scrubber: scrubber) {
                admitted.append(field)
            } else {
                out.unrecognised += 1
            }
        }
        if admitted.count > limit { admitted = Array(admitted.suffix(limit)) }
        out.fields = admitted
        return out
    }

    /// `2026-08-05 13:09:04.424841+0100` → `13:09:04`. A date in a bug report is
    /// only useful for lining two events up; the day and the offset are not.
    static func timeOfDay(_ timestamp: String) -> String {
        guard let re = try? NSRegularExpression(pattern: #"\b(\d{2}:\d{2}:\d{2})\b"#) else {
            return "unknown time"
        }
        let ns = timestamp as NSString
        guard let m = re.firstMatch(in: timestamp, range: NSRange(location: 0, length: ns.length)),
              m.numberOfRanges > 1 else { return "unknown time" }
        return ns.substring(with: m.range(at: 1))
    }
}
