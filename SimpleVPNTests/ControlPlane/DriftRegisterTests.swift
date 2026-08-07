// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DriftRegisterTests.swift
//  THE GUARD BEHIND `Docs/Drift.md`: a test that fails when a SECOND implementation of a
//  guarded concept appears.
//
//  WHY A GUARD RATHER THAN A COLLAPSE. A collapse fixes today; a guard prevents the
//  recurrence, and recurrence is what this repo's bug reports are made of. "Values aren't
//  right-aligned" was reported twice — the second time after a fix that had landed in one
//  of five copies. Two hardware-address parsers made guest names silently never attach.
//  Every one of those was a *second implementation appearing*, and every one was invisible
//  until a person noticed something missing.
//
//  WHAT IT IS NOT. It is not a rule that everything must be collapsed. `Docs/Drift.md` §6
//  is four implementations of prefix policy, with four different subsets of one rulebook,
//  each right for its own question — forcing agreement would break three of them. So this
//  table does not check that implementations AGREE. It checks that the SET OF PLACES has
//  not grown. A sixth prefix policy, a sixth IPv6 bracket, a third tun framing: those fail,
//  and the author then has to come to `Docs/Drift.md` and say which subset is theirs.
//
//  SOURCE-WALKING, like `SettingAlignmentTests` and `HardwareAddressTypeDisciplineTests`,
//  and for the same reason: what is being checked is a property of how the code is
//  WRITTEN. None of these offences has a runtime symptom until something is quietly
//  missing.
//
//  HOW TO FIX A FAILURE, in order of preference:
//   1. Use the existing implementation. Usually this is a one-line import of an idea.
//   2. If it genuinely must differ: add the file to the concept's `allowed` list AND add
//      the reason to `Docs/Drift.md`. Both, always — the table says WHERE and the register
//      says WHY, and neither may be the only record.
//   3. Never widen the needle until it stops matching. That turns the register decorative,
//      which is the failure mode this whole exercise exists to avoid.
//

import Foundation
import Testing

struct DriftRegisterTests {

    // MARK: The register, as a table

    /// One guarded concept: what it is, how to spot an implementation of it, and exactly
    /// which files are allowed to hold one.
    private struct Concept {
        /// The heading in `Docs/Drift.md` this row belongs to.
        let register: String
        /// What is duplicated, in one clause, for the failure message.
        let concept: String
        /// How to recognise an implementation on ONE LINE. Each element is an
        /// ALTERNATIVE, and each alternative is a set of substrings that must ALL appear
        /// on that line.
        ///
        /// Conjunctions rather than an exclusion list, deliberately. A single loose
        /// needle plus a growing list of "ignore this file" exceptions is the same
        /// widening-until-it-stops-matching this test forbids, wearing a rosette: it is
        /// the exceptions that get edited when the guard is inconvenient. A conjunction
        /// says what the concept IS, so `line.hasPrefix("[")` in an INI parser never
        /// matches in the first place and no exception is needed to say so.
        let needles: [[String]]
        /// The files (repo-relative) allowed to contain one. Exhaustive.
        let allowed: Set<String>
        /// What the author of a NEW site has to do — printed on failure, because a
        /// failing test that does not say what to do next gets deleted.
        let instead: String
    }

    private static let concepts: [Concept] = [

        // ── Docs/Drift.md §5 — five today, and the fifth already differs.
        //
        // Three shapes, because the bracket has three: rendering one INTO a string,
        // parsing one OFF the front, and the colon-counting guard that distinguishes
        // `host:443` from `::1`.
        Concept(register: "\u{00A7}5 IPv6 brackets",
                concept: "bracketing (or unbracketing) an IPv6 literal in a host:port string",
                needles: [["\"[\\(", "contains(\":\")"],
                          ["hasPrefix(\"[\")", "firstIndex(of: \"]\")"],
                          ["hasPrefix(\"[\")", "$0 == \":\""]],
                allowed: ["SimpleVPN/Geo/WireGuardEndpointSelection.swift",
                          "SimpleVPN/Geo/EndpointDiscovery.swift",
                          "SimpleVPN/Import/SSHConfigImport.swift",
                          "Shared/SSHNetworkTunnelConfig.swift",
                          "SimpleVPN/Credentials/BitwardenProvider.swift"],
                instead: """
                    five places already do this and they do NOT all agree \u{2014} \
                    BitwardenProvider omits the already-bracketed guard the other four \
                    carry, so a host arriving bracketed would become [[::1]]. Do not add \
                    a sixth: the design for the one type that owns the rendering is \
                    Docs/NetworkTypes.md \u{00A7}3.6
                    """),

        // ── Docs/Drift.md §6 — the model entry. Four subsets, each right; what is
        // bounded is the number of places that REFUSE a prefix, which is two.
        Concept(register: "\u{00A7}6 prefix policy",
                concept: "a refusal about what a CIDR prefix may be (a /0 refusal, a prefix floor)",
                needles: [["ipv4PrefixFloor"], ["ipv6PrefixFloor"], ["prefix > 0,"]],
                allowed: ["Shared/LocalNetworkCarveOut.swift", "Shared/RoutingRule.swift"],
                instead: """
                    prefix policy is deliberately four different subsets in four places \
                    (Docs/Drift.md \u{00A7}6) and they must NOT be forced into agreement \u{2014} \
                    RoutePrefixMath permits a /0 and RouteTableSource accepts a \
                    non-contiguous mask, both correctly. What is bounded is the number of \
                    places that REFUSE one. Say which subset is yours in Docs/Drift.md, or \
                    use one of the four
                    """),

        // ── Docs/Drift.md §7 — two on one screen, now one view.
        Concept(register: "\u{00A7}7 \u{201C}Change\u{2026}\u{201D}",
                concept: "the button that reopens the sign-in chooser",
                needles: [["Button(\"Change\\u{2026}\""]],
                allowed: ["SimpleVPN/UI/Credentials/SignInSourceChooser.swift"],
                instead: """
                    use ChangeSignInSourceButton. There were two of these ON ONE SCREEN \
                    AT ONCE \u{2014} the recovery banner sits directly above the summary \
                    line \u{2014} and they had already drifted into two button styles and \
                    two accessibility shapes
                    """),

        // ── Docs/Drift.md §8 — upstream's difference, not ours, and bounded at two.
        //
        // The tell is the socketpair a tun fd is made from. `SOCK_DGRAM` is part of it:
        // the SSH network tunnel makes a `SOCK_STREAM` socketpair for its control
        // channel, which carries no packets and frames nothing.
        Concept(register: "\u{00A7}8 tun framing",
                concept: "an fd-shaped engine, which must choose a framing for its tun fd",
                needles: [["socketpair(AF_UNIX, SOCK_DGRAM"]],
                allowed: ["PacketTunnel/Bridges/OpenVPN3Bridge.mm",
                          "PacketTunnel/Bridges/OpenConnectBridge.mm"],
                instead: """
                    the two fd-shaped engines frame differently because their own upstream \
                    sources do \u{2014} openvpn3 prepends a 4-byte AF header, libopenconnect \
                    carries raw IP (Docs/Networking.md \u{00A7}3.2, "the single most surprising \
                    thing in the packet path"). A third one must DECLARE its framing in \
                    Docs/Drift.md \u{00A7}8 rather than inherit whichever neighbour it was \
                    copied from; getting it wrong connects the tunnel and carries zero \
                    traffic, silently
                    """),

        // ── Docs/Drift.md §9 — the status vocabulary, and the literals that escaped it.
        Concept(register: "\u{00A7}9 status words",
                concept: "the words for a connection's state, written out instead of read from DotState",
                needles: [["? \"connected\" : \"disconnected\""],
                          ["? \"disconnected\" : \"connected\""]],
                allowed: [],
                instead: """
                    use DotState.accessibilityDescription. These exact literals existed in \
                    the two composition rows (ManageVPNsView and MenuBarView) with nothing \
                    keeping them in step with the enum every other row in the app reads
                    """),

        // ── Docs/Drift.md §10 — two private constants that happened to agree.
        Concept(register: "\u{00A7}10 selection tags",
                concept: "the sidebar's selection-tag prefixes",
                needles: [["= \"tunnel:\""], ["= \"native:\""]],
                allowed: ["SimpleVPN/ControlPlane/ConnectListing.swift"],
                instead: """
                    use ConnectListing.tunnelTag / .nativeTag. A settings route travelling \
                    between the two windows resolves BY TAG, so a second spelling selects \
                    nothing and reports as \u{201C}the link does nothing\u{201D}
                    """),
    ]

    // MARK: The walk

    /// The repo root, from this file's own compile-time path (the idiom
    /// `SettingRenderingTests` established).
    private static let repoRoot: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()      // ControlPlane/
        .deletingLastPathComponent()      // SimpleVPNTests/
        .deletingLastPathComponent()      // repo root

    /// Every source in every target we own, Swift and Objective-C++ alike — the tun
    /// framing lives in `.mm`. NOT the tests: a test may hold a spelling as text, because
    /// a spelling is what it is testing.
    private static func productionSources() throws -> [String: String] {
        var out: [String: String] = [:]
        for directory in ["SimpleVPN", "Shared", "PacketTunnel", "CLI",
                          "OPNativeHelper", "OCAuthHelper"] {
            let root = repoRoot.appendingPathComponent(directory)
            guard let walk = FileManager.default.enumerator(
                at: root, includingPropertiesForKeys: nil) else { continue }
            for case let url as URL in walk
            where ["swift", "mm", "m", "h"].contains(url.pathExtension) {
                let relative = url.path.replacingOccurrences(of: repoRoot.path + "/", with: "")
                out[relative] = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
            }
        }
        #expect(out.count > 100, "only \(out.count) sources found \u{2014} the walk is wrong")
        return out
    }

    /// Whether a line satisfies ANY of a concept's alternatives — an alternative being a
    /// set of substrings that must ALL be on that line.
    private static func matches(_ line: String, _ alternatives: [[String]]) -> Bool {
        alternatives.contains { all in all.allSatisfy(line.contains) }
    }

    /// Whether a whole FILE could satisfy an alternative (every substring appears
    /// somewhere in it). Used only by the staleness check below, where the question is
    /// "is the guard still watching anything here?".
    private static func couldMatch(_ text: String, _ alternatives: [[String]]) -> Bool {
        alternatives.contains { all in all.allSatisfy(text.contains) }
    }

    /// **NO GUARDED CONCEPT GAINS A NEW IMPLEMENTATION.**
    ///
    /// The one test that matters. It does not read what the code DOES; it reads where the
    /// code IS, which is the property that decides whether the next fix reaches every copy.
    @Test func noGuardedConceptGainsASecondImplementation() throws {
        let sources = try Self.productionSources()
        var report: [String] = []

        for concept in Self.concepts {
            var newSites: [String] = []
            for (file, text) in sources where !concept.allowed.contains(file) {
                for (number, line) in text.components(separatedBy: "\n").enumerated() {
                    let trimmed = line.trimmingCharacters(in: .whitespaces)
                    // Prose about a rule is not the rule.
                    guard !trimmed.hasPrefix("//"), !trimmed.hasPrefix("*") else { continue }
                    guard Self.matches(line, concept.needles) else { continue }
                    newSites.append("\(file):\(number + 1)")
                }
            }
            if !newSites.isEmpty {
                report.append("""
                    \u{2022} \(concept.register) \u{2014} \(concept.concept)
                      new site(s): \(newSites.sorted().joined(separator: ", "))
                      \(concept.instead)
                    """)
            }
        }

        #expect(report.isEmpty, """
            A GUARDED CONCEPT HAS A NEW IMPLEMENTATION. Every one of these is a copy that \
            the next fix will not reach \u{2014} which is how \u{201C}values aren't \
            right-aligned\u{201D} came to be reported twice and how guest names came to \
            silently never attach.

            \(report.joined(separator: "\n\n"))

            Fix by using the existing implementation. If it genuinely must differ, add the \
            file to this concept's `allowed` list AND the reason to Docs/Drift.md \u{2014} \
            both, so the table says where and the register says why. Never widen a needle \
            until it stops matching.
            """)
    }

    /// **EVERY GUARDED CONCEPT STILL EXISTS WHERE IT SAYS IT DOES.**
    ///
    /// The other half, and it is not decoration: a needle that has silently stopped
    /// matching anything is a guard that passes forever. When one of these fails because a
    /// concept was genuinely collapsed or renamed, the fix is to update the row here and
    /// the section in `Docs/Drift.md` together.
    @Test func everyGuardedConceptIsStillWhereTheRegisterSaysItIs() throws {
        let sources = try Self.productionSources()
        var stale: [String] = []
        for concept in Self.concepts where !concept.allowed.isEmpty {
            for file in concept.allowed.sorted() {
                guard let text = sources[file] else {
                    stale.append("\(concept.register): \(file) no longer exists")
                    continue
                }
                if !Self.couldMatch(text, concept.needles) {
                    stale.append("""
                        \(concept.register): \(file) no longer matches any of \
                        \(concept.needles) \u{2014} the guard is watching nothing there
                        """)
                }
            }
        }
        #expect(stale.isEmpty, """
            A guard's needle has stopped matching where the register says the \
            implementation is. A guard that matches nothing passes forever, which is worse \
            than no guard because it reads as coverage. Update the row AND Docs/Drift.md: \
            \(stale.joined(separator: " | "))
            """)
    }

    /// **THE REGISTER EXISTS AND EVERY GUARDED CONCEPT HAS A SECTION IN IT.**
    ///
    /// The table and `Docs/Drift.md` are read together on purpose: the table says WHERE an
    /// implementation is allowed and the register says WHY. A row added to the table with
    /// no section to explain it is the "sentence in a commit message nobody re-reads" that
    /// AGENTS.md forbids, in a new costume.
    @Test func everyGuardedConceptHasASectionInTheRegister() throws {
        let url = Self.repoRoot.appendingPathComponent("Docs/Drift.md")
        let register = try String(contentsOf: url, encoding: .utf8)
        #expect(!register.isEmpty, "no register at \(url.path)")
        var missing: [String] = []
        for concept in Self.concepts {
            // The heading marker (`§5`, `§6`, …) has to appear in the register.
            let marker = concept.register.components(separatedBy: " ").first ?? concept.register
            let number = marker.replacingOccurrences(of: "\u{00A7}", with: "")
            if !register.contains("\n## \(number).") {
                missing.append("\(concept.register) (\(concept.concept))")
            }
        }
        #expect(missing.isEmpty, """
            a guarded concept has no section in Docs/Drift.md, so a failure of the guard \
            sends its author to a table with no reason attached: \
            \(missing.joined(separator: " | "))
            """)
    }
}
