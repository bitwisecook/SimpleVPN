// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CustomRoutingTabView.swift
//  The "Custom Routing" tab/section embedded in every VPN kind's editor — the SwiftUI
//  surface over Mediators/CustomRouting.swift (the model is done; this only binds to
//  it). Three sub-sections (Routes / DNS / Proxy), each an ordered rule list the user
//  builds against the profile's last-seen PUSHED reference (works offline), with
//  field-level inline validation and a small set of status icons driven entirely by
//  the model (`ruleStatus`, `CustomRoutingValidator`, `CustomRoutingDiff`).
//
//  Commit model: the HOST editor owns the draft (`profile` + the proxy-auth keychain
//  fields) as plain @State, because every editor here has its own Save button that
//  must persist even while this tab/section never disappears (a Form-embedded
//  section, or the active tab in a TabView, doesn't fire onDisappear just because
//  Save was clicked). `commitCustomRouting` is the single place that syncs the proxy
//  keychain ref, sanitizes out rules with field ERRORS (so a broken CIDR never
//  reaches the mediators — see `sanitizedCustomRoutingProfile`), and calls
//  `VPNController.setCustomRouting`. Every host calls it from Save AND this view
//  calls it from `onDisappear` (covers "navigated to another tab" and "closed the
//  editor" alike) — safe to call repeatedly, exactly like `setCustomRouting` itself.
//
//  Animated arrow (Routes only — DNS/proxy `RuleStatus` never reports `.overlapping`):
//  the rule list + pushed-route reference live in ONE fixed-height ScrollView so the
//  Canvas overlay, laid over that same ScrollView via `.onPreferenceChange` +
//  `.overlay`, has a real viewport to clamp against. Row anchors are collected with
//  `anchorPreference` (`RouteAnchorKey`) — Anchor resolution is scroll-offset aware by
//  construction, so the arrow tracks live as the list scrolls, no timer/polling. An
//  endpoint scrolled
//  out of the viewport is clamped to the nearest edge and gets a small chevron
//  pointing toward the true (off-screen) position; the arrow itself animates in via a
//  0→1 progress value on focus (a Path trim) and then sits still — no persistent
//  animation. `accessibilityReduceMotion` snaps the progress straight to 1.
//
//  Crash invariant (see AGENTS.md / layout-loop-crash memory): the ONLY thing that
//  animates is the Canvas overlay's path trim. Every control (Picker, TextField,
//  SecureField, Toggle, Button) lives in an ordinary, untransformed sibling — never
//  inside a scaled/animated container — exactly like RouteGraphView's edge Canvas
//  sits apart from its cards' real controls.
//

import SwiftUI

// MARK: - Free helpers (shared by this view AND every host editor's Save button)

/// Drop any rule/domain whose OWN validation reports a field ERROR before this profile
/// reaches the mediators. Warnings are non-blocking (kept); an erroring rule stays in
/// the user's draft (so they don't lose what they typed) but never gets applied —
/// `RouteFilter.apply`/`DNSCustomization.apply` emit a target verbatim with no syntax
/// check of their own, so an unfixed `10.0.0.0/33` would otherwise reach the OS. Proxy
/// needs no such filtering: `ProxyCustomization.apply` already falls back to the
/// captured intent when `.custom` doesn't parse.
func sanitizedCustomRoutingProfile(_ profile: CustomRoutingProfile) -> CustomRoutingProfile {
    var out = profile
    // …and blank the fields each verb doesn't use. The editor clears them as the
    // verb changes, but a profile stored before that did (or one written by MDM
    // or the CLI) can still carry a hidden target on an Accept — see
    // `RouteRule.clearingUnusedFields()`.
    out.routes.rules = profile.routes.rules
        .filter { !CustomRoutingValidator.validate($0).contains(where: \.isError) }
        .map { $0.clearingUnusedFields() }
    out.dns.resolverRules = profile.dns.resolverRules
        .filter { !CustomRoutingValidator.validate($0).contains(where: \.isError) }
        .map { $0.clearingUnusedFields() }
    out.dns.addSearchDomains = profile.dns.addSearchDomains.filter(CustomRoutingValidator.isValidDomain)
    out.dns.addMatchDomains = profile.dns.addMatchDomains.filter(CustomRoutingValidator.isValidDomain)
    out.dns.ignoreSearchDomains = profile.dns.ignoreSearchDomains.filter(CustomRoutingValidator.isValidDomain)
    out.dns.ignoreMatchDomains = profile.dns.ignoreMatchDomains.filter(CustomRoutingValidator.isValidDomain)
    return out
}

/// Sync the Custom Routing proxy auth fields into the keychain + the profile's
/// `authSource` ref (NEVER inline credentials in the model). Clearing both fields
/// deletes the stored secret and clears the ref. The sign-in applies to Accept (a
/// PUSHED proxy behind authentication) and Custom alike; Ignore means direct, so it
/// keeps the stored secret (a mode flip shouldn't lose what was typed) but drops the
/// ref — an unreferenced secret can never reach an apply.
func syncCustomRoutingProxyAuth(username: String, password: String,
                                profile: inout CustomRoutingProfile, profileID: String) {
    guard !(username.isEmpty && password.isEmpty) else {
        KeychainCredentialStore.deleteCustomRoutingProxyAuth(profile: profileID)
        profile.proxy.authSource = nil
        return
    }
    try? KeychainCredentialStore.saveCustomRoutingProxyAuth(
        profile: profileID, .init(username: username, password: password))
    profile.proxy.authSource = profile.proxy.mode == .ignore
        ? nil : ProxyAuthSourceRef.ref(forProfile: profileID)
}

/// Load the proxy auth fields once (write-only convention elsewhere in this app
/// reads a stored SECRET back only when the user is actively editing it — this one
/// is a plain per-profile pair, not a shared credential, so reading it back to
/// pre-fill the fields is safe and expected).
func loadCustomRoutingProxyAuthFields(profileID: String) -> (username: String, password: String) {
    guard let auth = KeychainCredentialStore.loadCustomRoutingProxyAuth(profile: profileID) else {
        return ("", "")
    }
    return (auth.username, auth.password)
}

/// THE commit point: on Save, on navigating away from the tab, and on leaving the
/// edited item, every host calls this. Idempotent — safe to call more than once (the
/// mediators re-arbitrate a pure/idempotent plan; `setCustomRouting` documents the
/// same guarantee).
@MainActor
func commitCustomRouting(_ vpn: VPNController, profileID: String, profile: CustomRoutingProfile,
                         proxyAuthUsername: String, proxyAuthPassword: String) async -> CustomRoutingProfile {
    var p = profile
    syncCustomRoutingProxyAuth(username: proxyAuthUsername, password: proxyAuthPassword,
                              profile: &p, profileID: profileID)
    await vpn.setCustomRouting(sanitizedCustomRoutingProfile(p), for: profileID)
    return p
}

// MARK: - Row anchoring (Routes overlap arrow only)

private struct RouteAnchorKey: PreferenceKey {
    static var defaultValue: [String: Anchor<CGPoint>] = [:]
    static func reduce(value: inout [String: Anchor<CGPoint>], nextValue: () -> [String: Anchor<CGPoint>]) {
        value.merge(nextValue()) { _, new in new }
    }
}

private extension View {
    /// Tag a row with a stable key ("rule:<uuid>" / "pushed:<value>") whose CENTER
    /// point is later resolved, scroll-and-all, by the arrow overlay.
    func routingAnchor(_ key: String) -> some View {
        anchorPreference(key: RouteAnchorKey.self, value: .center) { [key: $0] }
    }
}

// MARK: - Small shared badges

/// One glyph for the three non-`.active` statuses `RuleStatus` reports — the same
/// vocabulary RouteGraphView's icons use, so the two surfaces read as one system.
private struct RuleStatusBadge: View {
    let status: RuleStatus

    /// The glyph is the tooltip's target, so it obeys the app-wide 22×22 minimum
    /// like every other hit/hover target — at intrinsic ~13pt the explanation was
    /// behind a pixel-hunt.
    private func glyph(_ name: String) -> some View {
        Image(systemName: name)
            .frame(width: 22, height: 22)
            .contentShape(Rectangle())
    }

    var body: some View {
        switch status {
        case .active:
            EmptyView()
        case .orphaned:
            glyph("questionmark.circle")
                .foregroundStyle(.secondary)
                .help("This rule doesn't match anything this VPN currently pushes.")
                .accessibilityLabel("Orphaned rule")
        case .redundant:
            glyph("arrow.triangle.merge")
                .foregroundStyle(.secondary)
                // Covers both redundancies the model reports: a Replace/Add whose
                // target already matches a pushed item, and an Ignore in a section
                // that already ignores everything unmatched.
                .help("This rule can't change anything — the outcome is the same without it.")
                .accessibilityLabel("Redundant rule")
        case .overlapping:
            glyph("exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .help("This overlaps a route already carried by this VPN.")
                .accessibilityLabel("Overlapping rule")
        }
    }
}

/// Inline field-level validation, rendered right under the control it's about —
/// non-blocking warnings and blocking-on-commit errors look different so the user
/// can tell which is which at a glance.
private struct IssueCaption: View {
    let issues: [ValidationIssue]
    var body: some View {
        ForEach(issues) { issue in
            Label(issue.message, systemImage: issue.isError ? "xmark.octagon.fill" : "exclamationmark.triangle.fill")
                .font(.caption2)
                .foregroundStyle(issue.isError ? Color.red : Color.orange)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityLabel("\(issue.isError ? "Error" : "Warning"): \(issue.message)")
        }
    }
}

// MARK: - The view

struct CustomRoutingTabView: View {
    let vpn: VPNController
    let profileID: String
    @Binding var profile: CustomRoutingProfile
    @Binding var proxyAuthUsername: String
    @Binding var proxyAuthPassword: String
    /// The profile's VPN kind, for the kind-aware proxy-auth captions. NE-backed
    /// profiles resolve through the controller; hosts living outside it (the native
    /// NEVPNManager kinds) pass it explicitly.
    var kind: VPNKind? = nil

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// The route rule whose overlap arrow(s) are currently shown; nil = none focused.
    @State private var focusedRuleID: UUID?
    /// 0→1 draw-in of the arrow's path trim; settles at 1 and stays there.
    @State private var arrowProgress: CGFloat = 0
    /// Row anchors collected via `.onPreferenceChange` (not the deprecated
    /// `overlayPreferenceValue(_:_:)`) — Anchor resolution is still scroll-offset
    /// aware regardless of how the dictionary reaches the Canvas.
    @State private var routeAnchors: [String: Anchor<CGPoint>] = [:]

    /// Live when connected, last-known when offline — the whole point of this tab
    /// working the same either way.
    private var pushed: PushedIntentSnapshot { vpn.lastPushedIntent(for: profileID) ?? PushedIntentSnapshot() }

    var body: some View {
        Group {
            routesSection
            dnsSection
            proxySection
        }
        .onChange(of: focusedRuleID) { _, new in
            guard new != nil else { return }
            if reduceMotion {
                arrowProgress = 1
            } else {
                arrowProgress = 0
                withAnimation(.easeOut(duration: 0.35)) { arrowProgress = 1 }
            }
        }
        .onDisappear {
            let id = profileID
            Task { @MainActor in
                profile = await commitCustomRouting(vpn, profileID: id, profile: profile,
                                                    proxyAuthUsername: proxyAuthUsername,
                                                    proxyAuthPassword: proxyAuthPassword)
            }
        }
    }

    // MARK: Routes

    /// The spec catalog for this whole surface, in one place
    /// (CustomRoutingSettingDescriptors). Every control below is descriptor-backed:
    /// a name, a plain-English summary, a manual anchor behind a help button, and
    /// an id the CLI and MDM can address.
    private static let specs = CustomRoutingSettings.catalog

    /// The header for a control that is a LIST rather than a single value (the
    /// rule editors, the domain pairs): the same name / summary / help-button
    /// arrangement `EngineSettingRow` gives a one-line control, without wrapping a
    /// 300pt scroll view and its Canvas overlay inside a row's HStack.
    @ViewBuilder private func crHeader(_ spec: EngineSettingSpec, changed: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .center, spacing: 8) {
                EngineSettingLabel(spec: spec, changed: changed)
                    .frame(maxWidth: .infinity, alignment: .leading)
                ManualLink(anchor: spec.manualAnchor, settingName: spec.name)
            }
            Text(spec.summary)
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.top, 4)
        .help(spec.summary)
        .accessibilityElement(children: .contain)
    }

    @ViewBuilder private var routesSection: some View {
        Section("Custom Routing — Routes") {
            EngineSettingRow(spec: Self.specs["cr.routes-default"],
                             value: profile.routes.defaultDisposition) {
                Picker(selection: $profile.routes.defaultDisposition) {
                    Text("Accept").tag(UnmatchedDisposition.accept)
                    Text("Ignore (allow-list)").tag(UnmatchedDisposition.ignore)
                } label: {
                    EngineSettingLabel(spec: Self.specs["cr.routes-default"],
                                       value: profile.routes.defaultDisposition)
                }
                .pickerStyle(.segmented)
            }

            crHeader(Self.specs["cr.route-rule"], changed: !profile.routes.rules.isEmpty)

            ScrollView {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach($profile.routes.rules) { $rule in
                        routeRuleRow($rule)
                    }
                    if profile.routes.rules.isEmpty {
                        Text("No rules yet — routes pass through unchanged.")
                            .font(.caption).foregroundStyle(.tertiary)
                    }
                    Divider()
                    pushedRoutesReferenceList
                }
                .padding(.vertical, 4)
                .padding(.trailing, 6)
            }
            .frame(height: 300)
            .onPreferenceChange(RouteAnchorKey.self) { routeAnchors = $0 }
            .overlay(alignment: .topLeading) { routeArrowOverlay(routeAnchors) }

            Button {
                profile.routes.rules.append(.init(verb: .accept))
            } label: {
                Label("Add Route Rule", systemImage: "plus")
            }
        }
    }

    private func routeRuleRow(_ rule: Binding<RouteFilter.RouteRule>) -> some View {
        let r = rule.wrappedValue
        let issues = CustomRoutingValidator.validate(r)
        let status = profile.routes.ruleStatus(r, against: pushed.routes)
        let overlaps = overlapTargets(for: r)

        let sentence = Self.routeRuleSentence(r, status: status, overlapping: !overlaps.isEmpty)
        return VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 8) {
                // The verb is the row's grammatical subject — an unnamed popup
                // ("pop up button, Replace") strands the reader mid-sentence.
                // Writing through `verbBinding` clears the field the new verb
                // hides, so nothing invisible survives the change.
                Picker("Rule action", selection: Self.verbBinding(rule)) {
                    Text("Accept").tag(FilterVerb.accept)
                    Text("Ignore").tag(FilterVerb.ignore)
                    Text("Replace").tag(FilterVerb.replace)
                    Text("Add").tag(FilterVerb.add)
                }
                .labelsHidden()
                .accessibilityLabel("Rule action")
                .frame(width: 96)

                if r.verb != .add {
                    TextField("CIDR or default", text: routePrefixBinding(rule, \.match))
                        .textFieldStyle(.roundedBorder)
                        .frame(minWidth: 130)
                        // Two identically-titled fields per row — name the slots.
                        .accessibilityLabel("Network to match")
                }
                if r.verb == .replace || r.verb == .add {
                    Image(systemName: "arrow.right").foregroundStyle(.secondary).font(.caption)
                        .accessibilityHidden(true)
                    TextField("CIDR or default", text: routePrefixBinding(rule, \.target))
                        .textFieldStyle(.roundedBorder)
                        .frame(minWidth: 130)
                        .accessibilityLabel(r.verb == .replace ? "Replace with" : "Network to add")
                }

                Spacer(minLength: 4)

                if status != .active { RuleStatusBadge(status: status) }
                if !overlaps.isEmpty {
                    Button {
                        focusedRuleID = (focusedRuleID == r.id) ? nil : r.id
                    } label: {
                        Image(systemName: "arrow.triangle.branch")
                            .foregroundStyle(focusedRuleID == r.id ? Color.accentColor : Color.orange)
                            .frame(width: 22, height: 22).contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .help(overlapHelp(overlaps))
                    .accessibilityLabel("Show what this overlaps")
                    // WHAT it overlaps lived only in the hover help; the arrow
                    // overlay itself is a Canvas VoiceOver can't see.
                    .accessibilityValue(overlapHelp(overlaps))
                    .accessibilityAddTraits(focusedRuleID == r.id ? .isSelected : [])
                }
                Button {
                    if focusedRuleID == r.id { focusedRuleID = nil }
                    profile.routes.rules.removeAll { $0.id == r.id }
                } label: {
                    Image(systemName: "trash").frame(width: 22, height: 22).contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
                .accessibilityLabel("Delete the \(sentence) rule")
            }
            IssueCaption(issues: issues)
        }
        .padding(.vertical, 2)
        // The row reads as ONE sentence incl. status ("Add 10.0.0.0/8,
        // overlaps a pushed route"), with the controls still reachable inside.
        .accessibilityElement(children: .contain)
        .accessibilityLabel(sentence)
        .routingAnchor("rule:\(r.id.uuidString)")
    }

    /// The rule in words — the container sentence VoiceOver announces when it
    /// enters a row, and the delete button's subject.
    private static func routeRuleSentence(_ r: RouteFilter.RouteRule,
                                          status: RuleStatus, overlapping: Bool) -> String {
        let match = r.match?.value ?? "anything"
        let target = r.target?.value ?? "nothing"
        var out: String = switch r.verb {
        case .accept: "Accept \(match)"
        case .ignore: "Ignore \(match)"
        case .replace: "Replace \(match) with \(target)"
        case .add: "Add \(target)"
        }
        switch status {
        case .active: break
        case .orphaned: out += ", matches nothing this VPN pushes"
        case .redundant: out += ", no effect — the outcome is the same without it"
        case .overlapping: out += ", overlaps a pushed route"
        }
        if overlapping, status != .overlapping { out += ", overlaps another rule or route" }
        return out
    }

    /// The verb, written back through `clearingUnusedFields()`: changing a rule's
    /// verb hides a field, and a hidden field the filter still reads is state the
    /// user cannot see but the tunnel obeys.
    private static func verbBinding(_ rule: Binding<RouteFilter.RouteRule>) -> Binding<FilterVerb> {
        Binding(
            get: { rule.wrappedValue.verb },
            set: { newVerb in
                var next = rule.wrappedValue
                next.verb = newVerb
                rule.wrappedValue = next.clearingUnusedFields()
            })
    }

    /// The DNS rows' equivalent.
    private static func verbBinding(_ rule: Binding<DNSCustomization.ResolverRule>) -> Binding<FilterVerb> {
        Binding(
            get: { rule.wrappedValue.verb },
            set: { newVerb in
                var next = rule.wrappedValue
                next.verb = newVerb
                rule.wrappedValue = next.clearingUnusedFields()
            })
    }

    /// `RoutePrefix?` field ↔ plain text, blank = nil (the model treats a blank
    /// prefix as absent — see `RoutePrefix.isBlank`).
    private func routePrefixBinding(_ rule: Binding<RouteFilter.RouteRule>,
                                    _ path: WritableKeyPath<RouteFilter.RouteRule, RoutePrefix?>) -> Binding<String> {
        Binding(
            get: { rule.wrappedValue[keyPath: path]?.value ?? "" },
            set: { rule.wrappedValue[keyPath: path] = $0.isEmpty ? nil : RoutePrefix($0) }
        )
    }

    @ViewBuilder private var pushedRoutesReferenceList: some View {
        Text("Pushed by this VPN").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            .accessibilityAddTraits(.isHeader)
        if pushed.routes.advertisedPrefixes.isEmpty && !pushed.routes.wantsDefault {
            Text("Nothing pushed yet — connect once, or write rules against specific CIDRs / \"default\" offline.")
                .font(.caption2).foregroundStyle(.tertiary)
        } else {
            ForEach(pushed.routes.advertisedPrefixes, id: \.self) { p in
                Text(p).font(.caption.monospaced()).foregroundStyle(.secondary)
                    .routingAnchor("pushed:\(Self.norm(p))")
            }
            if pushed.routes.wantsDefault {
                Text("default").font(.caption.monospaced()).foregroundStyle(.secondary)
                    .routingAnchor("pushed:default")
            }
        }
    }

    private static func norm(_ s: String) -> String {
        s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    /// Every pushed route or SIBLING rule this rule's own match/target CIDRs overlap
    /// (containment/intersection, via `RoutePrefixMath` — the same primitive
    /// `CustomRoutingValidator` uses). Computed per-rule (not from
    /// `CustomRoutingValidator.validate(_:against:)`) because that whole-filter
    /// validator attributes issues by FIELD NAME only ("match"/"target"), which is
    /// ambiguous the moment two different rules share a field — this rebuilds the
    /// same geometry unambiguously for exactly one rule, using only the model's
    /// public primitives.
    private func overlapTargets(for rule: RouteFilter.RouteRule) -> [ValidationRef] {
        func candidates(_ r: RouteFilter.RouteRule) -> [String] {
            func take(_ p: RoutePrefix?) -> String? {
                guard let p, !p.isDefault, case .ok = CustomRoutingValidator.parseCIDR(p.value) else { return nil }
                return p.normalized
            }
            switch r.verb {
            case .accept, .ignore: return [take(r.match)].compactMap { $0 }
            case .replace:         return [take(r.match), take(r.target)].compactMap { $0 }
            case .add:              return [take(r.target)].compactMap { $0 }
            }
        }
        let mine = candidates(rule)
        guard !mine.isEmpty else { return [] }

        let pushedValid: [String] = pushed.routes.advertisedPrefixes.compactMap {
            guard case .ok = CustomRoutingValidator.parseCIDR($0) else { return nil }
            return Self.norm($0)
        }

        var refs: [ValidationRef] = []
        for value in mine {
            for p in pushedValid where RoutePrefixMath.overlaps(value, p) {
                refs.append(.pushedRoute(p))
            }
            for (idx, other) in profile.routes.rules.enumerated() where other.id != rule.id {
                for oValue in candidates(other) where RoutePrefixMath.overlaps(value, oValue) {
                    refs.append(.rule(other.id, index: idx, value: oValue))
                }
            }
        }
        return refs
    }

    private func overlapHelp(_ refs: [ValidationRef]) -> String {
        let names = refs.map { ref -> String in
            switch ref.kind {
            case .pushedRoute: return "\(ref.value) pushed by this VPN"
            case .rule:
                let verb = profile.routes.rules.first { $0.id == ref.ruleID }?.verb.rawValue ?? "other"
                return "the \(verb) rule for \(ref.value)"
            }
        }
        return "Overlaps " + names.joined(separator: ", ") + " — click to see it."
    }

    // MARK: Arrow overlay (Routes only)

    @ViewBuilder private func routeArrowOverlay(_ anchors: [String: Anchor<CGPoint>]) -> some View {
        GeometryReader { proxy in
            Canvas { ctx, size in
                guard let fid = focusedRuleID,
                      let rule = profile.routes.rules.first(where: { $0.id == fid }),
                      let fromAnchor = anchors["rule:\(fid.uuidString)"] else { return }
                let refs = overlapTargets(for: rule)
                guard !refs.isEmpty else { return }
                let from = endpoint(fromAnchor, proxy: proxy, size: size)
                for ref in refs {
                    let key = ref.kind == .rule ? "rule:\(ref.ruleID!.uuidString)" : "pushed:\(ref.value)"
                    guard let toAnchor = anchors[key] else { continue }
                    let to = endpoint(toAnchor, proxy: proxy, size: size)
                    drawArrow(ctx: ctx, from: from, to: to, progress: arrowProgress)
                }
            }
        }
        .allowsHitTesting(false)
    }

    /// One endpoint: the point clamped into the viewport (with a margin) plus the
    /// TRUE resolved point, so the caller can tell whether it had to clamp and, if
    /// so, which way the real target lies.
    private struct Endpoint { var point: CGPoint; var raw: CGPoint; var offscreen: Bool }

    private func endpoint(_ anchor: Anchor<CGPoint>, proxy: GeometryProxy, size: CGSize, margin: CGFloat = 12) -> Endpoint {
        let raw = proxy[anchor]
        let x = min(max(raw.x, margin), max(margin, size.width - margin))
        let y = min(max(raw.y, margin), max(margin, size.height - margin))
        let clamped = CGPoint(x: x, y: y)
        return Endpoint(point: clamped, raw: raw, offscreen: clamped != raw)
    }

    private func drawArrow(ctx: GraphicsContext, from: Endpoint, to: Endpoint, progress: CGFloat) {
        var path = Path()
        path.move(to: from.point)
        let dx = max(24, (to.point.x - from.point.x) * 0.5)
        path.addCurve(to: to.point,
                      control1: CGPoint(x: from.point.x + dx, y: from.point.y),
                      control2: CGPoint(x: to.point.x - dx, y: to.point.y))
        let clampedProgress = max(0, min(1, progress))
        let trimmed = path.trimmedPath(from: 0, to: clampedProgress)
        ctx.stroke(trimmed, with: .color(.orange),
                   style: StrokeStyle(lineWidth: 2, lineCap: .round, dash: [5, 4]))
        guard clampedProgress > 0.02 else { return }

        // A clamped (off-screen) endpoint gets a chevron pointing at the true spot —
        // so scrolling the source or the target out of view never draws a stray/
        // stale line, and the user can tell which way to scroll to find it.
        if from.offscreen {
            drawChevron(ctx: ctx, at: from.point,
                       direction: CGPoint(x: from.raw.x - from.point.x, y: from.raw.y - from.point.y))
        }
        if to.offscreen {
            drawChevron(ctx: ctx, at: to.point,
                       direction: CGPoint(x: to.raw.x - to.point.x, y: to.raw.y - to.point.y))
        } else if clampedProgress > 0.9 {
            let tip = trimmed.currentPoint ?? to.point
            drawChevron(ctx: ctx, at: tip,
                       direction: CGPoint(x: to.point.x - from.point.x, y: to.point.y - from.point.y))
        }
    }

    private func drawChevron(ctx: GraphicsContext, at point: CGPoint, direction: CGPoint) {
        let len = max(0.001, (direction.x * direction.x + direction.y * direction.y).squareRoot())
        let ux = direction.x / len, uy = direction.y / len
        let px = -uy, py = ux
        let size: CGFloat = 7
        var path = Path()
        path.move(to: CGPoint(x: point.x + ux * size, y: point.y + uy * size))
        path.addLine(to: CGPoint(x: point.x - ux * size * 0.4 + px * size * 0.6,
                                 y: point.y - uy * size * 0.4 + py * size * 0.6))
        path.addLine(to: CGPoint(x: point.x - ux * size * 0.4 - px * size * 0.6,
                                 y: point.y - uy * size * 0.4 - py * size * 0.6))
        path.closeSubpath()
        ctx.fill(path, with: .color(.orange))
    }

    // MARK: DNS

    @ViewBuilder private var dnsSection: some View {
        Section("Custom Routing — DNS") {
            EngineSettingRow(spec: Self.specs["cr.dns-default"],
                             value: profile.dns.defaultDisposition) {
                Picker(selection: $profile.dns.defaultDisposition) {
                    Text("Accept").tag(UnmatchedDisposition.accept)
                    Text("Ignore (allow-list)").tag(UnmatchedDisposition.ignore)
                } label: {
                    EngineSettingLabel(spec: Self.specs["cr.dns-default"],
                                       value: profile.dns.defaultDisposition)
                }
                .pickerStyle(.segmented)
            }

            crHeader(Self.specs["cr.dns-rule"], changed: !profile.dns.resolverRules.isEmpty)
            ForEach($profile.dns.resolverRules) { $rule in dnsRuleRow($rule) }
            Button {
                profile.dns.resolverRules.append(.init(verb: .accept))
            } label: {
                Label("Add Resolver Rule", systemImage: "plus")
            }

            Divider()
            EngineSettingRow(spec: Self.specs["cr.ignore-pushed-search"],
                             value: profile.dns.ignorePushedSearchDomains) {
                Toggle(isOn: $profile.dns.ignorePushedSearchDomains) {
                    EngineSettingLabel(spec: Self.specs["cr.ignore-pushed-search"],
                                       value: profile.dns.ignorePushedSearchDomains)
                }
            }
            crHeader(Self.specs["cr.add-search-domains"],
                     changed: !profile.dns.addSearchDomains.isEmpty
                              || !profile.dns.ignoreSearchDomains.isEmpty)
            domainListField("Add search domains", $profile.dns.addSearchDomains)
            // Ignoring ALL of them subsumes any list: `editDomains` starts from an
            // empty set under ignore-all and never consults the subtraction list,
            // so the field is genuinely inert — disabled, with the reason.
            domainListField("Ignore search domains", $profile.dns.ignoreSearchDomains,
                            disabledReason: profile.dns.ignorePushedSearchDomains
                                ? "\u{201C}Ignore all pushed search domains\u{201D} is on, which already drops every one."
                                : nil)

            Divider()
            EngineSettingRow(spec: Self.specs["cr.ignore-pushed-match"],
                             value: profile.dns.ignorePushedMatchDomains) {
                Toggle(isOn: $profile.dns.ignorePushedMatchDomains) {
                    EngineSettingLabel(spec: Self.specs["cr.ignore-pushed-match"],
                                       value: profile.dns.ignorePushedMatchDomains)
                }
            }
            crHeader(Self.specs["cr.match-domains"],
                     changed: !profile.dns.addMatchDomains.isEmpty
                              || !profile.dns.ignoreMatchDomains.isEmpty)
            domainListField("Add match domains", $profile.dns.addMatchDomains)
            domainListField("Ignore match domains", $profile.dns.ignoreMatchDomains,
                            disabledReason: profile.dns.ignorePushedMatchDomains
                                ? "\u{201C}Ignore all pushed match domains\u{201D} is on, which already drops every one."
                                : nil)

            if !pushed.dns.resolvers.isEmpty || !pushed.dns.searchDomains.isEmpty || !pushed.dns.matchDomains.isEmpty {
                Divider()
                pushedDNSReference
            }
        }
    }

    private func dnsRuleRow(_ rule: Binding<DNSCustomization.ResolverRule>) -> some View {
        let r = rule.wrappedValue
        let issues = CustomRoutingValidator.validate(r)
        let status = profile.dns.ruleStatus(r, against: pushed.dns)
        let sentence = Self.dnsRuleSentence(r, status: status)
        return VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 8) {
                Picker("Rule action", selection: Self.verbBinding(rule)) {
                    Text("Accept").tag(FilterVerb.accept)
                    Text("Ignore").tag(FilterVerb.ignore)
                    Text("Replace").tag(FilterVerb.replace)
                    Text("Add").tag(FilterVerb.add)
                }
                .labelsHidden()
                .accessibilityLabel("Rule action")
                .frame(width: 96)

                if r.verb != .add {
                    TextField("Resolver IP", text: Binding(
                        get: { rule.wrappedValue.match ?? "" },
                        set: { rule.wrappedValue.match = $0.isEmpty ? nil : $0 }))
                        .textFieldStyle(.roundedBorder).frame(minWidth: 120)
                        .accessibilityLabel("Resolver to match")
                }
                if r.verb == .replace || r.verb == .add {
                    Image(systemName: "arrow.right").foregroundStyle(.secondary).font(.caption)
                        .accessibilityHidden(true)
                    TextField("Resolver IP", text: Binding(
                        get: { rule.wrappedValue.target ?? "" },
                        set: { rule.wrappedValue.target = $0.isEmpty ? nil : $0 }))
                        .textFieldStyle(.roundedBorder).frame(minWidth: 120)
                        .accessibilityLabel(r.verb == .replace ? "Replace with resolver" : "Resolver to add")
                }
                Spacer(minLength: 4)
                if status != .active { RuleStatusBadge(status: status) }
                Button {
                    profile.dns.resolverRules.removeAll { $0.id == r.id }
                } label: {
                    Image(systemName: "trash").frame(width: 22, height: 22).contentShape(Rectangle())
                }
                .buttonStyle(.plain).foregroundStyle(.secondary)
                .accessibilityLabel("Delete the \(sentence) rule")
            }
            IssueCaption(issues: issues)
        }
        .padding(.vertical, 2)
        // Same sentence discipline as the route rows.
        .accessibilityElement(children: .contain)
        .accessibilityLabel(sentence)
    }

    private static func dnsRuleSentence(_ r: DNSCustomization.ResolverRule, status: RuleStatus) -> String {
        let match = r.match ?? "any resolver"
        let target = r.target ?? "nothing"
        var out: String = switch r.verb {
        case .accept: "Accept resolver \(match)"
        case .ignore: "Ignore resolver \(match)"
        case .replace: "Replace resolver \(match) with \(target)"
        case .add: "Add resolver \(target)"
        }
        switch status {
        case .active: break
        case .orphaned: out += ", matches nothing this VPN pushes"
        case .redundant: out += ", no effect — the outcome is the same without it"
        case .overlapping: out += ", overlaps a pushed resolver"
        }
        return out
    }

    private func domainListField(_ title: String, _ binding: Binding<[String]>,
                                 disabledReason: String? = nil) -> some View {
        let bad = disabledReason == nil
            ? binding.wrappedValue.filter { !CustomRoutingValidator.isValidDomain($0) } : []
        return VStack(alignment: .leading, spacing: 2) {
            LabeledContent(title) {
                TextField("example.com, other.example", text: Binding(
                    get: { binding.wrappedValue.joined(separator: ", ") },
                    set: { binding.wrappedValue = $0.split(separator: ",")
                        .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty } }))
                    .textFieldStyle(.roundedBorder)
                    // A dead field says why, in the tooltip AND to VoiceOver.
                    .disabled(disabledReason != nil)
                    .help(disabledReason ?? title)
                    .accessibilityValue(disabledReason.map { "unavailable — \($0)" }
                        ?? (bad.isEmpty
                            ? binding.wrappedValue.joined(separator: ", ")
                            : "\(binding.wrappedValue.joined(separator: ", ")). Problem: not a valid domain: \(bad.joined(separator: ", "))"))
            }
            if let disabledReason {
                Text(disabledReason)
                    .font(.caption2).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if !bad.isEmpty {
                Label("Not a valid domain: \(bad.joined(separator: ", "))", systemImage: "xmark.octagon.fill")
                    .font(.caption2).foregroundStyle(.red)
            }
        }
    }

    @ViewBuilder private var pushedDNSReference: some View {
        Text("Pushed by this VPN").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            .accessibilityAddTraits(.isHeader)
        if !pushed.dns.resolvers.isEmpty {
            Text("Resolvers: \(pushed.dns.resolvers.joined(separator: ", "))")
                .font(.caption.monospaced()).foregroundStyle(.secondary)
        }
        if !pushed.dns.searchDomains.isEmpty {
            Text("Search domains: \(pushed.dns.searchDomains.joined(separator: ", "))")
                .font(.caption).foregroundStyle(.secondary)
        }
        if !pushed.dns.matchDomains.isEmpty {
            Text("Match domains: \(pushed.dns.matchDomains.joined(separator: ", "))")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    // MARK: Proxy

    /// The kind for the kind-aware captions below: explicit (native hosts) or resolved
    /// through the controller (NE-backed hosts); nil for hosts outside both worlds.
    private var effectiveKind: VPNKind? {
        kind ?? vpn.profiles.first { $0.id == profileID }?.kind
    }

    /// The native NEVPNManager kinds: the OS owns the applied proxy (we set it only at
    /// connect, through the VPN configuration) — the Proxy mediator's `.limited` bucket.
    private var isObserveOnlyKind: Bool {
        effectiveKind.map { ProxyParticipation.classify($0) == .limited } ?? false
    }

    /// Whether a PAC URL is set — the value `ProxyCustomization.apply` prefers,
    /// which makes the manual proxy address inert.
    private var pacURLSet: Bool {
        !(profile.proxy.pacURL ?? "").trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    @ViewBuilder private var proxySection: some View {
        Section("Custom Routing — Proxy") {
            EngineSettingRow(spec: Self.specs["cr.proxy-mode"], value: profile.proxy.mode) {
                Picker(selection: $profile.proxy.mode) {
                    Text("Use pushed proxy").tag(ProxyCustomization.Mode.accept)
                    Text("Ignore (direct)").tag(ProxyCustomization.Mode.ignore)
                    Text("Custom").tag(ProxyCustomization.Mode.custom)
                } label: {
                    EngineSettingLabel(spec: Self.specs["cr.proxy-mode"], value: profile.proxy.mode)
                }
                .pickerStyle(.segmented)
                .accessibilityLabel(Self.specs["cr.proxy-mode"].name)
            }

            let status = profile.proxy.ruleStatus(against: pushed.proxy)
            if status != .active { RuleStatusBadge(status: status) }

            if profile.proxy.mode == .custom {
                let issues = CustomRoutingValidator.validate(profile.proxy)
                // `ProxyCustomization.apply` returns the PAC intent and never
                // looks at `manualURL` when a PAC URL is set, so the manual field
                // is inert — the PAC field's placeholder said so while the manual
                // field stayed live and editable.
                let manualDead: String? = pacURLSet
                    ? "The PAC URL below is set, and it wins — this address isn't used. Clear the PAC URL to use a manual proxy."
                    : nil
                // The house idiom: LabeledContent + a trailing plain field, like
                // every other editor's text rows (this was a full-width
                // `.roundedBorder` field whose placeholder carried its name).
                EngineSettingRow(spec: Self.specs["cr.proxy-manual-url"],
                                 value: profile.proxy.manualURL ?? "",
                                 disabledReason: manualDead) {
                    LabeledContent {
                        TextField("http(s)://host:port or socks5://host:port", text: Binding(
                            get: { profile.proxy.manualURL ?? "" },
                            set: { profile.proxy.manualURL = $0.isEmpty ? nil : $0 }))
                            .multilineTextAlignment(.trailing)
                            .autocorrectionDisabled()
                            .accessibilityLabel(Self.specs["cr.proxy-manual-url"].name)
                    } label: {
                        EngineSettingLabel(spec: Self.specs["cr.proxy-manual-url"],
                                           value: profile.proxy.manualURL ?? "")
                    }
                }
                if manualDead == nil {
                    IssueCaption(issues: issues.filter { $0.field == "manualURL" })
                }
                if manualDead == nil, isObserveOnlyKind, profile.proxy.customIsSOCKS {
                    Label("The native VPN configuration has no SOCKS slot — use an http:// or https:// proxy (or a PAC URL).",
                          systemImage: "exclamationmark.triangle.fill")
                        .font(.caption2).foregroundStyle(.orange)
                }

                EngineSettingRow(spec: Self.specs["cr.proxy-pac-url"],
                                 value: profile.proxy.pacURL ?? "") {
                    LabeledContent {
                        TextField("https://example.com/proxy.pac", text: Binding(
                            get: { profile.proxy.pacURL ?? "" },
                            set: { profile.proxy.pacURL = $0.isEmpty ? nil : $0 }))
                            .multilineTextAlignment(.trailing)
                            .autocorrectionDisabled()
                            .accessibilityLabel(Self.specs["cr.proxy-pac-url"].name)
                    } label: {
                        EngineSettingLabel(spec: Self.specs["cr.proxy-pac-url"],
                                           value: profile.proxy.pacURL ?? "")
                    }
                }
                IssueCaption(issues: issues.filter { $0.field == "pacURL" })

                Divider()
                proxyAuthFields(caption: isObserveOnlyKind
                    ? "Saved in your Keychain and applied when this VPN connects — the configuration only ever carries a reference."
                    : "Saved in your Keychain — the profile only ever carries a reference to it.")
            } else if profile.proxy.mode == .accept {
                // Authenticated PUSHED proxies: the push never carries credentials, so
                // the sign-in (if the proxy demands one) is stored here and attached
                // where we are the ones applying. For the OS-owned (observe-only)
                // kinds there is nothing we apply — say so instead of a dead field.
                if isObserveOnlyKind {
                    Label("macOS applies this VPN's proxy itself — SimpleVPN only observes it, so a pushed proxy's sign-in can't be added here. Use Custom to set an authenticated proxy.",
                          systemImage: "eye")
                        .font(.caption2).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    proxyAuthFields(caption: "Used if the pushed proxy requires sign-in. Saved in your Keychain — the profile only ever carries a reference to it.")
                }
            }

            let diff = CustomRoutingDiff.diffProxy(filter: profile.proxy, pushed: pushed.proxy)
            if !diff.isEmpty { proxyDiffCaption(diff) }

            if let p = pushed.proxy, !p.isEmpty {
                Divider()
                Text("Pushed by this VPN: \(pushedProxyDisplay(p))")
                    .font(.caption.monospaced()).foregroundStyle(.secondary)
            }
        }
    }

    /// The username/password pair for proxy auth — one control pair, reused by the
    /// Accept (pushed-proxy sign-in) and Custom (own-proxy sign-in) modes so the two
    /// read as one system. The caption names where the secret lives.
    @ViewBuilder private func proxyAuthFields(caption: String) -> some View {
        let set = !proxyAuthUsername.isEmpty || !proxyAuthPassword.isEmpty
        crHeader(Self.specs["cr.proxy-auth"], changed: set)
        LabeledContent("Username") {
            TextField("optional", text: $proxyAuthUsername)
                .multilineTextAlignment(.trailing)
                .textContentType(.username)
                .autocorrectionDisabled()
                // Host editors show several credential pairs — say whose this is.
                .accessibilityLabel("Proxy username (optional)")
        }
        LabeledContent("Password") {
            SecureField("optional", text: $proxyAuthPassword)
                .multilineTextAlignment(.trailing)
                .accessibilityLabel("Proxy password (optional)")
        }
        Label(caption, systemImage: "lock")
            .font(.caption2).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func pushedProxyDisplay(_ p: PushedIntentSnapshot.Proxy) -> String {
        CustomRoutingDiff.proxyDisplay(CustomRoutingDiff.proxyIntent(from: p)) ?? "—"
    }

    private func proxyDiffCaption(_ diff: ResourceDiff) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(diff.items) { item in
                Label(diffLabel(item), systemImage: diffSymbol(item.delta))
                    .font(.caption2).foregroundStyle(diffColor(item.delta))
            }
            ForEach(diff.removed, id: \.self) { r in
                Label("Removed: \(r)", systemImage: "minus.circle")
                    .font(.caption2).foregroundStyle(.red)
            }
        }
    }

    private func diffLabel(_ item: IntentDeltaItem) -> String {
        switch item.delta {
        case .unchanged: "Effective (unchanged): \(item.value)"
        case .added:     "Added: \(item.value)"
        case .replaced:  "Replaced with: \(item.value)"
        case .removed:   "Removed: \(item.value)"
        }
    }
    private func diffSymbol(_ d: IntentDelta) -> String {
        switch d {
        case .unchanged: "checkmark.circle"
        case .added:     "plus.circle.fill"
        case .replaced:  "arrow.triangle.2.circlepath"
        case .removed:   "minus.circle"
        }
    }
    private func diffColor(_ d: IntentDelta) -> Color {
        switch d {
        case .unchanged: .secondary
        case .added:     .green
        case .replaced:  .orange
        case .removed:   .red
        }
    }
}
