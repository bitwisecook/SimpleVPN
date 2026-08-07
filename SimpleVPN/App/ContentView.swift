// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ContentView.swift
//  Shared UI helpers/components used across the connection window, the VPN
//  management pane, and Settings.
//

import SwiftUI
import UniformTypeIdentifiers
import NetworkExtension
import CoreGraphics

enum UI {
    // (status→color lives in DotState.color — the single source; a duplicate here
    // had drifted to a contradictory mapping and was unused, so it's gone.)
    static var ovpnType: UTType { UTType(filenameExtension: "ovpn") ?? .data }
    static var appVersion: String {
        let i = Bundle.main.infoDictionary
        return "v\(i?["CFBundleShortVersionString"] as? String ?? "?") (build \(i?["CFBundleVersion"] as? String ?? "?"))"
    }
    /// THE cancel-a-connection look, everywhere it appears: xmark.circle.fill in this
    /// softened red. One definition because the sidebar and the header once drifted into
    /// two dialects of the same action (bare bright-red ✕ vs filled soft-red circle) —
    /// same session, same screen, different buttons.
    static let cancelRed = Color(red: 0.82, green: 0.36, blue: 0.36)

    static func isActive(_ s: NEVPNStatus) -> Bool { s == .connected || s == .connecting || s == .reasserting }
    // Remote parsing lives with the engine evaluator now (ProfileEvaluation) and
    // the multi-remote scanner (EndpointScanner).
}

/// Everything a status dot can say. Richer than NEVPNStatus: degraded (the
/// train-tunnel state, from reasserting or passive stall detection) and
/// captive-portal each get their own color and rhythm.
enum DotState: Equatable {
    case off             // disconnected/invalid — faint steady ember
    case busy            // connecting / disconnecting — quick breath + ripple
    case connected       // settles with a damped landing, then perfectly steady
    case paused          // user chose this — steady half-dim, no rhythm, no nagging
    case degraded        // connection lost/stalled — slow amber breath, no ripple
    case captivePortal   // sign-in page in the way — indigo knock-knock + beacon

    /// Standard mapping. `stalled` comes from passive traffic analysis where a
    /// monitor is running; `captive` from the failure diagnostics; `paused` is
    /// app-side state (NEVPNStatus has no paused).
    static func from(status: NEVPNStatus, stalled: Bool = false, captive: Bool = false,
                     paused: Bool = false) -> DotState {
        if captive { return .captivePortal }
        switch status {
        case .connected: return paused ? .paused : (stalled ? .degraded : .connected)
        case .reasserting: return .degraded
        case .connecting, .disconnecting: return .busy
        default: return .off
        }
    }

    /// Map a subprocess-engine status (SSH / OpenConnect) into the same dot
    /// language used for OpenVPN, so every backend reads identically.
    static func from(subprocess s: SubprocessTunnelManager.Status) -> DotState {
        switch s {
        case .connected: .connected
        case .connecting: .busy
        case .failed: .degraded
        case .disconnected: .off
        }
    }

    var color: Color {
        switch self {
        case .off: .secondary
        case .busy: .yellow
        case .connected: .green
        case .paused: .green
        case .degraded: .orange
        case .captivePortal: .indigo
        }
    }

    /// Differentiate Without Color: a bare circle differs only by hue, so each
    /// state gets its own SF-symbol SHAPE too (StatusDot swaps to these when the
    /// accommodation is on). Same palette — shape is added, color isn't removed.
    var symbolName: String {
        switch self {
        case .off: "circle"
        case .busy: "circle.dotted"
        case .connected: "checkmark.circle.fill"
        case .paused: "pause.circle.fill"
        case .degraded: "exclamationmark.circle.fill"
        case .captivePortal: "questionmark.circle.fill"
        }
    }

    /// The state in words, for the combined labels of rows and pills — the dot
    /// itself is accessibility-hidden everywhere, so this is how its information
    /// reaches VoiceOver (color is never the only carrier).
    var accessibilityDescription: String {
        switch self {
        case .off: "disconnected"
        case .busy: "working"
        case .connected: "connected"
        case .paused: "paused"
        case .degraded: "connection problem"
        case .captivePortal: "sign-in page in the way"
        }
    }
}

/// The status dot, alive only while something needs attention. Each animated
/// state has its own rhythm — busy: quick lopsided breath + ripple; degraded:
/// a slow, deep amber breath (deliberately eye-catching but unhurried);
/// captive portal: an indigo "knock-knock… rest" double pulse with a slow
/// beacon ring. Connected settles through a damped landing into a perfectly
/// steady dot (no perpetual motion), and off fades quickly to a faint ember.
///
/// Transitions never jump-cut between rhythms: on every state change the
/// animation amplitude eases to zero and the new rhythm swells up from calm.
/// Reduce Motion replaces all rhythms with static opacities.
///
/// WINDOWS ONLY. The TimelineView below is correct here, but must never be used
/// for the menu-bar label: measured on macOS 26.6, a TimelineView in a
/// MenuBarExtra label re-enters SwiftUI's update loop and spins the main thread
/// at 100%. The menu bar has its own dot, driven from a Task — see MenuBarIcon
/// and MenuBarLabel in MenuBarView.swift.
struct StatusDot: View {
    let state: DotState
    var size: CGFloat = 8
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor
    /// 0 = at rest, 1 = the state's rhythm at full swing.
    @State private var amplitude: Double = 0

    /// Convenience for call sites that only know the NE status.
    init(status: NEVPNStatus, size: CGFloat = 8) {
        self.init(state: .from(status: status), size: size)
    }

    init(state: DotState, size: CGFloat = 8) {
        self.state = state
        self.size = size
    }

    private var animated: Bool {
        switch state {
        case .busy, .degraded, .captivePortal: !reduceMotion
        case .off, .connected, .paused: false
        }
    }

    var body: some View {
        if differentiateWithoutColor {
            // Differentiate Without Color: the state's identity must not ride on
            // hue alone, so the dot becomes a per-state SF-symbol shape. Static
            // on purpose — the shape now carries what the rhythm carried.
            Image(systemName: state.symbolName)
                .resizable().scaledToFit()
                .foregroundStyle(state.color)
                .frame(width: size, height: size)
                .animation(.easeOut(duration: 0.25), value: state)
                .accessibilityHidden(true)   // rows/pills carry the status in text
        } else {
            animatedDot
        }
    }

    private var animatedDot: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 30.0, paused: amplitude == 0)) { context in
            let t = context.date.timeIntervalSinceReferenceDate
            let motion = motion(at: t)

            ZStack {
                Circle()   // ripple / beacon ring
                    .strokeBorder(state.color, lineWidth: max(1, size / 7))
                    .scaleEffect(1 + motion.ringPhase * 1.5)
                    .opacity((1 - motion.ringPhase) * motion.ringStrength * amplitude)
                Circle()   // core
                    .fill(state.color)
                    .scaleEffect(restScale + amplitude * motion.scaleSwing)
                    .opacity(restOpacity + amplitude * motion.opacitySwing)
            }
        }
        .frame(width: size, height: size)
        .animation(.easeOut(duration: 0.25), value: state)   // color/dim crossfade
        .onChange(of: state, initial: true) {
            // Dip through calm, then take up the new rhythm — no rhythm ever
            // cuts directly into another. Settling into connected/off is the
            // same dip, ending at rest: the breath damps out into a steady dot
            // while the color crossfades.
            withAnimation(.easeOut(duration: 0.3)) { amplitude = 0 }
            if animated {
                withAnimation(.easeIn(duration: 0.45).delay(0.3)) { amplitude = 1 }
            }
        }
        .accessibilityHidden(true)   // rows/pills carry the status in text
    }

    // MARK: Rhythms

    private struct Motion {
        var scaleSwing: Double = 0
        var opacitySwing: Double = 0
        var ringPhase: Double = 0      // 0…1 across the ring's cycle
        var ringStrength: Double = 0
    }

    private func motion(at t: Double) -> Motion {
        switch state {
        case .busy:
            // Quick lopsided breath (fundamental + offset harmonic) + busy ripple.
            let wave = sin(t * 2 * .pi / 1.7) + 0.3 * sin(t * 4 * .pi / 1.7 + 0.9)
            return Motion(scaleSwing: 0.11 * wave,
                          opacitySwing: -0.2 * (0.5 + 0.5 * wave),
                          ringPhase: t.truncatingRemainder(dividingBy: 1.25) / 1.25,
                          ringStrength: 0.5)
        case .degraded:
            // Slow, deep breath — attention through depth and patience, not speed.
            let wave = sin(t * 2 * .pi / 2.6)
            return Motion(scaleSwing: 0.09 * wave,
                          opacitySwing: -0.35 * (0.5 + 0.5 * wave))
        case .captivePortal:
            // Knock-knock… rest: two soft pulses early in a 3 s cycle (gaussian
            // envelopes, so they swell rather than blink), plus a slow beacon ring.
            let cycle = t.truncatingRemainder(dividingBy: 3.0)
            func pulse(at center: Double) -> Double {
                let d = (cycle - center) / 0.16
                return exp(-d * d)
            }
            let knock = pulse(at: 0.35) + pulse(at: 0.95)
            return Motion(scaleSwing: 0.14 * knock,
                          opacitySwing: -0.3 + 0.3 * min(1, knock),
                          ringPhase: cycle / 3.0,
                          ringStrength: 0.4)
        case .off, .connected, .paused:
            return Motion()
        }
    }

    private var restScale: Double { state == .off ? 0.9 : 1 }

    private var restOpacity: Double {
        switch state {
        case .connected: 1
        case .paused: 0.5                                // steady half-dim: intentional, not alarming
        case .off: 0.3                                   // faint ember
        case .busy, .degraded: reduceMotion ? 0.65 : 0.95
        case .captivePortal: reduceMotion ? 0.65 : 0.7   // knocks lift it to full
        }
    }
}

// `VPNRow` USED TO BE HERE — a fourth sidebar row shape: logo · name · pills, at its own
// height, with its own accessibility sentence, drawn only by Manage VPNs' profile rows
// while the two rows beside them in the same section were built by hand in that file. It
// is `ConnectionRowLayout` now (UI/Components/ConnectionRow.swift), which every
// non-interactive list row in both windows goes through. Deleted rather than deprecated:
// a spare row builder with no call sites is the next copy somebody reaches for.

struct LogoBadge: View {
    let id: String
    let status: NEVPNStatus
    /// Pass a richer state (stall/captive-portal aware) where the caller has one.
    var dotState: DotState? = nil
    /// What to draw when this connection has no logo of its own: **the KIND's symbol**.
    ///
    /// NO DEFAULT VALUE, and the compiler is the guard. It used to default to `"globe"`
    /// on the reasoning that a logo "is expected and simply absent" for an NE profile —
    /// which had stopped being true. Only the OpenVPN editor has a logo well, so a
    /// WireGuard, Tailscale, Proxy Tunnel or SSH Network Tunnel profile can never get a
    /// logo either, and still drew a globe that said nothing about it while the subprocess
    /// and native rows beside it in the SAME sidebar section said what they were. One
    /// badge, two fallback policies: `Docs/Drift.md` §12. A caller with genuinely no kind
    /// may still pass `"globe"` — having to type it is the point.
    let fallbackSymbol: String
    var body: some View {
        let state = dotState ?? .from(status: status)
        ZStack(alignment: .bottomTrailing) {
            logo.frame(width: 22, height: 22).clipShape(RoundedRectangle(cornerRadius: 5))
            StatusDot(state: state, size: 7)
                .overlay(Circle().strokeBorder(.white.opacity(0.9), lineWidth: 1)
                    .opacity(state == .connected ? 1 : 0))
        }
        // Decorative by convention: every badge sits beside text that carries
        // the name AND the dot's state in words (rows, headers, menu rows).
        .accessibilityHidden(true)
    }
    @ViewBuilder private var logo: some View {
        if let cg = LogoStore.load(id) { Image(decorative: cg, scale: 1).resizable().scaledToFill() }
        else { Image(systemName: fallbackSymbol).foregroundStyle(.secondary) }
    }
}

/// A tappable logo well (click to pick, or drop an image).
struct LogoWell: View {
    let image: CGImage?
    let pick: () -> Void
    let drop: (URL) -> Void
    var body: some View {
        // A real Button, not onTapGesture: a tap gesture is invisible to
        // VoiceOver and unreachable by keyboard; a button is both for free.
        Button(action: pick) {
            content
                .frame(width: 64, height: 64)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 12))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .dropDestination(for: URL.self) { urls, _ in if let u = urls.first { drop(u); return true }; return false }
        .accessibilityLabel("VPN logo")
        .accessibilityHint("Choose an image. You can also drop one here.")
    }
    @ViewBuilder private var content: some View {
        if let image { Image(decorative: image, scale: 1).resizable().scaledToFit() }
        else { Image(systemName: "photo.badge.plus").font(.largeTitle).foregroundStyle(.secondary) }
    }
}

// (ReachabilityPill is gone: a healthy connection no longer announces itself.
// The header shows ProblemPill — ConnectionView — only when something is wrong.)

/// AppKit-backed credential field that participates in system Password AutoFill.
///
/// Why AppKit: SwiftUI's `.textContentType` is a documented no-op for AutoFill on
/// macOS (dev-forums 809587) — only NSTextField/NSSecureTextField with
/// `contentType` set get the key-icon suggestions. With these, items from Apple
/// Passwords AND every credential provider the user enabled in System Settings ▸
/// AutoFill (Strongbox, KeePassium, 1Password's provider as it ships…) can fill
/// our fields, each provider handling its own Touch ID. Focus is bridged to a
/// plain SwiftUI state token so the shake/nudge machinery keeps working.
struct AutoFillField<Focus: Hashable>: NSViewRepresentable {
    enum Kind { case username, password, oneTimeCode }

    let kind: Kind
    let placeholder: String
    @Binding var text: String
    @Binding var focus: Focus?
    let focusValue: Focus
    var onSubmit: () -> Void = {}

    /// Optional gate on this field's Return, and a synchronous view of its text.
    ///
    /// It exists for one specific hazard: a hardware security key is a USB
    /// KEYBOARD, and it types its code and then presses Return. Left alone, that
    /// Return fires `onSubmit` — connecting half-composed and burning a one-time
    /// code on every single attempt. A policy object can watch the text as it
    /// arrives and swallow the key's own Return; the user's own Return still
    /// submits. See UI/Credentials/YubiKeyTouchPrompt.swift and
    /// Credentials/YubiKeyTouchCapture.swift.
    ///
    /// The hook is deliberately vendor-neutral and OFF by default: nil means this
    /// field behaves exactly as it always has, which is what every other call site
    /// gets.
    var returnPolicy: (any CredentialFieldReturnPolicy)? = nil

    func makeNSView(context: Context) -> NSTextField {
        let field: NSTextField = kind == .password ? NSSecureTextField() : NSTextField()
        field.placeholderString = placeholder
        field.bezelStyle = .roundedBezel
        field.font = .systemFont(ofSize: NSFont.systemFontSize)
        field.delegate = context.coordinator
        field.lineBreakMode = .byTruncatingTail
        field.cell?.usesSingleLineMode = true
        switch kind {
        case .username: field.contentType = .username
        case .password: field.contentType = .password
        case .oneTimeCode: field.contentType = .oneTimeCode
        }
        // NSAccessibility: placeholderString only surfaces as AXPlaceholderValue,
        // which VoiceOver stops reading the moment the field has content — the
        // field needs a real AXDescription of its own to stay nameable.
        field.setAccessibilityLabel(placeholder)
        // Fill the grid column like the SwiftUI fields these replace.
        field.setContentHuggingPriority(.defaultLow, for: .horizontal)
        return field
    }

    func updateNSView(_ field: NSTextField, context: Context) {
        context.coordinator.parent = self
        // .disabled() reaches a representable only through the environment —
        // without this line a "disabled" field would still take typing.
        field.isEnabled = context.environment.isEnabled
        // Don't clobber composition mid-edit: only push model→view when the
        // view isn't the one being typed into or the values genuinely differ.
        if field.stringValue != text, field.currentEditor() == nil {
            field.stringValue = text
        }
        if focus == focusValue, field.window != nil, field.currentEditor() == nil {
            DispatchQueue.main.async { [weak field] in
                guard let field, field.window?.firstResponder !== field.currentEditor() else { return }
                field.window?.makeFirstResponder(field)
            }
        }
    }

    /// Take the width offered, keep the field's own one-line height. Without
    /// this a Form row proposes a width and gets back the CONTENT's intrinsic
    /// width (an NSTextField hugs its text) — the field then wanders as you
    /// type. The Grid call sites relied on hugging priorities to stretch;
    /// answering the proposal directly serves both containers.
    func sizeThatFits(_ proposal: ProposedViewSize, nsView: NSTextField,
                      context: Context) -> CGSize? {
        let fitting = nsView.fittingSize
        return CGSize(width: proposal.width ?? fitting.width, height: fitting.height)
    }

    func makeCoordinator() -> Coordinator { Coordinator(parent: self) }

    final class Coordinator: NSObject, NSTextFieldDelegate {
        var parent: AutoFillField
        init(parent: AutoFillField) { self.parent = parent }

        func controlTextDidChange(_ note: Notification) {
            guard let field = note.object as? NSTextField else { return }
            parent.text = field.stringValue
            // SYNCHRONOUSLY, before the binding write has been through SwiftUI: a
            // security key types its whole code and its Return in one burst, so a
            // policy that only saw the text after a view update would not have
            // decided anything by the time the Return arrived.
            parent.returnPolicy?.fieldTextChanged(field.stringValue)
        }
        func controlTextDidBeginEditing(_ note: Notification) {
            parent.focus = parent.focusValue
        }
        func control(_ control: NSControl, textView: NSTextView, doCommandBy selector: Selector) -> Bool {
            if selector == #selector(NSResponder.insertNewline(_:)) {
                // A policy may swallow this Return — see `returnPolicy`. The
                // keystroke is still consumed (`true`), so it never reaches the
                // window's default button either; it simply does nothing.
                if let policy = parent.returnPolicy, !policy.fieldShouldSubmitOnReturn() {
                    return true
                }
                parent.onSubmit()
                return true
            }
            return false
        }
    }
}

extension AutoFillField where Focus == Bool {
    /// A field with no focus bridge — for editor forms that have no focus
    /// token (the shake/nudge machinery is a connect-form thing). The constant
    /// binding swallows the coordinator's focus writes; nil never equals the
    /// focusValue, so no focus is ever stolen either.
    init(kind: Kind, placeholder: String, text: Binding<String>,
         onSubmit: @escaping () -> Void = {}) {
        self.init(kind: kind, placeholder: placeholder, text: text,
                  focus: .constant(nil), focusValue: true, onSubmit: onSubmit)
    }
}

/// A toggleable label chip.
struct LabelChip: View {
    let label: LabelDef
    let on: Bool
    let toggle: () -> Void
    var body: some View {
        Button(action: toggle) {
            Text(label.name).font(.caption)
                .padding(.horizontal, 9).padding(.vertical, 3)
                // A caption in 3pt of padding is ~17pt tall; the app-wide minimum
                // hit target is 22 (the hitbox rule), and the capsule itself is
                // the shape being clicked.
                .frame(minHeight: 22)
                .background(on ? AnyShapeStyle(label.color) : AnyShapeStyle(.clear), in: Capsule())
                .overlay(Capsule().strokeBorder(label.color, lineWidth: on ? 0 : 1))
                .foregroundStyle(on ? AnyShapeStyle(.black.opacity(0.78)) : AnyShapeStyle(.primary))
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        // It toggles — say so, and say which way it currently is (the filled
        // capsule is the only visual carrier, and that's color+fill only).
        .accessibilityAddTraits(.isToggle)
        .accessibilityValue(on ? "On" : "Off")
    }
}

/// A monospaced, selectable value with a hover-reveal copy button and a Copy
/// context menu — used for every IP address, fingerprint, and identifier the
/// user might want on the clipboard.
struct CopyableValue: View {
    let value: String
    var font: Font = .callout.monospaced()

    @State private var hovering = false
    @State private var copied = false

    private func copy() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
    }

    var body: some View {
        HStack(spacing: 6) {
            Text(value)
                .font(font)
                .textSelection(.enabled)
                .lineLimit(1)
                .truncationMode(.middle)
            Button {
                copy()
                copied = true
                Task { try? await Task.sleep(for: .seconds(1.2)); copied = false }
            } label: {
                Image(systemName: copied ? "checkmark" : "doc.on.doc")
                    .foregroundStyle(copied ? AnyShapeStyle(.green) : AnyShapeStyle(.secondary))
                    .frame(width: 22, height: 22).contentShape(Rectangle())
            }
            .buttonStyle(.borderless)
            .opacity(hovering || copied ? 1 : 0)
            .help("Copy")
            .accessibilityLabel(copied ? "Copied" : "Copy \(value)")
        }
        .onHover { hovering = $0 }
        .contextMenu { Button("Copy") { copy() } }
        .accessibilityElement(children: .combine)
        .accessibilityValue(value)
    }
}

/// Minimal text document for exporting an .ovpn.
struct OVPNDocument: FileDocument {
    static var readableContentTypes: [UTType] { [UTType(filenameExtension: "ovpn") ?? .data, .plainText] }
    var text: String
    init(text: String) { self.text = text }
    init(configuration: ReadConfiguration) throws {
        text = String(data: configuration.file.regularFileContents ?? Data(), encoding: .utf8) ?? ""
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: Data(text.utf8))
    }
}


/// A platform-free activity spinner for transition-animated contexts.
///
/// SwiftUI's ProgressView on macOS is hosted AppKit (the layout-loop crash's context
/// log names it: AppKitPlatformViewHost<…AppKitProgressView>). Animating a scale/blur
/// transition over one — the connecting pill's glass morph, the sidebar row's
/// .blurReplace — calls setFrameTransform: on the hosted view every frame, which
/// changes its backing properties, invalidates intrinsic-size constraints MID-PASS,
/// and re-enters layout until AppKit's guard throws ("more Update Constraints in
/// Window passes than there are views"). Every crash (builds 50→63) happened at the
/// .connecting transition where those spinners animate. A drawn spinner keeps the
/// animated subtree free of platform views entirely.
struct DrawnSpinner: View {
    var size: CGFloat = 14
    var lineWidth: CGFloat = 1.8
    @State private var spinning = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Circle()
            .trim(from: 0.15, to: 1)
            .stroke(.secondary, style: StrokeStyle(lineWidth: lineWidth, lineCap: .round))
            .frame(width: size, height: size)
            .rotationEffect(.degrees(spinning ? 360 : 0))
            .onAppear {
                // Reduce Motion: a static open ring still reads as "busy"; no spin.
                guard !reduceMotion else { return }
                withAnimation(.linear(duration: 0.9).repeatForever(autoreverses: false)) {
                    spinning = true
                }
            }
            .accessibilityLabel("In progress")
    }
}
