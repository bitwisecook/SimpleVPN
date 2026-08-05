// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DiagnosticReportView.swift
//  The dialog. Three things it must get right, all of them promises made
//  elsewhere in this app:
//
//   1. NOTHING LEAVES WITHOUT BEING READ. The finished report is on screen,
//      verbatim, scrollable and EDITABLE, before any button that shares it is
//      pressed. Per-section switches, and the section that is about the person
//      rather than the software (their password managers) starts OFF.
//   2. IT ASKS A QUESTION. "What were you doing?" with a worked example, not a
//      blank box — and "what went wrong" is a separate box, because the two
//      answers are different and a single box gets one of them.
//   3. KEYBOARD-COMPLETE. Focus starts in the first box. ESC closes the window
//      (`DiagnosticReportCoordinator.ReportWindow.cancelOperation`). Every switch
//      carries its state in its VoiceOver value and its reason in its hint; the
//      preview is a named, readable text view. Nothing is hover-only.
//

import SwiftUI
import AppKit

// MARK: - Model

@MainActor
@Observable
final class DiagnosticReportModel {

    private(set) var request: DiagnosticReportRequest
    @ObservationIgnored private let context: DiagnosticReportContext

    var answers = DiagnosticReportAnswers()
    private(set) var included: Set<DiagnosticReportSectionID> = []
    private(set) var payload: DiagnosticReportPayload?
    private(set) var gathering = false
    /// The text that will actually be shared. Starts as the rendered payload and
    /// is the user's to change.
    var previewText = ""
    /// True once the user has changed the text, so rebuilding it asks first.
    private(set) var previewEdited = false
    /// The last thing that happened, shown and announced. Never a silent action.
    private(set) var lastOutcome: String?
    /// Set when an answer hit its length limit — visible, rather than the text
    /// quietly disappearing.
    private(set) var answerLimitHit = false

    /// `payload` is a test seam: gathering for real reads the system log, and the
    /// edit-tracking behaviour below is worth a unit test rather than a subprocess.
    init(request: DiagnosticReportRequest,
         context: DiagnosticReportContext,
         payload: DiagnosticReportPayload? = nil) {
        self.request = request
        self.context = context
        if let payload {
            self.payload = payload
            included = DiagnosticReportPayload.defaultSelection(for: payload.sections)
            renderPreview()
        }
    }

    func restart(with request: DiagnosticReportRequest) {
        self.request = request
        Task { await gather() }
    }

    // MARK: Gathering

    func gather() async {
        guard !gathering else { return }
        gathering = true
        defer { gathering = false }
        let built = await DiagnosticReportAssembler.assemble(request, context: context, answers: answers)
        payload = built
        included = DiagnosticReportPayload.defaultSelection(for: built.sections)
        previewEdited = false
        renderPreview()
    }

    /// The text as WE last rendered it. Needed because the preview's `onChange`
    /// cannot tell a keystroke from our own write, and a programmatic re-render
    /// that marked the text as "edited by you" would ask permission to rebuild
    /// something nobody had touched.
    @ObservationIgnored private var lastRendered = ""

    /// Re-render from the switches. Only called where losing edits is either
    /// impossible or has been agreed to.
    func renderPreview() {
        let text = payload?.markdown(including: included) ?? ""
        lastRendered = text
        previewText = text
    }

    /// The user changed an answer. Patch the one section that depends on it
    /// rather than re-gathering — re-reading the log to reflect a typed character
    /// would make the dialog stutter, and the facts have not changed.
    ///
    /// The preview re-render is DEBOUNCED. Rendering runs the scrubber over every
    /// field in the report (a full tool inventory is a hundred of them), which is
    /// measured in tens of milliseconds — fine once, unacceptable per keystroke.
    func answersChanged() {
        clampAnswers()
        guard var payload else { return }
        let rebuilt = DiagnosticReportAssembler.rebuildWhatHappened(
            request, answers: answers, in: payload)
        payload.sections = rebuilt
        self.payload = payload
        guard !previewEdited else { return }
        scheduleRender()
    }

    @ObservationIgnored private var renderDebounce: Task<Void, Never>?

    private func scheduleRender() {
        renderDebounce?.cancel()
        renderDebounce = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(350))
            guard !Task.isCancelled, let self, !self.previewEdited else { return }
            self.renderPreview()
        }
    }

    private func clampAnswers() {
        var hit = false
        if answers.whatYouWereDoing.count > DiagnosticReportAnswers.maximumAnswerLength {
            answers.whatYouWereDoing = String(answers.whatYouWereDoing
                .prefix(DiagnosticReportAnswers.maximumAnswerLength))
            hit = true
        }
        if answers.whatWentWrong.count > DiagnosticReportAnswers.maximumAnswerLength {
            answers.whatWentWrong = String(answers.whatWentWrong
                .prefix(DiagnosticReportAnswers.maximumAnswerLength))
            hit = true
        }
        answerLimitHit = hit
    }

    /// Called by the preview's `onChange`. Only a change that differs from what we
    /// rendered is the user's.
    func markPreviewEdited() {
        guard previewText != lastRendered else { return }
        previewEdited = true
    }

    // MARK: Switches

    func isIncluded(_ id: DiagnosticReportSectionID) -> Bool { included.contains(id) }

    /// Toggle a section. If the text has been edited by hand, ask before
    /// replacing it — the alternative is throwing away somebody's writing to
    /// honour a checkbox.
    func setIncluded(_ on: Bool, _ id: DiagnosticReportSectionID) {
        if previewEdited, !confirmRebuild() { return }
        if on { included.insert(id) } else { included.remove(id) }
        previewEdited = false
        renderPreview()
        AccessibilityAnnouncer.sayNow("\(id.title): \(on ? "included" : "left out").")
    }

    private func confirmRebuild() -> Bool {
        let alert = NSAlert()
        alert.messageText = "Rebuild the report?"
        alert.informativeText = "You\u{2019}ve edited the text. Changing what\u{2019}s included will replace it with a freshly built report."
        alert.addButton(withTitle: "Rebuild")
        alert.addButton(withTitle: "Keep My Edits")
        return alert.runModal() == .alertFirstButtonReturn
    }

    // MARK: Sharing

    var plan: DiagnosticReportSubmission.Plan {
        DiagnosticReportSubmission.prepare(request, answers: answers, fullReport: previewText)
    }

    /// Copy the report, then open the prefilled issue form. Two steps, in that
    /// order, so the clipboard is ready before the browser is.
    func openIssue(_ open: (URL) -> Void) {
        let plan = plan
        guard let url = plan.url else {
            saveToFile()
            return
        }
        DiagnosticReportSubmission.copyToClipboard(plan.fullReport)
        open(url)
        note("Report copied to the clipboard, and GitHub opened.")
    }

    func copyOnly() {
        DiagnosticReportSubmission.copyToClipboard(previewText)
        note("Report copied to the clipboard.")
    }

    func saveToFile() {
        let name = DiagnosticReportSubmission.suggestedFileName(request)
        let result = DiagnosticReportSubmission.save(previewText, suggestedName: name)
        if let error = result.error {
            note("The report couldn\u{2019}t be saved: \(error)")
        } else if result.url != nil {
            note("Report saved. Attach it to a new issue on GitHub.")
        }
    }

    private func note(_ sentence: String) {
        lastOutcome = sentence
        AccessibilityAnnouncer.sayNow(sentence)
    }
}

// MARK: - The dialog

struct DiagnosticReportView: View {

    @Bindable var model: DiagnosticReportModel
    @Environment(\.openURL) private var openURL

    private enum Field: Hashable { case doing, wrong, preview }
    @FocusState private var focus: Field?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    questions
                    switches
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            Divider()
            preview
            Divider()
            actions
        }
        .frame(minWidth: 560, minHeight: 620)
        .task {
            await model.gather()
            focus = .doing
        }
    }

    // MARK: Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Report a Problem")
                .font(.title2).bold()
                .accessibilityAddTraits(.isHeader)
            Text(model.request.reason.invitation)
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let kind = model.request.kind {
                Text("This report is about **\(kind.displayName)**.")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: The two questions

    private var questions: some View {
        VStack(alignment: .leading, spacing: 14) {
            answerBox(title: "What were you doing?",
                      prompt: model.request.reason.prompt,
                      text: $model.answers.whatYouWereDoing,
                      field: .doing,
                      axLabel: "What you were doing")
            answerBox(title: "What went wrong?",
                      prompt: "What did you expect, and what happened instead? \u{201C}It connected and stayed up for an hour\u{201D} is a useful answer too \u{2014} that is how an untested type gets marked as working.",
                      text: $model.answers.whatWentWrong,
                      field: .wrong,
                      axLabel: "What went wrong")
            if model.answerLimitHit {
                Label("That\u{2019}s as much as this box will hold. Nothing you typed was removed \u{2014} the rest just didn\u{2019}t go in.",
                      systemImage: "exclamationmark.triangle")
                    .font(.caption).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// A titled multi-line box. The example is a `Text` ABOVE the field, never
    /// the field's title argument — a title becomes visible content and becomes
    /// what VoiceOver calls the field, which is a bug this project has already
    /// fixed twenty-six times.
    private func answerBox(title: String, prompt: String,
                           text: Binding<String>, field: Field,
                           axLabel: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.headline)
            Text(prompt)
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            TextEditor(text: text)
                .font(.body)
                .frame(height: 74)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(.quaternary))
                .focused($focus, equals: field)
                .accessibilityLabel(axLabel)
                .accessibilityHint(prompt)
                .onChange(of: text.wrappedValue) { _, _ in model.answersChanged() }
        }
    }

    // MARK: Per-section switches

    private var switches: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("What SimpleVPN will include").font(.headline)
            Text("Everything below is already gathered. Switch off anything you\u{2019}d rather not share \u{2014} the report says what was left out, so nobody wonders.")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(model.payload?.availableSections ?? []) { section in
                sectionRow(section)
            }
            if model.gathering {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Gathering\u{2026}").foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Gathering the report")
            }
        }
    }

    private func sectionRow(_ section: DiagnosticReportSection) -> some View {
        // `.contain` rather than `.combine`: the row holds an interactive switch,
        // and a row-wide `.combine` swallows it (Docs/Accessibility.md, rule 4).
        VStack(alignment: .leading, spacing: 2) {
            Toggle(section.title, isOn: Binding(
                get: { model.isIncluded(section.id) },
                set: { model.setIncluded($0, section.id) }))
                .accessibilityLabel(section.title)
                .accessibilityValue(model.isIncluded(section.id) ? "included" : "left out")
                .accessibilityHint(section.id.whyItHelps)
            Text(section.id.whyItHelps)
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityHidden(true)   // said by the Toggle's hint, not twice
            if section.isEmpty, let note = section.emptyNote {
                Text(note).font(.caption).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.vertical, 3)
    }

    // MARK: The payload, verbatim

    private var preview: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text("Exactly what will be shared").font(.headline)
                Spacer()
                if model.previewEdited {
                    Label("edited by you", systemImage: "pencil")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Text("\(model.previewText.count.formatted()) characters")
                    .font(.caption).foregroundStyle(.secondary)
            }
            TextEditor(text: $model.previewText)
                .font(.system(.callout, design: .monospaced))
                .frame(height: 200)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(.quaternary))
                .focused($focus, equals: .preview)
                .accessibilityLabel("The report that will be shared")
                .accessibilityHint("Read it, and change anything you don\u{2019}t want to share. This is the exact text that leaves your Mac.")
                .onChange(of: model.previewText) { _, _ in model.markPreviewEdited() }
        }
        .padding(20)
    }

    // MARK: Actions

    private var actions: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(model.plan.explanation)
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let outcome = model.lastOutcome {
                Label(outcome, systemImage: "checkmark.circle.fill")
                    .font(.caption).foregroundStyle(.green)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                // Each `.help` sentence is repeated as an `accessibilityHint` — the
                // house rule (Docs/Accessibility.md rule 5/7): no hover-only
                // explanation, because a hover is invisible to VoiceOver and to
                // anyone driving from the keyboard. "sends nothing anywhere" is
                // exactly the reassurance this window owes, so it must be spoken.
                Button("Copy Report") { model.copyOnly() }
                    .help("Copies the text above to the clipboard, and sends nothing anywhere.")
                    .accessibilityHint("Copies the text above to the clipboard, and sends nothing anywhere.")
                Button("Save to a File\u{2026}") { model.saveToFile() }
                    .help("Saves the text above so you can attach it to an issue yourself.")
                    .accessibilityHint("Saves the text above so you can attach it to an issue yourself.")
                Spacer()
                Button("Close") { DiagnosticReportCoordinator.shared.close() }
                    .keyboardShortcut(.cancelAction)
                Button(model.plan.needsFile ? "Save and Open GitHub\u{2026}" : "Copy and Open GitHub\u{2026}") {
                    model.openIssue { openURL($0) }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.glassProminent)
                .disabled(model.gathering)
                .help(model.gathering ? "Still gathering the report." : model.plan.explanation)
                .accessibilityValue(model.gathering
                    ? "Not available yet: SimpleVPN is still gathering the report"
                    : model.plan.explanation)
            }
        }
        .padding(20)
    }
}
