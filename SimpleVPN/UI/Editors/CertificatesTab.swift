// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CertificatesTab.swift
//  The Certificates tab of the VPN editor: one well per slot (CA, client
//  certificate, private key, TLS key). Drop any common format — PEM, DER,
//  PKCS#12, OpenVPN static key — and it's converted and embedded into the
//  profile text as inline blocks. Populated slots render parsed cards (CN,
//  SANs, issuer, organisation, expiry badges, key↔certificate match), never
//  an opaque blob.
//

import SwiftUI
import UniformTypeIdentifiers

struct CertificatesTab: View {
    @Binding var ovpn: String
    let evaluation: ProfileEvaluation?

    // In-flight interactions
    @State private var pkcs12Data: Data?
    @State private var pkcs12Password = ""
    @State private var pkcs12Error: String?
    @FocusState private var pkcs12Focused: Bool
    @State private var wrongSlot: WrongSlotOffer?
    @State private var tlsModeChoice: SniffedPayload?
    @State private var importError: String?

    struct WrongSlotOffer: Identifiable {
        let id = UUID()
        let payload: SniffedPayload
        let dropped: CertSlot
        let correct: CertSlot
    }

    var body: some View {
        Form {
            slotSection(.ca)
            slotSection(.cert)
            slotSection(.key)
            slotSection(.tlsKey)
        }
        .formStyle(.grouped)
        .sheet(isPresented: Binding(get: { pkcs12Data != nil },
                                    set: { if !$0 { pkcs12Data = nil; pkcs12Password = ""; pkcs12Error = nil } })) {
            pkcs12PasswordSheet
        }
        .confirmationDialog("That file looks like it belongs somewhere else.",
                            isPresented: Binding(get: { wrongSlot != nil },
                                                 set: { if !$0 { wrongSlot = nil } }),
                            titleVisibility: .visible) {
            if let offer = wrongSlot {
                Button("Put it in \u{201C}\(offer.correct.title)\u{201D}") {
                    apply(offer.payload, to: offer.correct)
                    wrongSlot = nil
                }
                Button("Cancel", role: .cancel) { wrongSlot = nil }
            }
        } message: {
            if let offer = wrongSlot {
                Text("You dropped it on \u{201C}\(offer.dropped.title)\u{201D}, but its contents are a \(describe(offer.payload)).")
            }
        }
        .confirmationDialog("How does this VPN use its TLS key?",
                            isPresented: Binding(get: { tlsModeChoice != nil },
                                                 set: { if !$0 { tlsModeChoice = nil } }),
                            titleVisibility: .visible) {
            Button("TLS-Crypt (most modern setups)") { commitTLSKey(mode: "tls-crypt") }
            Button("TLS-Auth") { commitTLSKey(mode: "tls-auth") }
            Button("Cancel", role: .cancel) { tlsModeChoice = nil }
        } message: {
            Text("The configuration doesn't say. Your VPN provider's setup notes will — TLS-Crypt encrypts the handshake, TLS-Auth signs it.")
        }
        .alert("Couldn't Import", isPresented: Binding(get: { importError != nil },
                                                       set: { if !$0 { importError = nil } })) {
            Button("OK", role: .cancel) {}
        } message: { Text(importError ?? "") }
    }

    // MARK: Sections

    @ViewBuilder private func slotSection(_ slot: CertSlot) -> some View {
        Section(slot.title) {
            switch slot {
            case .ca, .cert:
                if let block = OVPNInline.block(for: slot, in: ovpn) {
                    let certs = CertificateImport.certificates(inPEM: block.content)
                    if certs.isEmpty {
                        unreadableRow("The embedded data couldn't be parsed as a certificate.")
                    }
                    ForEach(Array(certs.enumerated()), id: \.offset) { _, cert in
                        CertificateCard(summary: CertificateSummary(certificate: cert))
                    }
                }
            case .key:
                if let block = OVPNInline.block(for: slot, in: ovpn) {
                    PrivateKeyCard(summary: PrivateKeySummary(
                        pem: block.content,
                        certificatePEM: OVPNInline.block(for: .cert, in: ovpn)?.content))
                }
            case .tlsKey:
                if let block = OVPNInline.block(for: slot, in: ovpn) {
                    TLSKeyCard(summary: TLSKeySummary(mode: block.tag,
                                                      direction: OVPNInline.keyDirection(in: ovpn)))
                }
            }
            wellRow(slot)
        }
    }

    @ViewBuilder private func wellRow(_ slot: CertSlot) -> some View {
        let populated = OVPNInline.block(for: slot, in: ovpn) != nil
        HStack(spacing: 12) {
            CertDropWell(slot: slot, populated: populated) { url in ingest(url, into: slot) }
            VStack(alignment: .leading, spacing: 6) {
                Text(populated ? "Drop a file to replace" : "Drop a file, or")
                    .font(.callout).foregroundStyle(.secondary)
                ChooseFileButton(slot: slot) { url in ingest(url, into: slot) }
                    // Four slots, four "Choose File…" buttons — name the slot.
                    .accessibilityLabel("Choose \(slot.title) file")
                if populated {
                    Button("Remove", role: .destructive) { clear(slot) }
                        .accessibilityLabel("Remove \(slot.title)")
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 2)
    }

    private func unreadableRow(_ text: String) -> some View {
        Label(text, systemImage: "exclamationmark.triangle.fill")
            .font(.callout).foregroundStyle(.orange)
    }

    // MARK: Ingestion

    private func ingest(_ url: URL, into slot: CertSlot) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        guard let data = try? Data(contentsOf: url) else {
            importError = "Could not read \(url.lastPathComponent)."
            return
        }
        let payload = CertificateImport.sniff(data)

        switch payload {
        case .unknown:
            importError = "\(url.lastPathComponent) doesn't look like a certificate, key, or PKCS#12 bundle."
        case .pkcs12(let d):
            pkcs12Data = d
        default:
            if CertificateImport.payload(payload, fits: slot) {
                apply(payload, to: slot)
            } else if let correct = CertificateImport.naturalSlot(for: payload) {
                wrongSlot = WrongSlotOffer(payload: payload, dropped: slot, correct: correct)
            } else {
                // Certificates dropped on key/tls wells: offer the cert slot.
                wrongSlot = WrongSlotOffer(payload: payload, dropped: slot, correct: .cert)
            }
        }
    }

    private func apply(_ payload: SniffedPayload, to slot: CertSlot) {
        switch (payload, slot) {
        case (.certificates(let pem, _), .ca):
            ovpn = OVPNInline.setBlock("ca", content: pem, in: ovpn)
        case (.certificates(let pem, _), .cert):
            ovpn = OVPNInline.setBlock("cert", content: pem, in: ovpn)
        case (.privateKey(let pem, _), .key):
            ovpn = OVPNInline.setBlock("key", content: pem, in: ovpn)
        case (.staticKey, .tlsKey):
            if let mode = OVPNInline.tlsKeyMode(in: ovpn) {
                commitTLSKey(mode: mode, payload: payload)
            } else {
                tlsModeChoice = payload
            }
        default:
            break
        }
    }

    private func commitTLSKey(mode: String, payload: SniffedPayload? = nil) {
        guard case .staticKey(let text) = payload ?? tlsModeChoice else { tlsModeChoice = nil; return }
        // tls-auth is directional: the "tls-auth ta.key 1" file-reference form
        // carries the direction as its last arg, which setBlock strips when it
        // removes that line. Capture it first and re-assert it as an explicit
        // key-direction directive so inline tls-auth keeps the same HMAC framing.
        // tls-crypt is non-directional — key-direction must NOT be present.
        let existingDirection = OVPNInline.keyDirection(in: ovpn)

        // Only one TLS-key flavor can be active; clear the other.
        let other = mode == "tls-crypt" ? "tls-auth" : "tls-crypt"
        var updated = OVPNInline.setBlock(other, content: nil, in: ovpn)
        updated = OVPNInline.setBlock(mode, content: text, in: updated)

        updated = OVPNInline.setKeyDirection(
            mode == "tls-auth" ? (existingDirection ?? "1") : nil, in: updated)

        ovpn = updated
        tlsModeChoice = nil
    }

    private func clear(_ slot: CertSlot) {
        var updated = ovpn
        for tag in OVPNInline.tags(for: slot, in: ovpn) {
            updated = OVPNInline.setBlock(tag, content: nil, in: updated)
        }
        ovpn = updated
    }

    private func describe(_ payload: SniffedPayload) -> String {
        switch payload {
        case .certificates(_, let n): n == 1 ? "certificate" : "certificate chain"
        case .privateKey: "private key"
        case .staticKey: "TLS static key"
        case .pkcs12: "PKCS#12 bundle"
        case .unknown: "file"
        }
    }

    // MARK: PKCS#12 password sheet

    private var pkcs12PasswordSheet: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Enter the PKCS#12 Password").font(.headline)
            Text("This bundle contains a certificate and private key protected by a password (sometimes called the export or transport password).")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            SecureField("Password", text: $pkcs12Password)
                .onSubmit(openPKCS12)
                .focused($pkcs12Focused)
                // A wrong password is the FIELD's problem: the error rides its
                // AX value, not just red text below it.
                .accessibilityValue(pkcs12Error ?? "")
            if let pkcs12Error {
                Label(pkcs12Error, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout).foregroundStyle(.red)
            }
            HStack {
                Spacer()
                Button("Cancel") { pkcs12Data = nil; pkcs12Password = ""; pkcs12Error = nil }
                    .keyboardShortcut(.cancelAction)
                Button("Open", action: openPKCS12)
                    .buttonStyle(.glassProminent)
                    .disabled(pkcs12Data == nil)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 380)
        // The password is the only thing to do here — the cursor starts in it.
        .onAppear { pkcs12Focused = true }
    }

    private func openPKCS12() {
        guard let data = pkcs12Data else { return }
        do {
            let contents = try CertificateImport.extractPKCS12(data, password: pkcs12Password)
            var updated = ovpn
            if let cert = contents.certificatePEM {
                updated = OVPNInline.setBlock("cert", content: cert, in: updated)
            }
            if let key = contents.keyPEM {
                updated = OVPNInline.setBlock("key", content: key, in: updated)
            }
            if let chain = contents.chainPEM {
                updated = OVPNInline.setBlock("ca", content: chain, in: updated)
            }
            ovpn = updated
            pkcs12Data = nil; pkcs12Password = ""; pkcs12Error = nil
        } catch {
            pkcs12Error = error.localizedDescription
        }
    }
}

// MARK: - Wells

private struct CertDropWell: View {
    let slot: CertSlot
    let populated: Bool
    let onDrop: (URL) -> Void

    @State private var isTargeted = false

    var body: some View {
        VStack(spacing: 4) {
            Image(systemName: populated ? "checkmark.seal.fill" : symbol)
                .font(.title2)
                .foregroundStyle(populated ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
            Text(populated ? "Embedded" : "Drop here")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .frame(width: 96, height: 64)
        .background(.quaternary.opacity(isTargeted ? 1 : 0.5), in: RoundedRectangle(cornerRadius: 10))
        .overlay {
            RoundedRectangle(cornerRadius: 10)
                .strokeBorder(isTargeted ? AnyShapeStyle(.tint) : AnyShapeStyle(.separator),
                              style: StrokeStyle(lineWidth: isTargeted ? 2 : 1, dash: populated ? [] : [5, 4]))
        }
        .dropDestination(for: URL.self) { urls, _ in
            guard let url = urls.first else { return false }
            onDrop(url)
            return true
        } isTargeted: { isTargeted = $0 }
        .accessibilityLabel("\(slot.title) drop area, \(populated ? "filled" : "empty"). Use the Choose File button as an alternative.")
    }

    private var symbol: String {
        switch slot {
        case .ca: "building.columns"
        case .cert: "person.text.rectangle"
        case .key: "key"
        case .tlsKey: "lock.shield"
        }
    }
}

private struct ChooseFileButton: View {
    let slot: CertSlot
    let onPick: (URL) -> Void
    @State private var showImporter = false

    var body: some View {
        Button("Choose File…") { showImporter = true }
            .fileImporter(isPresented: $showImporter,
                          allowedContentTypes: [.data, .text],
                          onCompletion: { if case .success(let url) = $0 { onPick(url) } })
    }
}

// MARK: - Cards

private struct CertificateCard: View {
    let summary: CertificateSummary
    @State private var detailsExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            // The header block combines into one sentence; the Details
            // disclosure (and the Copy buttons inside it) must stay individually
            // operable, so the combine is scoped here and the card is a plain
            // container — a card-wide .combine made them unreachable.
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .firstTextBaseline) {
                    Text(summary.displayName).font(.body.weight(.semibold))
                    if summary.isSelfSigned {
                        TagBadge(text: "Self-signed", style: .neutral)
                    }
                    Spacer(minLength: 8)
                    expiryBadge
                }
                if !subtitle.isEmpty {
                    Text(subtitle).font(.callout).foregroundStyle(.secondary)
                }
            }
            .accessibilityElement(children: .combine)
            if !summary.sans.isEmpty {
                SANChips(names: summary.sans)
            }
            HStack(spacing: 12) {
                if let alg = summary.keyAlgorithm, let bits = summary.keyBits {
                    Label("\(alg) \(bits)", systemImage: "key.horizontal")
                        .font(.callout).foregroundStyle(.secondary)
                }
                if let notAfter = summary.notAfter, summary.expiryState == .ok(notAfter) {
                    Text("Expires \(notAfter.formatted(date: .abbreviated, time: .omitted))")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }
            .accessibilityElement(children: .combine)
            // A bare-string DisclosureGroup label leaves only the chevron and the
            // word clickable; the whole row is the target here, the same way the
            // OpenVPN form's disclosures and the SSH/SSL "Advanced" headers are.
            DisclosureGroup(isExpanded: $detailsExpanded) {
                VStack(alignment: .leading, spacing: 6) {
                    LabeledContent("Serial") { CopyableValue(value: summary.serialHex) }
                    LabeledContent("SHA-256") { CopyableValue(value: summary.sha256Fingerprint) }
                    if let nb = summary.notBefore {
                        LabeledContent("Valid from", value: nb.formatted(date: .abbreviated, time: .omitted))
                    }
                    if let na = summary.notAfter {
                        LabeledContent("Valid until", value: na.formatted(date: .abbreviated, time: .omitted))
                    }
                }
                .font(.callout)
            } label: {
                HStack {
                    Text("Details")
                    Spacer(minLength: 0)
                }
                .padding(.vertical, 4)
                .contentShape(Rectangle())
                .onTapGesture { withAnimation(.snappy) { detailsExpanded.toggle() } }
            }
            .font(.callout)
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .contain)
    }

    private var subtitle: String {
        var parts: [String] = []
        if !summary.organisation.isEmpty { parts.append(summary.organisation) }
        if !summary.issuerCommonName.isEmpty && !summary.isSelfSigned {
            parts.append("Issued by \(summary.issuerCommonName)")
        }
        return parts.joined(separator: " · ")
    }

    @ViewBuilder private var expiryBadge: some View {
        switch summary.expiryState {
        case .expired:
            TagBadge(text: "Expired", style: .bad)
        case .expiringSoon(let days):
            TagBadge(text: days == 0 ? "Expires today" : "Expires in \(days) day\(days == 1 ? "" : "s")",
                     style: .warning)
        case .ok:
            EmptyView()
        }
    }
}

private struct PrivateKeyCard: View {
    let summary: PrivateKeySummary

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "key.fill").foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text(title).font(.body.weight(.semibold))
                    if summary.encrypted { TagBadge(text: "Password-protected", style: .neutral) }
                }
                matchLine
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .combine)
    }

    private var title: String {
        if let alg = summary.algorithm, let bits = summary.bits { return "\(alg) \(bits)-bit private key" }
        return "Private key"
    }

    @ViewBuilder private var matchLine: some View {
        switch summary.matchesCertificate {
        case .some(true):
            Label("Matches the client certificate", systemImage: "checkmark.circle.fill")
                .font(.callout).foregroundStyle(.green)
        case .some(false):
            Label("Doesn't match the client certificate", systemImage: "exclamationmark.triangle.fill")
                .font(.callout).foregroundStyle(.orange)
        case .none:
            if summary.encrypted {
                Text("Enter its password in Options ▸ Sign-In to use it.")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
    }
}

private struct TLSKeyCard: View {
    let summary: TLSKeySummary

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "lock.shield.fill").foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 3) {
                Text("OpenVPN static key").font(.body.weight(.semibold))
                HStack(spacing: 12) {
                    Text(summary.displayMode).font(.callout).foregroundStyle(.secondary)
                    if let dir = summary.direction {
                        Text("Direction \(dir)").font(.callout).foregroundStyle(.secondary)
                    }
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Small pieces

private struct TagBadge: View {
    enum Style { case neutral, warning, bad }
    let text: String
    let style: Style

    var body: some View {
        Text(text)
            .font(.footnote.weight(.medium))
            .padding(.horizontal, 7).padding(.vertical, 1)
            .background(background, in: Capsule())
            .foregroundStyle(foreground)
    }

    private var background: AnyShapeStyle {
        switch style {
        case .neutral: AnyShapeStyle(.quaternary)
        case .warning: AnyShapeStyle(.orange.opacity(0.2))
        case .bad: AnyShapeStyle(.red.opacity(0.18))
        }
    }
    private var foreground: AnyShapeStyle {
        switch style {
        case .neutral: AnyShapeStyle(.secondary)
        case .warning: AnyShapeStyle(.orange)
        case .bad: AnyShapeStyle(.red)
        }
    }
}

/// Wrapping chips for a certificate's subject alternative names.
private struct SANChips: View {
    let names: [String]
    var body: some View {
        FlowLayout(spacing: 5) {
            ForEach(names, id: \.self) { name in
                Text(name)
                    .font(.footnote.monospaced())
                    .padding(.horizontal, 7).padding(.vertical, 2)
                    .background(.quaternary, in: Capsule())
            }
        }
        // One element, one sentence — without .ignore each chip also announces,
        // so every name arrived twice.
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Covers \(names.joined(separator: ", "))")
    }
}

/// Minimal wrapping layout for chip rows.
struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        arrange(proposal: proposal, subviews: subviews).size
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let placement = arrange(proposal: proposal, subviews: subviews)
        for (subview, point) in zip(subviews, placement.points) {
            subview.place(at: CGPoint(x: bounds.minX + point.x, y: bounds.minY + point.y),
                          proposal: .unspecified)
        }
    }

    private func arrange(proposal: ProposedViewSize, subviews: Subviews) -> (size: CGSize, points: [CGPoint]) {
        let maxWidth = proposal.width ?? .infinity
        var points: [CGPoint] = []
        var x: CGFloat = 0, y: CGFloat = 0, rowHeight: CGFloat = 0, width: CGFloat = 0
        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x > 0 && x + size.width > maxWidth {
                x = 0; y += rowHeight + spacing; rowHeight = 0
            }
            points.append(CGPoint(x: x, y: y))
            rowHeight = max(rowHeight, size.height)
            width = max(width, x + size.width)
            x += size.width + spacing
        }
        return (CGSize(width: width, height: y + rowHeight), points)
    }
}
