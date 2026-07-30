// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DiscoverEndpointView.swift
//  "I only know the address." Type a host (optionally host:port), scan it, and
//  get ranked candidates the probes could identify — each with a one-click Create
//  that pre-fills the right editor. Routing/creation is the caller's job (it owns
//  the stores); this sheet only drives the scan and renders results.
//

import SwiftUI

struct DiscoverEndpointView: View {
    /// Turn a chosen candidate into a real VPN and select it. The caller dismisses
    /// by returning; we close the sheet after invoking it.
    let onCreate: (DiscoveryCandidate) -> Void
    @Environment(\.dismiss) private var dismiss

    @State private var address = ""
    @State private var scanning = false
    @State private var scanned = false
    @State private var candidates: [DiscoveryCandidate] = []

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    HStack {
                        TextField("Host or host:port", text: $address,
                                  prompt: Text("vpn.example.com"))
                            .textFieldStyle(.roundedBorder)
                            .autocorrectionDisabled()
                            .onSubmit { Task { await scan() } }
                        Button {
                            Task { await scan() }
                        } label: {
                            if scanning { ProgressView().controlSize(.small) } else { Text("Scan") }
                        }
                        .disabled(scanning || address.trimmingCharacters(in: .whitespaces).isEmpty)
                        .keyboardShortcut(.defaultAction)
                    }
                    Text("SimpleVPN sends probe traffic to this address to work out what kind of VPN it is and how it signs in. Only scan servers you're allowed to.")
                        .font(.caption).foregroundStyle(.secondary)
                } header: { Text("Endpoint") }

                if scanning {
                    Section {
                        Label("Probing SSH, TLS VPN gateways, IKEv2 and OpenVPN…", systemImage: "dot.radiowaves.left.and.right")
                            .foregroundStyle(.secondary)
                    }
                } else if scanned {
                    if candidates.contains(where: { $0.kind != nil }) {
                        Section("What's There") {
                            ForEach(candidates) { c in candidateRow(c) }
                        }
                    } else {
                        Section {
                            ContentUnavailableView("Nothing Identifiable",
                                systemImage: "questionmark.circle",
                                description: Text("No engine answered in a way we could recognise. The server may be silent by design (WireGuard, or OpenVPN with tls-crypt), firewalled, or only reachable on a non-standard port — try adding :port."))
                            ForEach(candidates.filter { $0.kind == nil }) { c in candidateRow(c) }
                        }
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Discover a VPN")
            .frame(minWidth: 520, minHeight: 460)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } } }
        }
    }

    @ViewBuilder private func candidateRow(_ c: DiscoveryCandidate) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: c.systemImage)
                .font(.title3).foregroundStyle(.tint).frame(width: 24)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(c.title).font(.callout).bold()
                    ConfidencePill(confidence: c.confidence)
                    Text("\(c.transport)/\(c.port)").font(.caption).foregroundStyle(.secondary)
                }
                Text(c.detail).font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if !c.facts.isEmpty { factsLine(c) }
            }
            Spacer(minLength: 6)
            if c.kind != nil {
                Button("Create") { onCreate(c); dismiss() }
                    .buttonStyle(.borderedProminent).controlSize(.small)
            }
        }
        .padding(.vertical, 2)
    }

    @ViewBuilder private func factsLine(_ c: DiscoveryCandidate) -> some View {
        let order = ["software", "authMethods", "vendor", "encryption", "integrity",
                     "dhGroup", "sslProtocol", "clientCert", "saml", "serverCert"]
        let shown = order.compactMap { k in c.facts[k].map { "\(prettyKey(k)): \($0)" } }
        if !shown.isEmpty {
            Text(shown.joined(separator: " · "))
                .font(.caption).foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func prettyKey(_ k: String) -> String {
        switch k {
        case "authMethods": "auth"; case "dhGroup": "DH group"; case "sslProtocol": "protocol"
        case "clientCert": "client cert"; case "saml": "SAML"; case "serverCert": "cert"
        default: k
        }
    }

    private func scan() async {
        let raw = address
        scanning = true; scanned = false; candidates = []
        let host = EndpointDiscovery.normalizedHost(raw)
        let hint = EndpointDiscovery.portHint(from: raw)
        let results = await EndpointDiscovery.discover(host: host, hintPort: hint)
        candidates = results
        scanning = false; scanned = true
    }
}

private struct ConfidencePill: View {
    let confidence: DiscoveryConfidence
    var body: some View {
        Text(confidence.label)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 6).padding(.vertical, 1)
            .background(color.opacity(0.18), in: Capsule())
            .foregroundStyle(color)
    }
    private var color: Color {
        switch confidence { case .high: .green; case .medium: .orange; case .low: .secondary }
    }
}
