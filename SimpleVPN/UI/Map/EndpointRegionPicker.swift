// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  EndpointRegionPicker.swift
//  The one presentation of "which server?" that every surface shares: endpoints
//  grouped under region headings, flag and country beside each, quickest first
//  where we've measured and nearest first where we haven't — plus the sheet that
//  opens when someone clicks a flag to say "no, that one's actually in Sydney".
//
//  Kept out of the individual views so the sidebar menu, the connection page's
//  dropdown and the edit sheet can't drift into three different vocabularies for
//  the same list.
//

import SwiftUI

// MARK: - Assembling the ranked list

/// Joins the three sources the pickers need — the endpoints themselves, where
/// GeoIP puts them, and what (if anything) a probe measured — into the ranked,
/// grouped shape the UI draws. MainActor because the locator and the probe
/// store are observable app state; the ranking underneath it is pure.
@MainActor
enum EndpointRegions {

    static func ranked(_ endpoints: [VPNEndpoint],
                       locator: EndpointLocator?,
                       probes: EndpointProbeStore?) -> [RankedEndpoint] {
        // One call, because asking the locator is what kicks off the DNS/GeoIP
        // resolution for hosts it hasn't seen.
        let located = locator?.locations(for: endpoints.map(\.endpoint)) ?? []
        var byID: [String: EndpointLocation] = [:]
        for l in located { byID[l.endpoint.id] = l }

        return endpoints.map { e in
            let l = byID[e.id]
            let point = (l?.lat).flatMap { lat in (l?.lon).map { GeoPoint(lat: lat, lon: $0) } }
            return RankedEndpoint(endpoint: e,
                                  geoCountry: l?.countryCode,
                                  geoPoint: point,
                                  measurement: probes?.measurement(for: e.id))
        }
    }

    static func groups(_ endpoints: [VPNEndpoint],
                       locator: EndpointLocator?,
                       probes: EndpointProbeStore?,
                       home: GeoPoint?) -> [RegionGroup] {
        EndpointRanking.grouped(ranked(endpoints, locator: locator, probes: probes), home: home)
    }

    /// Where the user is, for the distance guess: the real device position when
    /// they've opted into location, otherwise the country their public address
    /// geolocates to (which can be a thousand kilometres out — good enough to
    /// order continents, which is all it's used for).
    static func home(publicIP: PublicIPMonitor?) -> GeoPoint? {
        let location = LocationAuthority.shared
        if location.status == .authorized, let c = location.coordinate {
            return GeoPoint(lat: c.latitude, lon: c.longitude)
        }
        if let lat = publicIP?.homeLat, let lon = publicIP?.homeLon {
            return GeoPoint(lat: lat, lon: lon)
        }
        if let lat = publicIP?.lat, let lon = publicIP?.lon {
            return GeoPoint(lat: lat, lon: lon)
        }
        return nil
    }

    /// The footnote under a picker, saying plainly what the order means.
    ///
    /// - Parameter connected: this VPN is up (or coming up). Its servers are not
    ///   speed-checked while that's true — the check would go through the tunnel
    ///   it is asking about — so the footnote must not promise numbers that
    ///   aren't coming.
    static func orderExplanation(_ groups: [RegionGroup], home: GeoPoint?,
                                 connected: Bool = false) -> String {
        let measured = groups.flatMap(\.endpoints).contains { $0.measurement?.rttMS != nil }
        if connected {
            return measured
                ? "Fastest first, from the last check before you connected."
                : "You're connected, so speed checks are paused until you disconnect."
        }
        if measured { return "Fastest first, from a quick check of each server." }
        if !EndpointProbeStore.isEnabled {
            return "Nearest first, by location. Turn on speed checks in Settings to order these by how quick they actually are."
        }
        if home != nil { return "Nearest first, by location — speed checks are still running." }
        return "In the order this VPN lists them."
    }
}

// MARK: - Row content

/// The line a user reads in any endpoint list: flag, their name for it, where it
/// is, and how quick it was if we know. A plain string rather than a view,
/// because a pop-up menu item on macOS won't lay out a stack.
enum EndpointRowLabel {
    /// - Parameter connected: this is the server the VPN is currently using.
    ///   Then say so instead of quoting a timing: being connected through it is
    ///   a better answer about reaching it than any check could give.
    static func oneLine(_ item: RankedEndpoint, connected: Bool = false) -> String {
        var s = item.flag.isEmpty ? "" : item.flag + " "
        s += item.endpoint.displayLabel
        if item.endpoint.displayLabel != item.address { s += " (\(item.address))" }
        if let proto = item.endpoint.proto { s += " · \(proto.uppercased())" }
        if let country = item.countryName { s += " — \(country)" }
        if connected { s += " · Connected" }
        else if let rtt = item.measurement?.rttText { s += " · \(rtt)" }
        else if item.measurement?.reachable == false { s += " · no answer" }
        return s
    }
}

// MARK: - Region / country override

/// The sheet behind a flag click: correct where an endpoint really is. GeoIP is
/// a guess from an address — providers reuse ranges, anycast exists, and the
/// person using the VPN often simply knows better.
struct EndpointRegionSheet: View {
    let item: RankedEndpoint
    /// Called with the updated endpoint; the caller persists it.
    let apply: (VPNEndpoint) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var search = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Where is this server?").font(.headline)
                Text(item.address).font(.callout).foregroundStyle(.secondary)
                if let guessed = item.geoCountry, item.endpoint.country == nil {
                    Text("SimpleVPN thinks \(CountryCentroids.name(for: guessed) ?? guessed). If that's wrong, pick the right one.")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(16)

            Divider()

            List {
                if item.endpoint.country != nil || item.endpoint.region != nil {
                    Section {
                        Button("Go back to SimpleVPN's guess") { choose(country: nil, region: nil) }
                    }
                }
                if search.isEmpty {
                    Section("Just the area, if you're not sure of the country") {
                        ForEach(RegionBucket.selectable) { region in
                            Button {
                                choose(country: nil, region: region)
                            } label: {
                                Label(region.name, systemImage: region.systemImage)
                            }
                        }
                    }
                }
                ForEach(RegionBucket.selectable) { region in
                    let countries = matches(in: region)
                    if !countries.isEmpty {
                        Section(region.name) {
                            ForEach(countries, id: \.code) { country in
                                Button {
                                    choose(country: country.code, region: nil)
                                } label: {
                                    HStack(spacing: 8) {
                                        Text(CountryCentroids.flag(for: country.code))
                                        Text(country.name)
                                        Spacer()
                                        if item.endpoint.country == country.code {
                                            Image(systemName: "checkmark")
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            .buttonStyle(.plain)
            .searchable(text: $search, prompt: "Search countries")

            Divider()
            HStack {
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            .padding(12)
        }
        .frame(width: 420, height: 520)
        // Done already owns Return; ESC must also close a picker-only sheet.
        .onExitCommand { dismiss() }
    }

    private func matches(in region: RegionBucket) -> [(code: String, name: String)] {
        let term = search.trimmingCharacters(in: .whitespaces)
        guard !term.isEmpty else { return region.countries }
        return region.countries.filter { $0.name.localizedCaseInsensitiveContains(term) }
    }

    private func choose(country: String?, region: RegionBucket?) {
        var e = item.endpoint
        e.country = country
        e.region = region
        apply(e)
        dismiss()
    }
}

/// The clickable flag itself. Deliberately a button everywhere it appears, so
/// "click the flag to fix it" is one rule rather than a hidden trick.
struct EndpointFlagButton: View {
    let item: RankedEndpoint
    let apply: (VPNEndpoint) -> Void
    @State private var showSheet = false

    var body: some View {
        Button {
            showSheet = true
        } label: {
            Text(item.flag.isEmpty ? "🏳️" : item.flag)
                .font(.title3)
                .frame(width: 30, height: 24)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(helpText)
        .accessibilityLabel("Location of \(item.endpoint.host): \(item.countryName ?? "unknown")")
        .accessibilityHint("Opens a list of countries so you can correct where this server is.")
        .sheet(isPresented: $showSheet) {
            EndpointRegionSheet(item: item, apply: apply)
        }
    }

    private var helpText: String {
        if item.endpoint.country != nil || item.endpoint.region != nil {
            return "You set this location. Click to change it."
        }
        return "SimpleVPN worked this location out from the address. Click to correct it."
    }
}

// MARK: - The per-VPN endpoint list (Edit VPN ▸ Endpoints)

/// Lists the addresses this VPN can be reached at, lets each one be named and
/// placed, and lets a user add one their config doesn't mention. Saves as it
/// goes — like the labels row, and unlike the tabs that hold a draft — so there
/// is no way to lose a correction by closing the sheet.
struct EndpointsEditor: View {
    @Bindable var vpn: VPNController
    let profileID: String

    @Environment(EndpointLocator.self) private var locator: EndpointLocator?
    @Environment(EndpointProbeStore.self) private var probes: EndpointProbeStore?
    @Environment(PublicIPMonitor.self) private var publicIP: PublicIPMonitor?

    @State private var newHost = ""
    @State private var newPort = ""
    @AppStorage(endpointProbeDefaultsKey) private var probingOn = true

    private var endpoints: [VPNEndpoint] { vpn.endpoints(for: profileID) }
    private var items: [RankedEndpoint] {
        EndpointRanking.ordered(EndpointRegions.ranked(endpoints, locator: locator, probes: probes),
                                home: EndpointRegions.home(publicIP: publicIP))
    }

    var body: some View {
        Form {
            Section("Servers") {
                if items.isEmpty {
                    Text("This VPN doesn't list any servers yet. Add one below, or import a configuration that names them.")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if connected {
                    Text("You're connected through this VPN, so its servers aren't being speed-checked right now — a check would go through the tunnel it's asking about. Disconnect to check them again.")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                ForEach(items) { item in
                    HStack(spacing: 8) {
                        EndpointFlagButton(item: item) { save($0) }
                        VStack(alignment: .leading, spacing: 2) {
                            TextField("Name (optional)", text: labelBinding(item),
                                      prompt: Text(item.endpoint.host))
                            Text(detail(item)).font(.caption).foregroundStyle(.secondary)
                        }
                        if probes?.probing.contains(item.id) == true {
                            Text("checking…").font(.caption).foregroundStyle(.secondary)
                        } else if let rtt = item.measurement?.rttText {
                            Text(rtt).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                                .accessibilityLabel("latency \(rtt)")
                        }
                        if item.endpoint.userAdded == true {
                            Button(role: .destructive) { remove(item.endpoint) } label: {
                                Image(systemName: "trash")
                            }
                            .buttonStyle(.borderless)
                            .help("Remove this server (you added it by hand).")
                        }
                    }
                    .padding(.vertical, 2)
                    // A named container: the row announces which server it is
                    // and everything known about it, while the flag button,
                    // name field and remove button stay reachable children.
                    .accessibilityElement(children: .contain)
                    .accessibilityLabel("Server \(item.endpoint.displayLabel)")
                    .accessibilityValue(detail(item))
                }
            }

            Section("Add a Server") {
                HStack(spacing: 8) {
                    TextField("Address", text: $newHost, prompt: Text("vpn.example.com"))
                        .autocorrectionDisabled()
                    TextField("Port", text: $newPort, prompt: Text("optional"))
                        .frame(width: 90)
                    Button("Add") { add() }
                        .disabled(newHost.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                Text("Servers listed in this VPN's configuration appear above automatically. Add one here only if you were given an extra address.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Section("Speed Checks") {
                Toggle("Check how quick each server is", isOn: $probingOn)
                    .onChange(of: probingOn) {
                        if probingOn {
                            probes?.refresh(endpoints, kind: kind, profile: profileID, force: true)
                        } else { probes?.clear() }
                    }
                Text("When this is on, SimpleVPN measures each server when you open a server list, and puts the quickest first. Off means no checks are made and the list is ordered by which servers are nearest to you. This is the same switch as in Settings.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .formStyle(.grouped)
        // User-initiated context: they opened this pane to look at the servers.
        // Re-driven on a network change, because the numbers on screen were
        // measured somewhere the user no longer is — and on disconnect, which is
        // the moment this VPN's servers become measurable again.
        .task(id: "\(NetworkMemory.shared.current?.key ?? "")\u{1F}\(connected)") {
            probes?.refresh(endpoints, kind: kind, profile: profileID)
        }
    }

    private var kind: VPNKind {
        vpn.profiles.first { $0.id == profileID }?.kind ?? .openVPN
    }

    /// Up or coming up — see VPNController.isEngaged.
    private var connected: Bool { vpn.isEngaged(id: profileID) }

    private func detail(_ item: RankedEndpoint) -> String {
        var bits = [item.address]
        if let proto = item.endpoint.proto { bits.append(proto.uppercased()) }
        bits.append(item.countryName ?? "location unknown")
        bits.append(item.region.name)
        if let d = item.measurement?.detail { bits.append(d) }
        return bits.joined(separator: " · ")
    }

    private func labelBinding(_ item: RankedEndpoint) -> Binding<String> {
        Binding(get: { item.endpoint.label ?? "" },
                set: { text in
                    var e = item.endpoint
                    let trimmed = text.trimmingCharacters(in: .whitespaces)
                    e.label = trimmed.isEmpty ? nil : trimmed
                    save(e)
                })
    }

    private func save(_ endpoint: VPNEndpoint) {
        Task { await vpn.updateEndpoint(endpoint, for: profileID) }
    }

    private func remove(_ endpoint: VPNEndpoint) {
        Task { await vpn.removeEndpoint(id: endpoint.id, for: profileID) }
    }

    private func add() {
        let host = newHost.trimmingCharacters(in: .whitespaces)
        guard !host.isEmpty else { return }
        var e = VPNEndpoint(host: EndpointDiscovery.normalizedHost(host))
        e.port = Int(newPort.trimmingCharacters(in: .whitespaces))
            ?? EndpointDiscovery.portHint(from: host)
        e.userAdded = true
        newHost = ""; newPort = ""
        save(e)
    }
}
