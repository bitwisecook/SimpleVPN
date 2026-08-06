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
//  Edit VPN ▸ Servers is NOT here: it is a table rather than a list, and it lives
//  in ServersTable.swift. It shares this file's ranking, flag button and region
//  sheet, so there is still one vocabulary and one ordering.
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
                                  measurement: probes?.measurement(for: e.id),
                                  // Whatever this network last answered for the
                                  // host. Already cached by the call above — no
                                  // second lookup, and none on hover.
                                  resolvedAddresses: l?.addresses ?? [])
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
        orderExplanation(items: groups.flatMap(\.endpoints), home: home, connected: connected)
    }

    /// The same sentence for a flat list — the Servers table is ungrouped, because
    /// a table has columns to carry what a region heading used to.
    static func orderExplanation(items: [RankedEndpoint], home: GeoPoint?,
                                 connected: Bool = false) -> String {
        // The user's own order comes FIRST in this sentence, because it beats every
        // reason below it: a footnote promising "fastest first" over a hand-made
        // order would be describing a list that isn't on screen.
        if EndpointRanking.isManuallyOrdered(items) {
            let unplaced = items.filter { $0.endpoint.order == nil }.count
            var s = "In the order you put them in. Speed checks fill in the Speed column"
                + " but no longer change the order."
            if unplaced > 0 {
                s += " \(unplaced) newer server\(unplaced == 1 ? "" : "s") from this VPN's"
                    + " configuration \(unplaced == 1 ? "sits" : "sit") at the end until you"
                    + " place \(unplaced == 1 ? "it" : "them")."
            }
            return s
        }
        let measured = items.contains { $0.measurement?.rttMS != nil }
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
        // Name if the user set one, else the address — and never both when they
        // are the same string (RankedEndpoint.primaryLabel is the rule).
        s += item.primaryLabel
        if item.primaryLabel != item.address { s += " (\(item.address))" }
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
