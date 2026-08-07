// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  GuestInventory.swift
//  THE NAMES — "postgres", "BIGIP-21.1.0.1" — and, much harder, WHICH NETWORK EACH
//  ONE IS REALLY ON.
//
//  FINDING A NAME IS EASY AND IS NOT THE PROBLEM. Every product on this list writes
//  its virtual machines' settings into a file in the user's own home, and the name is
//  right there. The problem is attaching that name to a guest network on a ROUTING
//  DIAGRAM, where somebody is about to decide whether to send it around a VPN. A
//  guest shown on the wrong network is worse than a guest shown with no network at
//  all: the decision is then made about the wrong guest, and nothing on screen says
//  so. `ONTOLOGY.md` binds it — a name is attached only where the mapping is
//  EVIDENCED, and everything else is listed as unattached, with the reason.
//
//  THE TWO KINDS OF EVIDENCE, and there are only two:
//
//   1. **A recorded hardware address seen on that interface right now.** UTM,
//      Parallels, VMware and VirtualBox all record the address their guest will use.
//      The kernel's neighbour cache says which interface an address is behind
//      (`NetworkTopology.neighbours`, harvested from the `netstat` output the app was
//      already taking and discarding). A match is proof, not a guess — and it also
//      correctly attaches a BRIDGED guest to `en0` rather than to a guest network,
//      which is the answer that stops us claiming a VPN affects it.
//   2. **A recorded network name, when there is exactly one network it could be.**
//      Apple's `container` records which network each container is on
//      (`"networks":[{"network":"default"}]`) but nothing on disk maps `default` to
//      `bridge100`. With one recorded network and one live guest network the mapping
//      is forced; with two of either it is not, and then we say so. This is the same
//      unanimity rule `VirtualizationDiscovery.mode` already applies, for the same
//      reason.
//
//  WHAT IS DELIBERATELY NOT A SOURCE:
//
//   • **`docker` and `podman`.** Their container names live behind a daemon socket,
//     not in a file. `LocalToolRunner` never consults `PATH` and this app does not run
//     a vendor's CLI to discover things; a daemon query is also a different privacy and
//     latency proposition from reading a file. So Docker's and Podman's CONTAINERS are
//     not nameable here and the UI says that rather than showing an empty list that
//     looks like "you have none". Their MACHINES are files and are read where they are.
//   • **Guessing by count.** "One container and one tap, so that must be it" is
//     applied ONLY where it is forced (rule 2 above), never as a tiebreak.
//
//  RUNNING IS NOT THE SAME AS EXISTING. A `.utm` bundle on disk is a virtual machine
//  the user owns; it says nothing about whether it is running. The graph is a picture
//  of the packet path, so a name must never imply a live guest: attachment to a live
//  interface IS the liveness signal, and everything else is "also on this Mac".
//
//  RULES INHERITED FROM `VirtualizationDiscovery` AND BINDING HERE: filesystem reads
//  only, nothing executed, no daemon woken, nothing sent anywhere — and every read
//  happens inside that file's bounded off-main half, because one of these directories
//  (UTM's sandbox container) has been MEASURED to block in `open` and never return.
//

import Foundation

// MARK: - A named guest

/// One virtual machine or container, as its own product records it.
nonisolated struct NamedGuest: Sendable, Equatable, Identifiable {
    /// What the user called it. Never invented: if the product has no name for it,
    /// there is no `NamedGuest`.
    var name: String
    /// Which product's records it came out of.
    var productID: String
    /// A second line worth showing — an image reference, an architecture. Optional
    /// because most products do not offer one worth the space.
    var detail: String?
    /// The product's own name for the network it is on, where it records one.
    var recordedNetwork: String?
    /// Hardware addresses it is recorded as using. The strongest evidence there is.
    ///
    /// `MACAddress`, so that the four products' four spellings are the same VALUE by
    /// the time they get here and the match against the neighbour cache is structural.
    var recordedMACs: [MACAddress] = []
    /// The arrangement its own settings record, where they do.
    var recordedMode: GuestNetworkMode = .unknown
    /// Stable within a product: the product's own identifier for it.
    var identifier: String

    var id: String { "\(productID)|\(identifier)" }

    var productTitle: String {
        VirtualizationCatalog.product(id: productID)?.title ?? productID
    }

    /// A name a person can read. Apple's `container` uses the container id as its
    /// name, and that id is a bare UUID when the user did not pass `--name` — 36
    /// characters is not a label, so it is shortened to the FIRST TWELVE HEX DIGITS,
    /// which is the short id every container tool prints and the form a user will
    /// recognise. The dashes go with them: `6a20af99-b55` is a UUID cut in half,
    /// `6a20af99b551` is a short id.
    ///
    /// A name the user actually chose is never shortened, however long — the whole
    /// point of a name is that they picked it.
    var displayName: String {
        guard UUID(uuidString: name) != nil else { return name }
        return String(name.filter(\.isHexDigit).prefix(12))
    }
}

// MARK: - Where it is, and why we say so

/// The answer to "which network is this guest on", with its reason attached.
/// `ONTOLOGY.md`: evidence is a sentence, never a score — there is no "probably".
nonisolated enum GuestAttachment: Sendable, Equatable {
    /// Bound to a host interface, for this stated reason.
    case interface(String, evidence: String)
    /// We found the guest but cannot prove where it is, for this stated reason.
    case unattached(reason: String)

    var interfaceName: String? {
        if case .interface(let name, _) = self { return name }
        return nil
    }
    var evidence: String {
        switch self {
        case .interface(_, let evidence): evidence
        case .unattached(let reason): reason
        }
    }
}

/// A guest and where it turned out to be. The pair the UI actually draws.
nonisolated struct PlacedGuest: Sendable, Equatable, Identifiable {
    var guest: NamedGuest
    var attachment: GuestAttachment

    var id: String { guest.id }

    /// One of `ONTOLOGY.md`'s three states, derived rather than stored so it cannot
    /// disagree with the attachment it came from.
    enum Presence: String, Sendable, Equatable {
        /// On a guest network of this Mac's.
        case runningHere
        /// Running, but on the same network as this Mac — bridged.
        case runningOnYourNetwork
        /// Its settings are on disk and nothing of it is on the network.
        case notRunning
    }

    func presence(guestInterfaces: Set<String>) -> Presence {
        guard let name = attachment.interfaceName else { return .notRunning }
        return guestInterfaces.contains(name) ? .runningHere : .runningOnYourNetwork
    }
}

// MARK: - Reading the records

nonisolated enum GuestInventory {

    /// Every named guest this Mac's own virtualization records describe.
    ///
    /// FILESYSTEM-BOUND — call it from the bounded off-main half of
    /// `VirtualizationDiscovery.snapshotOffMain`, never from the main actor.
    /// `installed` gates each reader so a product nobody has is not searched for.
    static func guests(env: VirtualizationEnvironment,
                       installed: [InstalledVirtualization]) -> [NamedGuest] {
        let have = Set(installed.map(\.productID))
        var out: [NamedGuest] = []
        if have.contains("apple-container") { out += appleContainerGuests(env: env) }
        if have.contains("utm") { out += utmNamedGuests(env: env) }
        if have.contains("parallels") { out += parallelsGuests(env: env) }
        if have.contains("vmware-fusion") { out += vmwareGuests(env: env) }
        if have.contains("virtualbox") { out += virtualBoxGuests(env: env) }
        return out
    }

    /// Apple's `container`. **VERIFIED ON A REAL MAC, 2026-08-07.** Each container has
    /// a directory under `containers/<id>/` whose `config.json` is, verbatim:
    ///
    /// ```
    /// {"id":"6a20af99-…","image":{"reference":"docker.io/library/alpine:latest",…},
    ///  "networks":[{"options":{"mtu":1280,"hostname":"6a20af99-…"},"network":"default"}],…}
    /// ```
    ///
    /// `id` is what `container ls` shows and what the user types to address it — it is
    /// the name when `--name` was given and a UUID when it was not (`displayName`
    /// handles that). `networks[].network` is the product's own name for the network,
    /// which is evidence of kind 2.
    ///
    /// NO LIVENESS HERE, and the directory survives the container: `service.plist` has
    /// `RunAtLoad` false and nothing else on disk says "running". Liveness comes from
    /// the interface list, which is the honest place for it.
    static func appleContainerGuests(env: VirtualizationEnvironment) -> [NamedGuest] {
        let root = env.home
            .appendingPathComponent("Library/Application Support/com.apple.container/containers")
        return env.listDirectory(root.path).sorted().compactMap { entry in
            let path = root.appendingPathComponent(entry)
                .appendingPathComponent("config.json").path
            guard let record = env.readContainerRecord(path) else { return nil }
            let id = record.id
            return NamedGuest(name: id, productID: "apple-container", detail: record.image,
                              recordedNetwork: record.network, recordedMACs: [],
                              // Apple's container puts every container on a vmnet
                              // network; which ARRANGEMENT that is comes from the
                              // network's own record, not the container's.
                              recordedMode: .unknown, identifier: id)
        }
    }

    /// UTM. **VERIFIED ON A REAL MAC, 2026-08-07** against `BIGIP-21.1.0.1.utm`:
    /// `Information.Name` is the VM's name, and `Network[].MacAddress`
    /// (`EA:85:74:8B:18:97`) is exactly the evidence-of-kind-1 this file wants —
    /// together with `Mode` (`Bridged`) and `BridgeInterface` (`en0`), which that VM's
    /// record also carried and which correctly says a VPN here cannot affect it.
    ///
    /// The name comes from the CONFIG rather than the bundle's filename: renaming a
    /// `.utm` bundle in Finder does not rename the machine, and the name UTM shows is
    /// the one in `Information`.
    static func utmNamedGuests(env: VirtualizationEnvironment) -> [NamedGuest] {
        let root = env.home
            .appendingPathComponent("Library/Containers/com.utmapp.UTM/Data/Documents").path
        return env.listDirectory(root)
            .filter { $0.hasSuffix(".utm") }
            .sorted()
            .compactMap { bundle -> NamedGuest? in
                let fallback = String(bundle.dropLast(".utm".count))
                guard let network = env.readUTMNetwork(root + "/" + bundle + "/config.plist")
                else { return nil }
                return NamedGuest(
                    name: network.machineName ?? fallback,
                    productID: "utm",
                    detail: nil,
                    recordedNetwork: nil,
                    recordedMACs: network.macAddresses,
                    recordedMode: GuestNetworkMode(vendorWord: network.mode),
                    identifier: network.machineUUID ?? fallback)
            }
    }

    /// Parallels Desktop. **NOT RUN HERE** — Parallels is not installed on this Mac,
    /// so this is written from its documented `config.pvs`, which is XML with
    /// `<VmName>` and a `<MAC>` per network adapter — written, like VirtualBox's,
    /// with no separators at all. Untested code that finds nothing is harmless;
    /// untested code that finds the WRONG thing cannot attach a name anyway, because
    /// attachment needs the address to match a live neighbour.
    static func parallelsGuests(env: VirtualizationEnvironment) -> [NamedGuest] {
        let root = env.home.appendingPathComponent("Parallels").path
        return env.listDirectory(root)
            .filter { $0.hasSuffix(".pvm") }
            .sorted()
            .compactMap { bundle in
                let path = root + "/" + bundle + "/config.pvs"
                guard let xml = env.readText(path) else { return nil }
                let fallback = String(bundle.dropLast(".pvm".count))
                return NamedGuest(
                    name: XMLScrape.firstElement("VmName", in: xml) ?? fallback,
                    productID: "parallels", detail: nil, recordedNetwork: nil,
                    recordedMACs: XMLScrape.elements("MAC", in: xml)
                        .compactMap(MACAddress.init),
                    recordedMode: .unknown, identifier: fallback)
            }
    }

    /// VMware Fusion. **NOT RUN HERE.** A `.vmwarevm` bundle contains a `.vmx`, which
    /// is `key = "value"` lines: `displayName` and `ethernet0.address` (or
    /// `.generatedAddress` when VMware assigned it).
    static func vmwareGuests(env: VirtualizationEnvironment) -> [NamedGuest] {
        let root = env.home.appendingPathComponent("Virtual Machines.localized").path
        return env.listDirectory(root)
            .filter { $0.hasSuffix(".vmwarevm") }
            .sorted()
            .compactMap { bundle -> NamedGuest? in
                let fallback = String(bundle.dropLast(".vmwarevm".count))
                let vmx = root + "/" + bundle + "/" + fallback + ".vmx"
                guard let text = env.readText(vmx) else { return nil }
                let settings = VMXScrape.settings(text)
                let macs = settings
                    .filter { $0.key.hasSuffix(".address") || $0.key.hasSuffix(".generatedAddress") }
                    .values
                    .compactMap(MACAddress.init)
                return NamedGuest(
                    name: settings["displayName"] ?? fallback,
                    productID: "vmware-fusion", detail: settings["guestOS"],
                    recordedNetwork: settings["ethernet0.vnet"],
                    recordedMACs: macs.sorted(), recordedMode: .unknown,
                    identifier: fallback)
            }
    }

    /// VirtualBox. **NOT RUN HERE.** `~/VirtualBox VMs/<name>/<name>.vbox` is XML with
    /// `<Machine … name="…">` and `<Adapter … MACAddress="0800271A2B3C">` — note
    /// VirtualBox writes the address with no separators, which is its own spelling and
    /// needs its own normaliser.
    static func virtualBoxGuests(env: VirtualizationEnvironment) -> [NamedGuest] {
        let root = env.home.appendingPathComponent("VirtualBox VMs").path
        return env.listDirectory(root).sorted().compactMap { folder -> NamedGuest? in
            let path = root + "/" + folder + "/" + folder + ".vbox"
            guard let xml = env.readText(path) else { return nil }
            return NamedGuest(
                name: XMLScrape.firstAttribute("name", ofElement: "Machine", in: xml) ?? folder,
                productID: "virtualbox", detail: nil, recordedNetwork: nil,
                recordedMACs: XMLScrape.attributes("MACAddress", ofElement: "Adapter", in: xml)
                    .compactMap(MACAddress.init),
                recordedMode: .unknown, identifier: folder)
        }
    }

    // MARK: - Placing them

    /// Attach each named guest to a host interface, or say why it cannot be.
    ///
    /// A PURE FUNCTION over facts the caller supplies, so every branch of this — the
    /// one that attaches, the one that refuses, and the elimination rule between them
    /// — is testable without a virtual machine running.
    ///
    /// - Parameters:
    ///   - neighbours: BSD name → hardware addresses seen there right now.
    ///   - guestNetworks: the live guest networks, in the order they should be tried.
    ///   - recordedNetworkNames: every network name the products have on disk, so the
    ///     elimination rule can tell "one network" from "one of several".
    static func place(_ guests: [NamedGuest],
                      neighbours: [String: Set<MACAddress>],
                      guestNetworks: [GuestNetwork],
                      recordedNetworkNames: Set<String>) -> [PlacedGuest] {

        // The elimination case, stated once so the two conditions cannot drift apart:
        // exactly one guest network is live AND the products know of exactly one
        // network. Either being plural means nothing on disk says which is which.
        let soleNetwork: GuestNetwork? =
            (guestNetworks.count == 1 && recordedNetworkNames.count <= 1)
            ? guestNetworks[0] : nil

        return guests.map { guest in
            // EVIDENCE 1 — a recorded address, seen right now. Tried first because it
            // is the only kind that is proof rather than deduction, and because it is
            // the kind that correctly places a BRIDGED guest on the LAN interface
            // instead of on a guest network.
            for (iface, seen) in neighbours.sorted(by: { $0.key < $1.key }) {
                if let match = guest.recordedMACs.first(where: seen.contains) {
                    // `canonicalText` and not interpolation: `MACAddress` has no
                    // `description` precisely so that showing one is deliberate. This
                    // sentence is ON SCREEN and nowhere else — it is not in the
                    // diagnostic report, not in a log line, and not in an error. It
                    // names the address the USER'S OWN virtual machine records, to a
                    // reader who is looking at that machine's card, because "we
                    // matched something" without saying what is not evidence.
                    return PlacedGuest(guest: guest, attachment: .interface(
                        iface,
                        evidence: "\(guest.productTitle) records this machine using the hardware "
                            + "address \(match.canonicalText), and that address is on \(iface) "
                            + "right now."))
                }
            }
            // EVIDENCE 2 — a recorded network name, when there is only one network it
            // could mean.
            if let recorded = guest.recordedNetwork, let only = soleNetwork {
                return PlacedGuest(guest: guest, attachment: .interface(
                    only.interfaceName,
                    evidence: "\(guest.productTitle) records this guest on its \u{201C}\(recorded)\u{201D} "
                        + "network, and that is the only guest network on this Mac."))
            }
            // Neither. Say WHICH is missing, because the two send a reader to
            // different places.
            if guest.recordedNetwork != nil {
                return PlacedGuest(guest: guest, attachment: .unattached(
                    reason: "\(guest.productTitle) records which of its networks this guest is on, "
                        + "but not which of this Mac\u{2019}s interfaces that network became \u{2014} "
                        + "and there is more than one it could be."))
            }
            if guest.recordedMACs.isEmpty {
                return PlacedGuest(guest: guest, attachment: .unattached(
                    reason: "\(guest.productTitle) does not record anything about this guest that "
                        + "could be matched against a live network."))
            }
            return PlacedGuest(guest: guest, attachment: .unattached(
                reason: "Nothing on any network is using the hardware address "
                    + "\(guest.productTitle) records for this guest, so it does not appear to be "
                    + "running."))
        }
    }
}

// MARK: - Two tiny scrapers, for two formats nobody should need a parser for

/// Enough XML to pull a value out of a vendor's config file, and no more.
///
/// NOT AN XML PARSER, and it must not grow into one. `XMLDocument` is AppKit-adjacent
/// (Foundation on macOS, but it builds a whole tree and throws on the ragged files
/// vendors really write); what is needed here is one element's text or one
/// attribute's value, and a scraper that finds nothing when the format changes is the
/// correct failure mode for code nobody can test on this machine.
nonisolated enum XMLScrape {

    /// The text of the first `<Name>…</Name>`.
    static func firstElement(_ name: String, in xml: String) -> String? {
        elements(name, in: xml).first
    }

    static func elements(_ name: String, in xml: String) -> [String] {
        var out: [String] = []
        var rest = Substring(xml)
        while let open = rest.range(of: "<\(name)>") {
            rest = rest[open.upperBound...]
            guard let close = rest.range(of: "</\(name)>") else { break }
            let text = rest[..<close.lowerBound].trimmingCharacters(in: .whitespacesAndNewlines)
            if !text.isEmpty { out.append(text) }
            rest = rest[close.upperBound...]
        }
        return out
    }

    /// The value of `attribute="…"` on the first `<Element …>`.
    static func firstAttribute(_ attribute: String, ofElement element: String,
                               in xml: String) -> String? {
        attributes(attribute, ofElement: element, in: xml).first
    }

    static func attributes(_ attribute: String, ofElement element: String,
                           in xml: String) -> [String] {
        var out: [String] = []
        var rest = Substring(xml)
        while let open = rest.range(of: "<\(element) ") {
            rest = rest[open.upperBound...]
            // Bounded to this tag, so an attribute of the NEXT element is never
            // attributed to this one.
            guard let tagEnd = rest.firstIndex(of: ">") else { break }
            let tag = rest[..<tagEnd]
            if let key = tag.range(of: "\(attribute)=\"") {
                let after = tag[key.upperBound...]
                if let quote = after.firstIndex(of: "\"") {
                    out.append(String(after[..<quote]))
                }
            }
            rest = rest[tagEnd...]
        }
        return out
    }
}

/// VMware's `.vmx`: `key = "value"` lines, one per line, `#` comments.
nonisolated enum VMXScrape {
    static func settings(_ text: String) -> [String: String] {
        var out: [String: String] = [:]
        for line in text.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.hasPrefix("#"), let equals = trimmed.firstIndex(of: "=") else { continue }
            let key = trimmed[..<equals].trimmingCharacters(in: .whitespaces)
            let value = trimmed[trimmed.index(after: equals)...]
                .trimmingCharacters(in: .whitespaces)
                .trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            guard !key.isEmpty, !value.isEmpty else { continue }
            out[key] = value
        }
        return out
    }
}
