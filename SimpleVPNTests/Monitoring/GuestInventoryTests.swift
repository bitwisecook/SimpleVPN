// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  GuestInventoryTests.swift
//  THE REFUSALS AGAIN. Finding a name is easy; the tests that matter are the ones
//  that stop a name being attached to the wrong network, because that is the error a
//  user would act on — they would route the wrong guest around their VPN, and nothing
//  on screen would say so.
//
//  So: two kinds of evidence, both pinned; the elimination rule pinned in BOTH
//  directions (it fires when forced, and refuses when it is merely likely); a stopped
//  guest never reading as a running one; and the two hardware-address spellings, which
//  is the bug that would have made every attachment silently fail.
//

import Testing
import Foundation
@testable import SimpleVPN

// MARK: - A machine whose every record we choose

private struct FakeRecords {
    var home = URL(fileURLWithPath: "/Users/fixture")
    var directories: [String: [String]] = [:]
    var containers: [String: ContainerRecord] = [:]
    var utm: [String: UTMNetworkConfig] = [:]
    var text: [String: String] = [:]
    var present: Set<String> = []

    var environment: VirtualizationEnvironment {
        VirtualizationEnvironment(
            home: home,
            fileExists: { [present] in present.contains($0) },
            applicationDirectories: ["/Applications"],
            listDirectory: { [directories] in directories[$0] ?? [] },
            readUTMNetwork: { [utm] in utm[$0] },
            readContainerRecord: { [containers] in containers[$0] },
            readText: { [text] in text[$0] },
            appleContainerNetworkModes: { _ in [] })
    }
}

private let containersRoot =
    "/Users/fixture/Library/Application Support/com.apple.container/containers"
private let utmRoot = "/Users/fixture/Library/Containers/com.utmapp.UTM/Data/Documents"

/// Parse-or-die, for fixtures. A fixture that will not parse is a broken fixture, not
/// a test result — `MACAddressTests` is where parsing itself is tried.
private func macs(_ text: String) -> MACAddress {
    guard let parsed = MACAddress(text) else {
        preconditionFailure("fixture \u{201C}\(text)\u{201D} is not a hardware address")
    }
    return parsed
}

/// The one UTM machine on this Mac, in UTM's own zero-padded upper-case spelling.
private let utmMAC = macs("EA:85:74:8B:18:97")

// MARK: - Reading the names

struct GuestNameReadingTests {

    /// Apple's `container`, against the shape MEASURED on a real Mac on 2026-08-07:
    /// `containers/<id>/config.json` with `id`, `image.reference` and
    /// `networks[].network`.
    @Test func appleContainerNamesComeFromItsOwnRecord() throws {
        var mac = FakeRecords()
        mac.directories[containersRoot] = ["postgres", "redis"]
        mac.containers["\(containersRoot)/postgres/config.json"] = ContainerRecord(
            id: "postgres", image: "docker.io/library/postgres:16", network: "default")
        mac.containers["\(containersRoot)/redis/config.json"] = ContainerRecord(
            id: "redis", image: "docker.io/library/redis:7", network: "default")
        let guests = GuestInventory.appleContainerGuests(env: mac.environment)
        #expect(guests.map(\.name) == ["postgres", "redis"])
        #expect(guests.first?.detail == "docker.io/library/postgres:16")
        #expect(guests.first?.recordedNetwork == "default")
        #expect(guests.allSatisfy { $0.productID == "apple-container" })
    }

    /// A container started without `--name` has a bare UUID for an id — 36 characters
    /// of hex is not a label, so it is shortened the way every container tool shortens
    /// an id, and the image reference beside it carries the meaning.
    @Test func aUUIDContainerIdIsShortenedRatherThanShownWhole() throws {
        var mac = FakeRecords()
        let uuid = "6a20af99-b551-4f2d-9e1e-a48ef91b0330"
        mac.directories[containersRoot] = [uuid]
        mac.containers["\(containersRoot)/\(uuid)/config.json"] = ContainerRecord(
            id: uuid, image: "docker.io/library/alpine:latest", network: "default")
        let guest = try #require(GuestInventory.appleContainerGuests(env: mac.environment).first)
        #expect(guest.name == uuid)             // the real id is kept
        #expect(guest.displayName == "6a20af99b551")    // …and shortened to a short id
        #expect(guest.detail == "docker.io/library/alpine:latest")
    }

    /// A name the user chose is never shortened, however long.
    @Test func aRealNameIsNeverShortened() {
        let guest = NamedGuest(name: "a-very-long-container-name-indeed",
                               productID: "apple-container", identifier: "x")
        #expect(guest.displayName == "a-very-long-container-name-indeed")
    }

    /// UTM, against the shape MEASURED on this Mac's own `BIGIP-21.1.0.1.utm`:
    /// `Information.Name`, `Information.UUID` and `Network[].MacAddress`.
    ///
    /// The name comes from the CONFIG, not the bundle's filename: renaming a `.utm`
    /// bundle in Finder does not rename the machine.
    @Test func utmNamesAndHardwareAddressesComeFromTheConfigNotTheFilename() throws {
        var mac = FakeRecords()
        mac.directories[utmRoot] = ["renamed-in-finder.utm"]
        mac.utm["\(utmRoot)/renamed-in-finder.utm/config.plist"] = UTMNetworkConfig(
            mode: "Bridged", bridgeInterface: "en0",
            machineName: "BIGIP-21.1.0.1",
            machineUUID: "5EF697AB-1A55-41A2-89C6-B15609691753",
            macAddresses: [utmMAC])
        let guest = try #require(GuestInventory.utmNamedGuests(env: mac.environment).first)
        #expect(guest.name == "BIGIP-21.1.0.1")
        #expect(guest.identifier == "5EF697AB-1A55-41A2-89C6-B15609691753")
        #expect(guest.recordedMode == .bridged)
        // Parsed on the way in, so what reaches the comparison is a value and not a
        // spelling — see `MACAddressTests`.
        #expect(guest.recordedMACs == [utmMAC])
    }

    /// A product nobody has installed is never searched for — the same gate every
    /// other reader in this file honours.
    @Test func aProductThatIsNotInstalledIsNotRead() {
        var mac = FakeRecords()
        mac.directories[containersRoot] = ["postgres"]
        mac.containers["\(containersRoot)/postgres/config.json"] = ContainerRecord(id: "postgres")
        #expect(GuestInventory.guests(env: mac.environment, installed: []).isEmpty)
        let installed = [InstalledVirtualization(
            productID: "apple-container", title: "Apple Containers (container)",
            networking: .routedSubnet)]
        #expect(GuestInventory.guests(env: mac.environment, installed: installed).count == 1)
    }
}

// MARK: - The spellings of a hardware address

/// THE BUG THAT WOULD HAVE MADE EVERY ATTACHMENT FAIL SILENTLY was a string
/// comparison: `netstat` prints octets without leading zeros in lower case
/// (`42:0:5c:85:fa:1a` — measured on this Mac) and UTM records `EA:85:74:8B:18:97`,
/// zero-padded and upper case, so compared raw they never match and the symptom is
/// "names are never attached" rather than a crash.
///
/// **That lives in `MACAddressTests` now**, together with the source scans that fail
/// if a hardware address is declared as a `String` again. What is left here is the
/// half that belongs to this file: that each product's own spelling is parsed at the
/// boundary where its file is read.
struct HardwareAddressSpellingTests {

    /// VirtualBox and Parallels write it with no separators at all. That used to need
    /// a second normaliser, which is how the two disagreed about what was legal.
    @Test func theUnseparatedSpellingIsTheSameAddress() {
        #expect(MACAddress("0800271A2B3C") == MACAddress("08:00:27:1a:2b:3c"))
    }
}

// MARK: - Attaching a name to a network, and refusing to

struct GuestPlacementTests {

    private func network(_ iface: String, subnet: String,
                         taps: [String] = ["vmenet0"]) -> GuestNetwork {
        GuestNetwork(interfaceName: iface, hostAddress: "192.168.64.1", subnet: subnet,
                     attachedGuestInterfaces: taps, mode: .shared)
    }

    private func utmGuest(_ name: String, mac text: String) -> NamedGuest {
        NamedGuest(name: name, productID: "utm", recordedMACs: [macs(text)],
                   identifier: name)
    }

    private func containerGuest(_ name: String, network: String?) -> NamedGuest {
        NamedGuest(name: name, productID: "apple-container", recordedNetwork: network,
                   identifier: name)
    }

    /// EVIDENCE 1 — a recorded address, seen on that interface right now. This is
    /// proof rather than deduction, and the evidence sentence has to say which address
    /// and which interface, because that is what makes it checkable.
    @Test func aRecordedAddressSeenOnAnInterfaceAttachesTheGuestToIt() throws {
        let placed = GuestInventory.place(
            [utmGuest("lab", mac: "ea:85:74:8b:18:97")],
            neighbours: ["bridge100": [macs("ea:85:74:8b:18:97")], "en0": [macs("aa:bb:cc:dd:ee:ff")]],
            guestNetworks: [network("bridge100", subnet: "192.168.64.0/24")],
            recordedNetworkNames: [])
        let one = try #require(placed.first)
        #expect(one.attachment.interfaceName == "bridge100")
        #expect(one.attachment.evidence.contains("ea:85:74:8b:18:97"))
        #expect(one.attachment.evidence.contains("bridge100"))
    }

    /// AND THE SAME RULE CORRECTLY PUTS A BRIDGED GUEST ON THE LAN, not on a guest
    /// network. That is the answer that stops us claiming a VPN here affects it — the
    /// placement and the arrangement have to agree, and this is why the address is
    /// tried before anything else.
    @Test func aBridgedGuestIsAttachedToThePhysicalInterfaceItIsReallyOn() throws {
        let placed = GuestInventory.place(
            [utmGuest("lab", mac: "ea:85:74:8b:18:97")],
            neighbours: ["en0": [macs("ea:85:74:8b:18:97")]],
            guestNetworks: [network("bridge100", subnet: "192.168.64.0/24")],
            recordedNetworkNames: [])
        #expect(placed.first?.attachment.interfaceName == "en0")
        // …and that reads as "running on your network", never as "running here".
        let presence = try #require(placed.first).presence(guestInterfaces: ["bridge100", "vmenet0"])
        #expect(presence == .runningOnYourNetwork)
    }

    /// EVIDENCE 2 — a recorded network name, when there is exactly one network it
    /// could mean. Forced, not guessed.
    @Test func aRecordedNetworkNameAttachesWhenThereIsOnlyOneItCouldBe() throws {
        let placed = GuestInventory.place(
            [containerGuest("postgres", network: "default")],
            neighbours: [:],
            guestNetworks: [network("bridge100", subnet: "192.168.64.0/24")],
            recordedNetworkNames: ["default"])
        let one = try #require(placed.first)
        #expect(one.attachment.interfaceName == "bridge100")
        #expect(one.attachment.evidence.contains("default"))
        #expect(one.attachment.evidence.contains("only guest network"))
    }

    /// …AND REFUSES WHEN IT IS MERELY LIKELY. Two live guest networks and nothing on
    /// disk saying which is which: the guest is listed unattached, with the reason.
    /// Same discipline as `VirtualizationDiscovery.mode`, which answers `.unknown`
    /// rather than taking the first match.
    @Test func twoGuestNetworksMeanTheNameCannotBePlaced() throws {
        let placed = GuestInventory.place(
            [containerGuest("postgres", network: "default")],
            neighbours: [:],
            guestNetworks: [network("bridge100", subnet: "192.168.64.0/24"),
                            network("bridge101", subnet: "192.168.65.0/24")],
            recordedNetworkNames: ["default"])
        let one = try #require(placed.first)
        #expect(one.attachment.interfaceName == nil)
        #expect(one.attachment.evidence.contains("more than one"))
    }

    /// Two RECORDED networks is the other half of the same refusal: one bridge is
    /// live, but the products know of two networks, so which one became that bridge is
    /// not established.
    @Test func twoRecordedNetworksAlsoMeanTheNameCannotBePlaced() {
        let placed = GuestInventory.place(
            [containerGuest("postgres", network: "default")],
            neighbours: [:],
            guestNetworks: [network("bridge100", subnet: "192.168.64.0/24")],
            recordedNetworkNames: ["default", "lab"])
        #expect(placed.first?.attachment.interfaceName == nil)
    }

    /// A guest whose recorded address is nowhere on any network is NOT RUNNING, and
    /// says so in those words — never "offline", which belongs to connection state.
    @Test func aGuestWhoseAddressIsNowhereReadsAsNotRunning() throws {
        let placed = GuestInventory.place(
            [utmGuest("lab", mac: "ea:85:74:8b:18:97")],
            neighbours: ["en0": [macs("aa:bb:cc:dd:ee:ff")]],
            guestNetworks: [], recordedNetworkNames: [])
        let one = try #require(placed.first)
        #expect(one.attachment.interfaceName == nil)
        #expect(one.attachment.evidence.contains("does not appear to be running"))
        #expect(one.presence(guestInterfaces: []) == .notRunning)
    }

    /// A product that records nothing matchable gets its own sentence — it sends the
    /// reader somewhere different from "it is not running".
    @Test func aGuestWithNothingRecordedSaysThatRatherThanNotRunning() throws {
        let placed = GuestInventory.place(
            [NamedGuest(name: "mystery", productID: "parallels", identifier: "mystery")],
            neighbours: ["en0": [macs("aa:bb:cc:dd:ee:ff")]],
            guestNetworks: [network("bridge100", subnet: "192.168.64.0/24")],
            recordedNetworkNames: [])
        let one = try #require(placed.first)
        #expect(one.attachment.interfaceName == nil)
        #expect(one.attachment.evidence.contains("does not record"))
    }

    /// An address wins over a network name when both are available: it is proof, and
    /// the other is deduction.
    @Test func aRecordedAddressBeatsARecordedNetworkName() {
        var guest = containerGuest("postgres", network: "default")
        guest.recordedMACs = [macs("ea:85:74:8b:18:97")]
        let placed = GuestInventory.place(
            [guest], neighbours: ["en0": [macs("ea:85:74:8b:18:97")]],
            guestNetworks: [network("bridge100", subnet: "192.168.64.0/24")],
            recordedNetworkNames: ["default"])
        #expect(placed.first?.attachment.interfaceName == "en0")
    }
}

// MARK: - What the snapshot then hands the two surfaces

struct PlacedGuestSurfaceTests {

    private func snapshot(_ placed: [PlacedGuest],
                          networks: [GuestNetwork] = []) -> VirtualizationSnapshot {
        VirtualizationSnapshot(guestNetworks: networks, placedGuests: placed)
    }

    private func placed(_ name: String, on iface: String?) -> PlacedGuest {
        PlacedGuest(guest: NamedGuest(name: name, productID: "apple-container", identifier: name),
                    attachment: iface.map { .interface($0, evidence: "because") }
                        ?? .unattached(reason: "because not"))
    }

    /// Names on one interface, alphabetical, so the card, the chip and the inspector
    /// list them in the same order every refresh.
    @Test func namesOnANetworkComeBackInAStableOrder() {
        let snap = snapshot([placed("redis", on: "bridge100"),
                             placed("alpine", on: "bridge100"),
                             placed("elsewhere", on: "en0")])
        #expect(snap.guests(on: "bridge100").map(\.guest.displayName) == ["alpine", "redis"])
        #expect(snap.guests(on: "en0").map(\.guest.displayName) == ["elsewhere"])
    }

    /// The unattached list is what "Also on this Mac" shows — the honest alternative
    /// to guessing, and to hiding them.
    @Test func unattachedGuestsAreListedRatherThanDropped() {
        let snap = snapshot([placed("postgres", on: "bridge100"), placed("mystery", on: nil)])
        #expect(snap.unattachedGuests.map(\.guest.displayName) == ["mystery"])
    }

    /// THE TRAFFIC GRAPH'S ELIMINATION RULE. One tap on the network and one named
    /// guest on it: no other assignment is possible, so the series may carry the name.
    @Test func aSoleTapWithASoleNamedGuestIsAttributed() throws {
        let network = GuestNetwork(interfaceName: "bridge100", hostAddress: "192.168.64.1",
                                   subnet: "192.168.64.0/24",
                                   attachedGuestInterfaces: ["vmenet0"])
        let snap = snapshot([placed("postgres", on: "bridge100")], networks: [network])
        #expect(snap.guest(onTap: "vmenet0")?.guest.displayName == "postgres")
        #expect(snap.guestTaps == ["vmenet0"])
    }

    /// TWO TAPS AND THE RULE REFUSES. Nothing on disk records which `vmenet` a guest
    /// got, so with two of them the assignment is a coin toss — and a mislabelled
    /// throughput series is acted on exactly like a mislabelled routing card.
    @Test func twoTapsMeanNoTapIsAttributed() {
        let network = GuestNetwork(interfaceName: "bridge100", hostAddress: "192.168.64.1",
                                   subnet: "192.168.64.0/24",
                                   attachedGuestInterfaces: ["vmenet0", "vmenet1"])
        let snap = snapshot([placed("postgres", on: "bridge100")], networks: [network])
        #expect(snap.guest(onTap: "vmenet0") == nil)
        #expect(snap.guest(onTap: "vmenet1") == nil)
    }

    /// Two named guests on one tap is impossible, so the rule refuses there too rather
    /// than picking the first.
    @Test func twoNamedGuestsMeanTheSoleTapIsStillNotAttributed() {
        let network = GuestNetwork(interfaceName: "bridge100", hostAddress: "192.168.64.1",
                                   subnet: "192.168.64.0/24",
                                   attachedGuestInterfaces: ["vmenet0"])
        let snap = snapshot([placed("postgres", on: "bridge100"),
                             placed("redis", on: "bridge100")], networks: [network])
        #expect(snap.guest(onTap: "vmenet0") == nil)
    }
}
