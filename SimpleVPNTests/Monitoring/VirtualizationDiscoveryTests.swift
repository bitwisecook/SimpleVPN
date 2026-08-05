// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VirtualizationDiscoveryTests.swift
//  The one thing these tests exist to protect is the A/B DISTINCTION. A
//  "detect the subnet and exclude it" feature that ignored it would look like it
//  worked, do nothing whatever for a Docker Desktop user, and leave us
//  confidently wrong — so the assertions below are mostly about refusing to offer
//  a routing fix where routing cannot help.
//
//  The fixtures are shaped from a REAL machine, measured live rather than
//  imagined: Apple's `container` 1.0.0 running an Alpine guest behind an active
//  Tailscale tunnel produced `vmenet0` with no IPv4 address at all and
//  `bridge100` holding `192.168.64.1/24`. Both traps in `guestNetworks` come from
//  that measurement, and each has a test named after it.
//

import Testing
import Foundation
@testable import SimpleVPN

// MARK: - A machine we can synthesise entirely

/// A fake Mac. Every path answer is explicit, so a result never depends on what
/// happens to be installed on the machine running the test — including the two
/// products that really ARE installed on the author's.
private struct FakeMac {
    var home = URL(fileURLWithPath: "/Users/fixture")
    var present: Set<String> = []
    var directories: [String: [String]] = [:]
    var networks: [String: UTMNetworkConfig] = [:]

    var environment: VirtualizationEnvironment {
        VirtualizationEnvironment(
            home: home,
            fileExists: { [present] in present.contains($0) },
            applicationDirectories: ["/Applications"],
            listDirectory: { [directories] in directories[$0] ?? [] },
            readUTMNetwork: { [networks] in networks[$0] })
    }
}

private func interface(_ name: String,
                       kind: NetInterface.Kind,
                       ipv4: [String] = [],
                       subnets: [String] = []) -> NetInterface {
    var out = NetInterface(name: name, kind: kind, displayName: name)
    out.ipv4 = ipv4
    out.ipv4Subnets = subnets
    out.isUp = true
    return out
}

// MARK: - The classification, which is the whole point

struct GuestNetworkClassTests {

    @Test func routingOnlyClaimsToHelpWhereThereIsASubnetToExclude() {
        #expect(GuestNetworkClass.routedSubnet.routingExclusionCanHelp)
        #expect(GuestNetworkClass.perGuest.routingExclusionCanHelp)
        // THE assertion this file exists for.
        #expect(GuestNetworkClass.userspace.routingExclusionCanHelp == false)
    }

    /// A userspace product's remedy must not mention excluding anything, and must
    /// name what actually works. Someone reading "keep its network out of the
    /// tunnel" for Docker Desktop is being sent to a checkbox that cannot work.
    @Test func theUserspaceRemedyNamesMTUAndDNSAndNeverAnExclusion() {
        let words = GuestNetworkClass.userspace.remedyWords
        #expect(words.localizedCaseInsensitiveContains("MTU"))
        #expect(words.localizedCaseInsensitiveContains("DNS")
                || words.localizedCaseInsensitiveContains("resolver"))
        #expect(words.localizedCaseInsensitiveContains("cannot help"))
    }

    @Test func everyClassHasItsOwnSentenceInBothVoices() {
        var titles = Set<String>()
        var remedies = Set<String>()
        for value in GuestNetworkClass.allCases {
            #expect(!value.title.isEmpty)
            #expect(!value.remedyWords.isEmpty)
            #expect(titles.insert(value.title).inserted)
            #expect(remedies.insert(value.remedyWords).inserted)
        }
    }

    /// Docker Desktop and QEMU are the reason the `.userspace` case exists. If
    /// either is ever reclassified as `.routedSubnet`, this feature starts telling
    /// people to exclude a subnet that does not exist.
    @Test func dockerIsUserspaceAndAppleContainerIsARoutedSubnet() throws {
        let docker = try #require(VirtualizationCatalog.product(id: "docker-desktop"))
        #expect(docker.networking == .userspace)
        #expect(docker.interfacePrefixes.isEmpty)   // it creates none, by design

        let container = try #require(VirtualizationCatalog.product(id: "apple-container"))
        #expect(container.networking == .routedSubnet)
        #expect(container.documentedSubnets.contains("192.168.64.0/24"))
    }

    @Test func utmIsPerGuestBecauseInstalledCannotDecideIt() throws {
        let utm = try #require(VirtualizationCatalog.product(id: "utm"))
        #expect(utm.networking == .perGuest)
    }

    @Test func catalogIDsAreUniqueAndStable() {
        var seen = Set<String>()
        for product in VirtualizationCatalog.all {
            #expect(seen.insert(product.id).inserted, "duplicate product id \(product.id)")
            #expect(!product.title.isEmpty)
        }
    }

    /// Only what someone has actually run may claim to have been verified. The doc
    /// makes this claim in public, so the code has to agree with it.
    @Test func onlyTheTwoProductsRunHereClaimVerification() {
        let verified = Set(VirtualizationCatalog.all.filter(\.verifiedLocally).map(\.id))
        #expect(verified == ["apple-container", "utm"])
    }
}

// MARK: - UTM, where the class is a per-machine fact

struct UTMGuestClassTests {

    @Test func emulatedIsUserspaceAndTheOthersAreSubnets() {
        #expect(UTMGuest(name: "a", mode: "Emulated", bridgeInterface: nil).networking == .userspace)
        #expect(UTMGuest(name: "a", mode: "Shared", bridgeInterface: nil).networking == .routedSubnet)
        #expect(UTMGuest(name: "a", mode: "Bridged", bridgeInterface: "en0").networking == .routedSubnet)
        #expect(UTMGuest(name: "a", mode: "Host", bridgeInterface: nil).networking == .routedSubnet)
    }

    /// An unrecognised mode must not be guessed into a class that would produce a
    /// routing offer.
    @Test func anUnknownModeStaysUndecided() {
        #expect(UTMGuest(name: "a", mode: "Something New", bridgeInterface: nil).networking == .perGuest)
    }

    /// Read from the shape of a REAL UTM config.plist, quoted from the machine this
    /// was written on (`Mode = Bridged`, `BridgeInterface = en0`).
    @Test func aVirtualMachinesModeIsReadFromItsOwnConfig() throws {
        var mac = FakeMac()
        let root = "/Users/fixture/Library/Containers/com.utmapp.UTM/Data/Documents"
        mac.directories[root] = ["BIGIP-21.1.0.1.utm", "Public", "notes.txt"]
        mac.networks[root + "/BIGIP-21.1.0.1.utm/config.plist"] =
            UTMNetworkConfig(mode: "Bridged", bridgeInterface: "en0")

        let guests = VirtualizationDiscovery.utmGuests(env: mac.environment)
        #expect(guests.count == 1)                 // "Public" and a stray file ignored
        let guest = try #require(guests.first)
        #expect(guest.name == "BIGIP-21.1.0.1")
        #expect(guest.mode == "Bridged")
        #expect(guest.bridgeInterface == "en0")
        #expect(guest.networking == .routedSubnet)
    }

    @Test func anEmulatedVirtualMachineIsReportedAsUserspace() throws {
        var mac = FakeMac()
        let root = "/Users/fixture/Library/Containers/com.utmapp.UTM/Data/Documents"
        mac.directories[root] = ["Old Linux.utm"]
        mac.networks[root + "/Old Linux.utm/config.plist"] =
            UTMNetworkConfig(mode: "Emulated", bridgeInterface: nil)
        let guest = try #require(VirtualizationDiscovery.utmGuests(env: mac.environment).first)
        #expect(guest.networking == .userspace)
        #expect(guest.networking.routingExclusionCanHelp == false)
    }
}

// MARK: - Installed, from the filesystem alone

struct VirtualizationInstalledTests {

    @Test func nothingInstalledIsAnEmptyAnswerRatherThanAGuess() {
        #expect(VirtualizationDiscovery.installed(env: FakeMac().environment).isEmpty)
    }

    @Test func aCLIPathAndAnAppBundleAreBothEvidence() throws {
        var mac = FakeMac()
        mac.present = ["/usr/local/bin/container", "/Applications/UTM.app"]

        let found = VirtualizationDiscovery.installed(env: mac.environment)
        let ids = Set(found.map(\.productID))
        #expect(ids == ["apple-container", "utm"])

        let container = try #require(found.first { $0.productID == "apple-container" })
        #expect(container.evidence.contains("/usr/local/bin/container"))
        #expect(container.networking == .routedSubnet)

        let utm = try #require(found.first { $0.productID == "utm" })
        #expect(utm.evidence.contains("/Applications/UTM.app"))
    }

    /// A support directory alone is evidence, because a CLI installed through a
    /// version manager may sit somewhere this map does not list — the same honesty
    /// `Docs/ToolDiscovery.md` requires of the password-manager map.
    @Test func aSupportDirectoryCountsAndIsNamedInTheEvidence() throws {
        var mac = FakeMac()
        mac.present = ["/Users/fixture/.docker"]
        let found = try #require(VirtualizationDiscovery.installed(env: mac.environment).first)
        #expect(found.productID == "docker-desktop")
        #expect(found.evidence == ["/Users/fixture/.docker"])
        #expect(found.networking == .userspace)
    }
}

// MARK: - The live guest networks, and the two traps

struct GuestNetworkDetectionTests {

    /// TRAP 1. Apple's vmnet gives the guest tap NO IPv4 address; the subnet is on
    /// the bridge. Reading the network off `vmenet0` finds nothing and concludes
    /// there is no VM network — which is what a plausible implementation does.
    ///
    /// This fixture is exactly what a real machine reported.
    @Test func theSubnetIsReadFromTheBridgeNotFromTheAddresslessTap() throws {
        let interfaces = [
            interface("vmenet0", kind: .virtualMachine),                       // no address at all
            interface("bridge100", kind: .bridge,
                      ipv4: ["192.168.64.1"], subnets: ["192.168.64.0/24"]),
        ]
        let installed = VirtualizationDiscovery.installed(
            env: { var m = FakeMac(); m.present = ["/usr/local/bin/container"]; return m }().environment)

        let networks = VirtualizationDiscovery.guestNetworks(
            interfaces: interfaces, installed: installed)

        #expect(networks.count == 1)
        let network = try #require(networks.first)
        #expect(network.subnet == "192.168.64.0/24")
        #expect(network.hostAddress == "192.168.64.1")
        #expect(network.interfaceName == "bridge100")
        // The tap is what proves a guest is actually attached.
        #expect(network.attachedGuestInterfaces == ["vmenet0"])
        // Apple's vmnet is a shared stack, so no single product may be NAMED as the
        // owner — it may be the container CLI, UTM's Apple backend, or anything else
        // on Virtualization.framework.
        #expect(network.productID == nil)
        #expect(network.candidateProductIDs.contains("apple-container"))
    }

    /// TRAP 2. `bridge0` is the ordinary user-configurable Thunderbolt/Ethernet
    /// bridge that exists on stock macOS. Treating it as a guest network would
    /// invite someone to route their REAL LAN around their VPN, which is a security
    /// consequence rather than a cosmetic bug.
    @Test func bridge0IsNeverAGuestNetworkEvenWithAnAddress() {
        let interfaces = [
            interface("bridge0", kind: .bridge,
                      ipv4: ["192.168.9.88"], subnets: ["192.168.9.0/24"]),
        ]
        let networks = VirtualizationDiscovery.guestNetworks(interfaces: interfaces, installed: [])
        #expect(networks.isEmpty)
    }

    /// Wi-Fi, Ethernet and the VPN's own utun must never be offered as things to
    /// route around the VPN.
    @Test func ordinaryInterfacesAreNotGuestNetworks() {
        let interfaces = [
            interface("en0", kind: .wifi, ipv4: ["192.168.9.88"], subnets: ["192.168.9.0/24"]),
            interface("utun4", kind: .tunnel, ipv4: ["100.116.119.124"],
                      subnets: ["100.116.119.124/32"]),
            interface("lo0", kind: .other, ipv4: ["127.0.0.1"], subnets: ["127.0.0.0/8"]),
        ]
        #expect(VirtualizationDiscovery.guestNetworks(interfaces: interfaces, installed: []).isEmpty)
    }

    /// VMware's `vmnet8` and Apple's `vmenet0` differ by one letter and belong to
    /// different products. Attributing a VMware network to Apple's stack would put
    /// the wrong product name in a bug report.
    @Test func vmwareAndAppleVMNetAreNotConfused() throws {
        let vmware = try #require(VirtualizationDiscovery.attribute(interfaceName: "vmnet8"))
        #expect(vmware.productID == "vmware-fusion")
        #expect(vmware.isAppleVMNet == false)

        let apple = try #require(VirtualizationDiscovery.attribute(interfaceName: "bridge100"))
        #expect(apple.productID == nil)
        #expect(apple.isAppleVMNet)

        #expect(VirtualizationDiscovery.attribute(interfaceName: "vmenet0") == nil,
                "the tap carries no subnet, so it must not be attributed as a network")
    }

    @Test func parallelsAndVirtualBoxAdaptersAreAttributedDirectly() throws {
        let interfaces = [
            interface("vnic0", kind: .virtualMachine,
                      ipv4: ["10.211.55.2"], subnets: ["10.211.55.0/24"]),
            interface("vboxnet0", kind: .virtualMachine,
                      ipv4: ["192.168.56.1"], subnets: ["192.168.56.0/24"]),
        ]
        let networks = VirtualizationDiscovery.guestNetworks(interfaces: interfaces, installed: [])
        #expect(networks.count == 2)
        #expect(networks.first { $0.interfaceName == "vnic0" }?.productID == "parallels")
        #expect(networks.first { $0.interfaceName == "vboxnet0" }?.productID == "virtualbox")
    }

    /// A bridge with no mask recorded yields no subnet rather than a guessed one. An
    /// exclusion built from a bare address would be the wrong prefix.
    @Test func anInterfaceWithNoRecordedSubnetIsSkipped() {
        let interfaces = [
            interface("bridge100", kind: .bridge, ipv4: ["192.168.64.1"], subnets: [""]),
        ]
        #expect(VirtualizationDiscovery.guestNetworks(interfaces: interfaces, installed: []).isEmpty)
    }
}

// MARK: - The snapshot, and what an empty one means

struct VirtualizationSnapshotTests {

    @Test func detectionOffSaysSoRatherThanLookingEmpty() {
        var mac = FakeMac()
        mac.present = ["/usr/local/bin/container"]
        let snapshot = VirtualizationDiscovery.snapshot(
            interfaces: [interface("bridge100", kind: .bridge,
                                   ipv4: ["192.168.64.1"], subnets: ["192.168.64.0/24"])],
            detectionEnabled: false, env: mac.environment)

        #expect(snapshot.detectionEnabled == false)
        #expect(snapshot.isEmpty)
        #expect(snapshot.excludableSubnets.isEmpty)
    }

    /// A machine with only class-B software has NOTHING to exclude, and that empty
    /// list is the correct answer rather than a detection failure.
    @Test func aDockerOnlyMachineOffersNoSubnetsButIsStillReported() throws {
        var mac = FakeMac()
        mac.present = ["/usr/local/bin/docker", "/Applications/Docker.app"]

        let snapshot = VirtualizationDiscovery.snapshot(
            interfaces: [interface("en0", kind: .wifi,
                                   ipv4: ["192.168.9.88"], subnets: ["192.168.9.0/24"])],
            detectionEnabled: true, env: mac.environment)

        #expect(snapshot.excludableSubnets.isEmpty)
        #expect(snapshot.installed.count == 1)
        #expect(snapshot.userspaceOnlyProducts.map(\.productID) == ["docker-desktop"])
        // And it is NOT reported as "nothing found" — the product is known, it simply
        // cannot be helped by routing.
        #expect(!snapshot.isEmpty)
    }

    @Test func duplicateSubnetsAreOfferedOnce() {
        let interfaces = [
            interface("bridge100", kind: .bridge,
                      ipv4: ["192.168.64.1"], subnets: ["192.168.64.0/24"]),
            interface("bridge101", kind: .bridge,
                      ipv4: ["192.168.64.1"], subnets: ["192.168.64.0/24"]),
        ]
        let snapshot = VirtualizationSnapshot(
            guestNetworks: VirtualizationDiscovery.guestNetworks(
                interfaces: interfaces, installed: []))
        #expect(snapshot.excludableSubnets == ["192.168.64.0/24"])
    }

    @Test func aGuestNetworkWithNoAttributionStillReadsAsASentence() {
        let network = GuestNetwork(interfaceName: "bridge100", hostAddress: "192.168.64.1",
                                   subnet: "192.168.64.0/24")
        #expect(network.attribution == "a virtual machine or container")
    }

    @Test func severalCandidatesAreNamedRatherThanOneBeingPicked() {
        let network = GuestNetwork(interfaceName: "bridge100", hostAddress: "192.168.64.1",
                                   subnet: "192.168.64.0/24",
                                   candidateProductIDs: ["apple-container", "utm"])
        #expect(network.attribution.contains("Apple Containers"))
        #expect(network.attribution.contains("UTM"))
    }
}

// MARK: - Subnet arithmetic (an exclusion is only as good as its prefix)

struct InterfaceSubnetMathTests {

    @Test func aNetmaskBecomesAPrefixLength() {
        // `.bigEndian` because `ifa_netmask` hands us network byte order, which is
        // what the function is written to take.
        #expect(TopologyMonitor.prefixLength(mask: UInt32(0xFFFFFF00).bigEndian) == 24)
        #expect(TopologyMonitor.prefixLength(mask: UInt32(0xFFFF0000).bigEndian) == 16)
        #expect(TopologyMonitor.prefixLength(mask: UInt32(0xFFFFFFFF).bigEndian) == 32)
        #expect(TopologyMonitor.prefixLength(mask: UInt32(0xFFFFF800).bigEndian) == 21)
        #expect(TopologyMonitor.prefixLength(mask: 0) == 0)
    }

    /// A non-contiguous mask is refused rather than summarised into a prefix that
    /// would silently mean something else.
    @Test func aNonContiguousMaskIsRefused() {
        #expect(TopologyMonitor.prefixLength(mask: UInt32(0xFF00FF00).bigEndian) == nil)
    }

    /// THE arithmetic an exclusion depends on: the host bits must be cleared.
    /// `192.168.64.1/24` is not a network, and excluding it would carve out the host
    /// end while leaving every guest captured.
    @Test func theNetworkAddressHasItsHostBitsCleared() {
        #expect(TopologyMonitor.networkCIDR(address: "192.168.64.1", prefix: 24) == "192.168.64.0/24")
        #expect(TopologyMonitor.networkCIDR(address: "10.211.55.2", prefix: 24) == "10.211.55.0/24")
        #expect(TopologyMonitor.networkCIDR(address: "198.19.249.7", prefix: 21) == "198.19.248.0/21")
        #expect(TopologyMonitor.networkCIDR(address: "192.168.9.88", prefix: 16) == "192.168.0.0/16")
        #expect(TopologyMonitor.networkCIDR(address: "100.116.119.124", prefix: 32)
                == "100.116.119.124/32")
    }

    @Test func nonsenseIsRefusedRatherThanCoerced() {
        #expect(TopologyMonitor.networkCIDR(address: "not an address", prefix: 24) == nil)
        #expect(TopologyMonitor.networkCIDR(address: "192.168.64.1", prefix: 33) == nil)
        #expect(TopologyMonitor.networkCIDR(address: "192.168.64.1", prefix: -1) == nil)
    }
}

// MARK: - What the diagnostic report says

struct VirtualizationReportTests {

    /// The report must state, in the report itself, that routing cannot help a
    /// class-B product. Otherwise the first day of debugging goes on excluded
    /// routes that were never going to do anything.
    @Test func theReportSaysRoutingCannotHelpAUserspaceProduct() {
        let words = DiagnosticReportInventory.classWords(.userspace)
        #expect(words.localizedCaseInsensitiveContains("cannot help"))
        #expect(words.localizedCaseInsensitiveContains("MTU"))
    }

    @Test func everyClassHasItsOwnReportSentence() {
        var seen = Set<String>()
        for value in GuestNetworkClass.allCases {
            let words = DiagnosticReportInventory.classWords(value)
            #expect(!words.isEmpty)
            #expect(seen.insert(words).inserted)
        }
    }

    @Test func detectionBeingOffIsSaidRatherThanImplied() throws {
        let fields = DiagnosticReportInventory.virtualizationFields(
            snapshot: VirtualizationSnapshot(detectionEnabled: false))
        let field = try #require(fields.first)
        #expect(field.value == .flag(false))
        #expect(fields.count == 1)
    }

    @Test func anUnverifiedProductSaysNobodyHasRunIt() throws {
        let snapshot = VirtualizationSnapshot(installed: [
            InstalledVirtualization(productID: "virtualbox", title: "VirtualBox",
                                    networking: .routedSubnet, evidence: ["/Applications/VirtualBox.app"],
                                    verifiedLocally: false),
        ])
        let fields = DiagnosticReportInventory.virtualizationFields(snapshot: snapshot)
        #expect(fields.flatMap(\.detail).contains { value in
            if case .words(let text) = value { return text.contains("reasoned from the vendor") }
            return false
        })
    }

    /// No guest running is the expected state most of the time, and it must not read
    /// as "detection is broken".
    @Test func noLiveNetworkExplainsWhyRatherThanLookingLikeAFailure() throws {
        let snapshot = VirtualizationSnapshot(installed: [
            InstalledVirtualization(productID: "apple-container",
                                    title: "Apple Containers (container)",
                                    networking: .routedSubnet,
                                    evidence: ["/usr/local/bin/container"],
                                    verifiedLocally: true),
        ])
        let fields = DiagnosticReportInventory.virtualizationFields(snapshot: snapshot)
        let live = try #require(fields.first { $0.label == "Live guest networks" })
        if case .words(let text) = live.value {
            #expect(text.contains("none"))
        } else {
            Issue.record("expected words, got \(live.value)")
        }
        #expect(live.detail.contains { value in
            if case .words(let text) = value { return text.contains("assigned when a guest boots") }
            return false
        })
    }

    @Test func aLiveNetworkReportsItsSubnetAsThePayload() throws {
        let snapshot = VirtualizationSnapshot(guestNetworks: [
            GuestNetwork(interfaceName: "bridge100", hostAddress: "192.168.64.1",
                         subnet: "192.168.64.0/24",
                         candidateProductIDs: ["apple-container"],
                         attachedGuestInterfaces: ["vmenet0"]),
        ])
        let fields = DiagnosticReportInventory.virtualizationFields(snapshot: snapshot)
        let field = try #require(fields.first { $0.label.contains("bridge100") })
        #expect(field.value == .path("192.168.64.0/24"))
    }
}

// MARK: - The settings, and their defaults

@MainActor
struct VirtualizationSettingsTests {

    /// A `UserDefaults` nobody has written must read as ON. `bool(forKey:)` alone
    /// reads as false, which would silently disable a feature no one turned off.
    @Test func anUntouchedDefaultsReadsAsOn() throws {
        let suite = "vm.tests.\(UUID().uuidString)"
        let store = try #require(UserDefaults(suiteName: suite))
        defer { store.removePersistentDomain(forName: suite) }
        #expect(VirtualizationSettings.isEnabled(VirtualizationSettings.detectDefaultsKey, store: store))
        store.set(false, forKey: VirtualizationSettings.detectDefaultsKey)
        #expect(VirtualizationSettings.isEnabled(VirtualizationSettings.detectDefaultsKey,
                                                 store: store) == false)
    }

    /// The defaults keys and the setting ids must be the same strings: the id is the
    /// CLI/MDM/manual-anchor contract, and a second spelling is a setting the CLI
    /// cannot address.
    @Test func theDefaultsKeysAreTheSettingIDs() {
        #expect(VirtualizationSettings.detectDefaultsKey == VirtualizationSettings.detect.id)
        #expect(VirtualizationSettings.warnOnConnectDefaultsKey
                == VirtualizationSettings.warnOnConnect.id)
    }

    @Test func theSurfaceOwnsItsNamespace() {
        #expect(SettingSurface.owning("vm.detect") == .virtualization)
        #expect(SettingSurface.owning("vm.warn-on-connect") == .virtualization)
        #expect(SettingSurface.virtualization.isAppLevel)
        // App-level, so it belongs to no VPN kind — that is what stops a global search
        // hit being routed into an editor with no such row.
        #expect(SettingSurface.virtualization.kinds.isEmpty)
    }

    @Test func bothSettingsAreNamedSummarisedAndGrouped() {
        for spec in VirtualizationSettings.all {
            #expect(spec.id.hasPrefix("vm."))
            #expect(!spec.name.isEmpty)
            #expect(!spec.summary.isEmpty)
            #expect(spec.group != nil)
            #expect(!spec.manualAnchor.contains("."))
        }
    }
}
