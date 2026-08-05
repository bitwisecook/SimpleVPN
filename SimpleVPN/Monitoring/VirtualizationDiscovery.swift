// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VirtualizationDiscovery.swift
//  Which virtual machines and containers this Mac can run, which of their
//  networks are LIVE right now, and — the part that decides whether this feature
//  does anything at all — whether excluding a subnet from a tunnel could possibly
//  help them.
//
//  THE DISTINCTION THIS FILE EXISTS FOR. There are two ways a macOS
//  virtualization product puts a guest on the network, and they need OPPOSITE
//  fixes:
//
//   • `.routedSubnet` — a real host interface with a guest subnet behind it
//     (Apple's vmnet, VMware's `vmnet1`/`vmnet8`, Parallels' `vnic0`,
//     VirtualBox's `vboxnet0`, host-only and bridged modes generally). A tunnel
//     that captures or blackholes that subnet breaks the guest, and an excluded
//     route is exactly the fix.
//
//   • `.userspace` — no host interface at all. Docker Desktop's vpnkit/gVisor
//     proxy and QEMU's slirp translate guest traffic in a user process, so it
//     leaves as ORDINARY HOST APPLICATION TRAFFIC. There is no subnet to
//     exclude, and a routing exclusion would do NOTHING. The real failure modes
//     are MTU and DNS.
//
//  A "detect the subnet and exclude it" feature that skipped this distinction
//  would look like it worked, fix nothing whatever for Docker users, and leave us
//  confidently wrong. So detection CLASSIFIES, and the UI must never offer a
//  routing fix to a `.userspace` product.
//
//  `.perGuest` is the honest third answer rather than a fudge: UTM and plain QEMU
//  support both, chosen per virtual machine. "UTM is installed" therefore does not
//  determine the class — the VM's own config does, which is why `utmGuests` reads
//  it.
//
//  RULES, taken from `Docs/ToolDiscovery.md` and binding here for the same
//  reasons:
//
//   1. FILESYSTEM AND `getifaddrs` ONLY. Nothing is executed — not `container
//      network list`, not `docker inspect`, not `ifconfig`, not a `--version`.
//      Asking a virtualization daemon a question means starting it, and running a
//      binary we just found on disk to describe it is precisely what the
//      execution allow-list exists to prevent. No privileged call either: every
//      fact below comes from a `stat`, a plist read, or the interface list any
//      process may read.
//   2. LOCAL. No network, nothing written, no daemon woken. It is therefore on by
//      default (`vm.detect`) — a detection feature that defaults to not detecting is
//      inert.
//   3. NOT ENTIRELY SILENT, and the earlier claim that it was has been corrected here
//      because it was wrong. `utmGuests` enumerates
//      `~/Library/Containers/com.utmapp.UTM/Data/Documents` — ANOTHER APPLICATION'S
//      SANDBOX CONTAINER — and macOS gates that behind a consent check. Measured
//      consequence: with the check unanswered, `open` does not fail, it BLOCKS
//      indefinitely, and the first time this feature was actually wired the whole app
//      froze on it. Hence `snapshotOffMain`: off the main thread AND on a deadline, with
//      the guest-network half (`getifaddrs` only, which is what the connect-time warning
//      needs) computed before any filesystem call so it survives the timeout.
//
//  WHAT IS NOT KNOWABLE WHILE NOTHING IS RUNNING, and it is not a gap to paper
//  over: a guest subnet is assigned when a guest BOOTS. With no VM running there
//  is no `vmenet0`, no `bridge100`, and Apple's own on-disk network record
//  (`~/Library/Application Support/com.apple.container/networks/default/entity.json`)
//  contains `"mode":"nat"` and NO subnet — measured, not assumed. So "installed"
//  and "running on 192.168.64.0/24" are two genuinely different questions and
//  `VirtualizationSnapshot` carries both, separately.
//

import Foundation

// MARK: - How a product puts its guests on the network

/// The mechanism a product uses, and therefore whether a routing exclusion can
/// help it. This is the type the whole feature turns on.
nonisolated enum GuestNetworkClass: String, Sendable, CaseIterable, Equatable {
    /// A host interface with a routed guest subnet. Excluding the subnet works.
    case routedSubnet
    /// Userspace translation, no host interface. Excluding a subnet does nothing.
    case userspace
    /// The product does both, decided per virtual machine.
    case perGuest

    /// Plain language, no jargon — this wording reaches the diagnostic report and
    /// the settings copy, so it has to read as a sentence to someone who has never
    /// heard of slirp.
    var title: String {
        switch self {
        case .routedSubnet: "its guests sit on their own network behind this Mac"
        case .userspace: "its guests have no network of their own \u{2014} their traffic leaves as this Mac\u{2019}s"
        case .perGuest: "either, depending on how each virtual machine is set up"
        }
    }

    /// Could keeping a subnet out of the tunnel possibly help? The UI must not
    /// offer a routing fix where this is false.
    var routingExclusionCanHelp: Bool {
        switch self {
        case .routedSubnet: true
        case .userspace: false
        case .perGuest: true    // for the guests that are on a subnet
        }
    }

    /// What actually fixes it. For `.userspace` this is the whole answer, and
    /// saying "exclude the subnet" there would be a lie.
    var remedyWords: String {
        switch self {
        case .routedSubnet:
            "Keep the guest network out of the tunnel \u{2014} add its subnet to this VPN\u{2019}s "
            + "kept-direct routes."
        case .userspace:
            "There is no subnet to keep out, so routing settings cannot help. Lower the guest\u{2019}s "
            + "MTU to at or below the tunnel\u{2019}s, and point the guest at a resolver it can reach."
        case .perGuest:
            "Depends on the virtual machine: one on its own network needs its subnet kept out of the "
            + "tunnel, one using emulated networking needs the MTU and DNS answers instead."
        }
    }
}

// MARK: - One product

/// A virtualization product worth looking for. Declarative: adding one is a row
/// in `VirtualizationCatalog.all` and it appears in detection, the diagnostic
/// report and the docs with no new branch anywhere.
nonisolated struct VirtualizationProduct: Sendable, Equatable, Identifiable {
    /// Stable id. Reaches the diagnostic report, so it never changes.
    var id: String
    /// What to call it in a sentence.
    var title: String
    /// How it networks its guests — the A/B answer.
    var networking: GuestNetworkClass
    /// Bundle names on disk, e.g. `UTM.app`. Searched as plain `stat`s inside the
    /// application directories.
    ///
    /// Detection is by NAME rather than by bundle identifier on purpose: this file
    /// lives in `Monitoring/`, which the house rule keeps free of AppKit, and
    /// `NSWorkspace.urlForApplication(withBundleIdentifier:)` is AppKit. A
    /// filesystem check is also the cheaper and quieter answer — it consults no
    /// Launch Services database.
    var appBundleNames: [String] = []
    /// Bundle identifiers, used ONLY by the diagnostic report to read a version
    /// out of an `Info.plist`. Not a detection path here.
    var bundleIDs: [String] = []
    /// Absolute paths a vendor's own installer documents for its CLI. Searched as
    /// plain `stat`s; never executed.
    var cliPaths: [String] = []
    /// Paths under the user's home that only exist once the product has been set
    /// up. Relative to `home`.
    var homeRelativePaths: [String] = []
    /// Host interface name prefixes this product creates. The attribution seam
    /// for a LIVE network.
    var interfacePrefixes: [String] = []
    /// Subnets the vendor documents, for recognising a network we cannot
    /// otherwise attribute. Never used as a substitute for reading the live
    /// interface — a documented default is not what a machine is actually using.
    var documentedSubnets: [String] = []
    /// True only where SimpleVPN's own maintainers have run this product against a
    /// live tunnel. Everything else is reasoned from the vendor's documentation and
    /// says so — see `Docs/LocalVirtualNetworks.md`.
    var verifiedLocally = false
}

nonisolated enum VirtualizationCatalog {

    /// Every product worth looking for, whether or not anyone has tested it.
    ///
    /// Ordered so the ones whose behaviour is CONFIRMED come first — a reader of
    /// the diagnostic report should meet the rows we can stand behind before the
    /// ones we merely researched.
    static let all: [VirtualizationProduct] = [

        // --- Confirmed on a real machine ---------------------------------
        // Apple's own container runtime. vmnet in NAT mode: a `vmenet*` tap per
        // guest plus a `bridge1xx` carrying the host address. MEASURED: guests
        // land on 192.168.64.0/24, the guest's default MTU is 1280, and the
        // guest's only resolver is the bridge address (vmnet's DNS proxy).
        VirtualizationProduct(
            id: "apple-container", title: "Apple Containers (container)",
            networking: .routedSubnet,
            cliPaths: ["/usr/local/bin/container"],
            homeRelativePaths: ["Library/Application Support/com.apple.container"],
            interfacePrefixes: ["vmenet"],
            documentedSubnets: ["192.168.64.0/24"],
            verifiedLocally: true),
        // UTM. BOTH classes, per virtual machine: `Shared`/`Bridged`/`Host` put
        // the guest on a subnet, `Emulated` is QEMU slirp and puts it nowhere.
        // Which one is in force is read per VM by `utmGuests`, because the
        // installed-or-not answer cannot tell you.
        VirtualizationProduct(
            id: "utm", title: "UTM",
            networking: .perGuest,
            appBundleNames: ["UTM.app"],
            bundleIDs: ["com.utmapp.UTM"],
            homeRelativePaths: ["Library/Containers/com.utmapp.UTM/Data/Documents"],
            interfacePrefixes: ["vmenet"],
            verifiedLocally: true),

        // --- Researched, not run here ------------------------------------
        // Docker Desktop. THE class-B case, and the reason this file classifies at
        // all: vpnkit (and now the gVisor-based proxy) translate in userspace, so
        // there is no host interface and nothing to exclude. `docker0` is INSIDE
        // the Linux VM and never appears on the Mac.
        VirtualizationProduct(
            id: "docker-desktop", title: "Docker Desktop",
            networking: .userspace,
            appBundleNames: ["Docker.app"],
            bundleIDs: ["com.docker.docker"],
            cliPaths: ["/usr/local/bin/docker"],
            homeRelativePaths: [".docker"]),
        // OrbStack. Its own host interface and a documented range.
        VirtualizationProduct(
            id: "orbstack", title: "OrbStack",
            networking: .routedSubnet,
            appBundleNames: ["OrbStack.app"],
            bundleIDs: ["dev.orbstack.OrbStack"],
            cliPaths: ["/usr/local/bin/orb", "/usr/local/bin/orbctl"],
            homeRelativePaths: [".orbstack"],
            documentedSubnets: ["198.19.248.0/21"]),
        // Colima and Lima. `socket_vmnet` gives a real subnet when the VM is
        // started with a vmnet network; the default user-mode network is class B.
        VirtualizationProduct(
            id: "colima", title: "Colima",
            networking: .perGuest,
            cliPaths: ["/opt/homebrew/bin/colima", "/usr/local/bin/colima"],
            homeRelativePaths: [".colima"],
            documentedSubnets: ["192.168.105.0/24"]),
        VirtualizationProduct(
            id: "lima", title: "Lima",
            networking: .perGuest,
            cliPaths: ["/opt/homebrew/bin/limactl", "/usr/local/bin/limactl"],
            homeRelativePaths: [".lima"],
            documentedSubnets: ["192.168.105.0/24"]),
        VirtualizationProduct(
            id: "multipass", title: "Multipass",
            networking: .routedSubnet,
            cliPaths: ["/usr/local/bin/multipass"],
            interfacePrefixes: ["bridge"]),
        // VMware Fusion. `vmnet1` host-only and `vmnet8` NAT, with the subnets in
        // a plain text file we can read. NOTE the spelling trap: VMware's `vmnet*`
        // is NOT Apple's `vmenet*`.
        VirtualizationProduct(
            id: "vmware-fusion", title: "VMware Fusion",
            networking: .routedSubnet,
            appBundleNames: ["VMware Fusion.app"],
            bundleIDs: ["com.vmware.fusion"],
            interfacePrefixes: ["vmnet"]),
        VirtualizationProduct(
            id: "parallels", title: "Parallels Desktop",
            networking: .routedSubnet,
            appBundleNames: ["Parallels Desktop.app"],
            bundleIDs: ["com.parallels.desktop.console"],
            cliPaths: ["/usr/local/bin/prlctl"],
            interfacePrefixes: ["vnic"],
            documentedSubnets: ["10.211.55.0/24", "10.37.129.0/24"]),
        VirtualizationProduct(
            id: "virtualbox", title: "VirtualBox",
            networking: .routedSubnet,
            appBundleNames: ["VirtualBox.app"],
            bundleIDs: ["org.virtualbox.app.VirtualBox"],
            cliPaths: ["/usr/local/bin/VBoxManage", "/usr/local/bin/vboxmanage"],
            interfacePrefixes: ["vboxnet"],
            documentedSubnets: ["192.168.56.0/24"]),
        // Plain QEMU, outside UTM. Its default `-netdev user` is slirp: class B.
        VirtualizationProduct(
            id: "qemu", title: "QEMU",
            networking: .perGuest,
            cliPaths: ["/opt/homebrew/bin/qemu-system-aarch64",
                       "/usr/local/bin/qemu-system-aarch64",
                       "/opt/homebrew/bin/qemu-system-x86_64",
                       "/usr/local/bin/qemu-system-x86_64"]),
        VirtualizationProduct(
            id: "podman", title: "Podman",
            networking: .userspace,
            appBundleNames: ["Podman Desktop.app"],
            bundleIDs: ["io.podman.desktop"],
            cliPaths: ["/opt/homebrew/bin/podman", "/usr/local/bin/podman"],
            homeRelativePaths: [".config/containers"]),
        VirtualizationProduct(
            id: "rancher-desktop", title: "Rancher Desktop",
            networking: .perGuest,
            appBundleNames: ["Rancher Desktop.app"],
            bundleIDs: ["io.rancherdesktop.app"],
            homeRelativePaths: ["Library/Application Support/rancher-desktop"]),
    ]

    static func product(id: String) -> VirtualizationProduct? { all.first { $0.id == id } }
}

// MARK: - What was found

/// A product that is installed, and the evidence for saying so. The evidence is
/// reported because "Docker Desktop is installed" and "there is a `~/.docker`
/// directory left over from an uninstall" are different facts.
nonisolated struct InstalledVirtualization: Sendable, Equatable, Identifiable {
    var productID: String
    var title: String
    var networking: GuestNetworkClass
    /// Paths and bundle ids that were actually found, verbatim.
    var evidence: [String] = []
    var verifiedLocally = false

    var id: String { productID }
}

/// One LIVE guest network: a host interface with a guest subnet behind it right
/// now. Only ever `.routedSubnet` products produce these — that is the point.
nonisolated struct GuestNetwork: Sendable, Equatable, Identifiable {
    /// The interface carrying the host end (`bridge100`, `vmnet8`, `vboxnet0`).
    var interfaceName: String
    /// This Mac's address on it.
    var hostAddress: String
    /// The guest subnet, as CIDR. THE value an exclusion is built from.
    var subnet: String
    /// Which product we can attribute it to, when we honestly can.
    var productID: String?
    /// Products installed on this Mac that use this stack, when the interface
    /// alone cannot single one out. Apple's vmnet is shared by the `container`
    /// CLI, UTM's Apple backend and anything else using Virtualization.framework,
    /// so naming one of them would be a guess.
    var candidateProductIDs: [String] = []
    /// Guest taps attached to this network — how many guests are actually on it.
    var attachedGuestInterfaces: [String] = []

    var id: String { "\(interfaceName)|\(subnet)" }

    /// What the network is called in a sentence, without pretending to know which
    /// product owns it when we do not.
    var attribution: String {
        if let productID, let product = VirtualizationCatalog.product(id: productID) {
            return product.title
        }
        let titles = candidateProductIDs.compactMap { VirtualizationCatalog.product(id: $0)?.title }
        switch titles.count {
        case 0: return "a virtual machine or container"
        case 1: return titles[0]
        default: return "one of " + titles.joined(separator: ", ")
        }
    }
}

/// One UTM network interface as its config records it. UTM's own spelling is kept
/// verbatim (`Shared`, `Bridged`, `Host`, `Emulated`) rather than translated —
/// the house rule is to keep another product's proper terms.
nonisolated struct UTMNetworkConfig: Sendable, Equatable {
    var mode: String
    var bridgeInterface: String?
}

/// A UTM virtual machine's network mode, read from its own config. UTM is the
/// product where the class is a per-VM fact, so this is what makes the A/B answer
/// truthful for it.
nonisolated struct UTMGuest: Sendable, Equatable, Identifiable {
    var name: String
    /// UTM's own spelling: `Shared`, `Bridged`, `Host`, `Emulated`.
    var mode: String
    /// The interface it bridges onto, for `Bridged`.
    var bridgeInterface: String?

    var id: String { name }

    /// The class this VM actually is. `Emulated` is QEMU slirp — userspace, no
    /// interface, nothing to exclude.
    var networking: GuestNetworkClass {
        switch mode.lowercased() {
        case "emulated": .userspace
        case "shared", "bridged", "host": .routedSubnet
        default: .perGuest
        }
    }
}

/// Everything detection can say, with "installed" and "running" kept apart.
nonisolated struct VirtualizationSnapshot: Sendable, Equatable {
    var installed: [InstalledVirtualization] = []
    var guestNetworks: [GuestNetwork] = []
    var utmGuests: [UTMGuest] = []
    /// False when the user turned detection off (`vm.detect`). Reported rather
    /// than implied, so an empty result is never mistaken for "you have none".
    var detectionEnabled = true

    var isEmpty: Bool { installed.isEmpty && guestNetworks.isEmpty }

    /// Live networks a VPN could capture. The list an exclusion offer is built
    /// from — and it is empty for a machine that only runs class-B products, which
    /// is the correct answer rather than a failure.
    var excludableSubnets: [String] {
        var seen = Set<String>()
        return guestNetworks.compactMap { seen.insert($0.subnet).inserted ? $0.subnet : nil }
    }

    /// Installed products that a routing exclusion could never help. The UI owes
    /// these a different sentence, not a toggle.
    var userspaceOnlyProducts: [InstalledVirtualization] {
        installed.filter { $0.networking == .userspace }
    }
}

// MARK: - Discovery

nonisolated struct VirtualizationEnvironment: Sendable {
    var home: URL
    /// Injected wholesale so a test can synthesise any machine — including one
    /// with every product installed — without depending on the machine running
    /// the test.
    var fileExists: @Sendable (String) -> Bool = { FileManager.default.fileExists(atPath: $0) }
    /// Where application bundles are looked for, in order. Injectable so a fixture
    /// test never depends on what happens to be in `/Applications` on the machine
    /// running it.
    var applicationDirectories: [String] = []
    /// Directory listing, for UTM's VM folder.
    var listDirectory: @Sendable (String) -> [String] = {
        (try? FileManager.default.contentsOfDirectory(atPath: $0)) ?? []
    }
    /// A UTM virtual machine's first network interface, read from its own
    /// `config.plist`.
    ///
    /// The environment exposes the FACT rather than a raw plist dictionary on
    /// purpose: `[String: Any]` is not `Sendable`, so a generic plist reader cannot
    /// cross into a `@Sendable` closure, and a narrow accessor is in any case the
    /// honest shape — this is the only plist question the whole file asks.
    var readUTMNetwork: @Sendable (String) -> UTMNetworkConfig? = { path in
        guard let data = FileManager.default.contents(atPath: path),
              let plist = (try? PropertyListSerialization.propertyList(
                from: data, options: [], format: nil)) as? [String: Any],
              let networks = plist["Network"] as? [[String: Any]],
              let first = networks.first,
              let mode = first["Mode"] as? String
        else { return nil }
        return UTMNetworkConfig(mode: mode, bridgeInterface: first["BridgeInterface"] as? String)
    }

    static func live(home: URL = FileManager.default.homeDirectoryForCurrentUser)
        -> VirtualizationEnvironment {
        VirtualizationEnvironment(
            home: home,
            applicationDirectories: [
                "/Applications",
                "/Applications/Setapp",
                home.appendingPathComponent("Applications").path,
            ])
    }
}

nonisolated enum VirtualizationDiscovery {

    /// Which products are installed. Filesystem and Launch Services only.
    static func installed(env: VirtualizationEnvironment) -> [InstalledVirtualization] {
        VirtualizationCatalog.all.compactMap { product in
            var evidence: [String] = []
            for name in product.appBundleNames {
                for directory in env.applicationDirectories {
                    let path = directory + "/" + name
                    if env.fileExists(path) { evidence.append(path) }
                }
            }
            for path in product.cliPaths where env.fileExists(path) {
                evidence.append(path)
            }
            for relative in product.homeRelativePaths {
                let path = env.home.appendingPathComponent(relative).path
                if env.fileExists(path) { evidence.append(path) }
            }
            guard !evidence.isEmpty else { return nil }
            return InstalledVirtualization(
                productID: product.id, title: product.title, networking: product.networking,
                evidence: evidence, verifiedLocally: product.verifiedLocally)
        }
    }

    /// The live guest networks, from the interface list alone.
    ///
    /// TWO TRAPS, both of which a plausible implementation falls into and both
    /// measured on a real machine:
    ///
    ///  1. **The subnet is on the BRIDGE, not on the tap.** Apple's vmnet creates
    ///     `vmenet0` (the guest's tap, which has NO IPv4 address at all) and
    ///     `bridge100` (which holds `192.168.64.1/24`). Reading the guest network
    ///     off `vmenet0` finds nothing and concludes there is no VM network.
    ///  2. **`bridge0` is not a guest network.** It is the ordinary
    ///     user-configurable Thunderbolt/Ethernet bridge that exists on stock
    ///     macOS. macOS allocates vmnet bridges from `bridge100` upwards, so the
    ///     number is the discriminator — and treating `bridge0` as a VM network
    ///     would invite someone to route their real LAN around their VPN.
    static func guestNetworks(interfaces: [NetInterface],
                              installed: [InstalledVirtualization]) -> [GuestNetwork] {
        // Guest taps present right now. Their names are what tells us a guest is
        // actually attached, even though they carry no address.
        let taps = interfaces.filter { $0.name.hasPrefix("vmenet") }.map(\.name)
        // Everything installed that shares Apple's vmnet stack, so an unattributable
        // vmnet bridge can name its candidates instead of guessing one.
        let vmnetCandidates = installed
            .filter { VirtualizationCatalog.product(id: $0.productID)?
                        .interfacePrefixes.contains("vmenet") == true }
            .map(\.productID)

        var out: [GuestNetwork] = []
        for interface in interfaces {
            for (index, subnet) in interface.ipv4Subnets.enumerated() where !subnet.isEmpty {
                guard index < interface.ipv4.count else { continue }
                let address = interface.ipv4[index]
                guard let attribution = attribute(interfaceName: interface.name) else { continue }
                out.append(GuestNetwork(
                    interfaceName: interface.name,
                    hostAddress: address,
                    subnet: subnet,
                    productID: attribution.productID,
                    candidateProductIDs: attribution.isAppleVMNet ? vmnetCandidates : [],
                    attachedGuestInterfaces: attribution.isAppleVMNet ? taps : []))
            }
        }
        return out
    }

    /// Which product, if any, an interface name belongs to — and whether it is
    /// Apple's shared vmnet stack, where the name cannot single a product out.
    static func attribute(interfaceName name: String)
        -> (productID: String?, isAppleVMNet: Bool)? {

        // A vmnet bridge. `bridge0` is excluded by the numbering rule above; the
        // stack is shared, so no single product is named.
        if name.hasPrefix("bridge"), let number = Int(name.dropFirst("bridge".count)), number >= 100 {
            return (nil, true)
        }
        // VMware's own adapters. Checked BEFORE any generic prefix walk, because
        // "vmnet1" also starts with "vmnet" and VMware is the only product that
        // puts an address on one.
        if name.hasPrefix("vmnet") { return ("vmware-fusion", false) }
        if name.hasPrefix("vnic") { return ("parallels", false) }
        if name.hasPrefix("vboxnet") { return ("virtualbox", false) }
        return nil
    }

    /// UTM's virtual machines and the network mode each is set to — the per-VM
    /// fact that decides UTM's class. A plist read; UTM is never launched and no
    /// VM is started.
    static func utmGuests(env: VirtualizationEnvironment) -> [UTMGuest] {
        let root = env.home
            .appendingPathComponent("Library/Containers/com.utmapp.UTM/Data/Documents").path
        return env.listDirectory(root)
            .filter { $0.hasSuffix(".utm") }
            .sorted()
            .map { bundle -> UTMGuest in
                let name = String(bundle.dropLast(".utm".count))
                // A `.utm` bundle whose config will not answer is reported as
                // `unknown` rather than dropped: a virtual machine we cannot classify
                // is exactly the one somebody needs told about, and `unknown` lands in
                // `.perGuest`, which offers no routing fix on its own.
                guard let network = env.readUTMNetwork(root + "/" + bundle + "/config.plist") else {
                    return UTMGuest(name: name, mode: "unknown", bridgeInterface: nil)
                }
                return UTMGuest(name: name, mode: network.mode,
                                bridgeInterface: network.bridgeInterface)
            }
    }

    /// The whole answer, TAKEN OFF THE MAIN THREAD — which is the only way any caller
    /// in the app should ask for it.
    ///
    /// MEASURED, NOT PRECAUTIONARY. The synchronous `snapshot(...)` below is ~40 `stat`s,
    /// a directory enumeration of UTM's container and a plist read per virtual machine.
    /// Called on the main actor it wedged the app outright: `contentsOfDirectory` on
    /// `~/Library/Containers/com.utmapp.UTM/Data/Documents` blocked in `open` and never
    /// returned, and the whole UI went with it — caught by the Report a Problem
    /// accessibility audit, whose "wait for the app to idle" never came back. A
    /// filesystem call another process can stall must never be on the main thread, and
    /// "it is only forty stats" is exactly the reasoning that put it there.
    ///
    /// `nonisolated` + `async` rather than a cache: the answer is only true for the
    /// instant it is taken (a guest's subnet exists only while the guest runs), so a
    /// stale cached snapshot would be a wrong answer rather than a cheap one.
    /// How long the filesystem half of the scan gets before the answer is given without
    /// it. Generous for the work (tens of `stat`s and a small directory) and short enough
    /// that nothing visible waits on it.
    nonisolated static let scanBudget: Duration = .seconds(2)

    nonisolated static func snapshotOffMain(
        interfaces: [NetInterface],
        detectionEnabled: Bool,
        env: VirtualizationEnvironment) async -> VirtualizationSnapshot {

        guard detectionEnabled else { return VirtualizationSnapshot(detectionEnabled: false) }

        // THE LIVE NETWORKS FIRST, AND WITHOUT TOUCHING THE FILESYSTEM AT ALL. This is
        // the half the connect-time warning actually needs, it comes from the interface
        // list the caller already holds, and it can never stall — so the warning works
        // even when everything below times out. Attribution by interface name
        // (`bridge1xx`, `vmnet1`, `vnic0`, `vboxnet0`) needs no installed list; only the
        // vmnet CANDIDATES do, and those are filled in below when they arrive.
        let networksWithoutAttribution = guestNetworks(interfaces: interfaces, installed: [])

        // AND THE FILESYSTEM HALF ON A DEADLINE, because one of its reads can block for
        // ever. MEASURED: `utmGuests` enumerates `~/Library/Containers/com.utmapp.UTM/
        // Data/Documents` — ANOTHER APPLICATION'S SANDBOX CONTAINER — and macOS gates
        // that behind a consent check. With the check unanswered, `open` does not fail,
        // it BLOCKS, and it blocked for as long as it was left to. Waiting on that from
        // a connect or from the report is not acceptable at any duration, so the answer
        // is bounded and the missing half is simply absent.
        let filesystem = await answer(within: scanBudget) { () -> ([InstalledVirtualization], [UTMGuest]) in
            (installed(env: env), utmGuests(env: env))
        }
        guard let (found, guests) = filesystem else {
            return VirtualizationSnapshot(guestNetworks: networksWithoutAttribution,
                                          detectionEnabled: true)
        }
        return VirtualizationSnapshot(
            installed: found,
            guestNetworks: guestNetworks(interfaces: interfaces, installed: found),
            utmGuests: guests,
            detectionEnabled: true)
    }

    /// `work`'s answer, or nil if it has not produced one inside `budget`.
    ///
    /// The abandoned task is NOT killed and cannot be: a thread parked in `open` is in an
    /// uninterruptible syscall, and `Task.cancel` has nothing to deliver to. It is left to
    /// finish and its answer dropped, which is why the budget exists at all rather than a
    /// retry loop — one stalled read must cost one thread once, not one per connect. That
    /// is also why the caller above never re-asks on a timeout.
    private nonisolated static func answer<T: Sendable>(
        within budget: Duration,
        work: @escaping @Sendable () -> T) async -> T? {

        await withTaskGroup(of: T?.self, returning: T?.self) { group in
            group.addTask(priority: .utility) { work() }
            group.addTask { try? await Task.sleep(for: budget); return nil }
            defer { group.cancelAll() }
            for await first in group { return first }
            return nil
        }
    }

    /// The whole answer. `detectionEnabled == false` yields an empty snapshot that
    /// SAYS it is empty by choice.
    ///
    /// SYNCHRONOUS AND FILESYSTEM-BOUND: call it from a test, or through
    /// `snapshotOffMain`. Never from the main actor — see above.
    static func snapshot(interfaces: [NetInterface],
                         detectionEnabled: Bool,
                         env: VirtualizationEnvironment) -> VirtualizationSnapshot {
        guard detectionEnabled else { return VirtualizationSnapshot(detectionEnabled: false) }
        let found = installed(env: env)
        return VirtualizationSnapshot(
            installed: found,
            guestNetworks: guestNetworks(interfaces: interfaces, installed: found),
            utmGuests: utmGuests(env: env),
            detectionEnabled: true)
    }
}
