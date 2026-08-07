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

// MARK: - How a guest network is wired

/// The three arrangements `ONTOLOGY.md` names, plus the honest fourth answer.
///
/// THIS IS NOT A REFINEMENT OF `GuestNetworkClass` — the two answer different
/// questions and both are needed. `GuestNetworkClass` says whether there is a host
/// interface at all (and therefore whether a route could ever help). This says, for
/// a network that *has* one, **who decides where its guests' traffic goes** — which
/// is what makes the difference between a VPN that can affect them and one that
/// cannot.
///
///  • `.shared` — the guests are behind this Mac and their traffic is translated
///    out of it. This Mac's routing table is on their path.
///  • `.bridged` — the guests are on the same network as this Mac, with addresses
///    of their own from it. **This Mac's routing table is not consulted at all**, so
///    no VPN of ours can capture them and no divert rule of ours can move them.
///  • `.hostOnly` — this Mac and its guests, and nothing else. There is no way out
///    to lose; the only thing a tunnel can take away is this Mac's own path TO them.
///  • `.unknown` — see the note in `ONTOLOGY.md`. Telling `.shared` from `.hostOnly`
///    means reading `pf`, and `pfctl` is `Permission denied` for every unprivileged
///    process (`Docs/Networking.md` §6.1). Where the product does not write the
///    answer down somewhere we may read, this is the truthful answer and the UI says
///    it in those words rather than assuming the common case.
nonisolated enum GuestNetworkMode: String, Sendable, CaseIterable, Equatable {
    case shared
    case bridged
    case hostOnly
    case unknown

    /// The house term, as a label.
    var title: String {
        switch self {
        case .shared: "Shared network"
        case .bridged: "Bridged network"
        case .hostOnly: "Host-only network"
        case .unknown: "Arrangement not visible"
        }
    }

    /// What it means to the person reading it — consequences, not mechanism.
    var summary: String {
        switch self {
        case .shared:
            "Guests sit behind this Mac and share its connection, so their traffic goes wherever "
            + "this Mac\u{2019}s does."
        case .bridged:
            "Guests are on the same network as this Mac, with addresses of their own. This Mac "
            + "does not decide where their traffic goes, so a VPN here cannot change it."
        case .hostOnly:
            "Guests can reach this Mac and each other and nothing else. There is no way out for a "
            + "VPN to take away \u{2014} only this Mac\u{2019}s own path to them."
        case .unknown:
            "SimpleVPN cannot tell whether these guests share this Mac\u{2019}s connection or can "
            + "only reach this Mac. Seeing that needs administrator access this app does not take."
        }
    }

    /// Is this Mac's routing table on the guests' path at all? `.unknown` answers
    /// yes, which is the cautious direction: it keeps the network visible and keeps
    /// the choice offered, rather than quietly deciding a VPN is irrelevant to it.
    var thisMacIsOnThePath: Bool {
        switch self {
        case .shared, .hostOnly, .unknown: true
        case .bridged: false
        }
    }

    /// Whether keeping this network out of a tunnel is a choice worth offering. False
    /// for `.bridged` for the reason above — a rule there would apply cleanly, change
    /// nothing whatever, and look like a fix.
    var routingChoiceApplies: Bool { thisMacIsOnThePath }

    /// ONE place where every vendor's spelling is translated into ours, so the same
    /// word cannot mean two things in two files. The vendor words are exactly the
    /// ones in `ONTOLOGY.md`'s table; anything unrecognised is `.unknown` rather
    /// than a guess at the nearest match.
    init(vendorWord: String) {
        switch vendorWord.lowercased() {
        case "nat", "shared":                 self = .shared
        case "bridged", "bridge":             self = .bridged
        case "host", "host-only", "hostonly": self = .hostOnly
        default:                              self = .unknown
        }
    }
}

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
    /// Shared, bridged, host-only — or, honestly, not visible. See
    /// `GuestNetworkMode`; the default is the honest one, so a construction that
    /// never asked cannot accidentally claim to know.
    var mode: GuestNetworkMode = .unknown
    /// WHERE the mode answer came from, verbatim enough to argue with — a vendor's
    /// own record, a vendor's own fixed convention, or the reason we cannot see it.
    /// Surfaced in the inspector and the diagnostic report, because "shared" and
    /// "shared, because Apple's own network record on this Mac says `nat`" are
    /// different claims.
    var modeEvidence: String = ""

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

/// A guest that is running but is NOT on a network of this Mac's — a guest tap with
/// no host-side guest network carrying an address behind it.
///
/// WHY THIS IS A SEPARATE TYPE AND NOT A `GuestNetwork` WITH NO SUBNET. Every field
/// of `GuestNetwork` that matters — the subnet, this Mac's address on it, the rule
/// that could be built from it — is meaningless here, and an optional subnet
/// threaded through the offer path would be an invitation to build a rule for
/// nothing. What we know is exactly this: something is running, on this tap, and
/// this Mac is not on its path. That is worth SAYING (it is the one arrangement the
/// user can see nothing about today) and worth refusing to offer a routing change
/// for.
///
/// MEASURED-ADJACENT, NOT MEASURED: this Mac has Apple Containers but no bridged
/// guest was run to confirm the interface shape, so the inference is stated as an
/// inference in the UI and here. The observation is only ever "there is a tap and
/// no guest network", which is true whatever produced it.
nonisolated struct BridgedGuest: Sendable, Equatable, Identifiable {
    /// The guest tap (`vmenet0`).
    var interfaceName: String
    /// Products on this Mac that use this stack, when the tap alone cannot single
    /// one out — same honesty as `GuestNetwork.candidateProductIDs`.
    var candidateProductIDs: [String] = []

    var id: String { interfaceName }

    var mode: GuestNetworkMode { .bridged }

    var attribution: String {
        let titles = candidateProductIDs.compactMap { VirtualizationCatalog.product(id: $0)?.title }
        switch titles.count {
        case 0: return "a virtual machine or container"
        case 1: return titles[0]
        default: return "one of " + titles.joined(separator: ", ")
        }
    }
}

/// One container as `~/Library/Application Support/com.apple.container/containers/
/// <id>/config.json` records it. MEASURED on a real Mac, 2026-08-07 — the file really
/// does carry all three, and `network` is the product's own name for the network
/// (`"default"`), which is what `GuestInventory` attaches a guest by.
nonisolated struct ContainerRecord: Sendable, Equatable {
    /// What `container ls` shows and what the user types to address it: the name when
    /// `--name` was given, a UUID when it was not.
    var id: String
    /// `image.reference` — "docker.io/library/alpine:latest".
    var image: String?
    /// `networks[].network` — the product's own name for the network it is on.
    var network: String?
}

/// One UTM network interface as its config records it. UTM's own spelling is kept
/// verbatim (`Shared`, `Bridged`, `Host`, `Emulated`) rather than translated —
/// the house rule is to keep another product's proper terms.
nonisolated struct UTMNetworkConfig: Sendable, Equatable {
    var mode: String
    var bridgeInterface: String?
    /// `Information.Name` — the name UTM itself shows. Preferred over the bundle's
    /// filename: renaming a `.utm` bundle in Finder does not rename the machine.
    var machineName: String?
    /// `Information.UUID`, so a renamed machine is still the same machine.
    var machineUUID: String?
    /// `Network[].MacAddress`, verbatim in UTM's spelling — normalised at the one
    /// comparison point (`NetworkTopology.normalisedMAC`), never here.
    /// **MEASURED**: `EA:85:74:8B:18:97` on this Mac's one UTM machine.
    var macAddresses: [String] = []
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
    /// Guests that are running but are not on a network of this Mac's. Kept apart
    /// from `guestNetworks` for the reason `BridgedGuest` gives: they are worth
    /// showing and must never be offered a routing change.
    var bridgedGuests: [BridgedGuest] = []
    var utmGuests: [UTMGuest] = []
    /// EVERY NAMED GUEST, and where it turned out to be — or why we cannot say.
    /// `GuestInventory` has the whole argument; the short version is that a name on a
    /// routing diagram is a claim, so it is attached only on evidence and listed as
    /// unattached otherwise.
    var placedGuests: [PlacedGuest] = []
    /// False when the user turned detection off (`vm.detect`). Reported rather
    /// than implied, so an empty result is never mistaken for "you have none".
    var detectionEnabled = true

    /// The names on one host interface, in a stable order. THE accessor every
    /// surface uses, so the route diagram's card, the traffic graph's chip and the
    /// inspector cannot disagree about who is where.
    func guests(on interfaceName: String) -> [PlacedGuest] {
        placedGuests
            .filter { $0.attachment.interfaceName == interfaceName }
            .sorted { $0.guest.displayName < $1.guest.displayName }
    }

    /// Every guest tap that is up right now, in a stable order. One per running
    /// guest: every packet a guest sends crosses its own tap, which is what makes a
    /// per-guest throughput series a real measurement rather than an apportionment.
    var guestTaps: [String] {
        (guestNetworks.flatMap(\.attachedGuestInterfaces) + bridgedGuests.map(\.interfaceName))
            .reduce(into: [String]()) { out, name in
                if !out.contains(name) { out.append(name) }
            }
    }

    /// WHICH NAMED GUEST IS ON THIS TAP — only where it is forced, never as a tiebreak.
    ///
    /// **Nothing on disk records a tap name.** Neither Apple's `container` nor UTM
    /// writes down which `vmenet` its guest got, so there is no evidence of kind 1 or
    /// 2 (`GuestInventory`) to be had here at all. What there IS, sometimes, is
    /// elimination: if this tap is the ONLY tap on a guest network and exactly ONE
    /// named guest is placed on that network, then no other assignment is possible.
    ///
    /// Two taps, or two names, and the answer is nil — the traffic graph then plots
    /// the tap under its own name rather than pinning somebody's container to a line
    /// that might be a different container's. A mislabelled throughput series is the
    /// same class of error as a mislabelled routing card: it is acted on.
    func guest(onTap tapName: String) -> PlacedGuest? {
        guard let network = guestNetworks.first(where: {
            $0.attachedGuestInterfaces.contains(tapName)
        }) else { return nil }
        guard network.attachedGuestInterfaces.count == 1 else { return nil }
        let named = guests(on: network.interfaceName)
        return named.count == 1 ? named[0] : nil
    }

    /// Named guests we could not place. `ONTOLOGY.md` calls these **unattached** and
    /// puts them under "Also on this Mac" — listing them is the honest alternative to
    /// guessing, and hiding them would leave a user wondering where their container
    /// went.
    var unattachedGuests: [PlacedGuest] {
        placedGuests
            .filter { $0.attachment.interfaceName == nil }
            .sorted { $0.guest.displayName < $1.guest.displayName }
    }

    var isEmpty: Bool { installed.isEmpty && guestNetworks.isEmpty && bridgedGuests.isEmpty }

    /// ONE ROW PER HOST INTERFACE — the list every surface that DRAWS a guest network
    /// must use.
    ///
    /// `guestNetworks` is per address, because a bridge may hold more than one and
    /// each is a genuinely different subnet. But a bridge reporting two addresses on
    /// the SAME subnet (a secondary address, an alias) is still one guest network,
    /// and drawing it twice would put the same containers on the diagram twice with
    /// two controls that fight. First row per interface wins: it is the one the
    /// kernel reports first, which is the interface's primary.
    var distinctGuestNetworks: [GuestNetwork] {
        var seen = Set<String>()
        return guestNetworks.filter { seen.insert($0.interfaceName).inserted }
    }

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
        let information = plist["Information"] as? [String: Any]
        return UTMNetworkConfig(
            mode: mode,
            bridgeInterface: first["BridgeInterface"] as? String,
            machineName: information?["Name"] as? String,
            machineUUID: information?["UUID"] as? String,
            macAddresses: networks.compactMap { $0["MacAddress"] as? String })
    }

    /// One container as Apple's `container` records it.
    ///
    /// A NARROW ACCESSOR, for exactly the reason `readUTMNetwork` above is one:
    /// `[String: Any]` is not `Sendable`, so a generic "read me this JSON" closure
    /// cannot be captured by a test that wants to supply a fixture — the compiler
    /// says so, and the answer is the same as it was for the plist. This is also the
    /// honest shape: two fields and a network name are the whole of what this file
    /// asks of that record.
    var readContainerRecord: @Sendable (String) -> ContainerRecord? = { path in
        guard let data = FileManager.default.contents(atPath: path),
              let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let id = json["id"] as? String, !id.isEmpty
        else { return nil }
        return ContainerRecord(
            id: id,
            image: (json["image"] as? [String: Any])?["reference"] as? String,
            network: (json["networks"] as? [[String: Any]])?
                .compactMap { $0["network"] as? String }.first)
    }

    /// A text file, for the two vendors whose records are XML and `key = "value"`.
    /// Bounded: a `.vbox` or `.vmx` is kilobytes, but a path can point anywhere, and
    /// reading an arbitrarily large file to scrape one name is not a trade worth
    /// making.
    var readText: @Sendable (String) -> String? = { path in
        guard let handle = FileManager.default.contents(atPath: path),
              handle.count <= 1_048_576
        else { return nil }
        return String(data: handle, encoding: .utf8)
    }

    /// The `mode` Apple's `container` records for each network it has created, in
    /// its own words (`"nat"`), from
    /// `~/Library/Application Support/com.apple.container/networks/<name>/entity.json`.
    ///
    /// MEASURED ON THIS MAC, 2026-08-07, with nothing running:
    /// ```
    /// {"creationDate":803319258.7,"plugin":"container-network-vmnet","mode":"nat",
    ///  "name":"default","labels":{…},"options":{}}
    /// ```
    /// That file is the ONLY unprivileged source on this Mac for shared-versus-
    /// host-only, and it is why `apple-container` gets a real answer where the other
    /// vmnet products get `.unknown` (`Docs/Networking.md` §6.1: `pf` is the other
    /// source and it is `Permission denied`).
    ///
    /// TWO DELIBERATE LIMITS, both of which keep this from over-claiming:
    ///  • it is a record of the network by NAME, and nothing on disk maps `default`
    ///    to `bridge100` — so the answer is only used when there is exactly one, and
    ///    `mode(...)` says so;
    ///  • it records what the network was CREATED as, not what the kernel is doing
    ///    now. That is still a vendor's own record rather than our guess, which is
    ///    the bar the evidence string states.
    ///
    /// The mode strings are returned verbatim (rule 2 — a vendor's own spelling) and
    /// mapped in one place, `GuestNetworkMode.init(vendorWord:)`.
    var appleContainerNetworkModes: @Sendable (URL) -> [String] = { home in
        let root = home
            .appendingPathComponent("Library/Application Support/com.apple.container/networks")
        let names = (try? FileManager.default.contentsOfDirectory(atPath: root.path)) ?? []
        return names.sorted().compactMap { name in
            let path = root.appendingPathComponent(name).appendingPathComponent("entity.json").path
            guard let data = FileManager.default.contents(atPath: path),
                  let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                  let mode = json["mode"] as? String
            else { return nil }
            return mode
        }
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
    ///
    /// `appleContainerModes` and `utmGuests` are the vendors' OWN records of how each
    /// network was set up, and they are the only unprivileged source for shared vs
    /// host-only. Both default to empty so the interface-list-only call (the one that
    /// must never touch the filesystem — see `snapshotOffMain`) still works and
    /// simply answers `.unknown`, which is true.
    static func guestNetworks(interfaces: [NetInterface],
                              installed: [InstalledVirtualization],
                              appleContainerModes: [String] = [],
                              utmGuests: [UTMGuest] = []) -> [GuestNetwork] {
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
                let wiring = mode(interfaceName: interface.name,
                                  appleContainerModes: appleContainerModes,
                                  utmGuests: utmGuests)
                out.append(GuestNetwork(
                    interfaceName: interface.name,
                    hostAddress: address,
                    subnet: subnet,
                    productID: attribution.productID,
                    candidateProductIDs: attribution.isAppleVMNet ? vmnetCandidates : [],
                    attachedGuestInterfaces: attribution.isAppleVMNet ? taps : [],
                    mode: wiring.mode,
                    modeEvidence: wiring.evidence))
            }
        }
        return out
    }

    /// Guests that are running with no guest network of this Mac's behind them.
    ///
    /// THE OBSERVATION IS NARROW ON PURPOSE: a `vmenet*` tap exists, and no vmnet
    /// bridge carries a subnet. What that means is that this Mac is not on those
    /// guests' path — which is the *bridged* arrangement, and is also what a guest
    /// mid-boot briefly looks like. Both are honestly described by "we can see a
    /// guest and we cannot see a network of ours behind it", which is what the UI
    /// says; neither is offered a routing change.
    ///
    /// If ANY vmnet bridge is carrying a subnet the taps are attributed to it
    /// instead (`attachedGuestInterfaces`) and nothing is reported here — a tap can
    /// only be counted once, which is what keeps a guest network off the graph twice.
    static func bridgedGuests(interfaces: [NetInterface],
                              guestNetworks: [GuestNetwork]) -> [BridgedGuest] {
        let claimed = Set(guestNetworks.flatMap(\.attachedGuestInterfaces))
        return interfaces
            .filter { $0.name.hasPrefix("vmenet") && !claimed.contains($0.name) }
            .map { BridgedGuest(interfaceName: $0.name) }
    }

    /// Shared, bridged, host-only or "we cannot see" — with the evidence, which is
    /// half the answer.
    ///
    /// The vendors' FIXED CONVENTIONS are used where a vendor genuinely has one and
    /// documents it, and nowhere else:
    ///  • VMware Fusion ships `vmnet1` as host-only and `vmnet8` as NAT, and has for
    ///    twenty years. Any other `vmnet*` is one the user made, so it is unknown.
    ///  • VirtualBox's `vboxnet*` adapters ARE the host-only ones — its NAT mode has
    ///    no host interface at all, so a `vboxnet` that exists is host-only by
    ///    construction rather than by convention.
    ///  • Parallels ships `vnic0` as shared and `vnic1` as host-only.
    ///
    /// Apple's shared vmnet stack (`bridge1xx`) has no convention to read, so it
    /// falls back to the records: Apple `container`'s `entity.json` and UTM's
    /// per-VM `config.plist`. **Only a UNANIMOUS answer is used** — two products (or
    /// two networks) on one stack disagreeing means we cannot say which bridge is
    /// which, and `.unknown` is then the truthful answer rather than the first match.
    static func mode(interfaceName name: String,
                     appleContainerModes: [String] = [],
                     utmGuests: [UTMGuest] = []) -> (mode: GuestNetworkMode, evidence: String) {

        if name.hasPrefix("vmnet") {
            switch name {
            case "vmnet1": return (.hostOnly, "VMware Fusion ships \u{201C}vmnet1\u{201D} as its host-only adapter.")
            case "vmnet8": return (.shared, "VMware Fusion ships \u{201C}vmnet8\u{201D} as its NAT adapter.")
            default: return (.unknown, unseeable)
            }
        }
        if name.hasPrefix("vboxnet") {
            return (.hostOnly, "A VirtualBox \u{201C}vboxnet\u{201D} adapter is host-only \u{2014} its NAT mode creates no interface at all.")
        }
        if name.hasPrefix("vnic") {
            switch name {
            case "vnic0": return (.shared, "Parallels Desktop ships \u{201C}vnic0\u{201D} as its shared adapter.")
            case "vnic1": return (.hostOnly, "Parallels Desktop ships \u{201C}vnic1\u{201D} as its host-only adapter.")
            default: return (.unknown, unseeable)
            }
        }

        // Apple's shared vmnet stack. Every record we may read, translated once.
        var words: [String] = appleContainerModes
        var sources: [String] = appleContainerModes.isEmpty ? [] :
            ["Apple\u{2019}s own network record on this Mac says \u{201C}\(appleContainerModes.joined(separator: "\u{201D}, \u{201C}"))\u{201D}"]
        // An Emulated UTM machine is not on this stack at all (it is QEMU slirp with
        // no interface), so it must not get a vote on what a bridge is.
        let utmWords = utmGuests.filter { $0.networking != .userspace }.map(\.mode)
        if !utmWords.isEmpty {
            words += utmWords
            sources.append("UTM\u{2019}s own settings say \u{201C}\(Set(utmWords).sorted().joined(separator: "\u{201D}, \u{201C}"))\u{201D}")
        }
        let modes = Set(words.map { GuestNetworkMode(vendorWord: $0) })
        guard modes.count == 1, let only = modes.first, only != .unknown else {
            return (.unknown, words.isEmpty ? unseeable
                    : "More than one arrangement is set up on this Mac (\(sources.joined(separator: "; "))), "
                    + "and nothing on disk says which of them this network is.")
        }
        return (only, sources.joined(separator: "; ") + ".")
    }

    /// The one sentence for "no unprivileged process can see this", said the same way
    /// everywhere it is true. `Docs/Networking.md` §6.1 is the measurement behind it.
    static let unseeable =
        "Telling a shared network from a host-only one means reading this Mac\u{2019}s packet "
        + "filter, which needs administrator access SimpleVPN does not take."

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

    ///
    /// `neighbours` is the kernel's neighbour cache (`NetworkTopology.neighbours`),
    /// defaulted so every existing caller is untouched. Without it the named guests
    /// are still found and still listed; they simply cannot be ATTACHED by hardware
    /// address, which is exactly what an unattached guest means.
    nonisolated static func snapshotOffMain(
        interfaces: [NetInterface],
        detectionEnabled: Bool,
        env: VirtualizationEnvironment,
        neighbours: [String: Set<String>] = [:]) async -> VirtualizationSnapshot {

        guard detectionEnabled else { return VirtualizationSnapshot(detectionEnabled: false) }

        // THE LIVE NETWORKS FIRST, AND WITHOUT TOUCHING THE FILESYSTEM AT ALL. This is
        // the half the connect-time warning actually needs, it comes from the interface
        // list the caller already holds, and it can never stall — so the warning works
        // even when everything below times out. Attribution by interface name
        // (`bridge1xx`, `vmnet1`, `vnic0`, `vboxnet0`) needs no installed list; only the
        // vmnet CANDIDATES do, and those are filled in below when they arrive.
        //
        // The MODE half of that answer is `.unknown` here for Apple's shared vmnet
        // stack and correct for the products with a fixed convention, because the
        // records that would settle it are files — and reading a file is exactly
        // what this half must not do. `.unknown` is a true answer, and the UI says
        // it in those words.
        let networksWithoutAttribution = guestNetworks(interfaces: interfaces, installed: [])

        // AND THE FILESYSTEM HALF ON A DEADLINE, because one of its reads can block for
        // ever. MEASURED: `utmGuests` enumerates `~/Library/Containers/com.utmapp.UTM/
        // Data/Documents` — ANOTHER APPLICATION'S SANDBOX CONTAINER — and macOS gates
        // that behind a consent check. With the check unanswered, `open` does not fail,
        // it BLOCKS, and it blocked for as long as it was left to. Waiting on that from
        // a connect or from the report is not acceptable at any duration, so the answer
        // is bounded and the missing half is simply absent.
        let filesystem = await answer(within: scanBudget) { readEverything(env: env) }
        guard let scan = filesystem else {
            return VirtualizationSnapshot(
                guestNetworks: networksWithoutAttribution,
                bridgedGuests: bridgedGuests(interfaces: interfaces,
                                             guestNetworks: networksWithoutAttribution),
                detectionEnabled: true)
        }
        return assemble(interfaces: interfaces, scan: scan, neighbours: neighbours)
    }

    /// Everything the filesystem half reads, in one value.
    ///
    /// A STRUCT RATHER THAN A GROWING TUPLE: this is what `answer(within:)` carries
    /// across the deadline, and a five-element tuple whose members are told apart by
    /// position is how the wrong list ends up in the wrong field on the next
    /// addition.
    nonisolated struct FilesystemScan: Sendable {
        var installed: [InstalledVirtualization] = []
        var utmGuests: [UTMGuest] = []
        var appleContainerModes: [String] = []
        var named: [NamedGuest] = []
    }

    /// The whole filesystem half. Ordered so `installed` comes first — every other
    /// reader is gated on it, and a product nobody has is never searched for.
    static func readEverything(env: VirtualizationEnvironment) -> FilesystemScan {
        let found = installed(env: env)
        return FilesystemScan(
            installed: found,
            utmGuests: utmGuests(env: env),
            appleContainerModes: env.appleContainerNetworkModes(env.home),
            named: GuestInventory.guests(env: env, installed: found))
    }

    /// The filesystem half plus the live half, combined. Shared by the async and the
    /// synchronous entry points so the two can never build a different snapshot from
    /// the same facts.
    static func assemble(interfaces: [NetInterface],
                         scan: FilesystemScan,
                         neighbours: [String: Set<String>]) -> VirtualizationSnapshot {
        let networks = guestNetworks(interfaces: interfaces, installed: scan.installed,
                                     appleContainerModes: scan.appleContainerModes,
                                     utmGuests: scan.utmGuests)
        return VirtualizationSnapshot(
            installed: scan.installed,
            guestNetworks: networks,
            bridgedGuests: bridgedGuests(interfaces: interfaces, guestNetworks: networks)
                .map { withCandidates($0, installed: scan.installed) },
            utmGuests: scan.utmGuests,
            placedGuests: GuestInventory.place(
                scan.named, neighbours: neighbours, guestNetworks: networks,
                // Every network name the products know of — the denominator of the
                // elimination rule. Apple's own network records are the only source
                // today, and `mode(...)` already reads them.
                recordedNetworkNames: Set(scan.named.compactMap(\.recordedNetwork))),
            detectionEnabled: true)
    }

    /// A bridged guest's candidate products, once the installed list has arrived.
    /// Same honesty as `GuestNetwork.candidateProductIDs`: a `vmenet` tap belongs to
    /// Apple's shared stack, which several products use, so naming one would be a
    /// guess.
    private static func withCandidates(_ guest: BridgedGuest,
                                       installed: [InstalledVirtualization]) -> BridgedGuest {
        var out = guest
        out.candidateProductIDs = installed
            .filter { VirtualizationCatalog.product(id: $0.productID)?
                        .interfacePrefixes.contains("vmenet") == true }
            .map(\.productID)
        return out
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
                         env: VirtualizationEnvironment,
                         neighbours: [String: Set<String>] = [:]) -> VirtualizationSnapshot {
        guard detectionEnabled else { return VirtualizationSnapshot(detectionEnabled: false) }
        return assemble(interfaces: interfaces, scan: readEverything(env: env),
                        neighbours: neighbours)
    }
}
