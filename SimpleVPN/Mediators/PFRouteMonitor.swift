// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  PFRouteMonitor.swift
//  The Route mediator's Stage-4 monitor (Docs/StateMediators.md): a listen-only
//  `PF_ROUTE`/`SOCK_RAW` socket that reports EXTERNAL changes to the default route so
//  the mediator can diff-vs-expected and re-assert on genuine drift.
//
//  WHY app-side: the containing app is unsandboxed (`ENABLE_APP_SANDBOX: NO`); the
//  packet-tunnel extension is sandboxed and CANNOT open PF_ROUTE. Reading routing
//  messages needs no root — only writing the table would.
//
//  WHAT it parses: `RTM_ADD` / `RTM_DELETE` / `RTM_CHANGE` messages whose destination
//  is the default route (0.0.0.0/0 · ::/0). It reuses `RouteTableSource`'s sockaddr
//  walker (the packed present-only RTAX_* array, with all its alignment/truncation
//  quirks already solved) rather than re-deriving it. On a default-route message it
//  debounces, then snapshots the ACTUAL current default and hands the mediator a
//  `DefaultRouteState` to compare against what it expected.
//
//  LOOP AVOIDANCE lives in two places: this monitor only WAKES the mediator (it never
//  decides drift itself), and the mediator ignores observations inside a short window
//  after it applied a change AND always compares-to-expected — so our own NE-induced
//  route churn never triggers a re-assert against ourselves.
//
//  ISOLATION (load-bearing): the app target defaults to `@MainActor` isolation, and a
//  class-level `nonisolated` does NOT propagate to methods — they'd still default to
//  `@MainActor`. A `DispatchSource` handler then runs a `@MainActor` method on a
//  background queue and Swift 6 traps on the executor check (`swift_task_isCurrentExecutor`
//  → `dispatch_assert_queue`). So EVERY member here is explicitly `nonisolated`, and the
//  dispatch closures are explicitly `@Sendable`, keeping the whole read path off-actor.
//  The mediator hops to main to publish.
//

import Foundation
import Darwin

/// One parsed routing-socket message, reduced to what the Route monitor cares about.
nonisolated struct ParsedRouteMessage: Sendable, Equatable {
    enum Kind: Sendable, Equatable { case add, delete, change, other }
    var kind: Kind
    var family: IPFamily?      // of the destination, nil when undetermined
    var isDefault: Bool        // destination is 0.0.0.0/0 · ::/0 (a default route)
    var interfaceIndex: UInt16

    /// A change to the DEFAULT route we should wake the mediator for.
    var isDefaultRouteChange: Bool {
        isDefault && (kind == .add || kind == .delete || kind == .change)
    }
}

final class PFRouteMonitor: MediatorMonitor, @unchecked Sendable {
    // @unchecked Sendable: every mutable field is guarded by `lock`; the callback is
    // @Sendable and the dispatch source holds only a WEAK self.
    typealias Observation = DefaultRouteState

    private let debounceMS: Int
    private let queue = DispatchQueue(label: "com.bragi0.SimpleVPN.PFRouteMonitor")
    private let lock = NSLock()
    // All three are mutated only under `lock`, so `nonisolated(unsafe)` is the honest
    // annotation: it opts them out of the target's default @MainActor isolation (a
    // class-level `nonisolated` does NOT), which is what lets the off-actor dispatch
    // handlers touch them without an executor-check trap.
    nonisolated(unsafe) private var source: DispatchSourceRead?
    nonisolated(unsafe) private var generation: UInt64 = 0
    nonisolated(unsafe) private var onDrift: (@Sendable (DefaultRouteState) -> Void)?

    nonisolated init(debounce: Duration = .milliseconds(300)) {
        let ms = debounce.components.seconds * 1_000
            + debounce.components.attoseconds / 1_000_000_000_000_000
        self.debounceMS = Int(max(0, ms))
    }

    deinit { cancelSource() }

    nonisolated var isRunning: Bool { lock.withLock { source != nil } }

    /// Open the socket and begin watching. Idempotent.
    nonisolated func start(onDrift: @escaping @Sendable (DefaultRouteState) -> Void) throws {
        lock.lock()
        guard source == nil else { lock.unlock(); return }
        self.onDrift = onDrift
        lock.unlock()

        let descriptor = socket(PF_ROUTE, SOCK_RAW, 0)
        guard descriptor >= 0 else { throw RouteTableError.socketFailed(code: errno) }
        _ = fcntl(descriptor, F_SETFL, fcntl(descriptor, F_GETFL, 0) | O_NONBLOCK)

        let readSource = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
        // Explicit @Sendable so the handlers stay OFF the main actor (see ISOLATION note).
        let onEvent: @Sendable () -> Void = { [weak self] in self?.drain(descriptor) }
        let onCancel: @Sendable () -> Void = { close(descriptor) }
        readSource.setEventHandler(handler: onEvent)
        readSource.setCancelHandler(handler: onCancel)

        lock.lock()
        if source == nil {
            source = readSource
            lock.unlock()
            readSource.resume()
        } else {
            lock.unlock()
            readSource.cancel()   // lost a start() race
        }
    }

    nonisolated func stop() { cancelSource() }

    nonisolated private func cancelSource() {
        let doomed: DispatchSourceRead? = lock.withLock {
            generation &+= 1
            defer { source = nil; onDrift = nil }
            return source
        }
        doomed?.cancel()
    }

    // MARK: Reading (off-main)

    nonisolated private func drain(_ descriptor: Int32) {
        var buffer = [UInt8](repeating: 0, count: 8_192)
        var sawDefaultChange = false
        while true {
            let read = buffer.withUnsafeMutableBytes { raw in
                recv(descriptor, raw.baseAddress, raw.count, 0)
            }
            guard read > 0 else { break }
            for message in Self.parseMessages(buffer, length: read) where message.isDefaultRouteChange {
                sawDefaultChange = true
            }
        }
        if sawDefaultChange { scheduleCallback() }
    }

    nonisolated private func scheduleCallback() {
        let scheduled: UInt64 = lock.withLock { generation &+= 1; return generation }
        let work: @Sendable () -> Void = { [weak self] in
            guard let self else { return }
            let (current, callback) = self.lock.withLock {
                (self.generation == scheduled && self.source != nil, self.onDrift)
            }
            guard current, let callback else { return }   // superseded or stopped
            // Snapshot the REAL default now the burst has settled, and hand it up.
            callback(Self.observedDefault())
        }
        queue.asyncAfter(deadline: .now() + .milliseconds(debounceMS), execute: work)
    }

    // MARK: - Observation (snapshot the real default)

    /// The default route as the kernel currently has it. Prefers the IPv4 default;
    /// `ownedByTunnel` keys on the egress interface being a tunnel (utun/ipsec/ppp).
    nonisolated static func observedDefault() -> DefaultRouteState {
        guard let snapshot = try? RouteTableSource.snapshot() else {
            return DefaultRouteState(ownedByTunnel: false, interface: nil)
        }
        return observedDefault(in: snapshot)
    }

    /// Pure form (testable): the active default's egress from a snapshot. The active
    /// default is the unscoped, non-reject default with the lowest kernel order.
    nonisolated static func observedDefault(in snapshot: RouteTableSnapshot) -> DefaultRouteState {
        let winner = snapshot.routes
            .filter { $0.isDefault && $0.family == .v4 && !$0.isScoped && !$0.isReject }
            .min(by: { $0.order < $1.order })
        guard let iface = winner?.interfaceName else {
            return DefaultRouteState(ownedByTunnel: false, interface: nil)
        }
        return DefaultRouteState(ownedByTunnel: isTunnelInterface(iface), interface: iface)
    }

    /// VPN tunnels surface as `utun*`; native personal VPNs as `ipsec*`/`ppp*`.
    nonisolated static func isTunnelInterface(_ name: String) -> Bool {
        name.hasPrefix("utun") || name.hasPrefix("ipsec") || name.hasPrefix("ppp")
    }

    // MARK: - Parsing (pure — the tests drive this with hand-built rt_msghdr bytes)

    /// Walk a `PF_ROUTE` read buffer into `ParsedRouteMessage`s. Routing-socket
    /// messages are plain `rt_msghdr` (NOT `rt_msghdr2`) headers followed by the same
    /// packed RTAX_* sockaddr array the dump uses, so the sockaddr walker is shared.
    nonisolated static func parseMessages(_ bytes: [UInt8], length: Int) -> [ParsedRouteMessage] {
        var messages: [ParsedRouteMessage] = []
        let headerSize = MemoryLayout<rt_msghdr>.stride
        bytes.withUnsafeBytes { raw in
            var offset = 0
            let end = min(length, raw.count)
            while offset + MemoryLayout<UInt16>.size <= end {
                let messageLength = Int(raw.loadUnaligned(fromByteOffset: offset, as: UInt16.self))
                // A truncated/short read: stop rather than trust a length past the buffer.
                guard messageLength >= headerSize, offset + messageLength <= end else { break }
                let header = raw.loadUnaligned(fromByteOffset: offset, as: rt_msghdr.self)
                defer { offset += messageLength }

                let kind: ParsedRouteMessage.Kind
                switch Int32(header.rtm_type) {
                case RTM_ADD: kind = .add
                case RTM_DELETE: kind = .delete
                case RTM_CHANGE: kind = .change
                default: kind = .other
                }

                let addresses = RouteTableSource.sockaddrs(
                    in: raw, from: offset + headerSize, to: offset + messageLength,
                    mask: header.rtm_addrs)
                let (family, isDefault) = Self.classifyDestination(addresses, flags: header.rtm_flags)
                messages.append(ParsedRouteMessage(kind: kind, family: family,
                                                   isDefault: isDefault,
                                                   interfaceIndex: header.rtm_index))
            }
        }
        return messages
    }

    /// Is the message's destination the default route? A default is an all-zero
    /// destination address with a /0 (absent or all-zero) mask and NOT a host route.
    nonisolated static func classifyDestination(_ addresses: [Int: RouteTableSource.RawSockaddr],
                                                flags: Int32) -> (family: IPFamily?, isDefault: Bool) {
        guard let dst = addresses[Int(RTAX_DST)] else { return (nil, false) }
        let family: IPFamily
        switch Int32(dst.family) {
        case AF_INET: family = .v4
        case AF_INET6: family = .v6
        default: return (nil, false)
        }
        guard flags & RTF_HOST == 0 else { return (family, false) }
        let (destinationBytes, _) = RouteTableSource.addressBytes(dst, family: family)
        guard destinationBytes.allSatisfy({ $0 == 0 }) else { return (family, false) }
        // Mask absent ⇒ /0. Mask present ⇒ default only if every mask byte is zero.
        if let mask = addresses[Int(RTAX_NETMASK)], !mask.isEmpty {
            let maskBytes = mask.slice(RouteTableSource.addressOffset(family), family.byteCount)
            guard maskBytes.allSatisfy({ $0 == 0 }) else { return (family, false) }
        }
        return (family, true)
    }
}
