// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation

extension SVPPacketPolicy {
    static func compile(adapter: String, profile: String?, kind: VPNKind, source: String?) throws -> SVPPacketPolicy {
        var failure: UnsafeMutablePointer<CChar>?
        let identity = profile ?? ""
        guard identity.utf8.count <= 256, !identity.utf8.contains(0) else {
            throw NSError(domain: "SimpleVPN.PacketPolicy", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "The saved VPN has an invalid profile identifier."
            ])
        }
        let handle = PPCreateWithContext(adapter, identity, kind.rawValue, source ?? "", &failure)
        defer { if let failure { PPFree(failure) } }
        guard handle != 0 else {
            throw NSError(domain: "SimpleVPN.PacketPolicy", code: 1, userInfo: [
                NSLocalizedDescriptionKey: failure.map { String(cString: $0) } ?? "Could not initialize the packet routing policy."
            ])
        }
        return SVPPacketPolicy(handle: handle)
    }

    /// NE owns the original data. Only a direction with live handlers needs writable bytes.
    func routeOutbound(_ packets: [Data], send: (Data) -> Void) {
        if !inspectOutbound {
            guard observeOutboundBatch(packets) else { return }
            for packet in packets { send(packet) }
            return
        }
        for var packet in packets {
            let allowed = packet.withUnsafeMutableBytes { raw in
                guard let base = raw.baseAddress else { return false }
                return apply(base, length: UInt(raw.count), inbound: false)
            }
            if allowed { send(packet) }
        }
    }

    func routeInbound(_ packet: Data) -> Data? {
        if !inspectInbound {
            let allowed = packet.withUnsafeBytes { raw in
                guard let base = raw.baseAddress else { return false }
                return observePacket(base, length: UInt(raw.count), inbound: true)
            }
            return allowed ? packet : nil
        }
        var edited = packet
        let allowed = edited.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return false }
            return apply(base, length: UInt(raw.count), inbound: true)
        }
        return allowed ? edited : nil
    }
}
