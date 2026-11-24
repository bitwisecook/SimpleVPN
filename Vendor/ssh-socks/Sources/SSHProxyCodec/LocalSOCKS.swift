// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import NIOCore

public enum LocalSOCKS {
    public enum Request: Equatable, Sendable {
        case incomplete
        case invalid(UInt8)
        case connect(host: String, port: Int, consumed: Int)
    }

    public static func greeting(_ input: Data) throws -> (accepted: Bool, consumed: Int)? {
        var buffer = ByteBuffer(bytes: input)
        guard let greeting = try buffer.readClientGreeting() else { return nil }
        return (greeting.methods.contains(.noneRequired), buffer.readerIndex)
    }

    public static func selection(accepted: Bool) -> Data {
        var buffer = ByteBuffer()
        buffer.writeMethodSelection(.init(method: accepted ? .noneRequired : .noneAcceptable))
        return Data(buffer.readableBytesView)
    }

    public static func request(_ input: Data) -> Request {
        // Reply as soon as an unsupported command or empty name is known, even
        // if the peer waits for rejection before sending the rest of its frame.
        let head = input.prefix(5)
        if head.first == 5 && head.dropFirst().first.map({ $0 != SOCKSCommand.connect.value }) == true {
            return .invalid(SOCKSServerReply.commandUnsupported.value)
        }
        if head.elementsEqual([5,1,0,3,0]) { return .invalid(SOCKSServerReply.addressUnsupported.value) }
        var buffer = ByteBuffer(bytes: input)
        do {
            guard let frame = try buffer.readClientRequest() else { return .incomplete }
            let host: String
            let port: Int
            switch frame.addressType {
            case .address(let address):
                guard let ip = address.ipAddress, let number = address.port else { return .invalid(8) }
                host = ip
                port = number
            case .domain(let domain, let number):
                guard !domain.isEmpty, !domain.contains("\0"), !domain.contains("\u{FFFD}") else { return .invalid(8) }
                host = domain
                port = number
            }
            guard port != 0 else { return .invalid(1) }
            return .connect(host: host, port: port, consumed: buffer.readerIndex)
        } catch is SOCKSError.InvalidAddressType {
            return .invalid(SOCKSServerReply.addressUnsupported.value)
        } catch {
            return .invalid(SOCKSServerReply.serverFailure.value)
        }
    }

    // A fixed literal recognized by inet_pton on every supported platform.
    private static let unspecified = try! SocketAddress(ipAddress: "0.0.0.0", port: 0)

    public static func response(_ status: UInt8) -> Data {
        // RFC 1928 permits the all-zero bound endpoint for a CONNECT relay.
        var buffer = ByteBuffer()
        buffer.writeServerResponse(.init(reply: .init(value: status), boundAddress: .address(unspecified)))
        return Data(buffer.readableBytesView)
    }
}
