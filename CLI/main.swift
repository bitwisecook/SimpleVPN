// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  main.swift — the `simplevpn` command-line interface.
//
//  A THIN CLIENT: every command is one JSON line to the app's control socket
//  (ControlServer), so the CLI exercises exactly the code paths the UI does —
//  same dispatcher, same MDM guard chain, same readiness rules, same event
//  stream. There is deliberately no logic here beyond argument parsing and
//  rendering; if the CLI can do something the UI can't (or vice versa), that's
//  a bug in the control surface, not a feature of this file.
//
//  Exit codes: 0 ok · 1 failed · 2 not ready (open the app) · 3 denied by
//  policy · 4 app not running · 64 usage.
//

import Foundation
import Darwin

// MARK: - Usage

let usageText = """
simplevpn — control SimpleVPN from the terminal

usage:
  simplevpn list [--json]              every VPN: status, readiness, gateway
  simplevpn status <vpn> [--json]      one VPN in detail
  simplevpn connect <vpn>              connect (stored credentials only)
  simplevpn disconnect <vpn>
  simplevpn pause <vpn>                pause a connected VPN
  simplevpn resume <vpn>
  simplevpn gateway [--json]           which VPN owns the default route
  simplevpn gateway set <vpn>          route all internet traffic via <vpn>
  simplevpn gateway direct             no VPN owns the default route
  simplevpn watch [--json]             stream live events until interrupted
  simplevpn version [--json]           the running app's version

<vpn> is a VPN's name (case-insensitive; a unique prefix works) or its id.
"""

func fail(_ message: String, code: Int32) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(code)
}

// MARK: - Socket client

/// One blocking connection to the app's control socket.
final class ControlClient {
    private let fd: Int32
    private var buffer = Data()

    init() {
        let path = ControlSocket.path()
        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let fit = withUnsafeMutableBytes(of: &addr.sun_path) { raw -> Bool in
            let bytes = Array(path.utf8)
            guard bytes.count < raw.count else { return false }
            raw.copyBytes(from: bytes)
            return true
        }
        let connected = fit && (withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }) == 0
        if !connected {
            fail("SimpleVPN isn't running (no control socket at \(path))", code: 4)
        }
        // A socket can exist while the app is still mid-launch (or wedged) — without
        // timeouts a request then blocks FOREVER. 10s is generous for a local IPC;
        // `watch` overrides receive back to infinite after subscribing.
        setTimeout(seconds: 10)
    }

    /// 0 ⇒ block indefinitely (watch mode).
    func setTimeout(seconds: Int) {
        var tv = timeval(tv_sec: seconds, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
    }

    func send(_ envelope: ControlRequestEnvelope) {
        let data = (try? JSONEncoder().encode(envelope)) ?? Data()
        var line = data
        line.append(0x0A)
        line.withUnsafeBytes { raw in
            var sent = 0
            while sent < raw.count {
                let n = Darwin.send(fd, raw.baseAddress!.advanced(by: sent), raw.count - sent, 0)
                if n <= 0 { fail("SimpleVPN went away mid-request", code: 4) }
                sent += n
            }
        }
    }

    /// Next full JSON line (blocking). nil = the app closed the connection.
    func readLine() -> Data? {
        while true {
            if let nl = buffer.firstIndex(of: 0x0A) {
                let line = buffer.subdata(in: buffer.startIndex..<nl)
                buffer.removeSubrange(buffer.startIndex...nl)
                if !line.isEmpty { return line }
                continue
            }
            var scratch = [UInt8](repeating: 0, count: 16_384)
            let n = scratch.withUnsafeMutableBytes { raw in recv(fd, raw.baseAddress, raw.count, 0) }
            guard n > 0 else { return nil }
            buffer.append(contentsOf: scratch[0..<n])
        }
    }

    /// Send one request and wait for its (id-matched) reply.
    func roundTrip(_ envelope: ControlRequestEnvelope) -> ControlReply {
        send(envelope)
        while let line = readLine() {
            if let reply = try? JSONDecoder().decode(ControlReplyEnvelope.self, from: line),
               reply.id == envelope.id {
                return reply.reply
            }
            // Anything else (an event for another subscriber's fd can't appear
            // here, but be lenient) is skipped.
        }
        fail("SimpleVPN closed the connection without answering", code: 4)
    }
}

// MARK: - Rendering

let wantsJSON = CommandLine.arguments.contains("--json")
var arguments = CommandLine.arguments.dropFirst().filter { $0 != "--json" }

func printJSON(_ reply: ControlReply) {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    if let data = try? encoder.encode(reply) {
        print(String(decoding: data, as: UTF8.self))
    }
}

/// Render + exit with the reply-appropriate code. `render` handles the success shape.
@MainActor
func finish(_ reply: ControlReply, render: (ControlReply) -> Void) -> Never {
    if wantsJSON { printJSON(reply) }
    switch reply {
    case .denied(let why):
        if !wantsJSON { fail("denied by policy: \(why)", code: 3) } ; exit(3)
    case .notReady(let why):
        if !wantsJSON { fail("not ready: \(why)", code: 2) } ; exit(2)
    case .failed(let why):
        if !wantsJSON { fail("error: \(why)", code: 1) } ; exit(1)
    default:
        if !wantsJSON { render(reply) }
        exit(0)
    }
}

func pad(_ s: String, _ width: Int) -> String {
    s.count >= width ? s : s + String(repeating: " ", count: width - s.count)
}

func renderList(_ profiles: [ControlProfileSummary]) {
    guard !profiles.isEmpty else { print("no VPNs configured"); return }
    let nameW = max(4, profiles.map(\.name.count).max() ?? 4)
    let kindW = max(4, profiles.map(\.kind.count).max() ?? 4)
    print("\(pad("NAME", nameW))  \(pad("KIND", kindW))  \(pad("STATUS", 12))  \(pad("READY", 13))  GATEWAY")
    for p in profiles {
        let gw = p.gatewayOwner ? "default" : ""
        print("\(pad(p.name, nameW))  \(pad(p.kind, kindW))  \(pad(p.status, 12))  \(pad(p.readiness, 13))  \(gw)")
    }
}

func renderStatus(_ p: ControlProfileSummary) {
    print("""
    \(p.name) (\(p.kind))
      status:    \(p.status)
      readiness: \(p.readiness)
      server:    \(p.server.isEmpty ? "—" : p.server)
      gateway:   \(p.gatewayOwner ? "owns the default route" : "not the default route")
      id:        \(p.id)
    """)
}

/// Resolve a user-typed name to a profile id, with the SAME rules the app's
/// dispatcher uses (exact id → exact name → unique name prefix), against the
/// app's own profile list.
func resolve(_ text: String, client: ControlClient) -> String {
    let reply = client.roundTrip(ControlRequestEnvelope(id: 1, query: .profiles))
    guard case .profiles(let profiles) = reply else {
        fail("couldn't list VPNs", code: 1)
    }
    if profiles.contains(where: { $0.id == text }) { return text }
    let lowered = text.lowercased()
    if let exact = profiles.first(where: { $0.name.lowercased() == lowered }) { return exact.id }
    let prefixed = profiles.filter { $0.name.lowercased().hasPrefix(lowered) }
    if prefixed.count == 1 { return prefixed[0].id }
    if prefixed.isEmpty { fail("no VPN called \"\(text)\" — try `simplevpn list`", code: 1) }
    fail("\"\(text)\" is ambiguous: \(prefixed.map(\.name).joined(separator: ", "))", code: 1)
}

// MARK: - Commands

guard let verb = arguments.first else { fail(usageText, code: 64) }
arguments = Array(arguments.dropFirst())

@MainActor
func requireTarget(_ what: String) -> String {
    guard let t = arguments.first else { fail("usage: simplevpn \(what) <vpn>", code: 64) }
    return t
}

switch verb {
case "list", "ls":
    let client = ControlClient()
    finish(client.roundTrip(ControlRequestEnvelope(id: 2, query: .profiles))) { reply in
        if case .profiles(let list) = reply { renderList(list) }
    }

case "status":
    let client = ControlClient()
    let id = resolve(requireTarget("status"), client: client)
    finish(client.roundTrip(ControlRequestEnvelope(id: 2, query: .status(profile: id)))) { reply in
        if case .status(let p) = reply { renderStatus(p) }
    }

case "connect", "disconnect", "pause", "resume":
    let client = ControlClient()
    let id = resolve(requireTarget(verb), client: client)
    let command: ControlCommand = switch verb {
    case "connect": .connect(profile: id)
    case "disconnect": .disconnect(profile: id)
    case "pause": .pause(profile: id)
    default: .resume(profile: id)
    }
    finish(client.roundTrip(ControlRequestEnvelope(id: 2, command: command))) { _ in
        print("ok")
    }

case "gateway", "gw":
    let client = ControlClient()
    switch arguments.first {
    case nil:
        let reply = client.roundTrip(ControlRequestEnvelope(id: 2, query: .gateway))
        if case .gateway(let owner) = reply, let owner {
            // Show the NAME — ids are for scripts (--json has them).
            let profiles = client.roundTrip(ControlRequestEnvelope(id: 3, query: .profiles))
            var name = owner
            if case .profiles(let list) = profiles { name = list.first { $0.id == owner }?.name ?? owner }
            finish(reply) { _ in print("default route: \(name)") }
        } else {
            finish(reply) { _ in print("default route: direct (no VPN)") }
        }
    case "direct", "none":
        finish(client.roundTrip(ControlRequestEnvelope(id: 2, command: .setDefaultGateway(profile: nil)))) { _ in
            print("ok — default route is direct")
        }
    case "set":
        guard let target = arguments.dropFirst().first else {
            fail("usage: simplevpn gateway set <vpn>", code: 64)
        }
        let id = resolve(target, client: client)
        finish(client.roundTrip(ControlRequestEnvelope(id: 2, command: .setDefaultGateway(profile: id)))) { _ in
            print("ok")
        }
    default:
        fail("usage: simplevpn gateway [set <vpn> | direct]", code: 64)
    }

case "watch":
    let client = ControlClient()
    let subscribed = client.roundTrip(ControlRequestEnvelope(id: 2, watch: true))
    guard case .ok = subscribed else { fail("couldn't subscribe", code: 1) }
    // Names read better than ids in the human stream.
    var names: [String: String] = [:]
    if case .profiles(let list) = client.roundTrip(ControlRequestEnvelope(id: 3, query: .profiles)) {
        for p in list { names[p.id] = p.name }
    }
    // Watching waits for events indefinitely — lift the request timeout.
    client.setTimeout(seconds: 0)
    let clock = DateFormatter()
    clock.dateFormat = "HH:mm:ss"
    while let line = client.readLine() {
        guard let event = try? JSONDecoder().decode(ControlEvent.self, from: line) else { continue }
        if wantsJSON { print(String(decoding: line, as: UTF8.self)); continue }
        let stamp = clock.string(from: Date())
        switch event {
        case .statusChanged(let profile, let status):
            print("\(stamp)  \(names[profile] ?? profile) → \(status)")
        case .gatewayChanged(let owner):
            print("\(stamp)  default route → \(owner.flatMap { names[$0] ?? $0 } ?? "direct")")
        case .profilesChanged:
            print("\(stamp)  VPN list changed")
            if case .profiles(let list) = client.roundTrip(ControlRequestEnvelope(id: 4, query: .profiles)) {
                for p in list { names[p.id] = p.name }
            }
        case .commandDenied(let cmd, let profile, let reason):
            print("\(stamp)  DENIED \(cmd)\(profile.map { " \(names[$0] ?? $0)" } ?? ""): \(reason)")
        }
    }
    fail("SimpleVPN went away", code: 4)

case "version":
    let client = ControlClient()
    finish(client.roundTrip(ControlRequestEnvelope(id: 2, query: .version))) { reply in
        if case .version(let v) = reply { print("SimpleVPN \(v)") }
    }

case "help", "--help", "-h":
    print(usageText)
    exit(0)

default:
    fail("unknown command \"\(verb)\"\n\n\(usageText)", code: 64)
}
