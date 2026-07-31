// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  AppConnectionInspector.swift
//  Which applications hold live TCP connections over a VPN right now — the
//  answer the quit-confirmation needs ("Slack and Safari are using this VPN").
//
//  Mechanism: a connection routed through a tunnel binds its LOCAL address to
//  the tunnel's in-tunnel address, so matching established TCP sockets by
//  local address against the active tunnels' addresses identifies VPN traffic
//  exactly — no route lookups. Enumeration is libproc (proc_listpids →
//  PROC_PIDLISTFDS → PROC_PIDFDSOCKETINFO), the same kernel interface lsof
//  uses — binary structs, never parsed tool output (house rule). Only the
//  user's own processes are visible, which is precisely the set worth naming
//  in a quit dialog.
//

import Foundation
import AppKit

enum AppConnectionInspector {

    /// One application's use of the tunnel: a human name + connection count.
    struct AppUsage: Identifiable, Equatable {
        let name: String
        let connections: Int
        var id: String { name }
    }

    /// Applications with at least one ESTABLISHED TCP socket whose local
    /// address is one of `tunnelAddresses` (the active VPNs' in-tunnel IPv4/v6
    /// addresses). Sorted busiest-first. Our own process is excluded — the app
    /// asking the question isn't news.
    static func appsUsingTunnel(tunnelAddresses: Set<String>) -> [AppUsage] {
        guard !tunnelAddresses.isEmpty else { return [] }
        var counts: [String: Int] = [:]
        let ourPID = ProcessInfo.processInfo.processIdentifier

        for pid in allPIDs() where pid > 0 && pid != ourPID {
            let matches = establishedTunnelSockets(pid: pid, tunnelAddresses: tunnelAddresses)
            guard matches > 0 else { continue }
            counts[friendlyName(pid: pid), default: 0] += matches
        }
        return counts
            .map { AppUsage(name: $0.key, connections: $0.value) }
            .sorted { ($0.connections, $1.name) > ($1.connections, $0.name) }
    }

    // MARK: libproc plumbing

    private static func allPIDs() -> [pid_t] {
        let bytes = proc_listpids(UInt32(PROC_ALL_PIDS), 0, nil, 0)
        guard bytes > 0 else { return [] }
        // Headroom for processes spawned between the two calls.
        var pids = [pid_t](repeating: 0, count: Int(bytes) / MemoryLayout<pid_t>.size + 32)
        let filled = proc_listpids(UInt32(PROC_ALL_PIDS), 0, &pids,
                                   Int32(pids.count * MemoryLayout<pid_t>.size))
        guard filled > 0 else { return [] }
        return Array(pids.prefix(Int(filled) / MemoryLayout<pid_t>.size))
    }

    /// Count of this process's established TCP sockets local-bound to a tunnel.
    private static func establishedTunnelSockets(pid: pid_t, tunnelAddresses: Set<String>) -> Int {
        let fdBytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard fdBytes > 0 else { return 0 }   // not ours to inspect (or gone)
        var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(fdBytes) / MemoryLayout<proc_fdinfo>.size + 16)
        let got = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, Int32(fds.count * MemoryLayout<proc_fdinfo>.size))
        guard got > 0 else { return 0 }

        var matches = 0
        for fd in fds.prefix(Int(got) / MemoryLayout<proc_fdinfo>.size)
        where fd.proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) {
            var sock = socket_fdinfo()
            let size = proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDSOCKETINFO, &sock,
                                      Int32(MemoryLayout<socket_fdinfo>.size))
            guard size == Int32(MemoryLayout<socket_fdinfo>.size),
                  sock.psi.soi_kind == Int32(SOCKINFO_TCP),
                  sock.psi.soi_proto.pri_tcp.tcpsi_state == Int32(TSI_S_ESTABLISHED)
            else { continue }
            if let local = localAddress(of: sock.psi.soi_proto.pri_tcp.tcpsi_ini),
               tunnelAddresses.contains(local) {
                matches += 1
            }
        }
        return matches
    }

    /// The socket's local address, presentation form ("10.8.0.6", "fd00::5").
    private static func localAddress(of ini: in_sockinfo) -> String? {
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        if ini.insi_vflag & UInt8(INI_IPV4) != 0 {
            var a = ini.insi_laddr.ina_46.i46a_addr4
            guard inet_ntop(AF_INET, &a, &buf, socklen_t(buf.count)) != nil else { return nil }
        } else if ini.insi_vflag & UInt8(INI_IPV6) != 0 {
            var a = ini.insi_laddr.ina_6
            guard inet_ntop(AF_INET6, &a, &buf, socklen_t(buf.count)) != nil else { return nil }
        } else {
            return nil
        }
        return String(cBuffer: buf)
    }

    // MARK: Naming

    /// A name a person recognises: the running app's display name where there
    /// is one, else the BSD process name — with helper-process noise stripped
    /// so "Google Chrome Helper (Network)" reads as "Google Chrome".
    private static func friendlyName(pid: pid_t) -> String {
        if let app = NSRunningApplication(processIdentifier: pid),
           let name = app.localizedName, !name.isEmpty {
            return stripHelperNoise(name)
        }
        var buf = [CChar](repeating: 0, count: 2 * Int(MAXCOMLEN) + 1)
        let n = proc_name(pid, &buf, UInt32(buf.count))
        let raw = n > 0 ? String(cBuffer: buf) : "another program"
        return stripHelperNoise(raw)
    }

    private static func stripHelperNoise(_ name: String) -> String {
        var s = name
        if let r = s.range(of: " Helper") { s = String(s[..<r.lowerBound]) }
        if let r = s.range(of: " (") { s = String(s[..<r.lowerBound]) }
        let trimmed = s.trimmingCharacters(in: .whitespaces)
        return trimmed.isEmpty ? name : trimmed
    }
}
