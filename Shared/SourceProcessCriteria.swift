// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Network

/// Extra predicates evaluated only after verifying the executable's signing identity.
nonisolated struct SourceProcessCriteria: Codable, Equatable, Hashable, Sendable {
    var executableName: String?
    var executablePath: String?
    var ancestorPath: String?
    var httpProxyEndpoint: String?
    var httpProxyVariable: String?

    var isEmpty: Bool {
        executableName == nil && executablePath == nil && ancestorPath == nil
            && httpProxyEndpoint == nil && httpProxyVariable == nil
    }

    var canonicalProxyEndpoint: String? {
        httpProxyEndpoint.flatMap(Self.canonicalEndpoint)
    }

    var isValid: Bool { !isEmpty && problem == nil }

    var problem: String? {
        if let name = executableName, name.isEmpty || name.utf8.count > 255 || name.contains("/")
            || name == "." || name == ".." || Self.hasControl(name) {
            return "Enter an executable filename without a slash."
        }
        for path in [executablePath, ancestorPath].compactMap({ $0 }) where !Self.validPath(path) {
            return "Enter the full executable path, without relative components or a trailing slash."
        }
        if let name = executableName, let path = executablePath,
           path.split(separator: "/").last?.utf8.elementsEqual(name.utf8) != true {
            return "The executable name must match the last component of its path."
        }
        if let key = httpProxyVariable, !["HTTP_PROXY", "http_proxy"].contains(key) || httpProxyEndpoint == nil {
            return "Select a proxy variable and enter its endpoint."
        }
        if httpProxyEndpoint != nil && canonicalProxyEndpoint == nil {
            return "Enter an HTTP proxy host and port. Omit credentials, paths, queries and fragments."
        }
        return nil
    }

    private static func hasControl(_ s: String) -> Bool {
        s.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }

    private static func validPath(_ path: String) -> Bool {
        path.hasPrefix("/") && !path.hasSuffix("/") && path.utf8.count < Int(PATH_MAX) && !hasControl(path)
            && path.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
                .allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }
    }

    /// Resolve spelling differences locally. Never resolve the hostname or retain userinfo.
    static func canonicalEndpoint(_ value: String) -> String? {
        guard !value.isEmpty, value.utf8.count <= 512,
              value.utf8.allSatisfy({ (33...126).contains($0) }),
              !value.contains(where: { "@#?%\\".contains($0) }) else { return nil }
        let authority = value.lowercased().hasPrefix("http://") ? String(value.dropFirst(7)) : value
        let text = authority.hasSuffix("/") ? String(authority.dropLast()) : authority
        guard !text.contains("/"), let colon = text.lastIndex(of: ":") else { return nil }
        let portText = text[text.index(after: colon)...]
        guard !portText.isEmpty, portText.utf8.allSatisfy({ (48...57).contains($0) }),
              let port = UInt16(portText), port > 0 else { return nil }
        let rawHost = String(text[..<colon])
        let host: String
        if rawHost.first == "[", rawHost.last == "]",
           let ip = IPv6Address(String(rawHost.dropFirst().dropLast())) {
            host = "[" + ip.debugDescription + "]"
        } else if let ip = IPv4Address(rawHost) {
            host = ip.debugDescription
        } else {
            let dns = rawHost.hasSuffix(".") ? String(rawHost.dropLast()) : rawHost
            guard !dns.isEmpty, dns.utf8.count <= 253,
                  dns.utf8.contains(where: { (65...90).contains($0) || (97...122).contains($0) }),
                  dns.split(separator: ".", omittingEmptySubsequences: false).allSatisfy({ label in
                      (1...63).contains(label.utf8.count) && label.first != "-" && label.last != "-"
                          && label.utf8.allSatisfy { (97...122).contains($0) || (65...90).contains($0) || (48...57).contains($0) || $0 == 45 }
                  }) else { return nil }
            host = dns.lowercased()
        }
        return host + ":" + String(port)
    }
}

nonisolated enum SourceCriterionVerdict: Equatable, Sendable {
    case matched, different, unavailable
}

extension SourceProcessCriteria {
    /// An older helper must reject any restriction it cannot enforce.
    nonisolated init(from decoder: any Decoder) throws {
        let fields = try decoder.singleValueContainer().decode([String: String].self)
        guard fields.keys.allSatisfy({ CodingKeys(stringValue: $0) != nil }) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath,
                                                     debugDescription: "Unsupported process condition."))
        }
        self.init(executableName: fields["executableName"], executablePath: fields["executablePath"],
                  ancestorPath: fields["ancestorPath"], httpProxyEndpoint: fields["httpProxyEndpoint"],
                  httpProxyVariable: fields["httpProxyVariable"])
    }
}
