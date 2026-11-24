// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import NetworkExtension

/// IDs survive renames. The executable's designated requirement binds the rule
/// to a signer, while the name is only used for display.
nonisolated struct VPNApplicationRoute: Codable, Hashable, Identifiable, Sendable {
    var id: String
    var name: String
    var signingIdentifier: String
    var designatedRequirement: String
    var port: String
    struct Destination: Codable, Equatable, Hashable, Sendable {
        var prefix: String
        var port: String
    }
    var destinations: [Destination]?
    /// A present but incomplete constraint is never an app-wide rule.
    var processCriteria: SourceProcessCriteria? = nil

    var processCriteriaProblem: String? {
        guard let processCriteria else { return nil }
        if processCriteria.isEmpty { return "Enter a process condition or explicitly turn off process conditions." }
        return processCriteria.problem
    }

    /// Two instances of the same signed executable can be assigned to different
    /// VPNs only if their conditions cannot both pass. A process can have more
    /// than one ancestor, so different ancestor paths alone do not establish that.
    func conflicts(with other: Self) -> Bool {
        guard signingIdentifier == other.signingIdentifier else { return false }
        if processCriteria == nil && other.processCriteria == nil {
            return designatedRequirement == other.designatedRequirement
        }
        guard let lhs = processCriteria, let rhs = other.processCriteria else { return true }
        if let a = lhs.executableName, let b = rhs.executableName, a != b { return false }
        if let a = lhs.executablePath, let b = rhs.executablePath, a != b { return false }
        if (lhs.httpProxyVariable ?? "HTTP_PROXY") == (rhs.httpProxyVariable ?? "HTTP_PROXY"),
           let a = lhs.canonicalProxyEndpoint, let b = rhs.canonicalProxyEndpoint, a != b { return false }
        return true
    }

    func destinationProblem(memberIDs: Set<String>) -> String? {
        guard let destinations else { return nil }
        guard destinations.count <= 64 else { return "Choose up to 64 destination overrides per source." }
        var networks = Set<String>()
        for override in destinations {
            guard memberIDs.contains(override.port) else { return "Choose an available VPN for each destination." }
            guard let prefix = RoutePrefixMath.canonicalNetwork(override.prefix) else {
                return "Enter an IPv4 or IPv6 address, or a subnet starting at its network address."
            }
            guard networks.insert(prefix).inserted else { return "Choose each destination only once for this source." }
        }
        return nil
    }
}

/// A process selection belongs only to this run of the app. Never encode the
/// full selection into preferences, logs, or an exported composition.
nonisolated struct VPNProcessRoute: Equatable, Sendable {
    var route: VPNApplicationRoute
    var auditToken: Data
}

nonisolated struct VPNApplicationCapture: Codable, Equatable, Sendable {
    var routes: [VPNApplicationRoute]
    var processRouteIDs: Set<String>
    /// Populated only in the generated provider configuration, after checking the signed app on disk.
    var launcherIdentities: [String: SourceSigningIdentity]?

    /// The packet router counts each source default and each destination override.
    static let maximumRules = 4096
    var fitsRuleBudget: Bool {
        routes.reduce(routes.count) { $0 + ($1.destinations?.count ?? 0) } <= Self.maximumRules
    }

    var requiresProcessCriteria: Bool { routes.contains { $0.processCriteria != nil } }

    var sourceRules: [VirtualRoutingPolicy.SourceRule] {
        routes.map { route in
            .init(source: route.id, port: route.port, destinations: route.destinations?.map { target in
                .init(prefix: RoutePrefixMath.canonicalNetwork(target.prefix) ?? target.prefix, port: target.port)
            })
        }
    }

    private struct CaptureExecutable: Hashable {
        let identifier: String
        let requirement: String
        var path: String?

        static func == (a: Self, b: Self) -> Bool {
            a.identifier.utf8.elementsEqual(b.identifier.utf8) && a.requirement.utf8.elementsEqual(b.requirement.utf8)
                && a.path.map { Data($0.utf8) } == b.path.map { Data($0.utf8) }
        }

        func hash(into hasher: inout Hasher) {
            hasher.combine(Data(identifier.utf8))
            hasher.combine(Data(requirement.utf8))
            hasher.combine(path.map { Data($0.utf8) })
        }

        static func ordered(_ a: Self, _ b: Self) -> Bool {
            (a.identifier, a.requirement, a.path ?? "") < (b.identifier, b.requirement, b.path ?? "")
        }

        func rule() -> NEAppRule {
            let rule = NEAppRule(signingIdentifier: identifier, designatedRequirement: requirement)
            if let path { rule.matchPath = path }
            return rule
        }

        func matches(_ actual: NEAppRule) -> Bool {
            guard actual.matchSigningIdentifier.utf8.elementsEqual(identifier.utf8),
                  actual.matchDesignatedRequirement.utf8.elementsEqual(requirement.utf8) else { return false }
            switch (path, actual.matchPath) {
            case (nil, nil): return true
            case (let left?, let right?): return left.utf8.elementsEqual(right.utf8)
            default: return false
            }
        }
    }

    private struct CaptureRule {
        let executable: CaptureExecutable
        var tools: Set<CaptureExecutable>?

        func matches(_ actual: NEAppRule, strictDomains: Bool) -> Bool {
            guard executable.matches(actual),
                  strictDomains ? actual.matchDomains == nil : (actual.matchDomains ?? []).isEmpty else { return false }
            switch (tools, actual.matchTools) {
            case (nil, nil): return true
            case (let expected?, let installed?):
                guard !expected.isEmpty, expected.count == installed.count else { return false }
                var remaining = Array(expected)
                for tool in installed {
                    guard tool.matchTools == nil, tool.matchDomains == nil,
                          let index = remaining.firstIndex(where: { $0.matches(tool) }) else { return false }
                    remaining.remove(at: index)
                }
                return remaining.isEmpty
            default: return false
            }
        }
    }

    // The responsible app can be several generations above the actual tool.
    // A bare shell executable has no enclosing application to place in an NEAppRule.
    private static func appBundle(containing path: String) -> URL? {
        guard path.hasPrefix("/") else { return nil }
        let components = path.split(separator: "/")
        guard let index = components.lastIndex(where: { $0.lowercased().hasSuffix(".app") }) else { return nil }
        return URL(fileURLWithPath: "/" + components[...index].joined(separator: "/"), isDirectory: true)
    }

    private var launcherPaths: Set<String> {
        Set(routes.compactMap { route in
            guard let path = route.processCriteria?.ancestorPath, Self.appBundle(containing: path) != nil else { return nil }
            return path
        })
    }

    var requiresLauncherRules: Bool { !launcherPaths.isEmpty }

    var hasPreparedLauncherRules: Bool {
        let paths = launcherPaths
        if paths.isEmpty { return launcherIdentities == nil }
        guard let identities = launcherIdentities, identities.count == paths.count,
              routes.allSatisfy({ route in
                  guard let path = route.processCriteria?.ancestorPath, Self.appBundle(containing: path) != nil else { return true }
                  return identities.keys.contains { $0.utf8.elementsEqual(path.utf8) }
              }) else { return false }
        return identities.allSatisfy { path, identity in
            guard !identity.signingIdentifier.isEmpty, identity.signingIdentifier.utf8.count <= 512,
                  !identity.signingIdentifier.utf8.contains(0),
                  SourceIdentityWire.isBoundRequirement(identity.designatedRequirement, temporary: false),
                  let bundle = Self.appBundle(containing: path) else { return false }
            let executable = URL(fileURLWithPath: path)
            return executable.deletingLastPathComponent().path.utf8.elementsEqual(bundle.appendingPathComponent("Contents/MacOS").path.utf8)
        }
    }

    /// Resolve the launcher's signed bundle and main executable before writing NE preferences.
    /// The provider validates the frozen plan without needing filesystem access to the selected apps.
    func preparingLauncherRules(inspect: @Sendable (URL) async throws -> SourceSigningIdentity) async throws -> Self {
        let paths = launcherPaths
        guard !paths.isEmpty else { return self }
        func unavailable(_ message: String) -> NSError {
            NSError(domain: "SimpleVPN.AppRules", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
        }
        var identities: [String: SourceSigningIdentity] = [:]
        var verifiedTools: [String: SourceSigningIdentity] = [:]
        for path in paths.sorted() {
            try Task.checkCancellation()
            let url = URL(fileURLWithPath: path)
            guard let app = Self.appBundle(containing: path), let bundle = Bundle(url: app),
                  bundle.object(forInfoDictionaryKey: "CFBundlePackageType") as? String == "APPL",
                  let executable = bundle.executableURL, executable.path.utf8.elementsEqual(path.utf8),
                  url.resolvingSymlinksInPath().path.utf8.elementsEqual(path.utf8) else {
                throw unavailable("Choose the full path to the launcher app’s main executable in Contents/MacOS.")
            }
            let identity = try await inspect(app)
            let main = try await inspect(url)
            guard identity.signingIdentifier.utf8.elementsEqual(main.signingIdentifier.utf8),
                  identity.designatedRequirement.utf8.elementsEqual(main.designatedRequirement.utf8) else {
                throw unavailable("The launcher app and its main executable have different signing identities.")
            }
            identities[path] = identity
        }
        for route in routes {
            guard let criteria = route.processCriteria, let launcher = criteria.ancestorPath, paths.contains(launcher),
                  let toolPath = criteria.executablePath else { continue }
            try Task.checkCancellation()
            let url = URL(fileURLWithPath: toolPath, isDirectory: false)
            guard (try? url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true,
                  FileManager.default.isExecutableFile(atPath: toolPath),
                  url.resolvingSymlinksInPath().path.utf8.elementsEqual(toolPath.utf8) else {
                throw unavailable("Choose the tool’s executable file, using its full path after resolving symbolic links.")
            }
            if verifiedTools[toolPath] == nil { verifiedTools[toolPath] = try await inspect(url) }
            guard let actual = verifiedTools[toolPath], actual.signingIdentifier.utf8.elementsEqual(route.signingIdentifier.utf8),
                  actual.designatedRequirement.utf8.elementsEqual(route.designatedRequirement.utf8) else {
                throw unavailable("The tool at the configured path has a different signature from the selected application.")
            }
        }
        var result = self
        result.launcherIdentities = identities
        guard result.hasPreparedLauncherRules else { throw unavailable("The signed launcher rules could not be verified.") }
        return result
    }

    private var plannedRules: [CaptureRule]? {
        guard hasPreparedLauncherRules else { return nil }
        var direct = Set<CaptureExecutable>()
        var nested: [CaptureExecutable: Set<CaptureExecutable>] = [:]
        for route in routes {
            guard let original = SourceIdentityWire.captureRequirement(route.designatedRequirement, temporary: processRouteIDs.contains(route.id))
            else { return nil }
            var tool = CaptureExecutable(identifier: route.signingIdentifier, requirement: original)
            if let path = route.processCriteria?.ancestorPath, let app = launcherIdentities?[path] {
                guard let dr = SourceIdentityWire.captureRequirement(app.designatedRequirement, temporary: false) else { return nil }
                tool.path = route.processCriteria?.executablePath
                let launcher = CaptureExecutable(identifier: app.signingIdentifier, requirement: dr, path: path)
                nested[launcher, default: []].insert(tool)
            }
            direct.insert(tool)
        }
        // An explicit signer-wide tool already covers every path for that signer.
        // Keep a single direct rule when another source picked a narrower path.
        let ordinary = direct.filter { executable in
            executable.path == nil || !direct.contains(CaptureExecutable(identifier: executable.identifier, requirement: executable.requirement))
        }.sorted(by: CaptureExecutable.ordered).map { CaptureRule(executable: $0) }
        return ordinary + nested.keys.sorted(by: CaptureExecutable.ordered).map { CaptureRule(executable: $0, tools: nested[$0]) }
    }

    func makeAppRules() -> [NEAppRule] {
        guard let plannedRules else { return [] }
        return plannedRules.map { plan in
            let rule = plan.executable.rule()
            if let tools = plan.tools { rule.matchTools = tools.sorted(by: CaptureExecutable.ordered).map { $0.rule() } }
            return rule
        }
    }

    func matchesInstalledRules(_ installed: [NEAppRule]?) -> Bool {
        guard let installed, !installed.isEmpty, var remaining = plannedRules,
              installed.count == remaining.count else { return false }
        let strictDomains = requiresLauncherRules
        for rule in installed {
            guard let index = remaining.firstIndex(where: { $0.matches(rule, strictDomains: strictDomains) }) else { return false }
            remaining.remove(at: index)
        }
        return remaining.isEmpty
    }

    func isValid(memberIDs: Set<String>) -> Bool {
        let ids = Set(routes.map(\.id))
        let persistent = routes.filter { !processRouteIDs.contains($0.id) }
        return (1...SourceIdentityWire.maximumCandidates).contains(routes.count) && fitsRuleBudget && ids.count == routes.count
            && processRouteIDs.isSubset(of: ids)
            && !persistent.enumerated().contains { index, route in
                persistent.prefix(index).contains { route.conflicts(with: $0) }
            }
            && routes.allSatisfy {
                $0.processCriteriaProblem == nil && (!processRouteIDs.contains($0.id) || $0.processCriteria == nil)
                    && memberIDs.contains($0.port) && $0.destinationProblem(memberIDs: memberIDs) == nil && !$0.id.isEmpty && $0.id.utf8.count <= 80
                    && $0.id.utf8.allSatisfy { byte in
                        (65...90).contains(byte) || (97...122).contains(byte) || (48...57).contains(byte) || byte == 45 || byte == 95
                    }
                    && !$0.signingIdentifier.isEmpty && $0.signingIdentifier.utf8.count <= 512
                    && SourceIdentityWire.isBoundRequirement($0.designatedRequirement, temporary: processRouteIDs.contains($0.id))
                    && !$0.signingIdentifier.utf8.contains(0) && !$0.designatedRequirement.utf8.contains(0)
            }
    }

    func accepts(processTokens: [String: Data]) -> Bool {
        Set(processTokens.keys) == processRouteIDs && Set(processTokens.values).count == processTokens.count
            && processTokens.values.allSatisfy { SourceProcessInstance.processGeneration(auditToken: $0) != nil }
    }

    /// Only the selected process generation can use its override. If the app
    /// was also selected, other instances remain eligible for the app rule.
    func candidates(token: Data, signingIdentifier: String, processTokens: [String: Data]) -> [VPNApplicationRoute] {
        let matching = routes.filter { $0.signingIdentifier == signingIdentifier }
        if let exact = matching.first(where: { processTokens[$0.id] == token }) { return [exact] }
        return matching.filter { !processRouteIDs.contains($0.id) }
    }
}
