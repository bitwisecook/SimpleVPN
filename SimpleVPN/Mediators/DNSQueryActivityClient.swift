// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

enum DNSQueryActivityClient {
    static func fetch(generation: Data, ruleCount: Int) async -> DNSQueryActivity? {
        guard !Task.isCancelled, generation.count == 32, (0...256).contains(ruleCount) else { return nil }
        let connection = NSXPCConnection(machServiceName: DNSQueryActivityWire.serviceName, options: .privileged)
        let response = ProviderMessageResponse()
        connection.setCodeSigningRequirement(DNSQueryActivityWire.providerRequirement)
        connection.remoteObjectInterface = NSXPCInterface(with: DNSQueryActivityReading.self)
        connection.invalidationHandler = { response.finish(nil) }
        connection.interruptionHandler = { response.finish(nil) }
        connection.resume()
        defer { connection.invalidate() }
        let data: Data? = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                guard response.install(continuation) else { return }
                guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in response.finish(nil) }) as? DNSQueryActivityReading else {
                    response.finish(nil)
                    return
                }
                DispatchQueue.global().asyncAfter(deadline: .now() + 2) { [weak response] in response?.finish(nil) }
                proxy.readCounts(generation) { response.finish($0) }
            }
        } onCancel: { response.finish(nil) }

        guard !Task.isCancelled, let data, data.count <= DNSQueryActivityWire.maximumBytes,
              let sample = try? JSONDecoder().decode(DNSQueryActivity.self, from: data),
              sample.agrees(with: generation, ruleCount: ruleCount) else { return nil }
        return sample
    }
}
