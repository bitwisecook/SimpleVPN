// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

enum RoutingEventValidation {
    nonisolated enum Outcome: Equatable {
        case accepted
        case rejected(String)
    }

    private nonisolated struct Receipt: Decodable {
        let version: Int
        let adapter: String
        let engine: String
        let handlers: Int
        let scalarEvents: Int
        let generalEvents: Int
    }

    // The editor and provider each compile untrusted source. Only the checker
    // embedded with this build can attest to the native backend and adapter.
    nonisolated static func check(_ source: String, adapter: String = "wireguard-shared") async -> Outcome {
        guard source.utf8.count <= 32768, !source.utf8.contains(0) else {
            return .rejected("Use at most 32 KiB of handler code, without NUL characters.")
        }
        return await Task.detached(priority: .utility) {
            do {
                let (response, status) = try run(source, arguments: ["--check-live-events", adapter, "-"])
                return outcome(response: response, status: status, adapter: adapter)
            } catch {
                return .rejected("The session event checker could not run.")
            }
        }.value
    }

    // Called on the validation worker or the SSH engine's session queue.
    nonisolated static func run(_ source: String, arguments: [String]) throws -> (Data, Int32) {
        let tool = Process()
        tool.executableURL = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/routecheck")
        tool.arguments = arguments
        let input = Pipe(), output = Pipe()
        tool.standardInput = input
        tool.standardError = output
        tool.standardOutput = output
        do {
            try tool.run()
            try input.fileHandleForWriting.write(contentsOf: Data(source.utf8))
            try input.fileHandleForWriting.close()
            let data = try output.fileHandleForReading.readToEnd() ?? Data()
            tool.waitUntilExit()
            return (data, tool.terminationStatus)
        } catch {
            try? input.fileHandleForWriting.close()
            if tool.isRunning { tool.terminate() }
            throw error
        }
    }

    nonisolated static func outcome(response: Data, status: Int32, adapter: String = "wireguard-shared") -> Outcome {
        guard status == 0 else {
            let diagnostic = String(decoding: response.prefix(1024), as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            return .rejected(diagnostic.isEmpty ? "The session event checker exited before validating the rules." : diagnostic)
        }
        guard response.count <= 1024,
              let receipt = try? JSONDecoder().decode(Receipt.self, from: response),
              receipt.version == 1, receipt.adapter == adapter, receipt.engine == "rust-aot",
              (0...128).contains(receipt.handlers),
              (0...receipt.handlers).contains(receipt.scalarEvents),
              (0...(receipt.handlers - receipt.scalarEvents)).contains(receipt.generalEvents) else {
            return .rejected("The session event checker returned an incompatible routing plan response.")
        }
        return .accepted
    }
}
