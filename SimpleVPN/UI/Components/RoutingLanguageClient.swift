// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Darwin

/// One stdio peer serves open routing editors. Neither side opens the document URI.
@MainActor
final class RoutingLanguageClient {
    static let shared = RoutingLanguageClient()
    typealias Object = [String: Any]

    private var process: Process?
    private var writer: FileHandle?
    private var reader: FileHandle?
    private let writes = DispatchQueue(label: "com.bragi0.SimpleVPN.routing-lsp.send", qos: .utility)
    private var input = Data()
    private var initialized = false
    private var generation = UUID()
    private var documents: [String: RoutingEditorDocument] = [:]
    private var requests: [Int: (String?, (Any?) -> Void)] = [:]
    private var nextID = 0
    private static let limit = 1 << 20

    func open(_ document: RoutingEditorDocument) {
        documents[document.uri] = document
        if initialized { sendOpen(document); return }
        guard process == nil else { return }
        let worker = Process()
        let rx = Pipe(), tx = Pipe()
        worker.executableURL = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/routing-lsp")
        worker.standardInput = tx
        worker.standardOutput = rx
        worker.standardError = FileHandle.nullDevice
        let token = generation
        let handle = rx.fileHandleForReading
        handle.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            Task { @MainActor in
                guard let self, self.generation == token else { return }
                if data.isEmpty { self.failed() } else { self.receive(data) }
            }
        }
        worker.terminationHandler = { [weak self] _ in
            Task { @MainActor in
                guard let self, self.generation == token else { return }
                self.failed()
            }
        }
        process = worker
        writer = tx.fileHandleForWriting
        _ = fcntl(tx.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1)
        reader = handle
        do { try worker.run() }
        catch { failed(); return }
        request("initialize", params: ["processId": NSNull(), "rootUri": NSNull(), "capabilities": [:]], uri: nil) { [weak self] result in
            guard let self, result != nil else { self?.failed(); return }
            initialized = true
            notify("initialized", [:])
            for document in documents.values { sendOpen(document) }
        }
    }

    private func sendOpen(_ doc: RoutingEditorDocument) {
        notify("textDocument/didOpen", ["textDocument": ["uri": doc.uri, "version": doc.version,
                "text": doc.source, "languageId": "simplevpn-routing"], "adapter": doc.adapter])
        doc.opened()
    }

    func change(_ doc: RoutingEditorDocument) {
        guard initialized, documents[doc.uri] === doc else { return }
        notify("textDocument/didChange", ["textDocument": ["uri": doc.uri, "version": doc.version],
                                           "contentChanges": [["text": doc.source]]])
    }

    func close(_ doc: RoutingEditorDocument) {
        guard documents.removeValue(forKey: doc.uri) != nil else { return }
        if initialized { notify("textDocument/didClose", ["textDocument": ["uri": doc.uri]]) }
        requests = requests.filter { $0.value.0 != doc.uri }
        if documents.isEmpty { stop() }
    }

    func request(_ method: String, params: Object, uri: String?, reply: @escaping (Any?) -> Void) {
        guard process != nil, uri == nil || initialized, requests.count < 48 else { reply(nil); return }
        nextID += 1
        requests[nextID] = (uri, reply)
        send(["jsonrpc":"2.0", "id":nextID, "method":method, "params":params])
    }

    private func notify(_ method: String, _ params: Object) { send(["jsonrpc":"2.0", "method":method, "params":params]) }
    private func send(_ object: Object) {
        guard let writer, let body = try? JSONSerialization.data(withJSONObject: object), body.count <= Self.limit else { return }
        var frame = Data("Content-Length: \(body.count)\r\n\r\n".utf8)
        frame.append(body)
        let message = frame, token = generation
        writes.async { [weak self] in
            do { try writer.write(contentsOf: message) }
            catch { Task { @MainActor in if self?.generation == token { self?.failed() } } }
        }
    }

    private func receive(_ data: Data) {
        input.append(data)
        let separator = Data([13,10,13,10])
        while let header = input.range(of: separator) {
            guard header.lowerBound - input.startIndex <= 4096,
                  let raw = String(data: input[..<header.lowerBound], encoding: .ascii) else { failed(); return }
            let lengths = raw.components(separatedBy: "\r\n").compactMap { line -> Int? in
                let pair = line.split(separator: ":", maxSplits: 1)
                guard pair.count == 2 && pair[0].lowercased() == "content-length" else { return nil }
                return Int(pair[1].trimmingCharacters(in: .whitespaces))
            }
            guard lengths.count == 1, let length = lengths.first, (0...Self.limit).contains(length) else { failed(); return }
            let end = header.upperBound + length
            guard end <= input.endIndex else { return }
            let body = input[header.upperBound..<end]
            guard let msg = (try? JSONSerialization.jsonObject(with: body)) as? Object else { failed(); return }
            input.removeSubrange(input.startIndex..<end)
            if let id = msg["id"] as? Int {
                requests.removeValue(forKey: id)?.1(msg["result"] ?? msg["error"])
            } else if msg["method"] as? String == "textDocument/publishDiagnostics",
                      let p = msg["params"] as? Object, let uri = p["uri"] as? String {
                documents[uri]?.publish(p)
            }
        }
        if input.count > 4096 { failed() }
    }

    private func failed() {
        for doc in documents.values { doc.unavailable() }
        stop()
    }

    private func stop() {
        generation = UUID()
        initialized = false
        requests.removeAll()
        input.removeAll()
        reader?.readabilityHandler = nil
        if let process, process.isRunning { process.terminate() }
        try? writer?.close()
        try? reader?.close()
        process = nil
        writer = nil
        reader = nil
    }
}
