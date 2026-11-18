// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  opnative-helper — the 1Password SDK's process.
//
//  The Go-SDK c-archive dlopens 1Password's own (AgileBits-signed) IPC dylib,
//  which needs the disable-library-validation relaxation — and AMFI forbids
//  that relaxation on any binary that embeds a System Extension, i.e. the app.
//  So the SDK runs here: a one-shot helper the app spawns per request.
//
//  Protocol (matches OnePasswordNative.swift):
//    opnative-helper probe            → OPNativeProbe JSON on stdout
//    opnative-helper resolve          → reads request JSON on stdin (to EOF),
//                                       writes OPNativeResolve JSON on stdout
//    opnative-helper item             → reads request JSON on stdin (to EOF),
//                                       writes OPNativeGetItem JSON on stdout
//    opnative-helper list             → reads request JSON on stdin (to EOF),
//                                       writes OPNativeList JSON on stdout
//                                       (vault/item OVERVIEWS only — the
//                                       pickers never see a field value)
//    opnative-helper lookup           → reads request JSON on stdin (to EOF),
//                                       writes OPNativeLookup JSON on stdout
//                                       (name → item refs + the vault each
//                                       lives in; OVERVIEWS only)
//  Exit status 0 in all cases (errors travel INSIDE the JSON, so the app has
//  one parsing path); non-zero only for misuse.
//

import Foundation

func emit(_ cString: UnsafeMutablePointer<CChar>?) {
    if let cString {
        defer { OPNativeFree(cString) }
        let bytes = Data(bytesNoCopy: cString, count: strlen(cString), deallocator: .none)
        try? FileHandle.standardOutput.write(contentsOf: bytes)
    } else {
        replyError("empty reply from SDK shim", kind: "other")
    }
}

func replyError(_ message: String, kind: String = "badRequest") {
    let reply = ["error": ["kind": kind, "message": message]]
    if let data = try? JSONEncoder().encode(reply) {
        try? FileHandle.standardOutput.write(contentsOf: data)
    }
}

func request() -> String? {
    var bytes = Data()
    do {
        while let chunk = try FileHandle.standardInput.read(upToCount: 16384), !chunk.isEmpty {
            guard bytes.count + chunk.count <= 1024 * 1024 else { return nil }
            bytes.append(chunk)
        }
        guard !bytes.contains(0) else { return nil }
        return String(data: bytes, encoding: .utf8)
    } catch {
        return nil
    }
}

let mode = CommandLine.arguments.dropFirst().first ?? ""
switch mode {
case "probe":
    emit(OPNativeProbe())
case "resolve", "item", "list", "lookup":
    guard let input = request() else { replyError("unreadable request"); exit(0) }
    switch mode {
    case "resolve": emit(OPNativeResolve(input))
    case "item": emit(OPNativeGetItem(input))
    case "list": emit(OPNativeList(input))
    default: emit(OPNativeLookup(input))
    }
default:
    FileHandle.standardError.write(Data("usage: opnative-helper probe|resolve|item|list|lookup\n".utf8))
    exit(2)
}
