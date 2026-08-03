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
        FileHandle.standardOutput.write(Data(String(cString: cString).utf8))
        OPNativeFree(cString)
    } else {
        FileHandle.standardOutput.write(Data(#"{"error":{"kind":"other","message":"empty reply from SDK shim"}}"#.utf8))
    }
}

let mode = CommandLine.arguments.dropFirst().first ?? ""
switch mode {
case "probe":
    emit(OPNativeProbe())
case "resolve":
    let request = FileHandle.standardInput.readDataToEndOfFile()
    let requestString = String(data: request, encoding: .utf8) ?? ""
    emit(OPNativeResolve(requestString))
case "item":
    let request = FileHandle.standardInput.readDataToEndOfFile()
    let requestString = String(data: request, encoding: .utf8) ?? ""
    emit(OPNativeGetItem(requestString))
case "list":
    let request = FileHandle.standardInput.readDataToEndOfFile()
    let requestString = String(data: request, encoding: .utf8) ?? ""
    emit(OPNativeList(requestString))
case "lookup":
    let request = FileHandle.standardInput.readDataToEndOfFile()
    let requestString = String(data: request, encoding: .utf8) ?? ""
    emit(OPNativeLookup(requestString))
default:
    FileHandle.standardError.write(Data("usage: opnative-helper probe|resolve|item|list|lookup\n".utf8))
    exit(2)
}
