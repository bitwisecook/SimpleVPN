// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  LogoStore.swift
//  Per-profile custom logos, stored as PNG in Application Support (UI only — the
//  extension never needs them). Pure CoreGraphics/ImageIO, no AppKit.
//

import Foundation
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers

enum LogoStore {
    private static let dir: URL = {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("SimpleVPN/logos", isDirectory: true)
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        return base
    }()

    private static func url(for id: String) -> URL {
        let safe = id.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? "profile"
        return dir.appendingPathComponent(safe).appendingPathExtension("png")
    }

    static func exists(_ id: String) -> Bool { FileManager.default.fileExists(atPath: url(for: id).path) }

    static func load(_ id: String) -> CGImage? {
        guard let src = CGImageSourceCreateWithURL(url(for: id) as CFURL, nil) else { return nil }
        return CGImageSourceCreateImageAtIndex(src, 0, nil)
    }

    /// Import a user-chosen image file: downscale to ≤256px and store as PNG. Returns success.
    @discardableResult
    static func save(fromFile file: URL, id: String) -> Bool {
        guard let src = CGImageSourceCreateWithURL(file as CFURL, nil) else { return false }
        let opts: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceThumbnailMaxPixelSize: 256,
            kCGImageSourceCreateThumbnailWithTransform: true,
        ]
        guard let thumb = CGImageSourceCreateThumbnailAtIndex(src, 0, opts as CFDictionary),
              let dest = CGImageDestinationCreateWithURL(url(for: id) as CFURL, UTType.png.identifier as CFString, 1, nil)
        else { return false }
        CGImageDestinationAddImage(dest, thumb, nil)
        return CGImageDestinationFinalize(dest)
    }

    static func delete(_ id: String) { try? FileManager.default.removeItem(at: url(for: id)) }
}
