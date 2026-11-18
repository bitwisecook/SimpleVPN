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

@MainActor
enum LogoStore {
    private final class CachedLogo {
        let image: CGImage?
        init(_ image: CGImage?) { self.image = image }
    }
    private static let cache: NSCache<NSString, CachedLogo> = {
        let cache = NSCache<NSString, CachedLogo>()
        cache.countLimit = 256
        cache.totalCostLimit = 4 * 1024 * 1024
        return cache
    }()

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

    static func load(_ id: String) -> CGImage? {
        let key = id as NSString
        if let hit = cache.object(forKey: key) { return hit.image }
        let image = CGImageSourceCreateWithURL(url(for: id) as CFURL, nil)
            .flatMap { CGImageSourceCreateImageAtIndex($0, 0, nil) }
        cache.setObject(CachedLogo(image), forKey: key, cost: image.map { $0.bytesPerRow * $0.height } ?? 0)
        return image
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
        let saved = CGImageDestinationFinalize(dest)
        cache.removeObject(forKey: id as NSString)
        return saved
    }

    static func delete(_ id: String) {
        try? FileManager.default.removeItem(at: url(for: id))
        cache.removeObject(forKey: id as NSString)
    }
}
