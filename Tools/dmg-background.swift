// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit

let size = NSSize(width: 640, height: 540)
let image = NSImage(size: size, flipped: false) { bounds in
    NSColor(white: 0.95, alpha: 1).setFill()
    bounds.fill()

    NSColor(white: 0.89, alpha: 1).setStroke()
    for row in 0..<9 {
        for column in 0..<9 {
            let cloud = NSBezierPath()
            cloud.move(to: NSPoint(x: 7, y: 7))
            cloud.curve(to: NSPoint(x: 8, y: 19), controlPoint1: NSPoint(x: -2, y: 7), controlPoint2: NSPoint(x: -2, y: 19))
            cloud.curve(to: NSPoint(x: 28, y: 22), controlPoint1: NSPoint(x: 11, y: 30), controlPoint2: NSPoint(x: 23, y: 32))
            cloud.curve(to: NSPoint(x: 30, y: 7), controlPoint1: NSPoint(x: 39, y: 23), controlPoint2: NSPoint(x: 42, y: 7))
            cloud.close()
            cloud.lineWidth = 1.2
            let offset = AffineTransform(translationByX: CGFloat(column * 84 + (row % 2) * 42 - 18),
                                         byY: CGFloat(row * 62 - 6))
            cloud.transform(using: offset)
            cloud.stroke()
        }
    }

    func drawCentered(_ text: String, y: CGFloat, font: NSFont, color: NSColor) {
        let attributes: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: color]
        let width = (text as NSString).size(withAttributes: attributes).width
        (text as NSString).draw(at: NSPoint(x: (600 - width) / 2, y: y), withAttributes: attributes)
    }
    drawCentered("SimpleVPN", y: 470, font: .systemFont(ofSize: 30, weight: .semibold), color: NSColor(white: 0.14, alpha: 1))
    drawCentered("Double-click the app to install or update.", y: 439,
                 font: .systemFont(ofSize: 17, weight: .medium), color: NSColor(white: 0.27, alpha: 1))
    return true
}
guard let tiff = image.tiffRepresentation, let bitmap = NSBitmapImageRep(data: tiff),
      let png = bitmap.representation(using: .png, properties: [:]) else {
    fatalError("Could not render the disk image background")
}
try png.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
