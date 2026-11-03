// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit

let drivePath = "/System/Library/Extensions/IOStorageFamily.kext/Contents/Resources/Removable.icns"
guard let drive = NSImage(contentsOfFile: drivePath) else {
    fatalError("Could not load the macOS drive icon")
}

func blue(_ red: CGFloat, _ green: CGFloat, _ blue: CGFloat, _ alpha: CGFloat = 1) -> NSColor {
    NSColor(srgbRed: red, green: green, blue: blue, alpha: alpha)
}

func drawCaustic(pixels: CGFloat) {
    // A top-left light concentrates through the curved shackle into two
    // tapered reflections on the drive face, displaced down and right.
    NSGraphicsContext.saveGraphicsState()
    let scale = AffineTransform(scaleByX: pixels, byY: pixels)
    (scale as NSAffineTransform).concat()
    let reflection = NSBezierPath()
    reflection.move(to: NSPoint(x: 0.46, y: 0.735))
    reflection.curve(to: NSPoint(x: 0.59, y: 0.597),
                     controlPoint1: NSPoint(x: 0.535, y: 0.76),
                     controlPoint2: NSPoint(x: 0.599, y: 0.687))
    reflection.curve(to: NSPoint(x: 0.46, y: 0.735),
                     controlPoint1: NSPoint(x: 0.574, y: 0.663),
                     controlPoint2: NSPoint(x: 0.532, y: 0.729))
    reflection.close()
    NSGradient(starting: blue(0.61, 0.83, 0.98, 0.12),
               ending: blue(1, 1, 1, 0.96))?.draw(in: reflection, angle: 125)
    let inner = NSBezierPath()
    inner.move(to: NSPoint(x: 0.462, y: 0.707))
    inner.curve(to: NSPoint(x: 0.562, y: 0.611),
                controlPoint1: NSPoint(x: 0.523, y: 0.714),
                controlPoint2: NSPoint(x: 0.558, y: 0.67))
    inner.curve(to: NSPoint(x: 0.462, y: 0.707),
                controlPoint1: NSPoint(x: 0.549, y: 0.662),
                controlPoint2: NSPoint(x: 0.519, y: 0.697))
    inner.close()
    blue(1, 1, 1, 0.68).setFill()
    inner.fill()
    NSGraphicsContext.restoreGraphicsState()
}
func drawLock(pixels: CGFloat) {
    NSGraphicsContext.saveGraphicsState()
    (AffineTransform(scaleByX: pixels, byY: pixels) as NSAffineTransform).concat()

    let shackle = NSBezierPath()
    shackle.move(to: NSPoint(x: 0.355, y: 0.55))
    shackle.line(to: NSPoint(x: 0.355, y: 0.716))
    shackle.curve(to: NSPoint(x: 0.605, y: 0.716),
                  controlPoint1: NSPoint(x: 0.355, y: 0.887),
                  controlPoint2: NSPoint(x: 0.605, y: 0.887))
    shackle.line(to: NSPoint(x: 0.605, y: 0.55))
    shackle.lineWidth = 0.079
    blue(0.34, 0.55, 0.72, 0.54).setStroke()
    shackle.stroke()
    shackle.lineWidth = 0.063
    blue(0.87, 0.96, 1, 0.70).setStroke()
    shackle.stroke()
    shackle.lineWidth = 0.034
    blue(0.95, 0.98, 1, 0.36).setStroke()
    shackle.stroke()

    let glint = NSBezierPath()
    glint.move(to: NSPoint(x: 0.331, y: 0.708))
    glint.curve(to: NSPoint(x: 0.467, y: 0.856),
                controlPoint1: NSPoint(x: 0.331, y: 0.788),
                controlPoint2: NSPoint(x: 0.392, y: 0.85))
    glint.lineWidth = 0.012
    glint.lineCapStyle = .round
    NSColor.white.setStroke()
    glint.stroke()

    let plate = NSBezierPath(roundedRect: NSRect(x: 0.235, y: 0.245, width: 0.49, height: 0.34),
                             xRadius: 0.065, yRadius: 0.065)
    NSGradient(starting: blue(0.39, 0.64, 0.84), ending: blue(0.17, 0.37, 0.61))?
        .draw(in: plate, angle: -55)
    blue(0.12, 0.31, 0.53, 0.72).setStroke()
    plate.lineWidth = 0.006
    plate.stroke()

    let keyhole = NSBezierPath()
    keyhole.move(to: NSPoint(x: 0.458, y: 0.345))
    keyhole.line(to: NSPoint(x: 0.467, y: 0.408))
    keyhole.appendArc(withCenter: NSPoint(x: 0.48, y: 0.438), radius: 0.033,
                      startAngle: 247, endAngle: 293, clockwise: true)
    keyhole.line(to: NSPoint(x: 0.502, y: 0.345))
    keyhole.close()
    blue(0.07, 0.21, 0.38).setFill()
    keyhole.fill()
    NSGraphicsContext.restoreGraphicsState()
}

let output = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
for points in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let pixels = CGFloat(points * scale)
        let size = NSSize(width: pixels, height: pixels)
        let image = NSImage(size: size, flipped: false) { bounds in
            drive.draw(in: bounds)
            // The original drive has a centered download arrow. Sample a clean
            // strip beside it, preserving the drive face's vertical shading.
            let arrowArea = NSRect(x: pixels * 0.345, y: pixels * 0.376,
                                   width: pixels * 0.31, height: pixels * 0.355)
            let cleanStrip = NSRect(x: drive.size.width * 0.337, y: drive.size.height * 0.376,
                                    width: drive.size.width * 0.006, height: drive.size.height * 0.355)
            drive.draw(in: arrowArea, from: cleanStrip, operation: .copy, fraction: 1)
            drawCaustic(pixels: pixels)
            drawLock(pixels: pixels)
            return true
        }
        guard let tiff = image.tiffRepresentation, let bitmap = NSBitmapImageRep(data: tiff),
              let png = bitmap.representation(using: .png, properties: [:]) else {
            fatalError("Could not render the SimpleVPN disk icon")
        }
        let suffix = scale == 2 ? "@2x" : ""
        try png.write(to: output.appendingPathComponent("icon_\(points)x\(points)\(suffix).png"))
    }
}
