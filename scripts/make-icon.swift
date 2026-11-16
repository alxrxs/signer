// Draws the app icon and writes Resources/AppIcon.icns (and AppIcon.png for the README).
// Run from the repo root: swift scripts/make-icon.swift
import AppKit

func draw(size: CGFloat) -> NSBitmapImageRep {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size), pixelsHigh: Int(size),
                               bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                               colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let s = size / 1024
    func shadow(_ alpha: CGFloat, blur: CGFloat, y: CGFloat) {
        let shadow = NSShadow()
        shadow.shadowColor = .black.withAlphaComponent(alpha)
        shadow.shadowBlurRadius = blur * s
        shadow.shadowOffset = NSSize(width: 0, height: y * s)
        shadow.set()
    }

    // macOS icon grid: 824pt rounded square centred on a 1024 canvas.
    let tile = NSBezierPath(roundedRect: NSRect(x: 100 * s, y: 100 * s, width: 824 * s, height: 824 * s), xRadius: 185 * s, yRadius: 185 * s)
    shadow(0.3, blur: 20, y: -10)
    NSGradient(starting: NSColor(srgbRed: 0.20, green: 0.42, blue: 0.95, alpha: 1),
               ending: NSColor(srgbRed: 0.07, green: 0.17, blue: 0.52, alpha: 1))!.draw(in: tile, angle: -90)
    NSShadow().set()

    // A sheet of paper, slightly tilted.
    NSGraphicsContext.current!.cgContext.saveGState()
    let cg = NSGraphicsContext.current!.cgContext
    cg.translateBy(x: 512 * s, y: 512 * s)
    cg.rotate(by: -0.06)
    cg.translateBy(x: -512 * s, y: -512 * s)
    let paper = NSBezierPath(roundedRect: NSRect(x: 262 * s, y: 190 * s, width: 500 * s, height: 640 * s), xRadius: 34 * s, yRadius: 34 * s)
    shadow(0.35, blur: 30, y: -14)
    NSColor.white.setFill()
    paper.fill()
    NSShadow().set()
    NSColor(srgbRed: 0.80, green: 0.85, blue: 0.93, alpha: 1).setFill()
    for (i, width) in [360.0, 330, 360, 220].enumerated() {
        NSBezierPath(roundedRect: NSRect(x: 332 * s, y: CGFloat(700 - i * 66) * s, width: CGFloat(width) * s, height: 24 * s),
                     xRadius: 12 * s, yRadius: 12 * s).fill()
    }

    // The signature: one confident stroke.
    let stroke = NSBezierPath()
    stroke.move(to: NSPoint(x: 322 * s, y: 330 * s))
    stroke.curve(to: NSPoint(x: 452 * s, y: 380 * s), controlPoint1: NSPoint(x: 360 * s, y: 430 * s), controlPoint2: NSPoint(x: 420 * s, y: 450 * s))
    stroke.curve(to: NSPoint(x: 520 * s, y: 300 * s), controlPoint1: NSPoint(x: 480 * s, y: 310 * s), controlPoint2: NSPoint(x: 470 * s, y: 250 * s))
    stroke.curve(to: NSPoint(x: 640 * s, y: 370 * s), controlPoint1: NSPoint(x: 560 * s, y: 350 * s), controlPoint2: NSPoint(x: 600 * s, y: 390 * s))
    stroke.lineWidth = 22 * s
    stroke.lineCapStyle = .round
    stroke.lineJoinStyle = .round
    NSColor(srgbRed: 0.07, green: 0.17, blue: 0.52, alpha: 1).setStroke()
    stroke.stroke()
    cg.restoreGState()

    // The seal: a green disc with a check mark.
    let seal = NSBezierPath(ovalIn: NSRect(x: 600 * s, y: 160 * s, width: 230 * s, height: 230 * s))
    shadow(0.3, blur: 18, y: -8)
    NSGradient(starting: NSColor(srgbRed: 0.25, green: 0.80, blue: 0.45, alpha: 1),
               ending: NSColor(srgbRed: 0.08, green: 0.55, blue: 0.30, alpha: 1))!.draw(in: seal, angle: -90)
    NSShadow().set()
    let check = NSBezierPath()
    check.move(to: NSPoint(x: 662 * s, y: 278 * s))
    check.line(to: NSPoint(x: 703 * s, y: 236 * s))
    check.line(to: NSPoint(x: 772 * s, y: 318 * s))
    check.lineWidth = 30 * s
    check.lineCapStyle = .round
    check.lineJoinStyle = .round
    NSColor.white.setStroke()
    check.stroke()

    NSGraphicsContext.restoreGraphicsState()
    return rep
}

let fm = FileManager.default
let iconset = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("AppIcon.iconset")
try? fm.removeItem(at: iconset)
try fm.createDirectory(at: iconset, withIntermediateDirectories: true)
for base in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let name = scale == 1 ? "icon_\(base)x\(base).png" : "icon_\(base)x\(base)@2x.png"
        try draw(size: CGFloat(base * scale)).representation(using: .png, properties: [:])!
            .write(to: iconset.appendingPathComponent(name))
    }
}
try fm.createDirectory(atPath: "Resources", withIntermediateDirectories: true)
let iconutil = Process()
iconutil.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
iconutil.arguments = ["-c", "icns", iconset.path, "-o", "Resources/AppIcon.icns"]
try iconutil.run()
iconutil.waitUntilExit()
try draw(size: 256).representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: "Resources/AppIcon.png"))
print("wrote Resources/AppIcon.icns and Resources/AppIcon.png")
