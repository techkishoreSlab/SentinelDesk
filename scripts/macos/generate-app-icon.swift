import AppKit

/// Renders exact-pixel PNGs into an .iconset for iconutil.
let outDir = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon.iconset"
let fm = FileManager.default
try? fm.removeItem(atPath: outDir)
try fm.createDirectory(atPath: outDir, withIntermediateDirectories: true)

func shieldPath(in bounds: NSRect) -> NSBezierPath {
  let path = NSBezierPath()
  let w = bounds.width
  let h = bounds.height
  let x = bounds.minX
  let y = bounds.minY
  path.move(to: NSPoint(x: x + w * 0.50, y: y + h * 0.08))
  path.curve(
    to: NSPoint(x: x + w * 0.88, y: y + h * 0.28),
    controlPoint1: NSPoint(x: x + w * 0.72, y: y + h * 0.08),
    controlPoint2: NSPoint(x: x + w * 0.88, y: y + h * 0.14)
  )
  path.curve(
    to: NSPoint(x: x + w * 0.50, y: y + h * 0.92),
    controlPoint1: NSPoint(x: x + w * 0.88, y: y + h * 0.58),
    controlPoint2: NSPoint(x: x + w * 0.70, y: y + h * 0.82)
  )
  path.curve(
    to: NSPoint(x: x + w * 0.12, y: y + h * 0.28),
    controlPoint1: NSPoint(x: x + w * 0.30, y: y + h * 0.82),
    controlPoint2: NSPoint(x: x + w * 0.12, y: y + h * 0.58)
  )
  path.curve(
    to: NSPoint(x: x + w * 0.50, y: y + h * 0.08),
    controlPoint1: NSPoint(x: x + w * 0.12, y: y + h * 0.14),
    controlPoint2: NSPoint(x: x + w * 0.28, y: y + h * 0.08)
  )
  path.close()
  return path
}

func drawIcon(pixels: Int) -> NSBitmapImageRep {
  let size = CGFloat(pixels)
  let rep = NSBitmapImageRep(
    bitmapDataPlanes: nil,
    pixelsWide: pixels,
    pixelsHigh: pixels,
    bitsPerSample: 8,
    samplesPerPixel: 4,
    hasAlpha: true,
    isPlanar: false,
    colorSpaceName: .deviceRGB,
    bytesPerRow: 0,
    bitsPerPixel: 0
  )!
  NSGraphicsContext.saveGraphicsState()
  NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
  NSGraphicsContext.current?.imageInterpolation = .high

  let navy = NSColor(calibratedRed: 0.09, green: 0.12, blue: 0.16, alpha: 1)
  let mint = NSColor(calibratedRed: 0.78, green: 0.88, blue: 0.84, alpha: 1)
  let accent = NSColor(calibratedRed: 0.18, green: 0.42, blue: 0.36, alpha: 1)

  navy.setFill()
  NSBezierPath(
    roundedRect: NSRect(x: 0, y: 0, width: size, height: size),
    xRadius: size * 0.22,
    yRadius: size * 0.22
  ).fill()

  let inset = size * 0.18
  let shieldBounds = NSRect(x: inset, y: inset, width: size - inset * 2, height: size - inset * 2)
  let shield = shieldPath(in: shieldBounds)
  accent.setFill()
  shield.fill()
  mint.setStroke()
  shield.lineWidth = max(1.0, size * 0.03)
  shield.stroke()

  let check = NSBezierPath()
  check.move(to: NSPoint(x: size * 0.34, y: size * 0.48))
  check.line(to: NSPoint(x: size * 0.46, y: size * 0.36))
  check.line(to: NSPoint(x: size * 0.68, y: size * 0.62))
  check.lineWidth = max(1.5, size * 0.06)
  check.lineCapStyle = .round
  check.lineJoinStyle = .round
  mint.setStroke()
  check.stroke()

  NSGraphicsContext.restoreGraphicsState()
  return rep
}

func writePNG(pixels: Int, path: String) {
  let rep = drawIcon(pixels: pixels)
  guard let data = rep.representation(using: .png, properties: [:]) else { return }
  try? data.write(to: URL(fileURLWithPath: path))
}

let sizes: [(String, Int)] = [
  ("icon_16x16.png", 16),
  ("diana.k@example.org", 32),
  ("icon_32x32.png", 32),
  ("ivan.p@example.net", 64),
  ("icon_128x128.png", 128),
  ("wendy.h@example.net", 256),
  ("icon_256x256.png", 256),
  ("wendy.h@example.net", 512),
  ("icon_512x512.png", 512),
  ("walt.e@example.net", 1024),
]

for (name, px) in sizes {
  writePNG(pixels: px, path: (outDir as NSString).appendingPathComponent(name))
}

print(outDir)
