import CoreGraphics

/// Maps between a page as shown on screen (rotated, top-left origin, normalised 0…1) and the PDF's
/// default user space (unrotated, bottom-left origin, points).
public struct PageGeometry: Sendable, Equatable {
    /// The visible area in user space (the crop box).
    public let cropBox: CGRect
    /// The page's /Rotate, normalised to 0, 90, 180 or 270 (clockwise).
    public let rotation: Int

    public init(cropBox: CGRect, rotation: Int) {
        self.cropBox = cropBox.standardized
        self.rotation = ((rotation % 360) + 360) % 360 / 90 * 90
    }

    /// Size of the page as displayed, in points.
    public var displaySize: CGSize {
        rotation % 180 == 0 ? cropBox.size : CGSize(width: cropBox.height, height: cropBox.width)
    }

    /// A rectangle drawn on the displayed page (normalised, origin top-left) in user space.
    public func userRect(fromDisplay r: CGRect) -> CGRect {
        let W = cropBox.width, H = cropBox.height, x0 = cropBox.minX, y0 = cropBox.minY
        switch rotation {
        case 90: return CGRect(x: x0 + r.minY * W, y: y0 + r.minX * H, width: r.height * W, height: r.width * H)
        case 180: return CGRect(x: x0 + W - r.maxX * W, y: y0 + r.minY * H, width: r.width * W, height: r.height * H)
        case 270: return CGRect(x: x0 + W - r.maxY * W, y: y0 + H - r.maxX * H, width: r.height * W, height: r.width * H)
        default: return CGRect(x: x0 + r.minX * W, y: y0 + (1 - r.maxY) * H, width: r.width * W, height: r.height * H)
        }
    }

    /// Size of a normalised display rectangle, in points, as seen on screen.
    public func displayPointSize(of r: CGRect) -> CGSize {
        CGSize(width: r.width * displaySize.width, height: r.height * displaySize.height)
    }
}
