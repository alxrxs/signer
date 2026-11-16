import AppKit
import PDFKit
import SignerCore
import SwiftUI

/// Drag state for placing the stamp (kept out of observation: it changes on every mouse move).
@MainActor
final class BoxDrag {
    enum Mode { case create(anchor: CGPoint), move(start: CGRect, from: CGPoint), resize(start: CGRect) }
    var mode: Mode?
    /// Smallest box, in view points.
    static let minimum = CGSize(width: 24, height: 14)
    static let handleRadius: CGFloat = 7

    func changed(_ value: DragGesture.Value, in size: CGSize, model: SignerModel) {
        let point = CGPoint(x: clamp(value.location.x / size.width), y: clamp(value.location.y / size.height))
        if mode == nil {
            let start = CGPoint(x: value.startLocation.x / size.width, y: value.startLocation.y / size.height)
            if let box = model.box {
                let corner = CGPoint(x: box.maxX * size.width, y: box.maxY * size.height)
                if hypot(value.startLocation.x - corner.x, value.startLocation.y - corner.y) <= BoxDrag.handleRadius + 6 {
                    mode = .resize(start: box)
                } else if box.contains(start) {
                    mode = .move(start: box, from: start)
                }
            }
            if mode == nil { mode = .create(anchor: start) }
        }
        switch mode {
        case .create(let anchor):
            model.box = CGRect(x: min(anchor.x, point.x), y: min(anchor.y, point.y),
                               width: abs(point.x - anchor.x), height: abs(point.y - anchor.y))
        case .move(let start, let from):
            let x = min(max(start.minX + point.x - from.x, 0), 1 - start.width)
            let y = min(max(start.minY + point.y - from.y, 0), 1 - start.height)
            model.box = CGRect(origin: CGPoint(x: x, y: y), size: start.size)
        case .resize(let start):
            let minW = BoxDrag.minimum.width / size.width, minH = BoxDrag.minimum.height / size.height
            model.box = CGRect(x: start.minX, y: start.minY,
                               width: max(point.x - start.minX, minW), height: max(point.y - start.minY, minH))
        case nil: break
        }
    }

    func ended(in size: CGSize, model: SignerModel) {
        if case .create = mode, let box = model.box,
           box.width * size.width < BoxDrag.minimum.width || box.height * size.height < BoxDrag.minimum.height {
            model.box = nil
        }
        mode = nil
    }

    private func clamp(_ v: CGFloat) -> CGFloat { min(max(v, 0), 1) }
}

/// Renders pages, caching the last few.
@MainActor
final class PageRenderer {
    private var cache: [String: NSImage] = [:]

    func image(_ page: PDFPage, index: Int, size: CGSize, scale: CGFloat) -> NSImage {
        let pixels = CGSize(width: (size.width * scale).rounded(), height: (size.height * scale).rounded())
        let key = "\(index)-\(Int(pixels.width))x\(Int(pixels.height))"
        if let cached = cache[key] { return cached }
        if cache.count > 8 { cache.removeAll() }
        let image = page.thumbnail(of: pixels, for: .cropBox)
        image.size = size
        cache[key] = image
        return image
    }
}

struct PageView: View {
    @Bindable var model: SignerModel
    let drag: BoxDrag
    let renderer: PageRenderer
    @Environment(\.displayScale) private var displayScale

    var body: some View {
        GeometryReader { proxy in
            if let document = model.document, let page = document.pdf.page(at: model.pageIndex),
               let geometry = model.geometry {
                let display = geometry.displaySize
                let fit = min((proxy.size.width - 64) / display.width, (proxy.size.height - 64) / display.height)
                let size = CGSize(width: max(display.width * fit, 1), height: max(display.height * fit, 1))
                ZStack(alignment: .topLeading) {
                    Image(nsImage: renderer.image(page, index: model.pageIndex, size: size, scale: displayScale))
                        .resizable()
                        .interpolation(.high)
                    if let box = model.box {
                        StampOverlay(model: model, box: box, pageSize: size, pointsPerPixel: display.width / size.width)
                    }
                }
                .frame(width: size.width, height: size.height)
                .background(.white)
                .clipShape(.rect(cornerRadius: 2))
                .shadow(color: .black.opacity(0.18), radius: 10, y: 3)
                .contentShape(.rect)
                .gesture(
                    DragGesture(minimumDistance: 0)
                        .onChanged { drag.changed($0, in: size, model: model) }
                        .onEnded { _ in drag.ended(in: size, model: model) }
                )
                .onContinuousHover { phase in
                    if case .active = phase { NSCursor.crosshair.set() } else { NSCursor.arrow.set() }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .overlay(alignment: .bottom) {
                    if model.box == nil && model.drawStamp {
                        Label("Drag on the page to place your stamp", systemImage: "hand.draw")
                            .font(.callout)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 8)
                            .glassEffect()
                            .padding(.bottom, 18)
                            .allowsHitTesting(false)
                    }
                }
            }
        }
        .background(Color(nsColor: .underPageBackgroundColor))
    }
}

/// The stamp preview inside its box, drawn exactly as it will be signed.
struct StampOverlay: View {
    let model: SignerModel
    let box: CGRect
    let pageSize: CGSize
    /// PDF points per view point.
    let pointsPerPixel: CGFloat
    @Environment(\.displayScale) private var displayScale

    var body: some View {
        let frame = CGRect(x: box.minX * pageSize.width, y: box.minY * pageSize.height,
                           width: box.width * pageSize.width, height: box.height * pageSize.height)
        ZStack(alignment: .bottomTrailing) {
            if model.drawStamp, let preview = preview(frame.size) {
                Image(decorative: preview, scale: displayScale)
                    .resizable()
            } else {
                Rectangle().fill(.tint.opacity(0.08))
            }
            Rectangle()
                .strokeBorder(.tint, style: StrokeStyle(lineWidth: 1.5, dash: [5, 3]))
            Circle()
                .fill(.tint)
                .overlay(Circle().strokeBorder(.white, lineWidth: 1.5))
                .frame(width: BoxDrag.handleRadius * 2, height: BoxDrag.handleRadius * 2)
                .offset(x: BoxDrag.handleRadius, y: BoxDrag.handleRadius)
        }
        .frame(width: frame.width, height: frame.height)
        .offset(x: frame.minX, y: frame.minY)
        .allowsHitTesting(false)
    }

    /// The stamp drawn by the same code that makes the PDF appearance.
    private func preview(_ size: CGSize) -> CGImage? {
        let points = CGSize(width: size.width * pointsPerPixel, height: size.height * pointsPerPixel)
        let width = Int((size.width * displayScale).rounded()), height = Int((size.height * displayScale).rounded())
        guard width > 0, height > 0, points.width > 0,
              let context = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
                                      space: CGColorSpace(name: CGColorSpace.sRGB)!,
                                      bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return nil }
        context.scaleBy(x: CGFloat(width) / points.width, y: CGFloat(height) / points.height)
        Stamp.draw(model.style, in: context, size: points)
        return context.makeImage()
    }
}
