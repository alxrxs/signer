import CoreGraphics
import CoreText
import Foundation

/// How the visible signature stamp looks.
public struct StampStyle: Sendable, Equatable {
    public var text: String
    public var autoFit = true
    /// Used when `autoFit` is off.
    public var fontSize: CGFloat = 11
    public var whiteBackground = true
    public var border = true

    public init(text: String, autoFit: Bool = true, fontSize: CGFloat = 11, whiteBackground: Bool = true, border: Bool = true) {
        self.text = text
        self.autoFit = autoFit
        self.fontSize = fontSize
        self.whiteBackground = whiteBackground
        self.border = border
    }
}

/// Lays out and draws the stamp. The same drawing produces the on-screen preview and the PDF
/// appearance, so what you see is what gets signed.
public enum Stamp {
    public static let padding: CGFloat = 4
    public static let sizeRange: ClosedRange<CGFloat> = 4...48
    static let fontName = "HelveticaNeue"

    public struct Layout: Sendable, Equatable {
        public let fontSize: CGFloat
        /// Text does not fit the box at this size and is cut off.
        public let clipped: Bool
    }

    public static func layout(_ style: StampStyle, in size: CGSize) -> Layout {
        if !style.autoFit {
            return Layout(fontSize: style.fontSize, clipped: !fits(style.text, size: style.fontSize, in: size))
        }
        guard fits(style.text, size: sizeRange.lowerBound, in: size) else {
            return Layout(fontSize: sizeRange.lowerBound, clipped: true)
        }
        var low = sizeRange.lowerBound, high = sizeRange.upperBound
        while high - low > 0.1 {
            let mid = (low + high) / 2
            if fits(style.text, size: mid, in: size) { low = mid } else { high = mid }
        }
        return Layout(fontSize: (low * 10).rounded(.down) / 10, clipped: false)
    }

    static func attributed(_ text: String, size: CGFloat) -> NSAttributedString {
        let font = CTFontCreateWithName(fontName as CFString, size, nil)
        return NSAttributedString(string: text, attributes: [
            NSAttributedString.Key(kCTFontAttributeName as String): font,
            NSAttributedString.Key(kCTForegroundColorAttributeName as String): CGColor(gray: 0, alpha: 1),
        ])
    }

    static func fits(_ text: String, size: CGFloat, in box: CGSize) -> Bool {
        let width = box.width - 2 * padding, height = box.height - 2 * padding
        guard width > 0, height > 0 else { return false }
        // No word may be wider than the box (it would be broken mid-word).
        for word in text.split(whereSeparator: \.isWhitespace) {
            let line = CTLineCreateWithAttributedString(attributed(String(word), size: size))
            if CTLineGetTypographicBounds(line, nil, nil, nil) > width { return false }
        }
        let framesetter = CTFramesetterCreateWithAttributedString(attributed(text, size: size))
        let needed = CTFramesetterSuggestFrameSizeWithConstraints(
            framesetter, CFRange(), nil, CGSize(width: width, height: .greatestFiniteMagnitude), nil)
        return needed.height <= height + 0.01
    }

    /// Draws the stamp into `context` filling `size` (origin bottom-left).
    public static func draw(_ style: StampStyle, in context: CGContext, size: CGSize) {
        let box = CGRect(origin: .zero, size: size)
        if style.whiteBackground {
            context.setFillColor(gray: 1, alpha: 1)
            context.fill(box)
        }
        if style.border {
            context.setStrokeColor(gray: 0, alpha: 1)
            context.setLineWidth(0.7)
            context.stroke(box.insetBy(dx: 0.35, dy: 0.35))
        }
        let layout = layout(style, in: size)
        let framesetter = CTFramesetterCreateWithAttributedString(attributed(style.text, size: layout.fontSize))
        let path = CGPath(rect: box.insetBy(dx: padding, dy: padding), transform: nil)
        let frame = CTFramesetterCreateFrame(framesetter, CFRange(), path, nil)
        context.saveGState()
        context.clip(to: box)
        CTFrameDraw(frame, context)
        context.restoreGState()
    }

    /// The stamp as a one-page PDF (fonts embedded), ready to become the signature's appearance.
    public static func pdf(_ style: StampStyle, size: CGSize) -> Data {
        let data = NSMutableData()
        var box = CGRect(origin: .zero, size: size)
        guard let consumer = CGDataConsumer(data: data),
              let context = CGContext(consumer: consumer, mediaBox: &box, nil) else { return Data() }
        context.beginPDFPage(nil)
        draw(style, in: context, size: size)
        context.endPDFPage()
        context.closePDF()
        return data as Data
    }

    /// Replaces `{date}` with the signing time.
    public static func expand(_ text: String, date: Date = .now) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "dd.MM.yyyy HH:mm:ss"
        return text.replacingOccurrences(of: "{date}", with: formatter.string(from: date))
    }
}
