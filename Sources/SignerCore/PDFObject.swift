import Foundation
import zlib

/// A PDF object as read from a file or built for an incremental update.
public indirect enum PDFObject: Sendable, Equatable {
    case null
    case bool(Bool)
    case int(Int)
    case real(Double)
    case string(Data)
    case hexString(Data)
    case name(String)
    case array([PDFObject])
    case dict(PDFDict)
    case ref(Int, Int)
    case stream(PDFDict, Data)

    public var dict: PDFDict? {
        switch self {
        case .dict(let d), .stream(let d, _): d
        default: nil
        }
    }

    public var array: [PDFObject]? { if case .array(let a) = self { a } else { nil } }
    public var int: Int? { if case .int(let i) = self { i } else { nil } }
    public var name: String? { if case .name(let n) = self { n } else { nil } }

    public var number: Double? {
        switch self {
        case .int(let i): Double(i)
        case .real(let r): r
        default: nil
        }
    }

    public var ref: (Int, Int)? { if case .ref(let n, let g) = self { (n, g) } else { nil } }

    public var stringBytes: Data? {
        switch self {
        case .string(let d), .hexString(let d): d
        default: nil
        }
    }

    public static func text(_ s: String) -> PDFObject {
        // PDF text strings: PDFDocEncoding for ASCII, UTF-16BE with BOM otherwise.
        if s.allSatisfy({ $0.isASCII }) { return .string(Data(s.utf8)) }
        return .hexString(Data([0xFE, 0xFF]) + (s.data(using: .utf16BigEndian) ?? Data()))
    }
}

/// An ordered PDF dictionary (order is kept so rewritten objects stay recognisable).
public struct PDFDict: Sendable, Equatable {
    public private(set) var entries: [(key: String, value: PDFObject)] = []

    public init(_ entries: [(String, PDFObject)] = []) {
        for (key, value) in entries { self[key] = value }
    }

    public subscript(key: String) -> PDFObject? {
        get { entries.first { $0.key == key }?.value }
        set {
            if let index = entries.firstIndex(where: { $0.key == key }) {
                if let newValue { entries[index].value = newValue } else { entries.remove(at: index) }
            } else if let newValue {
                entries.append((key, newValue))
            }
        }
    }

    public static func == (a: PDFDict, b: PDFDict) -> Bool {
        a.entries.count == b.entries.count && zip(a.entries, b.entries).allSatisfy { $0.key == $1.key && $0.value == $1.value }
    }
}

// MARK: - serialization

extension PDFObject {
    public func serialized() -> Data {
        var out = Data()
        write(to: &out)
        return out
    }

    func write(to out: inout Data) {
        switch self {
        case .null: out.append(contentsOf: Array("null".utf8))
        case .bool(let b): out.append(contentsOf: Array((b ? "true" : "false").utf8))
        case .int(let i): out.append(contentsOf: Array(String(i).utf8))
        case .real(let r): out.append(contentsOf: Array(PDFObject.format(r).utf8))
        case .name(let n): out.append(contentsOf: Array(PDFObject.escapeName(n).utf8))
        case .ref(let n, let g): out.append(contentsOf: Array("\(n) \(g) R".utf8))
        case .hexString(let d):
            out.append(UInt8(ascii: "<"))
            out.append(contentsOf: Array(d.map { String(format: "%02X", $0) }.joined().utf8))
            out.append(UInt8(ascii: ">"))
        case .string(let d):
            out.append(UInt8(ascii: "("))
            for byte in d {
                switch byte {
                case UInt8(ascii: "("), UInt8(ascii: ")"), UInt8(ascii: "\\"):
                    out.append(UInt8(ascii: "\\")); out.append(byte)
                case 0x0A: out.append(contentsOf: Array("\\n".utf8))
                case 0x0D: out.append(contentsOf: Array("\\r".utf8))
                default: out.append(byte)
                }
            }
            out.append(UInt8(ascii: ")"))
        case .array(let items):
            out.append(UInt8(ascii: "["))
            for (i, item) in items.enumerated() {
                if i > 0 { out.append(UInt8(ascii: " ")) }
                item.write(to: &out)
            }
            out.append(UInt8(ascii: "]"))
        case .dict(let d):
            d.write(to: &out)
        case .stream(var d, let data):
            d["Length"] = .int(data.count)
            d.write(to: &out)
            out.append(contentsOf: Array("\nstream\n".utf8))
            out.append(data)
            out.append(contentsOf: Array("\nendstream".utf8))
        }
    }

    static func format(_ r: Double) -> String {
        if r == r.rounded(), abs(r) < 1e9 { return String(Int(r)) }
        var s = String(format: "%.4f", r)
        while s.hasSuffix("0") { s.removeLast() }
        if s.hasSuffix(".") { s.removeLast() }
        return s
    }

    static func escapeName(_ name: String) -> String {
        var out = "/"
        for byte in name.utf8 {
            if byte < 0x21 || byte > 0x7E || "#()<>[]{}/%".utf8.contains(byte) {
                out += String(format: "#%02X", byte)
            } else {
                out += String(UnicodeScalar(byte))
            }
        }
        return out
    }
}

extension PDFDict {
    func write(to out: inout Data) {
        out.append(contentsOf: Array("<<".utf8))
        for (key, value) in entries {
            out.append(contentsOf: Array(PDFObject.escapeName(key).utf8))
            out.append(UInt8(ascii: " "))
            value.write(to: &out)
        }
        out.append(contentsOf: Array(">>".utf8))
    }
}

// MARK: - parsing

public struct PDFError: LocalizedError, Sendable {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}

/// Tokenizer and object parser over the raw bytes of a PDF file.
struct PDFLexer {
    let data: Data
    var pos: Int

    init(_ data: Data, at pos: Int = 0) {
        self.data = data
        self.pos = pos
    }

    static func isWhite(_ c: UInt8) -> Bool { c == 0x20 || c == 0x0A || c == 0x0D || c == 0x09 || c == 0x0C || c == 0x00 }
    static func isDelimiter(_ c: UInt8) -> Bool { "()<>[]{}/%".utf8.contains(c) }

    var atEnd: Bool { pos >= data.endIndex }

    func peek(_ offset: Int = 0) -> UInt8? {
        let i = pos + offset
        return i < data.endIndex ? data[i] : nil
    }

    mutating func skipWhitespace() {
        while let c = peek() {
            if PDFLexer.isWhite(c) {
                pos += 1
            } else if c == UInt8(ascii: "%") {
                while let c = peek(), c != 0x0A, c != 0x0D { pos += 1 }
            } else {
                break
            }
        }
    }

    /// A bare keyword or number token.
    mutating func regularToken() -> String {
        let start = pos
        while let c = peek(), !PDFLexer.isWhite(c), !PDFLexer.isDelimiter(c) { pos += 1 }
        return String(decoding: data[start..<pos], as: UTF8.self)
    }

    mutating func expectKeyword(_ keyword: String) throws {
        skipWhitespace()
        let token = regularToken()
        guard token == keyword else { throw PDFError("expected \(keyword), found \(token.prefix(20)) at \(pos)") }
    }

    /// Nesting beyond this is refused (real files stay far below it; hostile ones would exhaust the stack).
    static let maxDepth = 64

    /// Parses one object. `resolveLength` resolves an indirect stream /Length.
    mutating func object(resolveLength: ((Int) -> Int?)? = nil, depth: Int = 0) throws -> PDFObject {
        guard depth < PDFLexer.maxDepth else { throw PDFError("The PDF nests objects too deeply.") }
        skipWhitespace()
        guard let c = peek() else { throw PDFError("unexpected end of file") }
        switch c {
        case UInt8(ascii: "/"):
            pos += 1
            var bytes: [UInt8] = []
            while let c = peek(), !PDFLexer.isWhite(c), !PDFLexer.isDelimiter(c) {
                if c == UInt8(ascii: "#"), let h = peek(1), let l = peek(2),
                   let v = UInt8(String(bytes: [h, l], encoding: .ascii) ?? "", radix: 16) {
                    bytes.append(v)
                    pos += 3
                } else {
                    bytes.append(c)
                    pos += 1
                }
            }
            return .name(String(decoding: bytes, as: UTF8.self))
        case UInt8(ascii: "("):
            return .string(literalString())
        case UInt8(ascii: "<"):
            if peek(1) == UInt8(ascii: "<") {
                pos += 2
                var dict = PDFDict()
                while true {
                    skipWhitespace()
                    if peek() == UInt8(ascii: ">"), peek(1) == UInt8(ascii: ">") {
                        pos += 2
                        break
                    }
                    guard !atEnd else { throw PDFError("unterminated dictionary") }
                    guard case .name(let key) = try object(resolveLength: resolveLength, depth: depth + 1) else {
                        throw PDFError("dictionary key is not a name at \(pos)")
                    }
                    dict[key] = try object(resolveLength: resolveLength, depth: depth + 1)
                }
                return try streamIfPresent(dict, resolveLength: resolveLength)
            }
            pos += 1
            var hex: [UInt8] = []
            while let c = peek(), c != UInt8(ascii: ">") {
                if !PDFLexer.isWhite(c) { hex.append(c) }
                pos += 1
            }
            pos += 1
            if hex.count % 2 == 1 { hex.append(UInt8(ascii: "0")) }
            var bytes = Data()
            var i = 0
            while i < hex.count {
                bytes.append(UInt8(String(bytes: hex[i...i + 1], encoding: .ascii) ?? "", radix: 16) ?? 0)
                i += 2
            }
            return .hexString(bytes)
        case UInt8(ascii: "["):
            pos += 1
            var items: [PDFObject] = []
            while true {
                skipWhitespace()
                if peek() == UInt8(ascii: "]") {
                    pos += 1
                    break
                }
                guard !atEnd else { throw PDFError("unterminated array") }
                items.append(try object(resolveLength: resolveLength, depth: depth + 1))
            }
            return .array(items)
        default:
            let token = regularToken()
            if token.isEmpty {
                pos += 1  // stray delimiter such as ')' or '}'
                return .null
            }
            switch token {
            case "true": return .bool(true)
            case "false": return .bool(false)
            case "null": return .null
            default: break
            }
            if let i = Int(token) {
                // "n g R" reference?
                let save = pos
                skipWhitespace()
                let generation = regularToken()
                if let g = Int(generation) {
                    skipWhitespace()
                    if peek() == UInt8(ascii: "R") && (peek(1).map { PDFLexer.isWhite($0) || PDFLexer.isDelimiter($0) } ?? true) {
                        pos += 1
                        return .ref(i, g)
                    }
                }
                pos = save
                return .int(i)
            }
            if let r = Double(token) { return .real(r) }
            return .name(token)  // unknown keyword; treated leniently
        }
    }

    mutating func literalString() -> Data {
        pos += 1
        var out = Data()
        var depth = 1
        while let c = peek() {
            pos += 1
            switch c {
            case UInt8(ascii: "\\"):
                guard let e = peek() else { break }
                pos += 1
                switch e {
                case UInt8(ascii: "n"): out.append(0x0A)
                case UInt8(ascii: "r"): out.append(0x0D)
                case UInt8(ascii: "t"): out.append(0x09)
                case UInt8(ascii: "b"): out.append(0x08)
                case UInt8(ascii: "f"): out.append(0x0C)
                case 0x0D: if peek() == 0x0A { pos += 1 }
                case 0x0A: break
                case UInt8(ascii: "0")...UInt8(ascii: "7"):
                    var value = Int(e - UInt8(ascii: "0"))
                    for _ in 0..<2 {
                        guard let d = peek(), (UInt8(ascii: "0")...UInt8(ascii: "7")).contains(d) else { break }
                        value = value * 8 + Int(d - UInt8(ascii: "0"))
                        pos += 1
                    }
                    out.append(UInt8(value & 0xFF))
                default: out.append(e)
                }
            case UInt8(ascii: "("):
                depth += 1
                out.append(c)
            case UInt8(ascii: ")"):
                depth -= 1
                if depth == 0 { return out }
                out.append(c)
            default:
                out.append(c)
            }
        }
        return out
    }

    mutating func streamIfPresent(_ dict: PDFDict, resolveLength: ((Int) -> Int?)?) throws -> PDFObject {
        let save = pos
        skipWhitespace()
        guard regularToken() == "stream" else {
            pos = save
            return .dict(dict)
        }
        if peek() == 0x0D { pos += 1 }
        if peek() == 0x0A { pos += 1 }
        let start = pos
        var length: Int?
        switch dict["Length"] {
        case .int(let l)?: length = l
        case .ref(let n, _)?: length = resolveLength?(n)
        default: break
        }
        if let length, length >= 0, start + length <= data.endIndex,
           PDFLexer.endstream(in: data, from: start + length) != nil {
            pos = start + length
        } else {
            // Wrong or missing /Length: find the keyword instead.
            guard let range = data.range(of: Data("endstream".utf8), in: start..<data.endIndex) else {
                throw PDFError("unterminated stream")
            }
            var end = range.lowerBound
            if end > start, data[end - 1] == 0x0A { end -= 1 }
            if end > start, data[end - 1] == 0x0D { end -= 1 }
            pos = end
        }
        let body = Data(data[start..<pos])
        skipWhitespace()
        _ = regularToken()  // endstream
        return .stream(dict, body)
    }

    static func endstream(in data: Data, from: Int) -> Int? {
        var lexer = PDFLexer(data, at: from)
        lexer.skipWhitespace()
        return lexer.regularToken() == "endstream" ? lexer.pos : nil
    }
}

// MARK: - filters

enum Filters {
    static func decode(_ dict: PDFDict, _ data: Data) throws -> Data {
        var filters: [String] = []
        switch dict["Filter"] {
        case .name(let n)?: filters = [n]
        case .array(let a)?: filters = a.compactMap(\.name)
        default: break
        }
        var params: [PDFDict?] = []
        switch dict["DecodeParms"] {
        case .dict(let d)?: params = [d]
        case .array(let a)?: params = a.map(\.dict)
        default: break
        }
        var out = data
        for (i, filter) in filters.enumerated() {
            guard filter == "FlateDecode" || filter == "Fl" else {
                throw PDFError("unsupported PDF filter \(filter)")
            }
            out = try inflate(out)
            if let p = i < params.count ? params[i] : nil, let predictor = p["Predictor"]?.int, predictor >= 10 {
                out = try unpredictPNG(out, columns: p["Columns"]?.int ?? 1, colors: p["Colors"]?.int ?? 1,
                                       bits: p["BitsPerComponent"]?.int ?? 8)
            }
        }
        return out
    }

    /// Decompressed streams larger than this are refused (decompression bombs).
    static let maxInflatedSize = 256 << 20

    static func inflate(_ data: Data) throws -> Data {
        var stream = z_stream()
        guard inflateInit_(&stream, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
            throw PDFError("zlib init failed")
        }
        defer { inflateEnd(&stream) }
        var output = Data()
        var input = [UInt8](data)
        let chunk = 64 * 1024
        var buffer = [UInt8](repeating: 0, count: chunk)
        var status: Int32 = Z_OK
        input.withUnsafeMutableBufferPointer { inBuf in
            stream.next_in = inBuf.baseAddress
            stream.avail_in = uInt(inBuf.count)
            repeat {
                buffer.withUnsafeMutableBufferPointer { outBuf in
                    stream.next_out = outBuf.baseAddress
                    stream.avail_out = uInt(chunk)
                    status = zlib.inflate(&stream, Z_NO_FLUSH)
                    output.append(outBuf.baseAddress!, count: chunk - Int(stream.avail_out))
                }
            } while status == Z_OK && (stream.avail_in > 0 || stream.avail_out == 0) && output.count <= maxInflatedSize
        }
        if output.count > maxInflatedSize { throw PDFError("A compressed stream in the PDF is too large.") }
        // Truncated or slightly corrupt streams are common; keep what decoded.
        if status != Z_STREAM_END && output.isEmpty { throw PDFError("corrupt compressed stream") }
        return output
    }

    static func deflate(_ data: Data) -> Data {
        var length = compressBound(uLong(data.count))
        var out = [UInt8](repeating: 0, count: Int(length))
        let status = data.withUnsafeBytes { raw in
            compress2(&out, &length, raw.bindMemory(to: Bytef.self).baseAddress, uLong(data.count), 9)
        }
        return status == Z_OK ? Data(out.prefix(Int(length))) : data
    }

    static func unpredictPNG(_ data: Data, columns: Int, colors: Int, bits: Int) throws -> Data {
        guard (1...1 << 16).contains(columns), (1...32).contains(colors), [1, 2, 4, 8, 16].contains(bits) else {
            throw PDFError("unsupported predictor parameters")
        }
        let bpp = max(1, colors * bits / 8)
        let rowLength = (columns * colors * bits + 7) / 8
        var out = Data()
        var previous = [UInt8](repeating: 0, count: rowLength)
        let bytes = [UInt8](data)
        var i = 0
        while i + rowLength < bytes.count + 1 && i < bytes.count {
            let type = bytes[i]
            var row = Array(bytes[(i + 1)..<min(i + 1 + rowLength, bytes.count)])
            if row.count < rowLength { row += [UInt8](repeating: 0, count: rowLength - row.count) }
            for x in 0..<rowLength {
                let left = x >= bpp ? Int(row[x - bpp]) : 0
                let up = Int(previous[x])
                let upLeft = x >= bpp ? Int(previous[x - bpp]) : 0
                let value: Int = switch type {
                case 1: left
                case 2: up
                case 3: (left + up) / 2
                case 4: {
                    let p = left + up - upLeft
                    let pa = abs(p - left), pb = abs(p - up), pc = abs(p - upLeft)
                    return pa <= pb && pa <= pc ? left : (pb <= pc ? up : upLeft)
                }()
                default: 0
                }
                row[x] = UInt8((Int(row[x]) + value) & 0xFF)
            }
            out.append(contentsOf: row)
            previous = row
            i += 1 + rowLength
        }
        return out
    }
}
