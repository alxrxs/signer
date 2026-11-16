import Foundation

/// Appends new and changed objects to a PDF without touching the original bytes, so earlier
/// signatures stay valid.
public struct IncrementalUpdate {
    public let file: PDFFile
    private(set) var nextNumber: Int
    private var objects: [(number: Int, generation: Int, object: PDFObject)] = []

    public init(_ file: PDFFile) {
        self.file = file
        nextNumber = file.size
    }

    /// Adds a new object and returns a reference to it.
    @discardableResult
    public mutating func add(_ object: PDFObject) -> PDFObject {
        let number = nextNumber
        nextNumber += 1
        objects.append((number, 0, object))
        return .ref(number, 0)
    }

    /// Reserves an object number to be filled in later with `set`.
    public mutating func reserve() -> PDFObject {
        let number = nextNumber
        nextNumber += 1
        return .ref(number, 0)
    }

    /// Writes (or rewrites) the object with the given number.
    public mutating func set(_ ref: PDFObject, _ object: PDFObject) {
        guard case .ref(let number, let generation) = ref else { return }
        objects.removeAll { $0.number == number }
        objects.append((number, generation, object))
    }

    /// Copies `object` from another PDF (e.g. a rendered stamp), renumbering what it references.
    public mutating func importObject(_ object: PDFObject, from source: PDFFile, map: inout [Int: PDFObject]) throws -> PDFObject {
        switch object {
        case .ref(let n, _):
            if let mapped = map[n] { return mapped }
            let ref = reserve()
            map[n] = ref
            set(ref, try importObject(try source.object(n), from: source, map: &map))
            return ref
        case .array(let items):
            return .array(try items.map { try importObject($0, from: source, map: &map) })
        case .dict(let dict):
            return .dict(try importDict(dict, from: source, map: &map))
        case .stream(let dict, let data):
            return .stream(try importDict(dict, from: source, map: &map), data)
        default:
            return object
        }
    }

    private mutating func importDict(_ dict: PDFDict, from source: PDFFile, map: inout [Int: PDFObject]) throws -> PDFDict {
        var out = PDFDict()
        for (key, value) in dict.entries where key != "Parent" {
            out[key] = try importObject(value, from: source, map: &map)
        }
        return out
    }

    /// The original file followed by this update.
    public func write() -> Data {
        var out = file.data
        if out.last != 0x0A && out.last != 0x0D { out.append(0x0A) }
        var offsets: [(number: Int, generation: Int, offset: Int)] = []
        for entry in objects.sorted(by: { $0.number < $1.number }) {
            offsets.append((entry.number, entry.generation, out.count))
            out.append(contentsOf: Array("\(entry.number) \(entry.generation) obj\n".utf8))
            entry.object.write(to: &out)
            out.append(contentsOf: Array("\nendobj\n".utf8))
        }

        var trailer = PDFDict()
        trailer["Size"] = .int(nextNumber + (file.usesXrefStream ? 1 : 0))
        for key in ["Root", "Info", "ID", "Encrypt"] { trailer[key] = file.trailer[key] }
        if file.lastXref > 0 { trailer["Prev"] = .int(file.lastXref) }
        let xrefOffset = out.count

        if file.usesXrefStream {
            let number = nextNumber
            offsets.append((number, 0, xrefOffset))
            var rows = Data()
            var index: [PDFObject] = []
            for entry in offsets {
                index += [.int(entry.number), .int(1)]
                rows.append(1)
                for shift in stride(from: 24, through: 0, by: -8) { rows.append(UInt8((entry.offset >> shift) & 0xFF)) }
                rows.append(UInt8((entry.generation >> 8) & 0xFF))
                rows.append(UInt8(entry.generation & 0xFF))
            }
            var dict = trailer
            dict["Type"] = .name("XRef")
            dict["W"] = .array([.int(1), .int(4), .int(2)])
            dict["Index"] = .array(index)
            out.append(contentsOf: Array("\(number) 0 obj\n".utf8))
            PDFObject.stream(dict, rows).write(to: &out)
            out.append(contentsOf: Array("\nendobj\n".utf8))
        } else {
            out.append(contentsOf: Array("xref\n".utf8))
            for entry in offsets {
                out.append(contentsOf: Array("\(entry.number) 1\n".utf8))
                out.append(contentsOf: Array(String(format: "%010d %05d n\r\n", entry.offset, entry.generation).utf8))
            }
            out.append(contentsOf: Array("trailer\n".utf8))
            trailer.write(to: &out)
            out.append(0x0A)
        }
        out.append(contentsOf: Array("startxref\n\(xrefOffset)\n%%EOF\n".utf8))
        return out
    }
}
