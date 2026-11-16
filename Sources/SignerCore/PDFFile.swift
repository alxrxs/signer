import Foundation

/// Read access to a PDF file's objects, enough to append an incremental update.
public final class PDFFile: @unchecked Sendable {
    public let data: Data
    public private(set) var trailer = PDFDict()
    /// Offset of the newest cross-reference section (`startxref`).
    public private(set) var lastXref = 0
    /// Whether the newest section is a cross-reference stream (the update must use one too).
    public private(set) var usesXrefStream = false
    public private(set) var size = 0

    enum Entry {
        case offset(Int, generation: Int)
        case compressed(stream: Int, index: Int)
        case free
    }

    private var entries: [Int: Entry] = [:]
    private var cache: [Int: PDFObject] = [:]
    private var objectStreams: [Int: [Int: PDFObject]] = [:]

    public convenience init(url: URL) throws {
        try self.init(data: Data(contentsOf: url))
    }

    public init(data: Data) throws {
        self.data = data
        guard data.starts(with: Data("%PDF-".utf8)) || data.prefix(1024).range(of: Data("%PDF-".utf8)) != nil else {
            throw PDFError("This file is not a PDF.")
        }
        // Damaged files are refused rather than repaired: guessing at a broken structure is how
        // signatures end up covering something other than what is shown.
        do {
            lastXref = try PDFFile.findStartXref(data)
            try readXrefChain(from: lastXref)
        } catch {
            throw PDFError("This PDF is damaged and can't be signed safely. Open it in Preview and export it again (File → Export as PDF).")
        }
        guard trailer["Root"] != nil else { throw PDFError("The PDF has no document catalog.") }
        size = max(trailer["Size"]?.int ?? 0, (entries.keys.max() ?? 0) + 1)
    }

    static func findStartXref(_ data: Data) throws -> Int {
        let tail = data.suffix(2048)
        guard let range = tail.range(of: Data("startxref".utf8), options: .backwards) else {
            throw PDFError("startxref not found")
        }
        var lexer = PDFLexer(data, at: range.upperBound)
        guard case .int(let offset) = try lexer.object(), offset > 0, offset < data.count else {
            throw PDFError("bad startxref")
        }
        return offset
    }

    private func readXrefChain(from start: Int) throws {
        var offset: Int? = start
        var visited = Set<Int>()
        var first = true
        while let current = offset, !visited.contains(current) {
            guard current >= 0, current < data.count, visited.count < 1000 else { throw PDFError("bad cross-reference offset") }
            visited.insert(current)
            var lexer = PDFLexer(data, at: current)
            lexer.skipWhitespace()
            let section: PDFDict
            if lexer.pos < data.endIndex, data[lexer.pos...].starts(with: Data("xref".utf8)) {
                section = try readXrefTable(&lexer)
                if first { usesXrefStream = false }
                if let hybrid = section["XRefStm"]?.int { try readXrefStream(at: hybrid) }
            } else {
                section = try readXrefStream(at: current)
                if first { usesXrefStream = true }
            }
            if first { trailer = section } else {
                for (key, value) in section.entries where trailer[key] == nil && key != "Prev" && key != "XRefStm" {
                    trailer[key] = value
                }
            }
            first = false
            offset = section["Prev"]?.int
        }
        trailer["Prev"] = nil
        trailer["XRefStm"] = nil
    }

    private func readXrefTable(_ lexer: inout PDFLexer) throws -> PDFDict {
        try lexer.expectKeyword("xref")
        while true {
            lexer.skipWhitespace()
            let save = lexer.pos
            let token = lexer.regularToken()
            if token == "trailer" { break }
            guard let first = Int(token) else {
                lexer.pos = save
                throw PDFError("bad xref table")
            }
            lexer.skipWhitespace()
            guard let count = Int(lexer.regularToken()), count >= 0, first >= 0,
                  count <= (data.count - lexer.pos) / 18 + 1 else { throw PDFError("bad xref subsection") }
            for i in 0..<count {
                lexer.skipWhitespace()
                let offset = Int(lexer.regularToken()) ?? 0
                lexer.skipWhitespace()
                let generation = Int(lexer.regularToken()) ?? 0
                lexer.skipWhitespace()
                let kind = lexer.regularToken()
                let number = first + i
                if entries[number] == nil {
                    entries[number] = kind == "n" ? .offset(offset, generation: generation) : .free
                }
            }
        }
        guard case .dict(let dict) = try lexer.object() else { throw PDFError("bad trailer") }
        return dict
    }

    @discardableResult
    private func readXrefStream(at offset: Int) throws -> PDFDict {
        var lexer = PDFLexer(data, at: offset)
        _ = try lexer.object()  // object number
        _ = try lexer.object()  // generation
        try lexer.expectKeyword("obj")
        guard case .stream(let dict, let raw) = try lexer.object(resolveLength: { [weak self] in self?.lengthObject($0) }) else {
            throw PDFError("bad cross-reference stream")
        }
        let body = try Filters.decode(dict, raw)
        let widths = (dict["W"]?.array ?? []).compactMap(\.int)
        guard widths.count == 3, widths.allSatisfy({ (0...8).contains($0) }) else { throw PDFError("bad /W in cross-reference stream") }
        let size = dict["Size"]?.int ?? 0
        var index = (dict["Index"]?.array ?? [.int(0), .int(size)]).compactMap(\.int)
        if index.count % 2 == 1 { index.removeLast() }
        let rowLength = widths.reduce(0, +)
        let bytes = [UInt8](body)
        var position = 0
        func field(_ width: Int, default value: Int) -> Int {
            guard width > 0 else { return value }
            var result = 0
            for _ in 0..<width {
                result = result << 8 | Int(position < bytes.count ? bytes[position] : 0)
                position += 1
            }
            return result
        }
        for pair in stride(from: 0, to: index.count, by: 2) {
            guard index[pair] >= 0, index[pair + 1] >= 0 else { throw PDFError("bad /Index in cross-reference stream") }
            for i in 0..<min(index[pair + 1], bytes.count / max(rowLength, 1) + 1) {
                guard position + rowLength <= bytes.count else { break }
                let type = field(widths[0], default: 1)
                let a = field(widths[1], default: 0)
                let b = field(widths[2], default: 0)
                let number = index[pair] + i
                guard entries[number] == nil else { continue }
                switch type {
                case 1: entries[number] = .offset(a, generation: b)
                case 2: entries[number] = .compressed(stream: a, index: b)
                default: entries[number] = .free
                }
            }
        }
        return dict
    }

    private func lengthObject(_ number: Int) -> Int? {
        guard case .offset(let offset, _)? = entries[number], offset >= 0, offset < data.count else { return nil }
        var lexer = PDFLexer(data, at: offset)
        _ = try? lexer.object()
        _ = try? lexer.object()
        try? lexer.expectKeyword("obj")
        return (try? lexer.object())?.int
    }

    // MARK: objects

    public func object(_ number: Int) throws -> PDFObject {
        if let cached = cache[number] { return cached }
        let result: PDFObject
        switch entries[number] {
        case .offset(let offset, _)?:
            guard offset >= 0, offset < data.count else { throw PDFError("bad object offset") }
            var lexer = PDFLexer(data, at: offset)
            _ = try lexer.object()
            _ = try lexer.object()
            try lexer.expectKeyword("obj")
            result = try lexer.object(resolveLength: { [weak self] in self?.lengthObject($0) })
        case .compressed(let stream, let index)?:
            result = try objectFromStream(stream, number: number, index: index)
        case .free?, nil:
            result = .null
        }
        cache[number] = result
        return result
    }

    private func objectFromStream(_ stream: Int, number: Int, index: Int) throws -> PDFObject {
        if objectStreams[stream] == nil {
            // An object stream must be stored directly (never inside another object stream).
            guard case .offset? = entries[stream], case .stream(let dict, let raw) = try object(stream) else {
                throw PDFError("bad object stream")
            }
            let body = try Filters.decode(dict, raw)
            let count = min(max(dict["N"]?.int ?? 0, 0), body.count / 2)
            let first = dict["First"]?.int ?? 0
            var lexer = PDFLexer(body)
            var header: [(Int, Int)] = []
            for _ in 0..<count {
                guard let n = try lexer.object().int, let o = try lexer.object().int else { break }
                header.append((n, o))
            }
            var objects: [Int: PDFObject] = [:]
            for (n, o) in header {
                var objectLexer = PDFLexer(body, at: first + o)
                objects[n] = try? objectLexer.object()
            }
            objectStreams[stream] = objects
        }
        return objectStreams[stream]?[number] ?? .null
    }

    /// Follows a reference; other objects are returned as they are.
    public func resolve(_ object: PDFObject?) throws -> PDFObject? {
        guard let object else { return nil }
        if case .ref(let n, _) = object { return try self.object(n) }
        return object
    }

    public var rootRef: (Int, Int) { trailer["Root"]?.ref ?? (0, 0) }

    /// Whether the current revision is PDF 2.0 (ISO 32000-2).
    public var isPDF2: Bool { version >= 2 }

    /// The PDF version: the header's, or a later /Version in the catalog (ISO 32000 clause 7.7.2).
    public var version: Double {
        var version = 0.0
        if let header = data.prefix(1024).range(of: Data("%PDF-".utf8)) {
            let digits = data[header.upperBound..<min(header.upperBound + 3, data.endIndex)]
            version = Double(String(decoding: digits, as: UTF8.self)) ?? 0
        }
        if let name = (try? catalog())?["Version"]?.name, let catalogVersion = Double(name) {
            version = max(version, catalogVersion)
        }
        return version
    }

    /// The DocMDP permission of a certification signature (1: no changes, 2: form filling and signing,
    /// 3: also annotations), or nil if the document is not certified (ISO 32000 clause 12.8.2.2).
    public func docMDPPermission() throws -> Int? {
        guard let perms = try resolve(try catalog()["Perms"])?.dict,
              let signature = try resolve(perms["DocMDP"])?.dict else { return nil }
        for reference in try resolve(signature["Reference"])?.array ?? [] {
            guard let dict = try resolve(reference)?.dict, dict["TransformMethod"]?.name == "DocMDP" else { continue }
            return try resolve(dict["TransformParams"])?.dict?["P"]?.int ?? 2
        }
        return 2
    }

    public func catalog() throws -> PDFDict {
        guard let dict = try resolve(trailer["Root"])?.dict else { throw PDFError("The PDF has no document catalog.") }
        return dict
    }

    /// References to the page objects, in order.
    public func pageRefs() throws -> [(Int, Int)] {
        var out: [(Int, Int)] = []
        var visited = Set<Int>()
        func walk(_ node: PDFObject?) throws {
            guard case .ref(let n, let g)? = node, !visited.contains(n) else { return }
            visited.insert(n)
            guard let dict = try object(n).dict else { return }
            if dict["Type"]?.name == "Pages" || dict["Kids"] != nil {
                for kid in try resolve(dict["Kids"])?.array ?? [] { try walk(kid) }
            } else {
                out.append((n, g))
            }
        }
        try walk(try catalog()["Pages"])
        return out
    }

    /// A page attribute that may be inherited from the page tree (MediaBox, CropBox, Resources, Rotate).
    public func inherited(_ key: String, page: PDFDict) throws -> PDFObject? {
        var node: PDFDict? = page
        var depth = 0
        while let current = node, depth < 64 {
            if let value = current[key] { return try resolve(value) }
            node = try resolve(current["Parent"])?.dict
            depth += 1
        }
        return nil
    }

    /// Fields of the interactive form, flattened (with their full names).
    public func signatureFields() throws -> [(ref: (Int, Int)?, name: String, signed: Bool)] {
        guard let form = try resolve(try catalog()["AcroForm"])?.dict else { return [] }
        var out: [(ref: (Int, Int)?, name: String, signed: Bool)] = []
        var visited = Set<Int>()
        func walk(_ node: PDFObject, prefix: String, inheritedType: String?) throws {
            if case .ref(let n, _) = node {
                guard !visited.contains(n) else { return }
                visited.insert(n)
            }
            guard let dict = try resolve(node)?.dict else { return }
            let partial = dict["T"]?.stringBytes.map { PDFFile.decodeText($0) }
            let name = [prefix, partial ?? ""].filter { !$0.isEmpty }.joined(separator: ".")
            let type = dict["FT"]?.name ?? inheritedType
            if let kids = try resolve(dict["Kids"])?.array, kids.contains(where: { (try? resolve($0)?.dict?["T"]) != nil }) {
                for kid in kids { try walk(kid, prefix: name, inheritedType: type) }
            } else if type == "Sig" {
                out.append((node.ref, name, dict["V"] != nil && dict["V"] != .null))
            }
        }
        for field in try resolve(form["Fields"])?.array ?? [] { try walk(field, prefix: "", inheritedType: nil) }
        return out
    }

    /// Names of all form fields (to avoid clashes).
    public func fieldNames() throws -> Set<String> {
        guard let form = try resolve(try catalog()["AcroForm"])?.dict else { return [] }
        var names = Set<String>()
        var visited = Set<Int>()
        func walk(_ node: PDFObject, prefix: String) throws {
            if case .ref(let n, _) = node {
                guard !visited.contains(n) else { return }
                visited.insert(n)
            }
            guard let dict = try resolve(node)?.dict else { return }
            let partial = dict["T"]?.stringBytes.map { PDFFile.decodeText($0) }
            let name = [prefix, partial ?? ""].filter { !$0.isEmpty }.joined(separator: ".")
            if !name.isEmpty { names.insert(name) }
            for kid in try resolve(dict["Kids"])?.array ?? [] { try walk(kid, prefix: name) }
        }
        for field in try resolve(form["Fields"])?.array ?? [] { try walk(field, prefix: "") }
        return names
    }

    static func decodeText(_ bytes: Data) -> String {
        if bytes.starts(with: [0xFE, 0xFF]) {
            return String(data: bytes.dropFirst(2), encoding: .utf16BigEndian) ?? ""
        }
        return String(data: bytes, encoding: .isoLatin1) ?? ""
    }
}
