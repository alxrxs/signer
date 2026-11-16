import AppKit
import CoreGraphics
import Foundation
import PDFKit
import Security
import Testing
@testable import SignerCore

/// A PDF drawn by Core Graphics (classic cross-reference table).
func makePDF(pages: Int = 1, size: CGSize = CGSize(width: 595, height: 842)) -> Data {
    let data = NSMutableData()
    var box = CGRect(origin: .zero, size: size)
    let context = CGContext(consumer: CGDataConsumer(data: data)!, mediaBox: &box, nil)!
    for _ in 0..<pages {
        context.beginPDFPage(nil)
        context.setFillColor(gray: 0.9, alpha: 1)
        context.fill(CGRect(x: 50, y: 50, width: 100, height: 100))
        context.endPDFPage()
    }
    context.closePDF()
    return data as Data
}

/// A PDF using a cross-reference stream and an object stream, like Word or Acrobat exports.
func makeXrefStreamPDF() -> Data {
    var out = Data("%PDF-1.7\n%\u{E2}\u{E3}\n".utf8)
    var offsets: [Int: Int] = [:]
    func object(_ n: Int, _ body: Data) {
        offsets[n] = out.count
        out += Data("\(n) 0 obj\n".utf8) + body + Data("\nendobj\n".utf8)
    }
    let content = Data("0.5 g 50 50 100 100 re f".utf8)
    object(4, PDFObject.stream(PDFDict(), content).serialized())
    // Objects 1–3 live compressed in object stream 5.
    let packed = [
        "<</Type/Catalog/Pages 2 0 R>>",
        "<</Type/Pages/Kids[3 0 R]/Count 1>>",
        "<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]/Contents 4 0 R/Resources<<>>>>",
    ]
    var header = "", body = ""
    for (i, text) in packed.enumerated() {
        header += "\(i + 1) \(body.utf8.count) "
        body += text + " "
    }
    let objstm = Data((header + body).utf8)
    var stmDict = PDFDict()
    stmDict["Type"] = .name("ObjStm")
    stmDict["N"] = .int(3)
    stmDict["First"] = .int(header.utf8.count)
    stmDict["Filter"] = .name("FlateDecode")
    object(5, PDFObject.stream(stmDict, Filters.deflate(objstm)).serialized())
    // xref stream, W [1 2 1], PNG Up predictor to exercise decoding.
    let xrefOffset = out.count
    var rows: [[UInt8]] = [[0, 0, 0, 255]]
    for n in 1...3 { rows.append([2, 0, 5, UInt8(n - 1)]) }
    rows.append([1, UInt8(offsets[4]! >> 8), UInt8(offsets[4]! & 0xFF), 0])
    rows.append([1, UInt8(offsets[5]! >> 8), UInt8(offsets[5]! & 0xFF), 0])
    rows.append([1, UInt8(xrefOffset >> 8), UInt8(xrefOffset & 0xFF), 0])
    var predicted = Data()
    var previous: [UInt8] = [0, 0, 0, 0]
    for row in rows {
        predicted.append(2)
        predicted.append(contentsOf: zip(row, previous).map { $0 &- $1 })
        previous = row
    }
    var xref = PDFDict()
    xref["Type"] = .name("XRef")
    xref["Size"] = .int(7)
    xref["W"] = .array([.int(1), .int(2), .int(1)])
    xref["Root"] = .ref(1, 0)
    xref["Filter"] = .name("FlateDecode")
    xref["DecodeParms"] = .dict(PDFDict([("Predictor", .int(12)), ("Columns", .int(4))]))
    object(6, PDFObject.stream(xref, Filters.deflate(predicted)).serialized())
    out += Data("startxref\n\(xrefOffset)\n%%EOF\n".utf8)
    return out
}

/// A one-page PDF to use as a stamp appearance.
func makeStamp(_ size: CGSize = CGSize(width: 200, height: 60)) -> Data {
    let data = NSMutableData()
    var box = CGRect(origin: .zero, size: size)
    let context = CGContext(consumer: CGDataConsumer(data: data)!, mediaBox: &box, nil)!
    context.beginPDFPage(nil)
    context.setStrokeColor(gray: 0, alpha: 1)
    context.stroke(box.insetBy(dx: 1, dy: 1))
    context.endPDFPage()
    context.closePDF()
    return data as Data
}

@discardableResult
func verifySignatures(_ pdf: Data) throws -> Int { try Verification.verify(pdf).count }

@Suite struct DERTests {
    @Test func oidsRoundTrip() {
        for oid in [OID.sha384, OID.p384, OID.qcTypeESign, OID.signingCertificateV2] {
            #expect(DER.oid(oid).oidString == oid)
        }
    }

    @Test func integersAreMinimalAndSigned() {
        #expect(DER.integer(0).encoded == Data([2, 1, 0]))
        #expect(DER.integer(128).encoded == Data([2, 2, 0, 0x80]))
        #expect(DER.integer(-1).encoded == Data([2, 1, 0xFF]))
        #expect(DER.integer(65537).int == 65537)
    }

    @Test func longLengthsRoundTrip() throws {
        let big = DER.octetString(Data(count: 70_000))
        #expect(try DER(big.encoded).content.count == 70_000)
    }
}

@Suite struct CertificateTests {
    @Test func readsWhatSigningDecisionsNeed() throws {
        let ec = try SoftwareSigner(.ecP384).certificate
        #expect(ec.commonName == "TEST SIGNER")
        #expect(ec.keyAlgorithm == .ec(curve: .p384))
        #expect(ec.digest == .sha384, "P-384 signs with SHA-384")
        #expect(ec.purpose == .signing)
        #expect(ec.isSelfSigned)
        let rsa = try SoftwareSigner(.rsa2048, keyUsage: 0x80).certificate
        #expect(rsa.keyAlgorithm == .rsa(bits: 2048))
        #expect(rsa.digest == .sha256)
        #expect(rsa.purpose == .authentication, "digitalSignature only means authentication")
        #expect(rsa.tier == .advanced)
    }
}

@Suite struct PDFTests {
    @Test func readsClassicAndStreamCrossReferences() throws {
        #expect(try PDFFile(data: makePDF(pages: 3)).pageRefs().count == 3)
        let modern = try PDFFile(data: makeXrefStreamPDF())
        #expect(modern.usesXrefStream)
        #expect(try modern.pageRefs().count == 1)
        #expect(try modern.catalog()["Type"]?.name == "Catalog")
    }

    @Test func incrementalUpdateKeepsTheOriginalBytes() throws {
        for original in [makePDF(), makeXrefStreamPDF()] {
            let file = try PDFFile(data: original)
            var update = IncrementalUpdate(file)
            update.add(.dict(PDFDict([("Hello", .string(Data("world".utf8)))])))
            let updated = update.write()
            #expect(updated.prefix(original.count) == original)
            let reread = try PDFFile(data: updated)
            #expect(try reread.pageRefs().count == 1)
            #expect(reread.usesXrefStream == file.usesXrefStream)
            #expect(try reread.object(file.size).dict?["Hello"] != nil)
        }
    }

    @Test func parsesStringsAndNames() throws {
        var lexer = PDFLexer(Data("<</A#20B (x\\(y\\)\\101) /C <48656c6c6f> /D [1 2 0 R 3.5]>>".utf8))
        let dict = try #require(try lexer.object().dict)
        #expect(dict["A B"]?.stringBytes == Data("x(y)A".utf8))
        #expect(dict["C"]?.stringBytes == Data("Hello".utf8))
        #expect(dict["D"]?.array == [.int(1), .ref(2, 0), .real(3.5)])
    }
}

@Suite struct SigningTests {
    @Test(arguments: [SoftwareSigner.Kind.ecP384, .rsa2048])
    func signsVisibleAndInvisible(kind: SoftwareSigner.Kind) async throws {
        let signer = try SoftwareSigner(kind)
        for original in [makePDF(pages: 2), makeXrefStreamPDF()] {
            let visible = try await PAdES.sign(
                pdf: original,
                placement: SignaturePlacement(pageIndex: 0, rect: CGRect(x: 300, y: 50, width: 200, height: 60), appearance: makeStamp()),
                info: SignatureInfo(reason: "Conform cu originalul", location: "București"),
                level: .b, signer: signer, chain: [])
            #expect(visible.prefix(original.count) == original)
            #expect(try verifySignatures(visible) == 1)

            // A second signature on top keeps the first one intact.
            let twice = try await PAdES.sign(pdf: visible, placement: SignaturePlacement(pageIndex: 0, rect: nil, appearance: nil),
                                             info: SignatureInfo(), level: .b, signer: signer, chain: [])
            #expect(try verifySignatures(twice) == 2)
            #expect(try PDFFile(data: twice).signatureFields().map(\.name) == ["Signature1", "Signature2"])
        }
    }

    @Test func rotatedPagesGetAnUprightStamp() async throws {
        let signer = try SoftwareSigner()
        let signed = try await PAdES.sign(
            pdf: makePDF(), placement: SignaturePlacement(pageIndex: 0, rect: CGRect(x: 50, y: 300, width: 60, height: 200),
                                                         appearance: makeStamp(), pageRotation: 90),
            info: SignatureInfo(), level: .b, signer: signer, chain: [])
        #expect(try verifySignatures(signed) == 1)
        #expect(String(decoding: signed, as: UTF8.self).contains("/BBox [0 0 60 200]"), "box in the page's own orientation")
    }
}

@Suite struct VerificationTests {
    @Test func detectsTampering() async throws {
        let signer = try SoftwareSigner()
        var signed = try await PAdES.sign(pdf: makePDF(), placement: SignaturePlacement(pageIndex: 0, rect: nil, appearance: nil),
                                          info: SignatureInfo(), level: .b, signer: signer, chain: [])
        // Flip one byte of page content inside the signed range.
        let target = try #require(signed.range(of: Data("stream".utf8)))
        signed[target.upperBound + 5] ^= 0x01
        #expect(throws: SigningError.self) { try Verification.verify(signed) }
    }

    @Test func refusesHostileInput() {
        var deep = Data("%PDF-1.7\n1 0 obj\n".utf8) + Data(repeating: UInt8(ascii: "["), count: 100_000)
        deep += Data("\nendobj\nxref\n0 2\n0000000000 65535 f\r\n0000000009 00000 n\r\ntrailer<</Root 1 0 R/Size 2>>\nstartxref\n".utf8)
        deep += Data("\(deep.count - 0)\n%%EOF".utf8)
        #expect(throws: (any Error).self) { _ = try PDFFile(data: deep).catalog() }
        #expect(throws: (any Error).self) { _ = try PDFFile(data: Data("%PDF-1.7\ngarbage".utf8)) }
        let truncated = makePDF().prefix(400)
        #expect(throws: (any Error).self) { _ = try PDFFile(data: Data(truncated)).pageRefs() }
    }
}

/// Writes signed files at every level for external validators. Opt-in, needs the network:
/// SIGNER_DUMP=/tmp/signer swift test --filter dumpForValidators
@Suite struct ExternalValidation {
    @Test(.enabled(if: ProcessInfo.processInfo.environment["SIGNER_DUMP"] != nil))
    func dumpForValidators() async throws {
        let directory = URL(fileURLWithPath: ProcessInfo.processInfo.environment["SIGNER_DUMP"]!)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let signer = try SoftwareSigner(.ecP384)
        try signer.certificate.der.write(to: directory.appendingPathComponent("signer.der"))
        // SIGNER_TSA=<url> makes one B-T sample with that timestamp server (for evaluating TSAs).
        if let tsa = ProcessInfo.processInfo.environment["SIGNER_TSA"], let url = URL(string: tsa) {
            let signed = try await PAdES.sign(pdf: makePDF(), placement: SignaturePlacement(pageIndex: 0, rect: nil, appearance: nil),
                                              info: SignatureInfo(), level: .t, signer: signer, chain: [],
                                              timestamper: Timestamper(url: url))
            try signed.write(to: directory.appendingPathComponent("tsa.pdf"))
            return
        }
        for (name, original) in [("classic", makePDF()), ("xrefstream", makeXrefStreamPDF())] {
            for level in SignatureLevel.allCases {
                let signed = try await PAdES.sign(
                    pdf: original,
                    placement: SignaturePlacement(pageIndex: 0, rect: CGRect(x: 300, y: 50, width: 200, height: 60), appearance: makeStamp()),
                    info: SignatureInfo(reason: "Conform cu originalul"), level: level, signer: signer, chain: [])
                try signed.write(to: directory.appendingPathComponent("\(name)-\(level.rawValue).pdf"))
            }
        }
    }
}

@Suite struct StampTests {
    @Test func autoFitGrowsWithTheBoxAndNeverClips() {
        let style = StampStyle(text: "Semnat digital de\nȘTEFĂNESCU ȚĂRANU\nData: 16.11.2026 14:00:00")
        let small = Stamp.layout(style, in: CGSize(width: 180, height: 50))
        let large = Stamp.layout(style, in: CGSize(width: 360, height: 100))
        #expect(!small.clipped && !large.clipped)
        #expect(large.fontSize > small.fontSize)
        #expect(Stamp.layout(style, in: CGSize(width: 30, height: 10)).clipped)
        var manual = style
        manual.autoFit = false
        manual.fontSize = 40
        #expect(Stamp.layout(manual, in: CGSize(width: 180, height: 50)).clipped)
    }

    @Test func expandsTheDate() {
        let date = Date(timeIntervalSince1970: 0)
        #expect(!Stamp.expand("Data: {date}", date: date).contains("{date}"))
    }
}

let popplerPath = ["/opt/homebrew/bin/pdftoppm", "/usr/local/bin/pdftoppm"].first { FileManager.default.isExecutableFile(atPath: $0) }

/// Renders page 0 (with PDFKit, or poppler's pdftoppm) and returns the grey level at a normalised
/// display point.
func greyLevel(_ pdf: Data, at point: CGPoint, poppler: Bool = false) throws -> CGFloat {
    let rep: NSBitmapImageRep
    if poppler {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let input = directory.appendingPathComponent("in.pdf")
        try pdf.write(to: input)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: try #require(popplerPath))
        process.arguments = ["-r", "72", "-png", "-singlefile", input.path, directory.appendingPathComponent("out").path]
        try process.run()
        process.waitUntilExit()
        rep = try #require(NSBitmapImageRep(data: try Data(contentsOf: directory.appendingPathComponent("out.png"))))
    } else {
        let page = try #require(PDFDocument(data: pdf)?.page(at: 0))
        let image = page.thumbnail(of: CGSize(width: 600, height: 600), for: .cropBox)
        let tiff = try #require(image.tiffRepresentation)
        rep = try #require(NSBitmapImageRep(data: tiff))
    }
    let color = try #require(rep.colorAt(x: Int(point.x * CGFloat(rep.pixelsWide)), y: Int(point.y * CGFloat(rep.pixelsHigh))))
    return color.usingColorSpace(.genericGray)?.whiteComponent ?? 1
}

@Suite struct GeometryTests {
    /// Sets /Rotate on page 0 via an incremental update.
    func rotated(_ pdf: Data, by degrees: Int) throws -> Data {
        let file = try PDFFile(data: pdf)
        let (n, g) = try file.pageRefs()[0]
        var page = try #require(try file.object(n).dict)
        page["Rotate"] = .int(degrees)
        var update = IncrementalUpdate(file)
        update.set(.ref(n, g), .dict(page))
        return update.write()
    }

    @Test(arguments: [0, 90, 180, 270])
    func stampLandsWhereItWasDrawn(rotation: Int) async throws {
        let original = try rotated(makePDF(size: CGSize(width: 400, height: 600)), by: rotation)
        let geometry = PageGeometry(cropBox: CGRect(x: 0, y: 0, width: 400, height: 600), rotation: rotation)
        // A box in the display's top-right region; its left half is black.
        let display = CGRect(x: 0.55, y: 0.05, width: 0.35, height: 0.12)
        let size = geometry.displayPointSize(of: display)
        let data = NSMutableData()
        var box = CGRect(origin: .zero, size: size)
        let context = CGContext(consumer: CGDataConsumer(data: data)!, mediaBox: &box, nil)!
        context.beginPDFPage(nil)
        context.setFillColor(gray: 0, alpha: 1)
        context.fill(CGRect(x: 0, y: 0, width: size.width / 2, height: size.height))
        context.endPDFPage()
        context.closePDF()
        let signed = try await PAdES.sign(
            pdf: original,
            placement: SignaturePlacement(pageIndex: 0, rect: geometry.userRect(fromDisplay: display),
                                          appearance: data as Data, pageRotation: rotation),
            info: SignatureInfo(), level: .b, signer: try SoftwareSigner(), chain: [])
        // NSBitmapImageRep rows run top-down, matching the display's top-left origin. poppler follows
        // the PDF specification; PDFKit does not draw signature widgets on rotated pages at all.
        var renderers = [false]
        if popplerPath != nil { renderers.append(true) }
        for poppler in renderers where !(rotation != 0 && !poppler) {
            #expect(try greyLevel(signed, at: CGPoint(x: display.minX + display.width * 0.25, y: display.midY), poppler: poppler) < 0.2,
                    "left half of the stamp is black on screen (poppler: \(poppler))")
            #expect(try greyLevel(signed, at: CGPoint(x: display.minX + display.width * 0.75, y: display.midY), poppler: poppler) > 0.8,
                    "right half stays white, so the stamp is upright (poppler: \(poppler))")
            #expect(try greyLevel(signed, at: CGPoint(x: 0.3, y: 0.5), poppler: poppler) > 0.8, "nothing drawn elsewhere")
        }
    }
}

@Suite struct PaddingTests {
    /// About 1 in 256 signatures end in a zero byte, which must not be mistaken for /Contents padding.
    @Test func signaturesEndingInZeroStillVerify() async throws {
        let signer = try SoftwareSigner()
        let pdf = makePDF()
        for _ in 0..<600 {
            let signed = try await PAdES.sign(pdf: pdf, placement: SignaturePlacement(pageIndex: 0, rect: nil, appearance: nil),
                                              info: SignatureInfo(), level: .b, signer: signer, chain: [])
            #expect(try verifySignatures(signed) == 1)
        }
    }
}

/// Requirements of ETSI EN 319 142-1 V1.3.1 that the output must meet to the letter.
@Suite struct ConformanceTests {
    func catalog(_ pdf: Data) throws -> (PDFFile, PDFDict) {
        let file = try PDFFile(data: pdf)
        return (file, try file.catalog())
    }

    func esicLevels(_ file: PDFFile, _ catalog: PDFDict) throws -> [Int] {
        guard let extensions = try file.resolve(catalog["Extensions"])?.dict else { return [] }
        let items: [PDFObject] = switch try file.resolve(extensions["ESIC"]) {
        case .array(let a)?: a
        case let item?: [item]
        case nil: []
        }
        return try items.compactMap { try file.resolve($0)?.dict?["ExtensionLevel"]?.int }.sorted()
    }

    func signatureDictionary(_ file: PDFFile) throws -> PDFDict {
        let field = try #require(try file.signatureFields().first)
        let ref = try #require(field.ref)
        let widget = try #require(try file.object(ref.0).dict)
        return try #require(try file.resolve(widget["V"])?.dict)
    }

    @Test func pdf17SignatureDeclaresESICLevel2() async throws {
        let signed = try await PAdES.sign(pdf: makePDF(), placement: SignaturePlacement(pageIndex: 0, rect: nil, appearance: nil),
                                          info: SignatureInfo(signerName: "TEST SIGNER"), level: .b, signer: try SoftwareSigner(), chain: [])
        let (file, catalog) = try catalog(signed)
        #expect(try esicLevels(file, catalog) == [2], "clause 5.6.1: ETSI.CAdES.detached needs ESIC level 2")
        let sig = try signatureDictionary(file)
        #expect(sig["SubFilter"]?.name == "ETSI.CAdES.detached", "clause 6.3 l")
        #expect(sig["Filter"] != nil && sig["M"] != nil && sig["ByteRange"] != nil, "clause 6.3: Filter, M, ByteRange")
        #expect(sig["Name"] == nil, "clause 5.3: no Name when it is in the certificate")
        #expect(sig["Cert"] == nil, "clause 6.3: Cert shall not be present")
        #expect(sig["Prop_Build"] != nil, "clause 5.3: Prop_Build")
    }

    /// SET OF elements must be in DER order (sorted by encoding).
    func isDERSorted(_ set: DER) throws -> Bool {
        let items = try set.children().map(\.encoded)
        return items == items.sorted { $0.lexicographicallyPrecedes($1) }
    }

    @Test func certificateSetIsDER() async throws {
        let signer = try SoftwareSigner()
        let others = try (0..<3).map { _ in try SoftwareSigner(name: "CA \(Int.random(in: 0...999))").certificate }
        let signed = try await PAdES.sign(pdf: makePDF(), placement: SignaturePlacement(pageIndex: 0, rect: nil, appearance: nil),
                                          info: SignatureInfo(), level: .b, signer: signer, chain: others)
        let file = try PDFFile(data: signed)
        let contents = try #require(try signatureDictionary(file)["Contents"]?.stringBytes)
        var offset = contents.startIndex
        let signedData = try DER.read(contents, at: &offset).child(1).child(0)
        let certificates = try #require(try signedData.context(0))
        #expect(try certificates.children().count == 4)
        #expect(try isDERSorted(certificates), "clause 4.1 a: DER-encoded SignedData")
    }

    @Test func dateIsUTC() async throws {
        let signed = try await PAdES.sign(pdf: makePDF(), placement: SignaturePlacement(pageIndex: 0, rect: nil, appearance: nil),
                                          info: SignatureInfo(), level: .b, signer: try SoftwareSigner(), chain: [])
        let m = String(decoding: try #require(try signatureDictionary(PDFFile(data: signed))["M"]?.stringBytes), as: UTF8.self)
        #expect(m.wholeMatch(of: /D:\d{14}Z/) != nil, "valid under ISO 32000-1 and -2: \(m)")
    }

    @Test func olderFilesAreRaisedTo17() async throws {
        let original = makePDF()
        #expect(try PDFFile(data: original).version < 1.7)
        let signed = try await PAdES.sign(pdf: original, placement: SignaturePlacement(pageIndex: 0, rect: nil, appearance: nil),
                                          info: SignatureInfo(), level: .b, signer: try SoftwareSigner(), chain: [])
        #expect(try PDFFile(data: signed).version == 1.7)
    }

    @Test func refusesCertifiedNoChanges() async throws {
        let file = try PDFFile(data: makePDF())
        var update = IncrementalUpdate(file)
        let params = PDFDict([("P", .int(1)), ("V", .name("1.2"))])
        let reference = PDFDict([("Type", .name("SigRef")), ("TransformMethod", .name("DocMDP")), ("TransformParams", .dict(params))])
        let certification = update.add(.dict(PDFDict([("Type", .name("Sig")), ("Reference", .array([.dict(reference)]))])))
        var catalog = try file.catalog()
        catalog["Perms"] = .dict(PDFDict([("DocMDP", certification)]))
        update.set(.ref(file.rootRef.0, file.rootRef.1), .dict(catalog))
        let certified = update.write()
        #expect(try PDFFile(data: certified).docMDPPermission() == 1)
        await #expect(throws: SigningError.self) {
            _ = try await PAdES.sign(pdf: certified, placement: SignaturePlacement(pageIndex: 0, rect: nil, appearance: nil),
                                     info: SignatureInfo(), level: .b, signer: try SoftwareSigner(), chain: [])
        }
    }

    @Test func refusesEncrypted() async throws {
        var pdf = makePDF()
        let trailer = try #require(pdf.range(of: Data("trailer".utf8), options: .backwards))
        let open = try #require(pdf.range(of: Data("<<".utf8), in: trailer.upperBound..<pdf.endIndex))
        pdf.replaceSubrange(open, with: Data("<< /Encrypt 9999 0 R ".utf8))
        await #expect(throws: SigningError.self) {
            _ = try await PAdES.sign(pdf: pdf, placement: SignaturePlacement(pageIndex: 0, rect: nil, appearance: nil),
                                     info: SignatureInfo(), level: .b, signer: try SoftwareSigner(), chain: [])
        }
    }

    @Test func pdf20DocumentsGetNoExtensions() async throws {
        var pdf = makePDF()
        let header = try #require(pdf.range(of: Data("%PDF-1.".utf8)))
        pdf.replaceSubrange(header.lowerBound..<(header.upperBound + 1), with: Data("%PDF-2.0".utf8))
        #expect(try PDFFile(data: pdf).isPDF2)
        let signed = try await PAdES.sign(pdf: pdf, placement: SignaturePlacement(pageIndex: 0, rect: nil, appearance: nil),
                                          info: SignatureInfo(), level: .b, signer: try SoftwareSigner(), chain: [])
        let (_, catalog) = try catalog(signed)
        #expect(catalog["Extensions"] == nil, "clause 5.6.2: no /Extensions for PDF 2.0")
        #expect(try verifySignatures(signed) == 1)
    }

    /// B-LTA specifics; needs the network (timestamp server, OCSP).
    @Test(.enabled(if: ProcessInfo.processInfo.environment["SIGNER_DUMP"] != nil))
    func longTermStructure() async throws {
        let signer = try SoftwareSigner()
        let result = try await PAdES.signDocument(pdf: makePDF(), placement: SignaturePlacement(pageIndex: 0, rect: nil, appearance: nil),
                                                  info: SignatureInfo(), level: .lta, signer: signer, chain: [])
        #expect(result.level == .lta && result.shortfall == nil)
        let (file, catalog) = try catalog(result.pdf)
        #expect(try esicLevels(file, catalog) == [1, 2], "clause 5.6.1: both ESIC levels")
        let dss = try #require(try file.resolve(catalog["DSS"])?.dict)
        #expect(dss["Type"]?.name == "DSS")
        #expect(dss["VRI"] == nil, "clause 6.3 v: VRI should not be used")
        let certs = try (try file.resolve(dss["Certs"])?.array ?? []).compactMap { ref -> Data? in
            guard case .stream(let dict, let raw)? = try file.resolve(ref) else { return nil }
            return try Filters.decode(dict, raw)
        }
        #expect(certs.contains(signer.certificate.der), "clause 6.3 r: full certificate set in the DSS (the EU validator needs it for B-LTA)")
        #expect(!(try file.resolve(dss["OCSPs"])?.array ?? []).isEmpty, "clause 6.3 t: revocation data")
        let timestamps = try Verification.verify(result.pdf).filter(\.isDocumentTimestamp)
        #expect(timestamps.count == 1, "clause 6.3: B-LTA has a document timestamp")
        // Every embedded OCSP answer passes the same checks Signer applies, and a tampered one doesn't.
        try checkEmbeddedOCSP(file, dss: dss)
        // Clause 6.3 o): the signature-time-stamp is DER, including its certificate set.
        let sig = try signatureDictionary(file)
        let contents = try #require(sig["Contents"]?.stringBytes)
        var offset = contents.startIndex
        let signerInfo = try DER.read(contents, at: &offset).child(1).child(0).children().last!.child(0)
        let unsigned = try #require(try signerInfo.context(1))
        let token = try unsigned.child(0).child(1).child(0)
        if let tokenCertificates = try token.child(1).child(0).context(0) {
            #expect(try isDERSorted(tokenCertificates))
        }
        // Clause 5.3: Prop_Build on the document timestamp as well.
        let docTimestamp = try #require(try file.signatureFields().first { $0.name.hasPrefix("Timestamp") })
        let tsRef = try #require(docTimestamp.ref)
        let tsDict = try #require(try file.resolve(try file.object(tsRef.0).dict?["V"])?.dict)
        #expect(tsDict["Prop_Build"] != nil && tsDict["Name"] == nil && tsDict["M"] == nil)
    }
}

@Suite struct AppConfigurationTests {
    /// OCSP, CRL and certificate links are plain HTTP by design (their content is signed) and can be on
    /// any host, so App Transport Security must let the app load them; otherwise B-LT fails in the app
    /// while passing in these command-line tests.
    @Test func appAllowsPlainHTTPForRevocationData() throws {
        let plist = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("Resources/Info.plist")
        let info = try #require(try PropertyListSerialization.propertyList(from: Data(contentsOf: plist), format: nil) as? [String: Any])
        let ats = try #require(info["NSAppTransportSecurity"] as? [String: Any])
        #expect(ats["NSAllowsArbitraryLoads"] as? Bool == true)
    }
}

/// Runs Revocation.checkOCSP over every OCSP answer in a DSS (matched to the certificate it is about),
/// and checks that a tampered copy is rejected. Returns how many answers were checked.
@discardableResult
func checkEmbeddedOCSP(_ file: PDFFile, dss: PDFDict) throws -> Int {
    func streams(_ key: String) throws -> [Data] {
        try (try file.resolve(dss[key])?.array ?? []).compactMap { ref -> Data? in
            guard case .stream(let dict, let raw)? = try file.resolve(ref) else { return nil }
            return try Filters.decode(dict, raw)
        }
    }
    let certificates = try streams("Certs").compactMap { try? Certificate(der: $0) }
    var checked = 0
    for response in try streams("OCSPs") {
        let basic = try DER(try #require(try DER(response).context(0)).child(0).child(1).content)
        let single = try basic.child(0).children().first { $0.tag == DER.Tag.sequence && (try? $0.child(0).child(0).child(0)) != nil }
        let serial = try #require(single).child(0).child(0).child(3).encoded
        guard let subject = certificates.first(where: { $0.serialNumber.encoded == serial }),
              let issuer = certificates.first(where: { subject.isIssued(by: $0) }) else { continue }
        try Revocation.checkOCSP(response, for: subject, issuer: issuer)
        // Tamper with the signed data and with the signature value; both must be rejected.
        let parts = try basic.children()
        for target in [parts[0].encoded, try #require(parts[2].bitStringBytes)] {
            let range = try #require(response.range(of: target))
            var tampered = response
            tampered[range.lowerBound + range.count / 2] ^= 0x01
            #expect(throws: (any Error).self) { try Revocation.checkOCSP(tampered, for: subject, issuer: issuer) }
        }
        checked += 1
    }
    #expect(checked > 0)
    return checked
}

/// Diagnostic: SIGNER_CHECK_PDF=<signed.pdf> swift test --filter embeddedRevocationData
@Suite struct RealFileDiagnostics {
    @Test(.enabled(if: ProcessInfo.processInfo.environment["SIGNER_CHECK_PDF"] != nil))
    func embeddedRevocationData() throws {
        let path = ProcessInfo.processInfo.environment["SIGNER_CHECK_PDF"]!
        let file = try PDFFile(data: Data(contentsOf: URL(fileURLWithPath: path)))
        let dss = try #require(try file.resolve(try file.catalog()["DSS"])?.dict)
        let checked = try checkEmbeddedOCSP(file, dss: dss)
        print("checked \(checked) OCSP answers")
    }

    /// Diagnostic: SIGNER_CHECK_CERT=<cert.der> SIGNER_CHECK_ISSUER=<issuer.der> swift test --filter liveRevocation
    /// Fetches live OCSP and CRL answers for a certificate and runs them through Signer's checks.
    @Test(.enabled(if: ProcessInfo.processInfo.environment["SIGNER_CHECK_CERT"] != nil))
    func liveRevocation() async throws {
        let env = ProcessInfo.processInfo.environment
        let cert = try Certificate(der: Data(contentsOf: URL(fileURLWithPath: env["SIGNER_CHECK_CERT"]!)))
        let issuer = try Certificate(der: Data(contentsOf: URL(fileURLWithPath: env["SIGNER_CHECK_ISSUER"]!)))
        let ocsp = try await Revocation.ocsp(for: cert, issuer: issuer)
        #expect(ocsp != nil, "a validated OCSP answer")
        let responders = ocsp.map(Revocation.ocspCertificates) ?? []
        print("OCSP: \(ocsp?.count ?? 0) bytes, responder certificates: \(responders.map(\.commonName))")
        let crl = try #require(await Revocation.crl(for: cert))
        try Revocation.checkCRL(crl, for: cert, signer: issuer)
        print("CRL: \(crl.count) bytes, valid, certificate not listed")
        try await Revocation.ensureNotRevoked(cert, pool: [issuer])
        print("not revoked")
    }
}
