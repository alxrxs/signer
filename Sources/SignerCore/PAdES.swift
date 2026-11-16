import CoreGraphics
import Foundation
import PDFKit

/// PAdES baseline levels (ETSI EN 319 142-1).
public enum SignatureLevel: String, CaseIterable, Sendable, Identifiable {
    case b = "B-B", t = "B-T", lt = "B-LT", lta = "B-LTA"
    public var id: String { rawValue }
    var timestamped: Bool { self != .b }
    var longTerm: Bool { self == .lt || self == .lta }
}

/// Where and how the signature appears.
public struct SignaturePlacement: Sendable {
    public var pageIndex: Int
    /// Widget rectangle in the page's default user space; nil for an invisible signature.
    public var rect: CGRect?
    /// One-page PDF holding the stamp, drawn upright at the size it is seen on screen.
    public var appearance: Data?
    /// The page's /Rotate, so the appearance is turned to read upright.
    public var pageRotation: Int

    public init(pageIndex: Int, rect: CGRect?, appearance: Data?, pageRotation: Int = 0) {
        self.pageIndex = pageIndex
        self.rect = rect
        self.appearance = appearance
        self.pageRotation = pageRotation
    }
}

public struct SignatureInfo: Sendable {
    public var reason: String?
    public var location: String?
    public var signerName: String?
    public init(reason: String? = nil, location: String? = nil, signerName: String? = nil) {
        self.reason = reason
        self.location = location
        self.signerName = signerName
    }
}

public enum PAdES {
    public enum Stage: Sendable {
        case preparing, waitingForSigner, timestamping, collectingValidationData, archiveTimestamp
    }

    /// The signed file and the level it actually reached.
    public struct Result: Sendable {
        public let pdf: Data
        public let level: SignatureLevel
        /// Why the requested level was not reached (the card has already signed, so the signature is
        /// kept at the highest level that succeeded rather than thrown away).
        public let shortfall: String?
    }

    /// Signs `pdf` and returns the signed file. Throws if the requested level could not be reached.
    public static func sign(pdf: Data, placement: SignaturePlacement, info: SignatureInfo,
                            level: SignatureLevel, signer: any DigestSigner, chain: [Certificate],
                            timestamper: Timestamper = .default, archiveTimestamper: Timestamper = .archive,
                            date: Date = .now,
                            progress: @Sendable (Stage) -> Void = { _ in }) async throws -> Data {
        let result = try await signDocument(pdf: pdf, placement: placement, info: info, level: level, signer: signer,
                                            chain: chain, timestamper: timestamper, archiveTimestamper: archiveTimestamper,
                                            date: date, progress: progress)
        if let shortfall = result.shortfall { throw SigningError(shortfall) }
        return result.pdf
    }

    /// Signs `pdf`. Once the card has signed, network failures lower the level instead of failing.
    public static func signDocument(pdf: Data, placement: SignaturePlacement, info: SignatureInfo,
                                    level: SignatureLevel, signer: any DigestSigner, chain: [Certificate],
                                    timestamper: Timestamper = .default, archiveTimestamper: Timestamper = .archive,
                                    date: Date = .now,
                                    progress: @Sendable (Stage) -> Void = { _ in }) async throws -> Result {
        progress(.preparing)
        let file = try PDFFile(data: pdf)
        let certificate = signer.certificate
        let digest = certificate.digest

        // EN 319 142-1 5.5: new objects would have to be encrypted too; this writer doesn't encrypt.
        guard file.trailer["Encrypt"] == nil else {
            throw SigningError("This PDF is encrypted. Remove the password first (open it in Preview and export a copy).")
        }
        // ISO 32000 12.8.2.2 (applies via EN 319 142-1 4.1 b): a certification with P=1 forbids any change.
        if try file.docMDPPermission() == 1 {
            throw SigningError("This PDF is certified so that no changes are allowed, including new signatures.")
        }
        // Never sign with a revoked certificate (checked before the PIN is asked).
        try await Revocation.ensureNotRevoked(certificate, pool: chain)
        // EN 319 142-1 6.2.1 / TS 119 312: no weak keys.
        switch certificate.keyAlgorithm {
        case .rsa(let bits) where bits < 2048:
            throw SigningError("The certificate's RSA key is only \(bits) bits; at least 2048 are required.")
        case .ec(.unknown), .other:
            throw SigningError("The certificate's key type is not supported.")
        default: break
        }

        var sig = PDFDict()
        sig["Type"] = .name("Sig")
        sig["Filter"] = .name("Adobe.PPKLite")
        sig["SubFilter"] = .name("ETSI.CAdES.detached")
        sig["M"] = .string(Data(pdfDate(date).utf8))
        // No /Name: the signer's name is in the certificate (EN 319 142-1 clause 5.3 and 6.3 z).
        // Prop_Build: optional for PDF 1.7, strongly recommended for PDF 2.0 (clause 5.3).
        sig["Prop_Build"] = propBuild
        if let reason = info.reason, !reason.isEmpty { sig["Reason"] = .text(reason) }
        if let location = info.location, !location.isEmpty { sig["Location"] = .text(location) }

        let certBytes = ([certificate] + chain).reduce(0) { $0 + $1.der.count }
        let capacity = 8192 + certBytes + (level.timestamped ? 16384 : 0)
        // ESIC extension level 2 announces the ETSI.CAdES.detached SubFilter (clause 5.6.1).
        var prepared = try prepare(file, signature: sig, fieldPrefix: "Signature", placement: placement,
                                   capacity: capacity, extensionLevels: [2])

        progress(.waitingForSigner)
        let documentDigest = digest.hash(prepared.signedBytes)
        let signedCMS = try await CMS.sign(documentDigest: documentDigest, digest: digest, signer: signer,
                                           chain: chain, timestamper: level.timestamped ? timestamper : nil,
                                           signed: { progress(.timestamping) })
        var signed = try prepared.fill(signedCMS.data)
        let signatureEnd = signed.count
        var reached = SignatureLevel.b
        var shortfall: String?
        var archiveEnd: Int?

        if let error = signedCMS.timestampError {
            shortfall = "Signed without a timestamp (B-B): the timestamp server could not be reached (\(error.localizedDescription))."
        } else if level.timestamped {
            reached = .t
        }

        if reached == .t, level.longTerm {
            progress(.collectingValidationData)
            var chains = [[certificate] + chain]
            let tsaCertificates = CMS.timestampCertificates(in: signedCMS.data)
            if let tsa = tsaCertificates.first(where: { !$0.isCA }) ?? tsaCertificates.first {
                chains.append(await Revocation.chain(for: tsa, pool: tsaCertificates))
            }
            // Every certificate goes into the DSS, including those already in the signature. Clause 6.3 s)
            // only says duplication "should be avoided", and the EU reference validator (DSS) does not
            // recognise B-LTA when the signer's certificates are missing from the DSS.
            do {
                signed = try addDSS(to: signed, try await Revocation.collect(chains))
                reached = .lt
            } catch {
                shortfall = "Signed at B-T, without long-term validation data: \(error.localizedDescription)"
            }

            if reached == .lt, level == .lta {
                progress(.archiveTimestamp)
                var ts = PDFDict()
                ts["Type"] = .name("DocTimeStamp")
                ts["Filter"] = .name("Adobe.PPKLite")
                ts["SubFilter"] = .name("ETSI.RFC3161")
                ts["Prop_Build"] = propBuild
                do {
                    prepared = try prepare(try PDFFile(data: signed), signature: ts, fieldPrefix: "Timestamp",
                                           placement: SignaturePlacement(pageIndex: 0, rect: nil, appearance: nil),
                                           capacity: 16384, extensionLevels: [1])
                    let token = try await archiveTimestamper.timestamp(DigestAlgorithm.sha256.hash(prepared.signedBytes), digest: .sha256)
                    signed = try prepared.fill(token.encoded)
                    archiveEnd = signed.count
                    reached = .lta
                    // Also embed what validating the archive timestamp itself needs. Usually the same TSA
                    // as before, so this adds little or nothing; missing it is not an error (it is added
                    // at the next renewal per EN 319 142-1).
                    let archiveCertificates = CMS.certificates(in: token.encoded)
                    if let tsa = archiveCertificates.first(where: { !$0.isCA }) ?? archiveCertificates.first,
                       let validation = try? await Revocation.collect([await Revocation.chain(for: tsa, pool: archiveCertificates)]) {
                        signed = try addDSS(to: signed, validation)
                    }
                } catch {
                    shortfall = "Signed at B-LT, without the archive timestamp: \(error.localizedDescription)"
                }
            }
        }
        try check(signed, original: pdf, signer: certificate, signatureEnd: signatureEnd, archiveEnd: archiveEnd)
        return Result(pdf: signed, level: reached, shortfall: shortfall)
    }

    /// Refuses to hand back a file unless it opens like the original and every signature in it checks out.
    static func check(_ signed: Data, original: Data, signer: Certificate, signatureEnd: Int, archiveEnd: Int?) throws {
        guard signed.prefix(original.count) == original else {
            throw SigningError("Internal error: the original bytes were changed.")
        }
        let signatures = try Verification.verify(signed)
        // The new signature covers exactly its own revision (B-LT appends validation data after it);
        // with B-LTA the archive timestamp covers everything up to its own revision.
        guard signatures.contains(where: { $0.signer == signer && $0.coveredLength == signatureEnd }),
              archiveEnd.map({ end in signatures.contains { $0.isDocumentTimestamp && $0.coveredLength == end } }) ?? true else {
            throw SigningError("Internal error: the new signature could not be verified.")
        }
        guard let before = PDFDocument(data: original), let after = PDFDocument(data: signed),
              before.pageCount == after.pageCount else {
            throw SigningError("Internal error: the signed file does not open like the original.")
        }
    }

    /// PDF date in UTC, e.g. D:20261116143000Z: valid under both ISO 32000-1 and -2 clause 7.9.4
    /// (which disagree on the trailing apostrophe of a numeric offset).
    static func pdfDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "'D:'yyyyMMddHHmmss'Z'"
        return formatter.string(from: date)
    }

    // MARK: preparing the update

    /// The file with a signature dictionary whose /Contents is still a zero-filled placeholder.
    struct Prepared {
        var data: Data
        let contentsStart: Int  // offset of '<'
        let contentsEnd: Int    // offset after '>'

        /// The bytes covered by the signature: everything except the /Contents value.
        var signedBytes: Data { data[0..<contentsStart] + data[contentsEnd...] }

        func fill(_ signature: Data) throws -> Data {
            let hex = Data(signature.map { String(format: "%02X", $0) }.joined().utf8)
            guard hex.count <= contentsEnd - contentsStart - 2 else {
                throw SigningError("The signature is larger than the space reserved for it.")
            }
            var out = data
            out.replaceSubrange((contentsStart + 1)..<(contentsStart + 1 + hex.count), with: hex)
            return out
        }
    }

    static let byteRangePlaceholder = PDFObject.array([.int(0), .int(9_999_999_999), .int(9_999_999_999), .int(9_999_999_999)])

    static func prepare(_ file: PDFFile, signature: PDFDict, fieldPrefix: String,
                        placement: SignaturePlacement, capacity: Int, extensionLevels: Set<Int>) throws -> Prepared {
        var update = IncrementalUpdate(file)
        var catalog = try file.catalog()
        let pages = try file.pageRefs()
        guard pages.indices.contains(placement.pageIndex) else { throw PDFError("The page does not exist.") }
        let (pageNumber, pageGeneration) = pages[placement.pageIndex]
        let pageRef = PDFObject.ref(pageNumber, pageGeneration)

        var sig = signature
        sig["ByteRange"] = byteRangePlaceholder
        sig["Contents"] = .hexString(Data(count: capacity))
        let sigRef = update.add(.dict(sig))

        let existing = try file.fieldNames()
        var counter = 1
        while existing.contains("\(fieldPrefix)\(counter)") { counter += 1 }

        var widget = PDFDict()
        widget["Type"] = .name("Annot")
        widget["Subtype"] = .name("Widget")
        widget["FT"] = .name("Sig")
        widget["T"] = .text("\(fieldPrefix)\(counter)")
        widget["V"] = sigRef
        widget["F"] = .int(132)  // Print | Locked
        widget["P"] = pageRef
        if let rect = placement.rect, let appearance = placement.appearance {
            widget["Rect"] = .array([.real(rect.minX), .real(rect.minY), .real(rect.maxX), .real(rect.maxY)])
            let form = try formXObject(from: appearance, rotation: placement.pageRotation, update: &update)
            widget["AP"] = .dict(PDFDict([("N", form)]))
        } else {
            widget["Rect"] = .array([.int(0), .int(0), .int(0), .int(0)])
        }
        let widgetRef = update.add(.dict(widget))

        // The page's annotations.
        guard var page = try file.object(pageNumber).dict else { throw PDFError("The page is damaged.") }
        if case .ref(let n, _)? = page["Annots"], let annots = try file.object(n).array {
            update.set(.ref(n, 0), .array(annots + [widgetRef]))
        } else {
            page["Annots"] = .array((page["Annots"]?.array ?? []) + [widgetRef])
            update.set(pageRef, .dict(page))
        }

        // The interactive form.
        var catalogChanged = false
        let formRef = catalog["AcroForm"]
        var form = try file.resolve(formRef)?.dict ?? PDFDict()
        if case .ref(let n, _)? = form["Fields"], let fields = try file.object(n).array {
            update.set(.ref(n, 0), .array(fields + [widgetRef]))
        } else {
            form["Fields"] = .array((form["Fields"]?.array ?? []) + [widgetRef])
        }
        form["SigFlags"] = .int(3)  // SignaturesExist | AppendOnly
        if case .ref? = formRef {
            update.set(formRef!, .dict(form))
        } else {
            catalog["AcroForm"] = .dict(form)
            catalogChanged = true
        }
        if try declareExtensions(extensionLevels, in: &catalog, file: file) { catalogChanged = true }
        // The ESIC extensions are declared against PDF 1.7; older files are raised to it (ISO 32000 7.7.2).
        if !file.isPDF2, file.version < 1.7 {
            catalog["Version"] = .name("1.7")
            catalogChanged = true
        }
        if catalogChanged {
            update.set(.ref(file.rootRef.0, file.rootRef.1), .dict(catalog))
        }

        var data = update.write()
        let appended = file.data.count..<data.count
        guard let contentsKey = data.range(of: Data("/Contents <".utf8), in: appended),
              let byteRange = data.range(of: byteRangePlaceholder.serialized(), in: appended) else {
            throw PDFError("Could not place the signature.")
        }
        let contentsStart = contentsKey.upperBound - 1
        let contentsEnd = contentsStart + capacity * 2 + 2
        let ranges = "[0 \(contentsStart) \(contentsEnd) \(data.count - contentsEnd)]"
        var text = Data(ranges.utf8)
        text.insert(contentsOf: [UInt8](repeating: 0x20, count: byteRange.count - text.count), at: text.count - 1)
        data.replaceSubrange(byteRange, with: text)
        return Prepared(data: data, contentsStart: contentsStart, contentsEnd: contentsEnd)
    }

    /// Turns the first page of a (Core Graphics generated) PDF into a Form XObject in `update`.
    static func formXObject(from appearance: Data, rotation: Int, update: inout IncrementalUpdate) throws -> PDFObject {
        let source = try PDFFile(data: appearance)
        guard let (pageNumber, _) = try source.pageRefs().first, let page = try source.object(pageNumber).dict else {
            throw PDFError("The stamp could not be drawn.")
        }
        var content = Data()
        var contents: [PDFObject] = []
        switch page["Contents"] {
        case .array(let items)?: contents = items
        case let item?: contents = [item]
        case nil: break
        }
        for item in contents {
            if case .stream(let dict, let raw)? = try source.resolve(item) {
                content.append(try Filters.decode(dict, raw))
                content.append(0x0A)
            }
        }
        let box = (try source.inherited("MediaBox", page: page)?.array ?? []).compactMap(\.number)
        guard box.count == 4 else { throw PDFError("The stamp could not be drawn.") }
        let w = box[2] - box[0], h = box[3] - box[1]  // as seen on screen
        // The drawing is upright on screen; turn it against the page's /Rotate inside the content
        // stream itself (viewers disagree on how to combine /Matrix with page rotation).
        let (bbox, transform): ([Double], [Double]) = switch ((rotation % 360) + 360) % 360 {
        case 90: ([0, 0, h, w], [0, 1, -1, 0, h, 0])
        case 180: ([0, 0, w, h], [-1, 0, 0, -1, w, h])
        case 270: ([0, 0, h, w], [0, -1, 1, 0, 0, w])
        default: ([0, 0, w, h], [1, 0, 0, 1, 0, 0])
        }
        content = Data(("q " + transform.map(PDFObject.format).joined(separator: " ") + " cm "
                        + "1 0 0 1 \(PDFObject.format(-box[0])) \(PDFObject.format(-box[1])) cm\n").utf8)
            + content + Data("Q\n".utf8)
        var map: [Int: PDFObject] = [:]
        var dict = PDFDict()
        dict["Type"] = .name("XObject")
        dict["Subtype"] = .name("Form")
        dict["BBox"] = .array(bbox.map { .real($0) })
        if let resources = try source.inherited("Resources", page: page) {
            dict["Resources"] = try update.importObject(resources, from: source, map: &map)
        }
        dict["Filter"] = .name("FlateDecode")
        return update.add(.stream(dict, Filters.deflate(content)))
    }

    /// Version recorded in the signature's build properties.
    static let signerVersion = "1.0.0"

    /// Prop_Build: the app that made the signature (EN 319 142-1 clause 5.3).
    static var propBuild: PDFObject {
        .dict(PDFDict([("App", .dict(PDFDict([
            ("Name", .name("Signer")), ("REx", .text(signerVersion)), ("OS", .array([.name("macOS")])),
        ])))]))
    }

    /// Declares the ESIC developer extensions in the catalog (EN 319 142-1 clause 5.6.1): level 1 for
    /// the DSS and document timestamps (clause 5.4), level 2 for the ETSI.CAdES.detached SubFilter. Both
    /// are kept when both are used. PDF 2.0 documents get none (clause 5.6.2). Returns whether the
    /// catalog changed.
    static func declareExtensions(_ levels: Set<Int>, in catalog: inout PDFDict, file: PDFFile) throws -> Bool {
        guard !file.isPDF2, !levels.isEmpty else { return false }
        var extensions = try file.resolve(catalog["Extensions"])?.dict ?? PDFDict()
        var present = Set<Int>()
        let existing: [PDFObject] = switch try file.resolve(extensions["ESIC"]) {
        case .array(let items)?: items
        case let item?: [item]
        case nil: []
        }
        for item in existing {
            if let dict = try file.resolve(item)?.dict, let level = dict["ExtensionLevel"]?.int { present.insert(level) }
        }
        let all = present.union(levels)
        guard all != present else { return false }
        let entries: [PDFObject] = all.sorted().map {
            .dict(PDFDict([("BaseVersion", .name("1.7")), ("ExtensionLevel", .int($0))]))
        }
        extensions["ESIC"] = entries.count == 1 ? entries[0] : .array(entries)
        catalog["Extensions"] = .dict(extensions)
        return true
    }

    // MARK: long-term validation data

    /// Adds validation data to the document security store, skipping what is already there.
    static func addDSS(to pdf: Data, _ validation: ValidationData) throws -> Data {
        let file = try PDFFile(data: pdf)
        var update = IncrementalUpdate(file)
        var catalog = try file.catalog()
        var dss = try file.resolve(catalog["DSS"])?.dict ?? PDFDict()
        var added = 0
        func streams(_ key: String, _ items: [Data]) throws {
            var refs = try file.resolve(dss[key])?.array ?? []
            var present = Set<Data>()
            for ref in refs {
                if case .stream(let dict, let raw)? = try file.resolve(ref) { present.insert((try? Filters.decode(dict, raw)) ?? raw) }
            }
            for item in items where present.insert(item).inserted {
                refs.append(update.add(.stream(PDFDict(), item)))
                added += 1
            }
            if !refs.isEmpty { dss[key] = .array(refs) }
        }
        try streams("Certs", validation.certificates.map(\.der))
        try streams("OCSPs", validation.ocspResponses)
        try streams("CRLs", validation.crls)
        guard added > 0 else { return pdf }
        dss["Type"] = .name("DSS")
        catalog["DSS"] = update.add(.dict(dss))
        _ = try declareExtensions([1], in: &catalog, file: file)
        update.set(.ref(file.rootRef.0, file.rootRef.1), .dict(catalog))
        return update.write()
    }
}

extension CMS {
    /// The TSA's certificates from the signature-timestamp token in a CMS signature.
    static func timestampCertificates(in contentInfo: Data) -> [Certificate] {
        guard let signedData = try? DER(contentInfo).child(1).child(0),
              let signerInfo = try? signedData.children().last?.child(0),
              let unsigned = try? signerInfo.context(1) else { return [] }
        for attribute in (try? unsigned.children()) ?? [] {
            if let parts = try? attribute.children(), parts.first?.oidString == OID.timeStampToken,
               let token = try? parts[1].child(0) {
                return certificates(in: token.encoded)
            }
        }
        return []
    }
}
