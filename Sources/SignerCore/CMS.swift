import Foundation

/// Something that can sign a digest with the private key belonging to `certificate`: a smart card or
/// token through the keychain in the app, a software key in tests.
public protocol DigestSigner: Sendable {
    var certificate: Certificate { get }
    /// Signs `digest` (already hashed with `algorithm`). Returns a DER ECDSA signature or a PKCS#1 v1.5
    /// RSA signature.
    func sign(digest: Data, algorithm: DigestAlgorithm) async throws -> Data
}

/// Builds detached CMS SignedData in the CAdES baseline profile PAdES requires.
public enum CMS {
    public struct Signed: Sendable {
        /// DER ContentInfo.
        public let data: Data
        /// Set when a timestamp was requested but could not be obtained; the signature is still valid.
        public let timestampError: (any Error)?
    }

    /// Signs `documentDigest` (the hash of the PDF's signed byte ranges).
    /// When `timestamper` is set, the signature is timestamped (PAdES-B-T).
    public static func sign(documentDigest: Data, digest: DigestAlgorithm, signer: any DigestSigner,
                            chain: [Certificate], timestamper: Timestamper?,
                            signed: @Sendable () -> Void = {}) async throws -> Signed {
        let certificate = signer.certificate
        let signedAttributes = DER.set([
            attribute(OID.contentType, .oid(OID.data)),
            attribute(OID.messageDigest, .octetString(documentDigest)),
            attribute(OID.signingCertificateV2, signingCertificateV2(certificate)),
        ])
        let signature = try await signer.sign(digest: digest.hash(signedAttributes.encoded), algorithm: digest)
        signed()

        var unsigned: DER?
        var timestampError: (any Error)?
        if let timestamper {
            do {
                let token = try await timestamper.timestamp(DigestAlgorithm.sha256.hash(signature), digest: .sha256)
                unsigned = .implicit(1, constructed: true, .set([attribute(OID.timeStampToken, token)]))
            } catch {
                timestampError = error
            }
        }

        let signerInfo = DER.sequence([
            .integer(1),
            .sequence([certificate.issuerName, certificate.serialNumber]),
            .algorithm(digest.oid),
            .implicit(0, constructed: true, signedAttributes),
            signatureAlgorithm(for: certificate, digest: digest),
            .octetString(signature),
        ] + (unsigned.map { [$0] } ?? []))

        var certificates = [certificate]
        for extra in chain where !certificates.contains(extra) { certificates.append(extra) }
        let signedData = DER.sequence([
            .integer(1),
            .set([.algorithm(digest.oid)]),
            .sequence([.oid(OID.data)]),
            // [0] IMPLICIT SET OF: DER requires the elements sorted by their encodings (EN 319 142-1 4.1 a).
            DER(tag: DER.Tag.context(0), content: certificates.map(\.der).sorted { $0.lexicographicallyPrecedes($1) }.reduce(Data(), +)),
            .set([signerInfo]),
        ])
        return Signed(data: DER.sequence([.oid(OID.signedData), .explicit(0, signedData)]).encoded, timestampError: timestampError)
    }

    static func attribute(_ oid: String, _ value: DER) -> DER { .sequence([.oid(oid), .set([value])]) }

    /// ESS signing-certificate-v2 (RFC 5035): binds the signature to the certificate, required by CAdES.
    static func signingCertificateV2(_ certificate: Certificate) -> DER {
        let issuerSerial = DER.sequence([
            .sequence([.explicit(4, certificate.issuerName)]),  // GeneralNames: directoryName
            certificate.serialNumber,
        ])
        // hashAlgorithm defaults to SHA-256 and is therefore omitted.
        let certID = DER.sequence([.octetString(certificate.sha256), issuerSerial])
        return .sequence([.sequence([certID])])
    }

    static func signatureAlgorithm(for certificate: Certificate, digest: DigestAlgorithm) -> DER {
        switch (certificate.keyAlgorithm, digest) {
        case (.ec, .sha256): .algorithm(OID.ecdsaSHA256)
        case (.ec, .sha384): .algorithm(OID.ecdsaSHA384)
        case (.ec, .sha512): .algorithm(OID.ecdsaSHA512)
        case (_, .sha256): .algorithm(OID.sha256WithRSA, parameters: .null)
        case (_, .sha384): .algorithm(OID.sha384WithRSA, parameters: .null)
        case (_, .sha512): .algorithm(OID.sha512WithRSA, parameters: .null)
        }
    }

    /// Certificates carried in a SignedData ContentInfo (e.g. a timestamp token's TSA chain).
    public static func certificates(in contentInfo: Data) -> [Certificate] {
        guard let signedData = try? DER(contentInfo).child(1).child(0),
              let set = try? signedData.context(0) else { return [] }
        return ((try? set.children()) ?? []).compactMap { try? Certificate(der: $0.encoded) }
    }
}

public struct SigningError: LocalizedError, Sendable {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}

/// RFC 3161 timestamping client. Tries each server in order until one answers.
public struct Timestamper: Sendable {
    public let urls: [URL]
    /// eIDAS qualified timestamp services on the EU Trusted List, so validators trust the timestamps
    /// themselves. Each is confirmed qualified by the EU reference validator, and none restricts free use
    /// (ACCV, personal use only, and IRN Portugal, rate-limited with legal warnings, are left out).
    static let sectigo = URL(string: "https://timestamp.sectigo.com/qualified")!  // Sectigo (Europe), ES
    static let bosa = URL(string: "http://tsa.belgium.be/connect")!               // Belgian government
    static let izenpe = URL(string: "http://tsa.izenpe.com")!                     // Basque government, ES
    static let aped = URL(string: "https://timestamp.aped.gov.gr/qtss")!          // Greek government

    /// For signature timestamps.
    public static let `default` = Timestamper(urls: [sectigo, bosa, izenpe, aped])
    /// For archive (document) timestamps: starts elsewhere, because Sectigo asks for 15 seconds between
    /// requests and B-LTA needs a second timestamp right after the first.
    public static let archive = Timestamper(urls: [bosa, izenpe, aped, sectigo])

    public init(urls: [URL]) { self.urls = urls }
    public init(url: URL) { self.urls = [url] }

    public func timestamp(_ hash: Data, digest: DigestAlgorithm) async throws -> DER {
        var lastError: any Error = SigningError("No timestamp server is configured.")
        for url in urls {
            do { return try await timestamp(hash, digest: digest, from: url) } catch { lastError = error }
        }
        throw lastError
    }

    /// The TimeStampToken (a CMS ContentInfo) over `hash` from one server.
    func timestamp(_ hash: Data, digest: DigestAlgorithm, from url: URL) async throws -> DER {
        let nonce = Data((0..<8).map { _ in UInt8.random(in: 0...255) })
        let request = DER.sequence([
            .integer(1),
            .sequence([.algorithm(digest.oid), .octetString(hash)]),
            .integer(unsigned: nonce),
            .boolean(true),  // certReq: include the TSA certificate
        ])
        var http = URLRequest(url: url, timeoutInterval: 30)
        http.httpMethod = "POST"
        http.setValue("application/timestamp-query", forHTTPHeaderField: "Content-Type")
        http.httpBody = request.encoded
        let (data, response) = try await URLSession.shared.data(for: http)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw SigningError("The timestamp server \(url.host() ?? "") did not answer.")
        }
        let parts = try DER(data).children()
        guard let status = try parts.first?.child(0).int, status == 0 || status == 1, parts.count > 1 else {
            throw SigningError("The timestamp server \(url.host() ?? "") refused the request.")
        }
        let token = parts[1]
        // The token must be for exactly what was asked (RFC 3161 clause 2.4.2; CAdES 5.3).
        let info = try TimestampToken.info(token)
        guard info.imprintAlgorithm == digest.oid, info.imprint == hash else {
            throw SigningError("The timestamp server \(url.host() ?? "") timestamped something else.")
        }
        guard info.nonce == DER.integer(unsigned: nonce).content else {
            throw SigningError("The timestamp server \(url.host() ?? "") answered with the wrong nonce.")
        }
        // Signed by a TSA the EU Trusted List names as a granted qualified timestamp service.
        try await TimestampToken.validate(token, info: info)
        return try TimestampToken.canonical(token)
    }
}

/// Reading and normalising RFC 3161 TimeStampTokens.
public enum TimestampToken {
    public struct Info: Sendable {
        public let imprintAlgorithm: String?
        public let imprint: Data
        public let nonce: Data?
        public let time: Date?
    }

    /// The TSTInfo inside a TimeStampToken (ContentInfo → SignedData → eContent).
    public static func info(_ token: DER) throws -> Info {
        let signedData = try token.child(1).child(0)
        guard let content = try signedData.child(2).context(0) else {
            throw SigningError("The timestamp has no content.")
        }
        let fields = try DER(try content.child(0).content).children()
        guard fields.count >= 5 else { throw SigningError("The timestamp is malformed.") }
        let imprint = try fields[2].children()
        // After genTime come optional accuracy (SEQUENCE), ordering (BOOLEAN) and nonce (INTEGER).
        let nonce = fields.dropFirst(5).first { $0.tag == DER.Tag.integer }?.content
        return Info(imprintAlgorithm: try imprint[0].child(0).oidString, imprint: imprint[1].content,
                    nonce: nonce, time: fields[4].date)
    }

    /// Checks that `token` is a genuine timestamp from an EU qualified timestamp service: the CMS signature
    /// verifies and covers the TSTInfo, the ESS signing-certificate attribute binds the TSA certificate,
    /// that certificate is for timestamping and valid at the timestamp's time, the time is current, and
    /// the certificate (or its issuer) is a granted QTST service in the EU Trusted List of its country.
    public static func validate(_ token: DER, info: Info, now: Date = .now) async throws {
        let tsa = try verifySignature(token)
        guard let time = info.time, abs(time.timeIntervalSince(now)) < 15 * 60 else {
            throw SigningError("The timestamp's time is not current.")
        }
        guard tsa.certificate.extendedKeyUsage.contains(OID.ekuTimeStamping), tsa.certificate.isValid(at: time) else {
            throw SigningError("The timestamp was not signed by a valid timestamping certificate.")
        }
        guard let country = tsa.certificate.country else {
            throw SigningError("The timestamp authority's country is unknown, so it can't be checked against the EU Trusted List.")
        }
        let qualified = try await EUTrustedList.qualifiedTimestampCertificates(country: country)
        guard SignatureCheck.chains(tsa.certificate, to: qualified, pool: tsa.pool, at: time) else {
            throw SigningError("“\(tsa.certificate.commonName)” is not a qualified timestamp service in the EU Trusted List.")
        }
    }

    /// Verifies the token's CMS signature; returns the TSA certificate and the token's other certificates.
    static func verifySignature(_ token: DER) throws -> (certificate: Certificate, pool: [Certificate]) {
        let signedData = try token.child(1).child(0)
        let parts = try signedData.children()
        guard parts.count >= 4, let content = try parts[2].context(0) else { throw SigningError("The timestamp is malformed.") }
        let eContent = try content.child(0).content
        let certificates = (try signedData.context(0)?.children() ?? []).compactMap { try? Certificate(der: $0.encoded) }
        let info = try parts.last!.child(0).children()
        guard info.count >= 6, info[3].tag == DER.Tag.context(0) else { throw SigningError("The timestamp is not signed properly.") }
        // Signer: issuerAndSerialNumber, or [0] subjectKeyIdentifier.
        let sid = info[1]
        let signer = certificates.first { certificate in
            if sid.tag == DER.Tag.sequence, let parts = try? sid.children(), parts.count == 2 {
                return certificate.issuerName.encoded == parts[0].encoded && certificate.serialNumber.encoded == parts[1].encoded
            }
            return sid.tag == DER.Tag.context(0, constructed: false) && certificate.subjectKeyIdentifier == sid.content
        }
        guard let signer else { throw SigningError("The timestamp does not include its signing certificate.") }
        let digest = try info[2].child(0).oidString
        var contentTypeOK = false, digestOK = false, bound = false
        for attribute in try info[3].children() {
            let oid = try attribute.child(0).oidString
            let value = try attribute.child(1).child(0)
            switch oid {
            case OID.contentType: contentTypeOK = value.oidString == OID.tstInfo
            case OID.messageDigest: digestOK = value.content == (try SignatureCheck.hash(eContent, oid: digest))
            case OID.signingCertificate:  // ESSCertID: SHA-1 certificate hash
                let id = try value.child(0).child(0)
                let matches = try id.child(0).content == SignatureCheck.hash(signer.der, oid: OID.sha1)
                bound = bound || matches
            case OID.signingCertificateV2:  // ESSCertIDv2: optional hash algorithm (default SHA-256)
                let id = try value.child(0).child(0)
                let fields = try id.children()
                let algorithm = fields[0].tag == DER.Tag.sequence ? try fields[0].child(0).oidString : OID.sha256
                let hash = fields[0].tag == DER.Tag.sequence ? fields[1] : fields[0]
                let matches = try hash.content == SignatureCheck.hash(signer.der, oid: algorithm)
                bound = bound || matches
            default: break
            }
        }
        let signedAttributes = DER(tag: DER.Tag.set, content: info[3].content).encoded
        guard contentTypeOK, digestOK, bound,
              SignatureCheck.verify(signedAttributes, signature: info[5].content, algorithm: info[4], digest: digest, by: signer) else {
            throw SigningError("The timestamp's signature is not valid.")
        }
        return (signer, certificates.filter { $0 != signer })
    }

    /// The token with its SET OF fields (digestAlgorithms, certificates, crls) in DER order. Those fields
    /// are outside the TSA's signature, so the token stays valid; EN 319 142-1 6.3 o) requires the
    /// signature-time-stamp in DER and some TSAs send the certificates unsorted.
    public static func canonical(_ token: DER) throws -> DER {
        let parts = try token.children()
        guard parts.count == 2 else { throw SigningError("The timestamp is malformed.") }
        let signedData = try parts[1].child(0)
        let fields = try signedData.children().map { field -> DER in
            switch field.tag {
            case DER.Tag.set, DER.Tag.context(0), DER.Tag.context(1):
                let sorted = try field.children().map(\.encoded).sorted { $0.lexicographicallyPrecedes($1) }
                return DER(tag: field.tag, content: sorted.reduce(Data(), +))
            default:
                return field
            }
        }
        return DER.sequence([parts[0], .explicit(0, DER(tag: DER.Tag.sequence, content: fields.joined))])
    }
}
