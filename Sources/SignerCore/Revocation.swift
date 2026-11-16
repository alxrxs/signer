import CryptoKit
import Foundation
import Security

/// Certificates and revocation answers embedded for long-term validation (PAdES B-LT).
public struct ValidationData: Sendable {
    public var certificates: [Certificate] = []
    public var ocspResponses: [Data] = []
    public var crls: [Data] = []
}

public enum Revocation {
    /// The issuing chain of `certificate`, leaf first. Uses `pool` (e.g. the CA certificates a token
    /// carries), then the system trust store, then the issuers' AIA download links.
    public static func chain(for certificate: Certificate, pool: [Certificate]) async -> [Certificate] {
        var candidates = pool
        candidates += systemChain(for: certificate, pool: pool)
        var chain = [certificate]
        while let last = chain.last, !last.isSelfSigned, chain.count < 8 {
            if let issuer = candidates.first(where: { last.isIssued(by: $0) && !chain.contains($0) }) {
                chain.append(issuer)
                continue
            }
            let fetched = await download(last.caIssuerURLs)
            guard let issuer = fetched.first(where: { last.isIssued(by: $0) }) else { break }
            candidates += fetched
            chain.append(issuer)
        }
        return chain
    }

    static func systemChain(for certificate: Certificate, pool: [Certificate]) -> [Certificate] {
        let refs = ([certificate] + pool).compactMap { SecCertificateCreateWithData(nil, $0.der as CFData) }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(refs as CFArray, SecPolicyCreateBasicX509(), &trust) == errSecSuccess,
              let trust else { return [] }
        SecTrustSetNetworkFetchAllowed(trust, true)
        _ = SecTrustEvaluateWithError(trust, nil)
        let chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
        return chain.compactMap { try? Certificate(der: SecCertificateCopyData($0) as Data) }
    }

    static func download(_ urls: [URL]) async -> [Certificate] {
        for url in urls where url.scheme == "http" || url.scheme == "https" {
            guard let (data, _) = try? await URLSession.shared.data(from: url) else { continue }
            if let cert = try? Certificate(der: data) { return [cert] }
            let certs = CMS.certificates(in: data)  // .p7c bundles
            if !certs.isEmpty { return certs }
            if let pem = String(data: data, encoding: .ascii), let der = pemBlocks(pem).first, let cert = try? Certificate(der: der) {
                return [cert]
            }
        }
        return []
    }

    static func pemBlocks(_ text: String) -> [Data] {
        text.components(separatedBy: "-----BEGIN").dropFirst().compactMap { block in
            let body = block.components(separatedBy: "-----")
            guard body.count >= 2 else { return nil }
            return Data(base64Encoded: body[1].components(separatedBy: .whitespacesAndNewlines).joined())
        }
    }

    /// Revocation data for every certificate in `chains` (each leaf first), and for the OCSP responders
    /// that answered (unless their certificate carries id-pkix-ocsp-nocheck), as EN 319 142-1 clause 6.3
    /// t) requires: "the full set of revocation data used in the validation". Throws if any status can't
    /// be obtained, since the result would not be a real B-LT signature.
    public static func collect(_ chains: [[Certificate]]) async throws -> ValidationData {
        var data = ValidationData()
        var done = Set<Data>()
        var known = chains.flatMap { $0 }
        var work: [(Certificate, Certificate?)] = []
        for chain in chains {
            for cert in chain where !data.certificates.contains(cert) { data.certificates.append(cert) }
            for (index, cert) in chain.enumerated() { work.append((cert, index + 1 < chain.count ? chain[index + 1] : nil)) }
        }
        while !work.isEmpty {
            let (cert, issuer) = work.removeFirst()
            guard !cert.isSelfSigned, done.insert(cert.sha256).inserted else { continue }
            guard let issuer else {
                throw SigningError("The issuer of “\(cert.commonName)” could not be found, so its revocation status can't be embedded.")
            }
            if let response = try await ocsp(for: cert, issuer: issuer) {
                data.ocspResponses.append(response)
                let responders = ocspCertificates(response)
                known += responders
                for responder in responders where !data.certificates.contains(responder) {
                    data.certificates.append(responder)
                }
                // A delegated responder's own status is part of the validation, unless it is exempt.
                for responder in responders where responder != issuer && !responder.ocspNoCheck && !responder.isSelfSigned {
                    var responderIssuer = known.first { responder.isIssued(by: $0) }
                    if responderIssuer == nil {
                        let fetched = await download(responder.caIssuerURLs)
                        known += fetched
                        responderIssuer = fetched.first { responder.isIssued(by: $0) }
                    }
                    if let responderIssuer, !data.certificates.contains(responderIssuer) { data.certificates.append(responderIssuer) }
                    work.append((responder, responderIssuer))
                }
            } else if let crl = await crl(for: cert) {
                // An indirect CRL (signed by someone other than the certificate's issuer) needs its
                // signer's certificate and status too (EN 319 142-1 6.3 t).
                var crlSigner = issuer
                if let crlIssuer = crlIssuerName(crl), crlIssuer.encoded != issuer.subjectName.encoded {
                    guard let signer = known.first(where: { $0.subjectName.encoded == crlIssuer.encoded }) else {
                        throw SigningError("The CRL for “\(cert.commonName)” was signed by an unknown authority.")
                    }
                    crlSigner = signer
                    if !data.certificates.contains(signer) { data.certificates.append(signer) }
                    var signerIssuer = known.first { signer.isIssued(by: $0) }
                    if signerIssuer == nil, !signer.isSelfSigned {
                        let fetched = await download(signer.caIssuerURLs)
                        known += fetched
                        signerIssuer = fetched.first { signer.isIssued(by: $0) }
                    }
                    if let signerIssuer, !data.certificates.contains(signerIssuer) { data.certificates.append(signerIssuer) }
                    work.append((signer, signerIssuer))
                }
                try checkCRL(crl, for: cert, signer: crlSigner)
                data.crls.append(crl)
            } else {
                throw SigningError("The revocation status of “\(cert.commonName)” could not be fetched (no OCSP or CRL answer).")
            }
        }
        return data
    }

    /// The issuer name of a DER CertificateList (RFC 5280 5.1).
    static func crlIssuerName(_ crl: Data) -> DER? {
        guard let tbs = try? DER(crl).child(0), let fields = try? tbs.children() else { return nil }
        // [version INTEGER OPTIONAL] signature AlgorithmIdentifier, issuer Name
        let start = fields.first?.tag == DER.Tag.integer ? 1 : 0
        return fields.count > start + 1 ? fields[start + 1] : nil
    }

    /// A checked OCSP response for `cert`: signed by the issuer or an authorised responder, current, and
    /// saying "good". nil if no responder gave a usable answer; throws CertificateRevoked if revoked.
    static func ocsp(for cert: Certificate, issuer: Certificate) async throws -> Data? {
        let certID = DER.sequence([
            .algorithm(OID.sha1, parameters: .null),
            .octetString(Data(Insecure.SHA1.hash(data: issuer.subjectName.encoded))),
            .octetString(Data(Insecure.SHA1.hash(data: issuer.publicKeyBits))),
            cert.serialNumber,
        ])
        let request = DER.sequence([.sequence([.sequence([.sequence([certID])])])])
        for url in cert.ocspURLs {
            var http = URLRequest(url: url, timeoutInterval: 20)
            http.httpMethod = "POST"
            http.setValue("application/ocsp-request", forHTTPHeaderField: "Content-Type")
            http.httpBody = request.encoded
            guard let (body, response) = try? await URLSession.shared.data(for: http),
                  (response as? HTTPURLResponse)?.statusCode == 200,
                  let status = try? DER(body).child(0).int, status == 0 else { continue }
            do {
                try checkOCSP(body, for: cert, issuer: issuer)
                return body
            } catch let revoked as CertificateRevoked {
                throw revoked
            } catch {
                continue  // unusable answer: try the next responder, then the CRL
            }
        }
        return nil
    }

    /// Validates an OCSP response (RFC 6960) for `cert`. Throws CertificateRevoked if it says revoked.
    static func checkOCSP(_ response: Data, for cert: Certificate, issuer: Certificate, now: Date = .now) throws {
        guard let bytes = try DER(response).context(0)?.child(0).child(1) else { throw SigningError("Empty OCSP response.") }
        let basic = try DER(bytes.content).children()
        guard basic.count >= 3, let signature = basic[2].bitStringBytes else { throw SigningError("Malformed OCSP response.") }
        let tbs = try basic[0].children()
        let offset = tbs.first?.tag == DER.Tag.context(0) ? 1 : 0  // [0] version
        guard tbs.count >= offset + 3 else { throw SigningError("Malformed OCSP response.") }
        let responderID = tbs[offset]
        let single = try tbs[offset + 2].children().first { (try? $0.child(0).child(3).encoded) == cert.serialNumber.encoded }
        guard let single else { throw SigningError("The OCSP response is about a different certificate.") }
        let fields = try single.children()
        switch fields[1].tag {
        case DER.Tag.context(0, constructed: false): break  // good
        case DER.Tag.context(1): throw CertificateRevoked(certificate: cert)
        default: throw SigningError("The OCSP responder does not know “\(cert.commonName)”.")
        }
        guard let thisUpdate = fields[2].date, thisUpdate <= now.addingTimeInterval(300) else {
            throw SigningError("The OCSP response is dated in the future.")
        }
        // nextUpdate is [0] EXPLICIT (constructed); "good" is also [0] but primitive, so match the exact tag.
        if let next = fields.dropFirst(3).first(where: { $0.tag == DER.Tag.context(0) }),
           let nextUpdate = try next.child(0).date, nextUpdate < now {
            throw SigningError("The OCSP response has expired.")
        }
        // Who signed it: the issuer itself, or a responder the issuer authorised (id-kp-OCSPSigning).
        let included = (try? DER(bytes.content).context(0)?.child(0).children())?.compactMap { try? Certificate(der: $0.encoded) } ?? []
        let candidates = [issuer] + included
        let signer = candidates.first { candidate in
            switch responderID.tag {
            case DER.Tag.context(1): return (try? responderID.child(0).encoded) == candidate.subjectName.encoded
            case DER.Tag.context(2): return (try? responderID.child(0).content) == Data(Insecure.SHA1.hash(data: candidate.publicKeyBits))
            default: return false
            }
        }
        guard let signer else { throw SigningError("The OCSP response's signer is not included.") }
        if signer != issuer {
            guard signer.extendedKeyUsage.contains(OID.ekuOCSPSigning), signer.isIssued(by: issuer),
                  SignatureCheck.chains(signer, to: [issuer], at: now) else {
                throw SigningError("The OCSP response was signed by an unauthorised responder.")
            }
        }
        guard SignatureCheck.verify(basic[0].encoded, signature: signature, algorithm: basic[1], by: signer) else {
            throw SigningError("The OCSP response's signature is not valid.")
        }
    }

    /// Validates a CRL (RFC 5280) for `cert`: signed by `signer`, current, and not listing the certificate.
    static func checkCRL(_ crl: Data, for cert: Certificate, signer: Certificate, now: Date = .now) throws {
        let parts = try DER(crl).children()
        guard parts.count == 3, let signature = parts[2].bitStringBytes,
              SignatureCheck.verify(parts[0].encoded, signature: signature, algorithm: parts[1], by: signer) else {
            throw SigningError("The CRL for “\(cert.commonName)” has an invalid signature.")
        }
        let fields = try parts[0].children()
        var index = fields.first?.tag == DER.Tag.integer ? 1 : 0  // version
        index += 2  // signature algorithm, issuer
        guard index < fields.count, let thisUpdate = fields[index].date, thisUpdate <= now.addingTimeInterval(300) else {
            throw SigningError("The CRL for “\(cert.commonName)” is malformed.")
        }
        index += 1
        if index < fields.count, let nextUpdate = fields[index].date {
            guard nextUpdate >= now else { throw SigningError("The CRL for “\(cert.commonName)” has expired.") }
            index += 1
        }
        if index < fields.count, fields[index].tag == DER.Tag.sequence {
            for entry in try fields[index].children() where try entry.child(0).encoded == cert.serialNumber.encoded {
                throw CertificateRevoked(certificate: cert)
            }
        }
    }

    /// Before signing: refuses a certificate its issuer has revoked. Does nothing if the status can't be
    /// fetched (offline signing stays possible; B-LT will report the missing data).
    public static func ensureNotRevoked(_ certificate: Certificate, pool: [Certificate]) async throws {
        guard !certificate.isSelfSigned else { return }
        let chain = await chain(for: certificate, pool: pool)
        guard chain.count > 1 else { return }
        if try await ocsp(for: certificate, issuer: chain[1]) != nil { return }
        if let crl = await crl(for: certificate) {
            do {
                try checkCRL(crl, for: certificate, signer: chain[1])
            } catch let revoked as CertificateRevoked {
                throw revoked
            } catch {}
        }
    }

    /// Certificates the OCSP responder included (its signing certificate).
    static func ocspCertificates(_ response: Data) -> [Certificate] {
        guard let bytes = try? DER(response).context(0)?.child(0).child(1),
              let basic = try? DER(bytes.content),
              let certs = try? basic.context(0)?.child(0).children() else { return [] }
        return certs.compactMap { try? Certificate(der: $0.encoded) }
    }

    static func crl(for cert: Certificate) async -> Data? {
        for url in cert.crlURLs where url.scheme == "http" || url.scheme == "https" {
            guard let (data, response) = try? await URLSession.shared.data(from: url),
                  (response as? HTTPURLResponse)?.statusCode == 200 else { continue }
            if (try? DER(data))?.tag == DER.Tag.sequence { return data }
            if let pem = String(data: data, encoding: .ascii), let der = pemBlocks(pem).first { return der }
        }
        return nil
    }
}

/// The certificate has been revoked by its issuer.
public struct CertificateRevoked: LocalizedError, Sendable {
    public let certificate: Certificate
    public var errorDescription: String? {
        "The certificate “\(certificate.commonName)” has been revoked by its issuer. It can't be used to sign."
    }
}
