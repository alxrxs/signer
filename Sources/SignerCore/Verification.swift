import Foundation
import Security

/// A signature found in a PDF, checked for integrity (not for trust: that is the validator's job).
public struct VerifiedSignature: Sendable {
    public let fieldName: String
    public let isDocumentTimestamp: Bool
    public let signer: Certificate?
    /// The signature covers the file up to here; later bytes are newer revisions.
    public let coveredLength: Int
}

public enum Verification {
    /// Checks every signature in `pdf`: the byte range excludes only /Contents, the message digest
    /// matches the covered bytes, and the signature verifies with the certificate's key (or, for a
    /// document timestamp, the token's message imprint matches). Throws on the first problem.
    public static func verify(_ pdf: Data) throws -> [VerifiedSignature] {
        let file = try PDFFile(data: pdf)
        var out: [VerifiedSignature] = []
        for field in try file.signatureFields() where field.signed {
            guard let ref = field.ref, let widget = try file.object(ref.0).dict,
                  let sig = try file.resolve(widget["V"])?.dict else { continue }
            let range = (sig["ByteRange"]?.array ?? []).compactMap(\.int)
            guard range.count == 4, range[0] == 0, range[1] > 0, range[2] > range[1], range[3] >= 0,
                  range[2] + range[3] <= pdf.count,
                  pdf[range[1]] == UInt8(ascii: "<"), pdf[range[2] - 1] == UInt8(ascii: ">") else {
                throw SigningError("Signature “\(field.name)” has an invalid byte range.")
            }
            let covered = pdf[0..<range[1]] + pdf[range[2]..<(range[2] + range[3])]
            // /Contents is zero-padded; read exactly one DER element (its own length says where it
            // ends; trimming zeros would cut a signature whose last byte is 0).
            let contents = sig["Contents"]?.stringBytes ?? Data()
            var offset = contents.startIndex
            let signedData = try DER.read(contents, at: &offset).child(1).child(0)

            if sig["SubFilter"]?.name == "ETSI.RFC3161" {
                // TSTInfo: version, policy, messageImprint { algorithm, hash }
                let content = try signedData.child(2).child(1).child(0)
                let imprint = try DER(content.content).child(2)
                let algorithm = try digestAlgorithm(try imprint.child(0).child(0).oidString)
                guard try imprint.child(1).content == algorithm.hash(covered) else {
                    throw SigningError("Document timestamp “\(field.name)” does not match the file.")
                }
                out.append(VerifiedSignature(fieldName: field.name, isDocumentTimestamp: true, signer: nil,
                                             coveredLength: range[2] + range[3]))
                continue
            }

            let signerInfo = try signedData.children().last!.child(0)
            let parts = try signerInfo.children()
            guard parts.count >= 6, let issuerSerial = try? parts[1].children(), issuerSerial.count == 2 else {
                throw SigningError("Signature “\(field.name)” is malformed.")
            }
            let certificates = (try signedData.context(0)?.children() ?? []).compactMap { try? Certificate(der: $0.encoded) }
            guard let certificate = certificates.first(where: {
                $0.issuerName.encoded == issuerSerial[0].encoded && $0.serialNumber.encoded == issuerSerial[1].encoded
            }) else { throw SigningError("Signature “\(field.name)” does not include its certificate.") }
            let algorithm = try digestAlgorithm(try parts[2].child(0).oidString)
            let signedAttributes = parts[3]
            var messageDigest: Data?
            for attribute in try signedAttributes.children() where try attribute.child(0).oidString == OID.messageDigest {
                messageDigest = try attribute.child(1).child(0).content
            }
            guard messageDigest == algorithm.hash(covered) else {
                throw SigningError("Signature “\(field.name)” does not match the file.")
            }
            // The signature covers the attributes re-tagged as a SET.
            let set = DER(tag: DER.Tag.set, content: signedAttributes.content).encoded
            guard let secCertificate = SecCertificateCreateWithData(nil, certificate.der as CFData),
                  let key = SecCertificateCopyKey(secCertificate),
                  SecKeyVerifySignature(key, verifyAlgorithm(certificate, algorithm), set as CFData, parts[5].content as CFData, nil) else {
                throw SigningError("Signature “\(field.name)” is not valid.")
            }
            // A signature-time-stamp must be over this signature's value (CAdES 5.3).
            if parts.count > 6, parts[6].tag == DER.Tag.context(1) {
                for attribute in try parts[6].children() where try attribute.child(0).oidString == OID.timeStampToken {
                    for token in try attribute.child(1).children() {
                        let info = try TimestampToken.info(token)
                        let algorithm = try digestAlgorithm(info.imprintAlgorithm)
                        guard info.imprint == algorithm.hash(parts[5].content) else {
                            throw SigningError("The timestamp on signature “\(field.name)” does not match it.")
                        }
                    }
                }
            }
            out.append(VerifiedSignature(fieldName: field.name, isDocumentTimestamp: false, signer: certificate,
                                         coveredLength: range[2] + range[3]))
        }
        return out
    }

    static func digestAlgorithm(_ oid: String?) throws -> DigestAlgorithm {
        switch oid {
        case OID.sha256: .sha256
        case OID.sha384: .sha384
        case OID.sha512: .sha512
        default: throw SigningError("Unsupported digest algorithm \(oid ?? "?").")
        }
    }

    static func verifyAlgorithm(_ certificate: Certificate, _ digest: DigestAlgorithm) -> SecKeyAlgorithm {
        switch (certificate.keyAlgorithm, digest) {
        case (.ec, .sha256): .ecdsaSignatureMessageX962SHA256
        case (.ec, .sha384): .ecdsaSignatureMessageX962SHA384
        case (.ec, .sha512): .ecdsaSignatureMessageX962SHA512
        case (_, .sha256): .rsaSignatureMessagePKCS1v15SHA256
        case (_, .sha384): .rsaSignatureMessagePKCS1v15SHA384
        case (_, .sha512): .rsaSignatureMessagePKCS1v15SHA512
        }
    }
}
