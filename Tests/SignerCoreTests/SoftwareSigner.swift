import Foundation
import Security
@testable import SignerCore

/// A throwaway key with a self-signed certificate, standing in for a smart card.
struct SoftwareSigner: DigestSigner, @unchecked Sendable {  // SecKey is thread-safe
    let key: SecKey
    let certificate: Certificate

    enum Kind { case ecP384, rsa2048 }

    init(_ kind: Kind = .ecP384, name: String = "TEST SIGNER", keyUsage: UInt8 = 0x40 /* nonRepudiation */) throws {
        let attributes: [String: Any] = switch kind {
        case .ecP384: [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits as String: 384]
        case .rsa2048: [kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits as String: 2048]
        }
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
              let publicKey = SecKeyCopyPublicKey(key),
              let raw = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        self.key = key
        let spki: DER, signatureAlgorithm: DER, algorithm: SecKeyAlgorithm
        switch kind {
        case .ecP384:
            spki = .sequence([.algorithm(OID.ecPublicKey, parameters: .oid(OID.p384)), .bitString(raw)])
            signatureAlgorithm = .algorithm(OID.ecdsaSHA384)
            algorithm = .ecdsaSignatureMessageX962SHA384
        case .rsa2048:
            spki = .sequence([.algorithm(OID.rsaEncryption, parameters: .null), .bitString(raw)])
            signatureAlgorithm = .algorithm(OID.sha256WithRSA, parameters: .null)
            algorithm = .rsaSignatureMessagePKCS1v15SHA256
        }
        let subject = DER.sequence([.set([.sequence([.oid(OID.commonName), .utf8(name)])])])
        let keyUsageExt = DER.sequence([
            .oid(OID.keyUsage), .boolean(true),
            .octetString(DER(tag: DER.Tag.bitString, content: Data([0x06, keyUsage])).encoded),
        ])
        let tbs = DER.sequence([
            .explicit(0, .integer(2)),
            .integer(Int.random(in: 1...Int(Int32.max))),
            signatureAlgorithm,
            subject,
            .sequence([.utcTime(.now.addingTimeInterval(-86400)), .utcTime(.now.addingTimeInterval(86400 * 365))]),
            subject,
            spki,
            .explicit(3, .sequence([keyUsageExt])),
        ])
        guard let signature = SecKeyCreateSignature(key, algorithm, tbs.encoded as CFData, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        certificate = try Certificate(der: DER.sequence([tbs, signatureAlgorithm, .bitString(signature)]).encoded)
    }

    func sign(digest: Data, algorithm: DigestAlgorithm) async throws -> Data {
        let secAlgorithm: SecKeyAlgorithm = switch (certificate.keyAlgorithm, algorithm) {
        case (.ec, .sha256): .ecdsaSignatureDigestX962SHA256
        case (.ec, .sha384): .ecdsaSignatureDigestX962SHA384
        case (.ec, .sha512): .ecdsaSignatureDigestX962SHA512
        case (_, .sha256): .rsaSignatureDigestPKCS1v15SHA256
        case (_, .sha384): .rsaSignatureDigestPKCS1v15SHA384
        case (_, .sha512): .rsaSignatureDigestPKCS1v15SHA512
        }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, secAlgorithm, digest as CFData, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        return signature
    }
}
