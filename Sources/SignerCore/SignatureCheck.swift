import CryptoKit
import Foundation
import Security

/// Verifies signatures inside third-party structures (timestamp tokens, OCSP responses, CRLs), so
/// nothing is embedded in a signed PDF without being checked first.
enum SignatureCheck {
    /// Hashes `data` with the digest algorithm `oid` (SHA-1 only for verifying other parties' data).
    static func hash(_ data: Data, oid: String?) throws -> Data {
        switch oid {
        case OID.sha1: Data(Insecure.SHA1.hash(data: data))
        case OID.sha256: Data(SHA256.hash(data: data))
        case OID.sha384: Data(SHA384.hash(data: data))
        case OID.sha512: Data(SHA512.hash(data: data))
        default: throw SigningError("Unsupported digest algorithm \(oid ?? "?").")
        }
    }

    /// The Security framework algorithm for a signature AlgorithmIdentifier. `digest` is the separate
    /// digest algorithm for CMS SignerInfos whose signature algorithm is plain rsaEncryption/ecPublicKey.
    static func algorithm(_ identifier: DER, digest: String? = nil) throws -> SecKeyAlgorithm {
        let oid = try identifier.child(0).oidString
        switch oid {
        case OID.sha256WithRSA: return .rsaSignatureMessagePKCS1v15SHA256
        case OID.sha384WithRSA: return .rsaSignatureMessagePKCS1v15SHA384
        case OID.sha512WithRSA: return .rsaSignatureMessagePKCS1v15SHA512
        case OID.sha1WithRSA: return .rsaSignatureMessagePKCS1v15SHA1
        case OID.ecdsaSHA256: return .ecdsaSignatureMessageX962SHA256
        case OID.ecdsaSHA384: return .ecdsaSignatureMessageX962SHA384
        case OID.ecdsaSHA512: return .ecdsaSignatureMessageX962SHA512
        case OID.ecdsaSHA1: return .ecdsaSignatureMessageX962SHA1
        case OID.rsaEncryption, OID.ecPublicKey:
            let ec = oid == OID.ecPublicKey
            switch digest {
            case OID.sha256: return ec ? .ecdsaSignatureMessageX962SHA256 : .rsaSignatureMessagePKCS1v15SHA256
            case OID.sha384: return ec ? .ecdsaSignatureMessageX962SHA384 : .rsaSignatureMessagePKCS1v15SHA384
            case OID.sha512: return ec ? .ecdsaSignatureMessageX962SHA512 : .rsaSignatureMessagePKCS1v15SHA512
            case OID.sha1: return ec ? .ecdsaSignatureMessageX962SHA1 : .rsaSignatureMessagePKCS1v15SHA1
            default: break
            }
        case OID.rsassaPSS:
            // RSASSA-PSS-params: [0] hashAlgorithm (default SHA-1); salt length is assumed to equal the hash length.
            let params = try? identifier.child(1)
            let hash = try params?.context(0)?.child(0).child(0).oidString ?? OID.sha1
            switch hash {
            case OID.sha256: return .rsaSignatureMessagePSSSHA256
            case OID.sha384: return .rsaSignatureMessagePSSSHA384
            case OID.sha512: return .rsaSignatureMessagePSSSHA512
            default: break
            }
        default: break
        }
        throw SigningError("Unsupported signature algorithm \(oid ?? "?").")
    }

    static func verify(_ data: Data, signature: Data, algorithm identifier: DER, digest: String? = nil, by certificate: Certificate) -> Bool {
        guard let key = certificate.publicKey, let algorithm = try? algorithm(identifier, digest: digest) else { return false }
        return SecKeyVerifySignature(key, algorithm, data as CFData, signature as CFData, nil)
    }

    /// Whether `certificate` chains (with signature checks) to one of `anchors` at `date`. Intermediates
    /// may come from `pool` or be fetched through AIA by the Security framework.
    static func chains(_ certificate: Certificate, to anchors: [Certificate], pool: [Certificate] = [], at date: Date) -> Bool {
        if anchors.contains(certificate) { return true }
        let refs = ([certificate] + pool.filter { $0 != certificate }).compactMap(\.secCertificate)
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(refs as CFArray, SecPolicyCreateBasicX509(), &trust) == errSecSuccess, let trust else {
            return false
        }
        SecTrustSetAnchorCertificates(trust, anchors.compactMap(\.secCertificate) as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)
        SecTrustSetVerifyDate(trust, date as CFDate)
        SecTrustSetNetworkFetchAllowed(trust, true)
        return SecTrustEvaluateWithError(trust, nil)
    }
}
