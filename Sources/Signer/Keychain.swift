import CryptoTokenKit
import Foundation
import LocalAuthentication
import Security
import SignerCore

/// A signing certificate on an inserted smart card or USB token.
struct TokenCertificate: Identifiable, Hashable, Sendable {
    let certificate: Certificate
    let tokenID: String
    /// Other certificates on the same token (usually the issuing CAs).
    let tokenCertificates: [Certificate]

    var id: Data { certificate.sha256 }

    /// What the device is, from the CryptoTokenKit driver that publishes it.
    var deviceName: String {
        let kinds: [(String, String)] = [
            ("com.alxrxs.rocei.connector", "Romanian eID"),
            ("com.gemalto.", "SafeNet token"),
            ("com.apple.CryptoTokenKit.pivtoken", "PIV card"),
            ("org.opensc-project.", "Smart card"),
        ]
        return kinds.first { tokenID.hasPrefix($0.0) }?.1 ?? "Token"
    }

    /// The PIN macOS will ask for, in the device's own terms.
    var pinName: String {
        guard certificate.isRomanianEID else { return "PIN" }
        return certificate.purpose == .signing ? "signing PIN (6 digits)" : "PIN (4 digits)"
    }
}

enum Keychain {
    /// Signing certificates on every inserted card or token, best first. Software identities in the
    /// login keychain are not offered.
    static func tokenCertificates() -> [TokenCertificate] {
        let identities = items(kSecClassIdentity)
        let certificatesByToken = Dictionary(grouping: items(kSecClassCertificate)) {
            $0[kSecAttrTokenID as String] as? String ?? ""
        }
        var seen = Set<Data>()
        var out: [TokenCertificate] = []
        for item in identities {
            guard let certificate = certificate(of: item), !certificate.isCA, seen.insert(certificate.sha256).inserted else { continue }
            let tokenID = item[kSecAttrTokenID as String] as? String ?? ""
            let others = (certificatesByToken[tokenID] ?? []).compactMap { self.certificate(of: $0) }.filter { $0 != certificate }
            out.append(TokenCertificate(certificate: certificate, tokenID: tokenID, tokenCertificates: others))
        }
        return out.sorted {
            let a = $0.certificate, b = $1.certificate
            return (a.isValid() ? 0 : 1, a.purpose, a.tier) < (b.isValid() ? 0 : 1, b.purpose, b.tier)
        }
    }

    private static func items(_ secClass: CFString, context: LAContext? = nil) -> [[String: Any]] {
        var query: [String: Any] = [
            kSecClass as String: secClass,
            kSecAttrAccessGroup as String: kSecAttrAccessGroupToken,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true,
            kSecReturnAttributes as String: true,
        ]
        if let context { query[kSecUseAuthenticationContext as String] = context }
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let items = result as? [[String: Any]] else { return [] }
        return items.filter { $0[kSecAttrTokenID as String] != nil }
    }

    private static func certificate(of item: [String: Any]) -> Certificate? {
        guard let ref = item[kSecValueRef as String] else { return nil }
        let cf = ref as CFTypeRef
        var secCertificate: SecCertificate?
        if CFGetTypeID(cf) == SecIdentityGetTypeID() {
            SecIdentityCopyCertificate(cf as! SecIdentity, &secCertificate)
        } else if CFGetTypeID(cf) == SecCertificateGetTypeID() {
            secCertificate = (cf as! SecCertificate)
        }
        guard let secCertificate else { return nil }
        return try? Certificate(der: SecCertificateCopyData(secCertificate) as Data)
    }

    /// The private key for `certificate`; macOS asks for the PIN (showing `reason`) when it is used.
    static func privateKey(for certificate: Certificate, reason: String) throws -> SecKey {
        let context = LAContext()
        context.localizedReason = reason
        for item in items(kSecClassIdentity, context: context) {
            guard self.certificate(of: item) == certificate, let ref = item[kSecValueRef as String] else { continue }
            var key: SecKey?
            guard SecIdentityCopyPrivateKey(ref as! SecIdentity, &key) == errSecSuccess, let key else { break }
            return key
        }
        throw SigningError("The card or token with “\(certificate.commonName)” is no longer inserted.")
    }
}

struct SigningCancelled: Error {}

/// Signs with a card or token key through the keychain.
struct KeychainSigner: DigestSigner, @unchecked Sendable {  // SecKey is thread-safe
    let certificate: Certificate
    let key: SecKey

    init(certificate: Certificate, reason: String) throws {
        self.certificate = certificate
        key = try Keychain.privateKey(for: certificate, reason: reason)
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
        guard SecKeyIsAlgorithmSupported(key, .sign, secAlgorithm) else {
            throw SigningError("The card or token can't sign with \(certificate.keyAlgorithm.description) and \(algorithm.name).")
        }
        // The PIN dialog blocks this call until the user answers, so keep it off the cooperative pool.
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                var error: Unmanaged<CFError>?
                if let signature = SecKeyCreateSignature(self.key, secAlgorithm, digest as CFData, &error) as Data? {
                    continuation.resume(returning: signature)
                    return
                }
                let nsError = error?.takeRetainedValue() as Error? as NSError?
                if let nsError, Self.isCancellation(nsError) {
                    continuation.resume(throwing: SigningCancelled())
                } else {
                    continuation.resume(throwing: SigningError(nsError?.localizedDescription ?? "The card or token did not sign."))
                }
            }
        }
    }

    static func isCancellation(_ error: NSError) -> Bool {
        switch error.domain {
        case NSOSStatusErrorDomain: error.code == Int(errSecUserCanceled)
        case LAErrorDomain: [LAError.userCancel, .appCancel, .systemCancel].map(\.rawValue).contains(error.code)
        case TKErrorDomain: error.code == TKError.Code.canceledByUser.rawValue
        default: false
        }
    }
}

/// Calls `changed` whenever a card or token is inserted or removed.
final class TokenMonitor: @unchecked Sendable {
    private let watcher = TKTokenWatcher()

    init(changed: @escaping @Sendable () -> Void) {
        watcher.setInsertionHandler { [weak self] tokenID in
            changed()
            self?.watcher.addRemovalHandler({ _ in changed() }, forTokenID: tokenID)
        }
    }
}
