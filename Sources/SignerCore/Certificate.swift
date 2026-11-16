import CryptoKit
import Foundation
import Security

/// An X.509 certificate, parsed just far enough for signing decisions and PAdES.
public struct Certificate: Sendable, Hashable, Identifiable {
    public let der: Data
    public let serialNumber: DER
    public let issuerName: DER
    public let subjectName: DER
    public let notBefore: Date
    public let notAfter: Date
    public let subjectPublicKeyInfo: DER
    public let commonName: String
    public let issuerCommonName: String
    public let organization: String?
    public let keyAlgorithm: KeyAlgorithm
    public private(set) var keyUsage: Set<KeyUsage> = []
    public private(set) var policies: [String] = []
    public private(set) var qcCompliance = false
    public private(set) var qcSSCD = false
    public private(set) var qcESign = false
    public private(set) var isCA = false
    /// id-pkix-ocsp-nocheck: an OCSP responder certificate whose own status need not be checked.
    public private(set) var ocspNoCheck = false
    public private(set) var caIssuerURLs: [URL] = []
    public private(set) var ocspURLs: [URL] = []
    public private(set) var crlURLs: [URL] = []
    /// Extended key usage purposes (OIDs), e.g. id-kp-timeStamping, id-kp-OCSPSigning.
    public private(set) var extendedKeyUsage: Set<String> = []
    public private(set) var subjectKeyIdentifier: Data?
    /// Country (C) of the subject, e.g. "BE".
    public var country: String? { Certificate.attribute("2.5.4.6", in: subjectName) }
    /// The subjectPublicKey bits (what OCSP key hashes are computed over).
    public var publicKeyBits: Data { (try? subjectPublicKeyInfo.child(1).bitStringBytes) ?? Data() }

    /// The certificate as a Security framework object, and its public key.
    public var secCertificate: SecCertificate? { SecCertificateCreateWithData(nil, der as CFData) }
    public var publicKey: SecKey? { secCertificate.flatMap { SecCertificateCopyKey($0) } }

    public var id: Data { sha256 }
    public var sha256: Data { Data(SHA256.hash(data: der)) }

    public static func == (a: Certificate, b: Certificate) -> Bool { a.der == b.der }
    public func hash(into hasher: inout Hasher) { hasher.combine(der) }

    public enum KeyAlgorithm: Sendable, Hashable {
        case ec(curve: Curve)
        case rsa(bits: Int)
        case other(String)

        public enum Curve: String, Sendable { case p256 = "P-256", p384 = "P-384", p521 = "P-521", unknown = "EC" }

        public var description: String {
            switch self {
            case .ec(let curve): "ECDSA \(curve.rawValue)"
            case .rsa(let bits): "RSA \(bits)"
            case .other(let oid): oid
            }
        }
    }

    public enum KeyUsage: Int, Sendable, CaseIterable {
        case digitalSignature = 0, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign
    }

    public init(der: Data) throws {
        self.der = der
        let tbs = try DER(der).child(0)
        var fields = try tbs.children()
        if fields.first?.tag == DER.Tag.context(0) { fields.removeFirst() }  // version
        guard fields.count >= 6 else { throw DER.ParseError(description: "not an X.509 certificate") }
        serialNumber = fields[0]
        issuerName = fields[2]
        let validity = try fields[3].children()
        notBefore = validity[0].date ?? .distantPast
        notAfter = validity[1].date ?? .distantFuture
        subjectName = fields[4]
        subjectPublicKeyInfo = fields[5]
        commonName = Certificate.attribute(OID.commonName, in: subjectName) ?? "?"
        issuerCommonName = Certificate.attribute(OID.commonName, in: issuerName) ?? "?"
        organization = Certificate.attribute("2.5.4.10", in: subjectName)

        let algorithm = try subjectPublicKeyInfo.child(0)
        switch try algorithm.child(0).oidString {
        case OID.ecPublicKey:
            let curve: KeyAlgorithm.Curve = switch try? algorithm.child(1).oidString {
            case OID.p256: .p256
            case OID.p384: .p384
            case OID.p521: .p521
            default: .unknown
            }
            keyAlgorithm = .ec(curve: curve)
        case OID.rsaEncryption:
            let key = try DER(try subjectPublicKeyInfo.child(1).bitStringBytes ?? Data())
            let modulus = try key.child(0).content.drop { $0 == 0 }
            keyAlgorithm = .rsa(bits: modulus.count * 8)
        case let oid:
            keyAlgorithm = .other(oid ?? "?")
        }

        if let extensions = fields.first(where: { $0.tag == DER.Tag.context(3) }) {
            for ext in try extensions.child(0).children() {
                let parts = try ext.children()
                guard let oid = parts.first?.oidString, let value = parts.last, value.tag == DER.Tag.octetString else { continue }
                try parseExtension(oid, try DER(value.content))
            }
        }
    }

    private mutating func parseExtension(_ oid: String, _ value: DER) throws {
        switch oid {
        case "2.5.29.37":
            extendedKeyUsage = Set(try value.children().compactMap(\.oidString))
        case "2.5.29.14":
            subjectKeyIdentifier = value.content
        case OID.keyUsage:
            let bits = [UInt8](value.bitStringBytes ?? Data())
            for usage in KeyUsage.allCases {
                let byte = usage.rawValue / 8
                if byte < bits.count, bits[byte] & (0x80 >> UInt8(usage.rawValue % 8)) != 0 { keyUsage.insert(usage) }
            }
        case "1.3.6.1.5.5.7.48.1.5":
            ocspNoCheck = true
        case OID.basicConstraints:
            isCA = (try value.children().first?.bool) ?? false
        case OID.certificatePolicies:
            policies = try value.children().compactMap { try $0.child(0).oidString }
        case OID.qcStatements:
            for statement in try value.children() {
                let parts = try statement.children()
                switch parts.first?.oidString {
                case OID.qcCompliance: qcCompliance = true
                case OID.qcSSCD: qcSSCD = true
                case OID.qcType:
                    if parts.count > 1, try parts[1].children().contains(where: { $0.oidString == OID.qcTypeESign }) {
                        qcESign = true
                    }
                default: break
                }
            }
        case OID.authorityInfoAccess:
            for description in try value.children() {
                let parts = try description.children()
                guard parts.count == 2, parts[1].tag == 0x86,
                      let url = URL(string: String(decoding: parts[1].content, as: UTF8.self)) else { continue }
                switch parts[0].oidString {
                case OID.caIssuers: caIssuerURLs.append(url)
                case OID.ocsp: ocspURLs.append(url)
                default: break
                }
            }
        case OID.crlDistributionPoints:
            for point in try value.children() {
                // DistributionPoint → [0] distributionPoint → [0] fullName → GeneralName [6] URI
                guard let name = try point.context(0), let full = try name.context(0) else { continue }
                for general in try full.children() where general.tag == 0x86 {
                    if let url = URL(string: String(decoding: general.content, as: UTF8.self)) { crlURLs.append(url) }
                }
            }
        default: break
        }
    }

    static func attribute(_ oid: String, in name: DER) -> String? {
        guard let rdns = try? name.children() else { return nil }
        for rdn in rdns {
            for pair in (try? rdn.children()) ?? [] {
                if let parts = try? pair.children(), parts.count == 2, parts[0].oidString == oid {
                    return parts[1].string
                }
            }
        }
        return nil
    }

    // MARK: decisions

    public var isSelfSigned: Bool { issuerName.encoded == subjectName.encoded }

    public func isIssued(by issuer: Certificate) -> Bool { issuerName.encoded == issuer.subjectName.encoded }

    public enum Purpose: Int, Sendable, Comparable {
        case signing, other, authentication
        public static func < (a: Purpose, b: Purpose) -> Bool { a.rawValue < b.rawValue }
    }

    /// Cards often carry an authentication certificate next to the signing one (the Romanian eID
    /// does). Validators reject document signatures made with an authentication key.
    public var purpose: Purpose {
        if keyUsage.contains(.nonRepudiation) { return .signing }
        if keyUsage.contains(.digitalSignature) { return .authentication }
        return .other
    }

    /// What eIDAS calls a signature made with this certificate.
    public enum Tier: Int, Sendable, Comparable {
        case qualified, advancedQualifiedCertificate, advanced
        public static func < (a: Tier, b: Tier) -> Bool { a.rawValue < b.rawValue }
        public var short: String {
            switch self {
            case .qualified: "QES"
            case .advancedQualifiedCertificate: "AdES/QC"
            case .advanced: "AdES"
            }
        }
    }

    public var tier: Tier {
        if qcCompliance && qcSSCD { return .qualified }
        if qcCompliance { return .advancedQualifiedCertificate }
        return .advanced
    }

    /// Issued by the Romanian electronic ID card's CA.
    public var isRomanianEID: Bool {
        issuerCommonName.contains("RO CEI MAI") || policies.contains { $0.hasPrefix("1.3.6.1.4.1.62458") }
    }

    public func isValid(at date: Date = .now) -> Bool { notBefore <= date && date <= notAfter }

    /// Digest matched to the key: ECDSA wants the curve's strength (P-384 → SHA-384).
    public var digest: DigestAlgorithm {
        switch keyAlgorithm {
        case .ec(.p384): .sha384
        case .ec(.p521): .sha512
        default: .sha256
        }
    }
}

public enum DigestAlgorithm: String, Sendable {
    case sha256, sha384, sha512

    public var oid: String {
        switch self {
        case .sha256: OID.sha256
        case .sha384: OID.sha384
        case .sha512: OID.sha512
        }
    }

    public func hash(_ data: Data) -> Data {
        switch self {
        case .sha256: Data(SHA256.hash(data: data))
        case .sha384: Data(SHA384.hash(data: data))
        case .sha512: Data(SHA512.hash(data: data))
        }
    }

    public var name: String { rawValue.uppercased().replacingOccurrences(of: "SHA", with: "SHA-") }
}
