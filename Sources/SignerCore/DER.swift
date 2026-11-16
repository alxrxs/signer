import Foundation

/// Minimal ASN.1 DER: enough to read X.509, OCSP and timestamp responses and to build CMS.
public struct DER: Sendable, Equatable {
    public var tag: UInt8
    /// Content octets (without tag and length).
    public var content: Data
    /// The complete encoding (tag, length, content), exactly as read or built.
    public var encoded: Data

    public enum Tag {
        public static let boolean: UInt8 = 0x01
        public static let integer: UInt8 = 0x02
        public static let bitString: UInt8 = 0x03
        public static let octetString: UInt8 = 0x04
        public static let null: UInt8 = 0x05
        public static let oid: UInt8 = 0x06
        public static let enumerated: UInt8 = 0x0A
        public static let utf8String: UInt8 = 0x0C
        public static let printableString: UInt8 = 0x13
        public static let ia5String: UInt8 = 0x16
        public static let utcTime: UInt8 = 0x17
        public static let generalizedTime: UInt8 = 0x18
        public static let sequence: UInt8 = 0x30
        public static let set: UInt8 = 0x31
        public static func context(_ n: UInt8, constructed: Bool = true) -> UInt8 {
            0x80 | (constructed ? 0x20 : 0) | n
        }
    }

    public struct ParseError: Error, CustomStringConvertible {
        public let description: String
    }

    // MARK: parsing

    public init(_ data: Data) throws {
        var offset = data.startIndex
        self = try DER.read(data, at: &offset)
    }

    /// Reads one element at `offset` and advances it.
    public static func read(_ data: Data, at offset: inout Data.Index) throws -> DER {
        let start = offset
        guard offset < data.endIndex else { throw ParseError(description: "truncated DER") }
        let tag = data[offset]
        offset += 1
        guard tag & 0x1F != 0x1F else { throw ParseError(description: "multi-byte DER tags are not supported") }
        guard offset < data.endIndex else { throw ParseError(description: "truncated DER length") }
        var length = Int(data[offset])
        offset += 1
        if length & 0x80 != 0 {
            let count = length & 0x7F
            guard count > 0, count <= 4, offset + count <= data.endIndex else {
                throw ParseError(description: "unsupported DER length")
            }
            length = 0
            for _ in 0..<count {
                length = length << 8 | Int(data[offset])
                offset += 1
            }
        }
        guard offset + length <= data.endIndex else { throw ParseError(description: "DER element overruns its container") }
        let content = Data(data[offset..<offset + length])
        offset += length
        return DER(tag: tag, content: content, encoded: Data(data[start..<offset]))
    }

    public var isConstructed: Bool { tag & 0x20 != 0 }

    /// Child elements of a constructed value.
    public func children() throws -> [DER] {
        var out: [DER] = []
        var offset = content.startIndex
        while offset < content.endIndex {
            out.append(try DER.read(content, at: &offset))
        }
        return out
    }

    public func child(_ index: Int) throws -> DER {
        let all = try children()
        guard index < all.count else { throw ParseError(description: "missing DER element \(index)") }
        return all[index]
    }

    /// Child with a context-specific tag `[n]`, if present.
    public func context(_ n: UInt8) throws -> DER? {
        try children().first { $0.tag & 0xC0 == 0x80 && $0.tag & 0x1F == n }
    }

    public var oidString: String? {
        guard tag == Tag.oid, !content.isEmpty else { return nil }
        let bytes = [UInt8](content)
        var parts = [Int(bytes[0]) / 40, Int(bytes[0]) % 40]
        var value = 0
        for byte in bytes.dropFirst() {
            value = value << 7 | Int(byte & 0x7F)
            if byte & 0x80 == 0 {
                parts.append(value)
                value = 0
            }
        }
        if bytes[0] >= 80 { parts = [2, Int(bytes[0]) - 80] + parts.dropFirst(2) }
        return parts.map(String.init).joined(separator: ".")
    }

    public var string: String? {
        switch tag {
        case Tag.utf8String, Tag.printableString, Tag.ia5String, 0x14, 0x1A:
            String(data: content, encoding: .utf8) ?? String(data: content, encoding: .isoLatin1)
        case 0x1E:  // BMPString
            String(data: content, encoding: .utf16BigEndian)
        default: nil
        }
    }

    public var date: Date? {
        guard let text = String(data: content, encoding: .ascii) else { return nil }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        switch tag {
        case Tag.utcTime: formatter.dateFormat = "yyMMddHHmmss'Z'"
        case Tag.generalizedTime:
            formatter.dateFormat = text.contains(".") ? "yyyyMMddHHmmss.SSS'Z'" : "yyyyMMddHHmmss'Z'"
        default: return nil
        }
        return formatter.date(from: text)
    }

    public var bool: Bool? { tag == Tag.boolean && content.count == 1 ? content.first != 0 : nil }

    /// Integer value for small integers (≤ 8 bytes).
    public var int: Int? {
        guard tag == Tag.integer || tag == Tag.enumerated, !content.isEmpty, content.count <= 8 else { return nil }
        var value = Int(Int8(bitPattern: content.first!))
        for byte in content.dropFirst() { value = value << 8 | Int(byte) }
        return value
    }

    /// Bits of a BIT STRING (after the unused-bits octet).
    public var bitStringBytes: Data? {
        tag == Tag.bitString && !content.isEmpty ? Data(content.dropFirst()) : nil
    }

    // MARK: building

    public init(tag: UInt8, content: Data) {
        self.tag = tag
        self.content = content
        self.encoded = Data([tag]) + DER.length(content.count) + content
    }

    private init(tag: UInt8, content: Data, encoded: Data) {
        self.tag = tag
        self.content = content
        self.encoded = encoded
    }

    static func length(_ n: Int) -> Data {
        if n < 0x80 { return Data([UInt8(n)]) }
        var bytes: [UInt8] = []
        var value = n
        while value > 0 {
            bytes.insert(UInt8(value & 0xFF), at: 0)
            value >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }

    public static func sequence(_ items: [DER]) -> DER { DER(tag: Tag.sequence, content: items.joined) }

    /// SET OF, sorted as DER requires.
    public static func set(_ items: [DER]) -> DER {
        let sorted = items.map(\.encoded).sorted { $0.lexicographicallyPrecedes($1) }
        return DER(tag: Tag.set, content: sorted.reduce(Data(), +))
    }

    public static func explicit(_ n: UInt8, _ item: DER) -> DER { DER(tag: Tag.context(n), content: item.encoded) }

    public static func implicit(_ n: UInt8, constructed: Bool, _ item: DER) -> DER {
        DER(tag: Tag.context(n, constructed: constructed), content: item.content)
    }

    public static func oid(_ dotted: String) -> DER {
        let parts = dotted.split(separator: ".").compactMap { Int($0) }
        var bytes = [UInt8(parts[0] * 40 + parts[1])]
        for part in parts.dropFirst(2) {
            var chunk = [UInt8(part & 0x7F)]
            var value = part >> 7
            while value > 0 {
                chunk.insert(UInt8(value & 0x7F) | 0x80, at: 0)
                value >>= 7
            }
            bytes += chunk
        }
        return DER(tag: Tag.oid, content: Data(bytes))
    }

    public static func integer(_ value: Int) -> DER {
        var bytes: [UInt8] = []
        var v = value
        repeat {
            bytes.insert(UInt8(v & 0xFF), at: 0)
            v >>= 8
        } while v != 0 && v != -1
        if value >= 0, bytes[0] & 0x80 != 0 { bytes.insert(0, at: 0) }
        if value < 0, bytes[0] & 0x80 == 0 { bytes.insert(0xFF, at: 0) }
        return DER(tag: Tag.integer, content: Data(bytes))
    }

    /// INTEGER from unsigned big-endian bytes.
    public static func integer(unsigned bytes: Data) -> DER {
        var trimmed = Data(bytes.drop { $0 == 0 })
        if trimmed.isEmpty || trimmed.first! & 0x80 != 0 { trimmed.insert(0, at: 0) }
        return DER(tag: Tag.integer, content: trimmed)
    }

    public static let null = DER(tag: Tag.null, content: Data())
    public static func boolean(_ value: Bool) -> DER { DER(tag: Tag.boolean, content: Data([value ? 0xFF : 0])) }
    public static func octetString(_ data: Data) -> DER { DER(tag: Tag.octetString, content: data) }
    public static func bitString(_ data: Data) -> DER { DER(tag: Tag.bitString, content: Data([0]) + data) }
    public static func utf8(_ text: String) -> DER { DER(tag: Tag.utf8String, content: Data(text.utf8)) }

    public static func generalizedTime(_ date: Date) -> DER {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyyMMddHHmmss'Z'"
        return DER(tag: Tag.generalizedTime, content: Data(formatter.string(from: date).utf8))
    }

    public static func utcTime(_ date: Date) -> DER {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyMMddHHmmss'Z'"
        return DER(tag: Tag.utcTime, content: Data(formatter.string(from: date).utf8))
    }

    /// AlgorithmIdentifier with optional parameters.
    public static func algorithm(_ oid: String, parameters: DER? = nil) -> DER {
        sequence([.oid(oid)] + (parameters.map { [$0] } ?? []))
    }
}

extension [DER] {
    var joined: Data { reduce(into: Data()) { $0.append($1.encoded) } }
}

public enum OID {
    public static let sha256 = "2.16.840.1.101.3.4.2.1"
    public static let sha384 = "2.16.840.1.101.3.4.2.2"
    public static let sha512 = "2.16.840.1.101.3.4.2.3"
    public static let sha1 = "1.3.14.3.2.26"
    public static let rsaEncryption = "1.2.840.113549.1.1.1"
    public static let sha256WithRSA = "1.2.840.113549.1.1.11"
    public static let sha384WithRSA = "1.2.840.113549.1.1.12"
    public static let sha512WithRSA = "1.2.840.113549.1.1.13"
    public static let ecPublicKey = "1.2.840.10045.2.1"
    public static let ecdsaSHA256 = "1.2.840.10045.4.3.2"
    public static let ecdsaSHA384 = "1.2.840.10045.4.3.3"
    public static let ecdsaSHA512 = "1.2.840.10045.4.3.4"
    public static let p256 = "1.2.840.10045.3.1.7"
    public static let p384 = "1.3.132.0.34"
    public static let p521 = "1.3.132.0.35"
    public static let data = "1.2.840.113549.1.7.1"
    public static let signedData = "1.2.840.113549.1.7.2"
    public static let contentType = "1.2.840.113549.1.9.3"
    public static let messageDigest = "1.2.840.113549.1.9.4"
    public static let signingCertificateV2 = "1.2.840.113549.1.9.16.2.47"
    public static let timeStampToken = "1.2.840.113549.1.9.16.2.14"
    public static let tstInfo = "1.2.840.113549.1.9.16.1.4"
    public static let commonName = "2.5.4.3"
    public static let keyUsage = "2.5.29.15"
    public static let basicConstraints = "2.5.29.19"
    public static let certificatePolicies = "2.5.29.32"
    public static let crlDistributionPoints = "2.5.29.31"
    public static let authorityInfoAccess = "1.3.6.1.5.5.7.1.1"
    public static let qcStatements = "1.3.6.1.5.5.7.1.3"
    public static let caIssuers = "1.3.6.1.5.5.7.48.2"
    public static let ocsp = "1.3.6.1.5.5.7.48.1"
    public static let ocspBasic = "1.3.6.1.5.5.7.48.1.1"
    public static let ekuTimeStamping = "1.3.6.1.5.5.7.3.8"
    public static let ekuOCSPSigning = "1.3.6.1.5.5.7.3.9"
    public static let signingCertificate = "1.2.840.113549.1.9.16.2.12"
    public static let rsassaPSS = "1.2.840.113549.1.1.10"
    public static let sha1WithRSA = "1.2.840.113549.1.1.5"
    public static let ecdsaSHA1 = "1.2.840.10045.4.1"
    public static let qcCompliance = "0.4.0.1862.1.1"
    public static let qcSSCD = "0.4.0.1862.1.4"
    public static let qcType = "0.4.0.1862.1.6"
    public static let qcTypeESign = "0.4.0.1862.1.6.1"
}
