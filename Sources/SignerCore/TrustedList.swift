import Foundation

/// The EU Trusted Lists (ETSI TS 119 612): which trust services are qualified under eIDAS.
///
/// The EU's list of lists (LOTL) points to each country's Trusted List; a country list names its trust
/// services with their type, current status and certificates. Lists are fetched over HTTPS from the
/// official locations and cached for a day. Their XML signatures are not verified here: integrity
/// rests on HTTPS to the publishing authorities.
public enum EUTrustedList {
    static let listOfLists = URL(string: "https://ec.europa.eu/tools/lotl/eu-lotl.xml")!
    static let qualifiedTimestampType = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"
    static let granted = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"

    /// Certificates of the qualified timestamp services currently granted in `country`'s Trusted List
    /// (ISO country code, e.g. "BE"; the list uses "EL" for Greece).
    public static func qualifiedTimestampCertificates(country: String) async throws -> [Certificate] {
        let territory = country.uppercased() == "GR" ? "EL" : country.uppercased()
        let lotl = try await fetch(listOfLists, cacheName: "eu-lotl.xml")
        guard let location = try countryListLocation(territory, in: lotl) else {
            throw SigningError("The EU Trusted List has no list for \(territory).")
        }
        let list = try await fetch(location, cacheName: "tl-\(territory).xml")
        return try grantedServiceCertificates(type: qualifiedTimestampType, in: list)
    }

    static func countryListLocation(_ territory: String, in lotl: Data) throws -> URL? {
        let document = try XMLDocument(data: lotl)
        for pointer in try document.nodes(forXPath: "//*[local-name()='OtherTSLPointer']") {
            let territories = try pointer.nodes(forXPath: ".//*[local-name()='SchemeTerritory']").compactMap(\.stringValue)
            let mime = try pointer.nodes(forXPath: ".//*[local-name()='MimeType']").compactMap(\.stringValue)
            guard territories.first == territory, mime.contains(where: { $0.contains("xml") }),
                  let location = try pointer.nodes(forXPath: "./*[local-name()='TSLLocation']").first?.stringValue,
                  let url = URL(string: location.trimmingCharacters(in: .whitespacesAndNewlines)),
                  url.scheme == "https" else { continue }
            return url
        }
        return nil
    }

    static func grantedServiceCertificates(type: String, in list: Data) throws -> [Certificate] {
        let document = try XMLDocument(data: list)
        var out: [Certificate] = []
        for information in try document.nodes(forXPath: "//*[local-name()='TSPService']/*[local-name()='ServiceInformation']") {
            let serviceType = try information.nodes(forXPath: "./*[local-name()='ServiceTypeIdentifier']").first?.stringValue
            let status = try information.nodes(forXPath: "./*[local-name()='ServiceStatus']").first?.stringValue
            guard serviceType?.trimmingCharacters(in: .whitespacesAndNewlines) == type,
                  status?.trimmingCharacters(in: .whitespacesAndNewlines) == granted else { continue }
            for node in try information.nodes(forXPath: ".//*[local-name()='X509Certificate']") {
                let base64 = (node.stringValue ?? "").components(separatedBy: .whitespacesAndNewlines).joined()
                if let der = Data(base64Encoded: base64), let certificate = try? Certificate(der: der) { out.append(certificate) }
            }
        }
        return out
    }

    /// Downloads `url`, caching it for a day; if the download fails, a cached copy up to a week old is used.
    static func fetch(_ url: URL, cacheName: String) async throws -> Data {
        let directory = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("com.alxrxs.signer/eu-trusted-lists", isDirectory: true)
        let file = directory.appendingPathComponent(cacheName)
        let age = (try? file.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate)
            .map { Date.now.timeIntervalSince($0) } ?? .infinity
        if age < 86_400, let cached = try? Data(contentsOf: file) { return cached }
        do {
            let (data, response) = try await URLSession.shared.data(for: URLRequest(url: url, timeoutInterval: 60))
            guard (response as? HTTPURLResponse)?.statusCode == 200, !data.isEmpty else {
                throw SigningError("The EU Trusted List at \(url.host() ?? "") did not answer.")
            }
            try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            try? data.write(to: file, options: .atomic)
            return data
        } catch {
            if age < 7 * 86_400, let cached = try? Data(contentsOf: file) { return cached }
            throw error
        }
    }
}
