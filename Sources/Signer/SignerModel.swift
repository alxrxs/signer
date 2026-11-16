import AppKit
import Observation
import PDFKit
import SignerCore

/// Everything the window shows. SwiftUI's @State is unavailable without Xcode's macro plugins, so view
/// state lives here too.
@MainActor @Observable
final class SignerModel {
    // MARK: document

    struct Document {
        let url: URL
        let data: Data
        let pdf: PDFDocument
        /// Signatures already in the file (they stay valid: signing only appends).
        let existingSignatures: Int
        var name: String { url.lastPathComponent }
    }

    var document: Document?
    var pageIndex = 0
    var errorMessage: String?
    var isImporting = false
    var isDropTargeted = false

    // MARK: placement and stamp

    /// The stamp's box on the displayed page, normalised (0…1, origin top-left).
    var box: CGRect?
    var drawStamp = true
    var stampText = ""
    var autoFit = true
    var fontSize: Double = 11
    var whiteBackground = true
    var border = true

    // MARK: signature

    var level: SignatureLevel = .lta
    var reason = "Conform cu originalul"
    var location = ""

    // MARK: certificates

    var certificates: [TokenCertificate] = []
    var selectedID: Data?
    var isScanning = false
    private var monitor: TokenMonitor?

    var selected: TokenCertificate? { certificates.first { $0.id == selectedID } ?? certificates.first }

    // MARK: signing state

    enum Phase: Equatable {
        case idle
        case working(String)
        case signed(URL, level: SignatureLevel, shortfall: String?)
        case cancelled
    }

    var phase: Phase = .idle
    var isWorking: Bool { if case .working = phase { true } else { false } }

    init() {
        monitor = TokenMonitor { [weak self] in
            Task { @MainActor in self?.refreshCertificates() }
        }
        refreshCertificates()
    }

    func refreshCertificates() {
        isScanning = true
        Task {
            let found = await Task.detached(priority: .userInitiated) { Keychain.tokenCertificates() }.value
            certificates = found
            if selectedID.map({ id in !found.contains { $0.id == id } }) ?? true { selectedID = found.first?.id }
            isScanning = false
            fillDefaultStampText()
        }
    }

    private var lastDefaultText = ""

    /// Pre-fills the stamp for the chosen certificate, unless the user has written their own.
    func fillDefaultStampText() {
        guard let certificate = selected?.certificate else { return }
        let text = "Semnat digital de\n\(certificate.commonName)\nData: {date}"
        if stampText.isEmpty || stampText == lastDefaultText {
            stampText = text
            lastDefaultText = text
        }
    }

    // MARK: opening

    func open(_ url: URL) {
        let access = url.startAccessingSecurityScopedResource()
        defer { if access { url.stopAccessingSecurityScopedResource() } }
        do {
            let data = try Data(contentsOf: url)
            guard let pdf = PDFDocument(data: data), pdf.pageCount > 0 else {
                throw SigningError("“\(url.lastPathComponent)” is not a PDF that can be opened.")
            }
            guard !pdf.isEncrypted else {
                throw SigningError("“\(url.lastPathComponent)” is password-protected. Remove the password first (open it in Preview and export a copy).")
            }
            let file = try PDFFile(data: data)
            let signatures = try file.signatureFields().filter(\.signed).count
            document = Document(url: url, data: data, pdf: pdf, existingSignatures: signatures)
            pageIndex = 0
            box = nil
            phase = .idle
            fillDefaultStampText()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func close() {
        document = nil
        box = nil
        phase = .idle
    }

    func choosePage(_ index: Int) {
        guard let document, (0..<document.pdf.pageCount).contains(index), index != pageIndex else { return }
        pageIndex = index
        box = nil
    }

    // MARK: geometry

    var geometry: PageGeometry? {
        guard let page = document?.pdf.page(at: pageIndex) else { return nil }
        return PageGeometry(cropBox: page.bounds(for: .cropBox), rotation: page.rotation)
    }

    var style: StampStyle {
        StampStyle(text: Stamp.expand(stampText), autoFit: autoFit, fontSize: fontSize,
                   whiteBackground: whiteBackground, border: border)
    }

    /// The stamp's size on the page in points (as seen), or nil without a box.
    var boxPointSize: CGSize? {
        guard let box, let geometry else { return nil }
        return geometry.displayPointSize(of: box)
    }

    var layout: Stamp.Layout? {
        boxPointSize.map { Stamp.layout(style, in: $0) }
    }

    var canSign: Bool {
        document != nil && selected != nil && !isWorking && (!drawStamp || box != nil)
    }

    // MARK: signing

    func sign() {
        guard let document, let token = selected, let geometry else { return }
        let stem = document.url.deletingPathExtension().lastPathComponent
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.pdf]
        panel.directoryURL = document.url.deletingLastPathComponent()
        panel.nameFieldStringValue = "\(stem) - semnat.pdf"
        panel.message = "Choose where to save the signed copy"
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        guard destination.standardizedFileURL != document.url.standardizedFileURL else {
            errorMessage = "Choose a different name: the original is needed while signing."
            return
        }

        var placement = SignaturePlacement(pageIndex: pageIndex, rect: nil, appearance: nil, pageRotation: geometry.rotation)
        if drawStamp, let box, let size = boxPointSize {
            placement.rect = geometry.userRect(fromDisplay: box)
            placement.appearance = Stamp.pdf(style, size: size)
        }
        let finalPlacement = placement
        let info = SignatureInfo(reason: reason, location: location, signerName: token.certificate.commonName)
        let level = self.level
        let original = document.data
        let reasonText = "sign “\(document.name)”"
        phase = .working("Preparing…")

        Task {
            do {
                let signer = try KeychainSigner(certificate: token.certificate, reason: reasonText)
                let pinName = token.pinName
                let result = try await Task.detached(priority: .userInitiated) {
                    let chain = await Revocation.chain(for: token.certificate, pool: token.tokenCertificates).dropFirst()
                    return try await PAdES.signDocument(
                        pdf: original, placement: finalPlacement, info: info, level: level,
                        signer: signer, chain: Array(chain)
                    ) { stage in
                        let text = switch stage {
                        case .preparing: "Preparing…"
                        case .waitingForSigner: "Enter your \(pinName) in the macOS dialog…"
                        case .timestamping: "Getting a timestamp…"
                        case .collectingValidationData: "Collecting revocation data…"
                        case .archiveTimestamp: "Adding the archive timestamp…"
                        }
                        Task { @MainActor in if self.isWorking { self.phase = .working(text) } }
                    }
                }.value
                try result.pdf.write(to: destination, options: .atomic)
                phase = .signed(destination, level: result.level, shortfall: result.shortfall)
            } catch is SigningCancelled {
                phase = .cancelled
            } catch {
                phase = .idle
                errorMessage = error.localizedDescription
            }
        }
    }
}
