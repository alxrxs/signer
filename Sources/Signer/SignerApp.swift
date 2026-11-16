import AppKit
import SignerCore
import SwiftUI
import UniformTypeIdentifiers

@main
struct SignerApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        Window("Signer", id: "main") {
            ContentView(model: delegate.model)
                .frame(minWidth: 900, minHeight: 620)
        }
        .windowToolbarStyle(.unified)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Open…") { delegate.model.isImporting = true }
                    .keyboardShortcut("o")
            }
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let model = SignerModel()

    /// Files dropped on the Dock icon or opened with "Open With → Signer".
    func application(_ application: NSApplication, open urls: [URL]) {
        if let url = urls.first(where: { $0.pathExtension.lowercased() == "pdf" }) { model.open(url) }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

struct ContentView: View {
    @Bindable var model: SignerModel
    private let drag = BoxDrag()
    private let renderer = PageRenderer()

    var body: some View {
        Group {
            if model.document != nil {
                HSplitView {
                    PageView(model: model, drag: drag, renderer: renderer)
                        .frame(minWidth: 480)
                    Inspector(model: model)
                        .frame(minWidth: 320, idealWidth: 340, maxWidth: 420)
                }
            } else {
                DropView(model: model)
            }
        }
        .navigationTitle(model.document?.name ?? "Signer")
        .toolbar { toolbar }
        .dropDestination(for: URL.self) { urls, _ in
            guard let url = urls.first(where: { $0.pathExtension.lowercased() == "pdf" }) else { return false }
            model.open(url)
            return true
        } isTargeted: { model.isDropTargeted = $0 }
        .fileImporter(isPresented: $model.isImporting, allowedContentTypes: [.pdf]) { result in
            if case .success(let url) = result { model.open(url) }
        }
        .alert("Can't continue", isPresented: Binding(get: { model.errorMessage != nil }, set: { if !$0 { model.errorMessage = nil } })) {
            Button("OK") { model.errorMessage = nil }
        } message: {
            Text(model.errorMessage ?? "")
        }
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        if let document = model.document {
            ToolbarItem(placement: .navigation) {
                Button("Close", systemImage: "chevron.backward") { model.close() }
                    .help("Choose another PDF")
            }
            if document.pdf.pageCount > 1 {
                ToolbarItem(placement: .principal) {
                    HStack(spacing: 6) {
                        Button("Previous page", systemImage: "chevron.left") { model.choosePage(model.pageIndex - 1) }
                            .disabled(model.pageIndex == 0)
                            .keyboardShortcut(.leftArrow, modifiers: [])
                        Text("Page \(model.pageIndex + 1) of \(document.pdf.pageCount)")
                            .monospacedDigit()
                            .frame(minWidth: 96)
                        Button("Next page", systemImage: "chevron.right") { model.choosePage(model.pageIndex + 1) }
                            .disabled(model.pageIndex + 1 >= document.pdf.pageCount)
                            .keyboardShortcut(.rightArrow, modifiers: [])
                    }
                    .labelStyle(.iconOnly)
                }
            }
            ToolbarItem(placement: .primaryAction) {
                Button("Clear stamp", systemImage: "rectangle.dashed") { model.box = nil }
                    .disabled(model.box == nil)
                    .help("Remove the stamp box")
            }
        }
    }
}

struct DropView: View {
    @Bindable var model: SignerModel

    var body: some View {
        VStack(spacing: 28) {
            Spacer()
            VStack(spacing: 14) {
                Image(systemName: "signature")
                    .font(.system(size: 54, weight: .light))
                    .foregroundStyle(.tint)
                    .symbolEffect(.bounce, value: model.isDropTargeted)
                Text("Drop a PDF to sign")
                    .font(.title.weight(.semibold))
                Text("Place a stamp, then sign with your ID card or USB token.")
                    .foregroundStyle(.secondary)
                Button("Choose PDF…") { model.isImporting = true }
                    .buttonStyle(.glassProminent)
                    .controlSize(.large)
                    .padding(.top, 6)
            }
            .padding(48)
            .frame(maxWidth: 520)
            .background {
                RoundedRectangle(cornerRadius: 28)
                    .strokeBorder(model.isDropTargeted ? AnyShapeStyle(.tint) : AnyShapeStyle(.quaternary),
                                  style: StrokeStyle(lineWidth: 2, dash: [8, 6]))
                    .background(model.isDropTargeted ? AnyShapeStyle(.tint.opacity(0.06)) : AnyShapeStyle(.clear),
                                in: .rect(cornerRadius: 28))
            }
            .animation(.snappy, value: model.isDropTargeted)
            Spacer()
            TokenStatus(model: model)
                .padding(.bottom, 22)
        }
        .padding(.horizontal, 40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct TokenStatus: View {
    let model: SignerModel

    var body: some View {
        HStack(spacing: 10) {
            if let token = model.selected {
                Circle().fill(.green).frame(width: 8, height: 8)
                Text("\(token.certificate.commonName) · \(token.deviceName)")
                TierBadge(tier: token.certificate.tier)
                if model.certificates.count > 1 {
                    Text("+\(model.certificates.count - 1) more").foregroundStyle(.secondary)
                }
            } else if model.isScanning {
                ProgressView().controlSize(.small)
                Text("Looking for cards and tokens…").foregroundStyle(.secondary)
            } else {
                Circle().fill(.orange).frame(width: 8, height: 8)
                Text("Insert your ID card or USB token").foregroundStyle(.secondary)
            }
        }
        .font(.callout)
        .padding(.horizontal, 16)
        .padding(.vertical, 9)
        .glassEffect()
    }
}
