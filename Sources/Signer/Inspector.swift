import SignerCore
import SwiftUI

struct Inspector: View {
    @Bindable var model: SignerModel

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section("Certificate") { CertificateSection(model: model) }

                if let document = model.document, document.existingSignatures > 0 {
                    Section {
                        Label {
                            Text("Already signed ^[\(document.existingSignatures) time](inflect: true). Those signatures stay valid: yours is added on top.")
                        } icon: {
                            Image(systemName: "checkmark.seal").foregroundStyle(.green)
                        }
                        .font(.callout)
                    }
                }

                Section("Stamp") {
                    Toggle("Visible stamp", isOn: $model.drawStamp)
                    if model.drawStamp {
                        TextEditor(text: $model.stampText)
                            .font(.body)
                            .frame(minHeight: 66, maxHeight: 110)
                            .scrollContentBackground(.hidden)
                        Text("`{date}` becomes the signing time.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Toggle("Fit text to the box", isOn: $model.autoFit)
                        if !model.autoFit {
                            LabeledContent("Size") {
                                HStack {
                                    Slider(value: $model.fontSize, in: Double(Stamp.sizeRange.lowerBound)...Double(Stamp.sizeRange.upperBound))
                                    Text("\(model.fontSize, format: .number.precision(.fractionLength(0))) pt")
                                        .monospacedDigit()
                                        .frame(width: 42, alignment: .trailing)
                                }
                            }
                        }
                        Toggle("White background", isOn: $model.whiteBackground)
                        Toggle("Border", isOn: $model.border)
                        if let layout = model.layout {
                            if layout.clipped {
                                Label("The text doesn't fit. Make the box bigger or the text smaller.", systemImage: "exclamationmark.triangle.fill")
                                    .font(.callout)
                                    .foregroundStyle(.orange)
                            } else if model.autoFit {
                                Text("Text size \(layout.fontSize, format: .number.precision(.fractionLength(1))) pt")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }

                Section("Signature") {
                    Picker("Level", selection: $model.level) {
                        ForEach(SignatureLevel.allCases) { level in
                            Text(level.title).tag(level)
                        }
                    }
                    Text(model.level.explanation)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    TextField("Reason", text: $model.reason)
                    TextField("Location", text: $model.location, prompt: Text("Optional"))
                }
            }
            .formStyle(.grouped)

            SignBar(model: model)
        }
    }
}

extension SignatureLevel {
    var title: String {
        switch self {
        case .b: "B-B: signature only"
        case .t: "B-T: with timestamp"
        case .lt: "B-LT: long-term"
        case .lta: "B-LTA: archival (recommended)"
        }
    }

    var explanation: String {
        switch self {
        case .b: "The signing time comes from your Mac's clock and is not attested. Avoid unless you have to."
        case .t: "Adds a trusted timestamp proving when you signed."
        case .lt: "Also embeds the certificate chain and revocation answers, so the signature can be checked years from now."
        case .lta: "Timestamp, certificate chain, revocation answers and an archive timestamp, so the signature can still be checked after your certificate expires."
        }
    }
}

struct CertificateSection: View {
    @Bindable var model: SignerModel

    var body: some View {
        if let token = model.selected {
            if model.certificates.count > 1 {
                Picker("Sign with", selection: Binding(get: { token.id }, set: {
                    model.selectedID = $0
                    model.fillDefaultStampText()
                })) {
                    ForEach(model.certificates) { item in
                        Text("\(item.certificate.commonName) · \(item.deviceName) · \(item.certificate.purpose.title)").tag(item.id)
                    }
                }
            }
            CertificateCard(token: token)
        } else {
            VStack(alignment: .leading, spacing: 6) {
                Label(model.isScanning ? "Looking for cards and tokens…" : "No card or token found",
                      systemImage: model.isScanning ? "magnifyingglass" : "creditcard.trianglebadge.exclamationmark")
                    .font(.headline)
                Text("Insert your ID card or USB token. It appears here as soon as macOS sees it.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            .padding(.vertical, 4)
        }
    }
}

extension Certificate.Purpose {
    var title: String {
        switch self {
        case .signing: "signing"
        case .authentication: "authentication"
        case .other: "other"
        }
    }
}

struct CertificateCard: View {
    let token: TokenCertificate

    var body: some View {
        let certificate = token.certificate
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Text(certificate.commonName)
                    .font(.headline)
                Spacer()
                TierBadge(tier: certificate.tier)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text("\(token.deviceName) · \(certificate.keyAlgorithm.description) · \(certificate.digest.name)")
                Text("Issued by \(certificate.issuerCommonName)")
                Text("Valid until \(certificate.notAfter.formatted(date: .long, time: .omitted))")
            }
            .font(.callout)
            .foregroundStyle(.secondary)
            Text(certificate.tierNote)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if !certificate.isValid() {
                Warning("This certificate has expired or is not valid yet. Validators will reject the signature.")
            } else if certificate.purpose == .authentication {
                Warning("This is an authentication certificate, not a signing one. Validators normally reject documents signed with it.")
            }
        }
        .padding(.vertical, 4)
    }
}

struct Warning: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Label(text, systemImage: "exclamationmark.triangle.fill")
            .font(.callout)
            .foregroundStyle(.orange)
            .fixedSize(horizontal: false, vertical: true)
    }
}

struct TierBadge: View {
    let tier: Certificate.Tier
    var body: some View {
        Text(tier.short)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .foregroundStyle(color)
            .background(color.opacity(0.14), in: .capsule)
    }

    var color: Color {
        switch tier {
        case .qualified: .green
        case .advancedQualifiedCertificate: .orange
        case .advanced: .secondary
        }
    }
}

extension Certificate {
    var tierNote: String {
        switch tier {
        case .qualified:
            "Qualified electronic signature: equivalent to a handwritten one across the EU (eIDAS Art. 25(2))."
        case .advancedQualifiedCertificate:
            "Advanced signature on a qualified certificate (the key is not attested to be in a qualified device)."
        case .advanced where isRomanianEID:
            "Advanced signature on the Romanian eID: legally valid in Romania, but not equivalent to a handwritten signature elsewhere."
        case .advanced:
            "Advanced electronic signature."
        }
    }
}

struct SignBar: View {
    @Bindable var model: SignerModel

    var body: some View {
        VStack(spacing: 10) {
            switch model.phase {
            case .working(let text):
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text(text).font(.callout)
                    Spacer()
                }
            case .cancelled:
                Label("Cancelled. Nothing was signed.", systemImage: "xmark.circle")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            case .signed(let url, let level, let shortfall):
                VStack(alignment: .leading, spacing: 8) {
                    Label("Signed (\(level.rawValue)): \(url.lastPathComponent)", systemImage: "checkmark.seal.fill")
                        .font(.callout.weight(.medium))
                        .foregroundStyle(.green)
                    if let shortfall {
                        Warning(shortfall)
                    }
                    HStack {
                        Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([url]) }
                        Button("Open") { NSWorkspace.shared.open(url) }
                    }
                    .controlSize(.small)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            case .idle:
                EmptyView()
            }
            Button {
                model.sign()
            } label: {
                Label("Sign PDF…", systemImage: "signature")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            .controlSize(.extraLarge)
            .disabled(!model.canSign)
            .keyboardShortcut(.return, modifiers: .command)
            if model.drawStamp && model.box == nil && model.document != nil {
                Text("Drag a box on the page first, or turn off the visible stamp.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
    }
}
