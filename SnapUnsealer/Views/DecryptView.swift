//
//  DecryptView.swift
//  SnapUnsealer
//

import SwiftUI
import UniformTypeIdentifiers
import AppKit

/// Job 2 UI: pick a `.snap.gpg`, pick a destination, decrypt. Touch ID
/// fires when `UnsealerService.decryptSnapshot` reloads the SE key —
/// nothing else is asked of the operator, since the passphrase (if any)
/// was already captured once at enrollment.
struct DecryptView: View {
    var onReplaceKey: () -> Void

    @State private var isImportingInput = false
    @State private var inputURL: URL?
    @State private var outputURL: URL?
    @State private var status = "Pick a .snap.gpg file to decrypt."
    @State private var isBusy = false

    private let snapGpgType = UTType(filenameExtension: "gpg") ?? .data

    var body: some View {
        VStack(spacing: 16) {
            Text("Decrypt Snapshot")
                .font(.title2)
                .bold()

            Text(status)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)

            Button {
                isImportingInput = true
            } label: {
                Label(inputURL == nil ? "Choose .snap.gpg…" : "Change .snap.gpg…", systemImage: "doc")
            }
            .disabled(isBusy)

            if let inputURL {
                Text(inputURL.lastPathComponent)
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Button {
                    chooseDestination(suggesting: inputURL)
                } label: {
                    Label(
                        outputURL == nil ? "Choose destination…" : "Change destination…",
                        systemImage: "square.and.arrow.down"
                    )
                }
                .disabled(isBusy)
            }

            if let outputURL {
                Text(outputURL.lastPathComponent)
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Button("Decrypt") {
                    decrypt()
                }
                .disabled(isBusy)
                .keyboardShortcut(.defaultAction)
            }

            Divider()

            Button("Replace enrolled key", role: .destructive, action: onReplaceKey)
                .disabled(isBusy)
        }
        .padding(40)
        .frame(minWidth: 460, minHeight: 360)
        .fileImporter(isPresented: $isImportingInput, allowedContentTypes: [snapGpgType, .data]) { result in
            handleInput(result)
        }
    }

    private func handleInput(_ result: Result<URL, Error>) {
        switch result {
        case .failure(let error):
            status = "File selection failed: \(error.localizedDescription)"
        case .success(let url):
            inputURL = url
            outputURL = nil
            status = "Selected \(url.lastPathComponent). Choose where to write the decrypted .snap."
        }
    }

    private func chooseDestination(suggesting inputURL: URL) {
        let panel = NSSavePanel()
        panel.title = "Save decrypted snapshot"
        var suggestedName = inputURL.deletingPathExtension().lastPathComponent
        if suggestedName.isEmpty {
            suggestedName = "decrypted"
        }
        panel.nameFieldStringValue = suggestedName
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        outputURL = url
        status = "Ready. Tap Decrypt — you'll be asked for Touch ID."
    }

    private func decrypt() {
        guard let inputURL, let outputURL else { return }
        isBusy = true
        status = "Decrypting…"
        let didStartInputAccess = inputURL.startAccessingSecurityScopedResource()
        defer {
            if didStartInputAccess { inputURL.stopAccessingSecurityScopedResource() }
            isBusy = false
        }
        do {
            try UnsealerService.decryptSnapshot(inputURL: inputURL, outputURL: outputURL)
            status = "Decrypted successfully to \(outputURL.lastPathComponent)."
        } catch {
            status = "Decrypt failed: \(error)"
        }
    }
}

#Preview {
    DecryptView(onReplaceKey: {})
}
