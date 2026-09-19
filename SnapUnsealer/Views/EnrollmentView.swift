//
//  EnrollmentView.swift
//  SnapUnsealer
//

import SwiftUI
import UniformTypeIdentifiers

/// Job 1 UI: pick the raw vault-backup `.asc`, optionally its GPG
/// passphrase, wrap both under a fresh Secure Enclave key, store only the
/// wrapped envelope. The original file is never retained or copied
/// anywhere by this app, and the passphrase (if any) is only ever needed
/// here — Job 2 never asks for it again.
struct EnrollmentView: View {
    var onEnrolled: () -> Void

    @State private var isImporting = false
    @State private var selectedURL: URL?
    @State private var passphrase = ""
    @State private var status =
        "No key enrolled yet. Pick your vault-backup private key (.asc) to enroll it behind Touch ID."
    @State private var isBusy = false

    private let ascType = UTType(filenameExtension: "asc") ?? .data

    var body: some View {
        VStack(spacing: 16) {
            Text("Enroll DR Key")
                .font(.title2)
                .bold()

            Text(status)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)

            Button {
                isImporting = true
            } label: {
                Label(selectedURL == nil ? "Choose .asc file…" : "Change .asc file…", systemImage: "key")
            }
            .disabled(isBusy)

            if let selectedURL {
                Text(selectedURL.lastPathComponent)
                    .font(.caption)
                    .foregroundStyle(.secondary)

                SecureField("Passphrase (leave blank if none)", text: $passphrase)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 280)
                    .disabled(isBusy)

                Button("Enroll") {
                    enroll(from: selectedURL)
                }
                .disabled(isBusy)
                .keyboardShortcut(.defaultAction)
            }

            Text("The original .asc file isn't needed by this app afterward — securely deleting it is your own responsibility.")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
        }
        .padding(40)
        .frame(minWidth: 420, minHeight: 300)
        .fileImporter(isPresented: $isImporting, allowedContentTypes: [ascType, .data]) { result in
            handle(result)
        }
    }

    private func handle(_ result: Result<URL, Error>) {
        switch result {
        case .failure(let error):
            status = "File selection failed: \(error.localizedDescription)"
        case .success(let url):
            selectedURL = url
            status = "Selected \(url.lastPathComponent). Enter its passphrase if it has one, then Enroll."
        }
    }

    private func enroll(from url: URL) {
        isBusy = true
        status = "Enrolling…"
        let didStartAccess = url.startAccessingSecurityScopedResource()
        let enteredPassphrase = passphrase
        defer {
            if didStartAccess { url.stopAccessingSecurityScopedResource() }
            passphrase = ""
            isBusy = false
        }
        do {
            try UnsealerService.enrollKey(
                ascFileURL: url,
                passphrase: enteredPassphrase.isEmpty ? nil : enteredPassphrase
            )
            status = "Enrolled successfully."
            onEnrolled()
        } catch {
            status = "Enrollment failed: \(error)"
        }
    }
}

#Preview {
    EnrollmentView(onEnrolled: {})
}
