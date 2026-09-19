//
//  UnsealerService.swift
//  SnapUnsealer
//

import Foundation
import CryptoKit

enum UnsealerServiceError: Error {
    case fileReadFailed(Error)
    case fileWriteFailed(Error)
    case notEnrolled
}

/// What actually gets envelope-wrapped and stored: the raw `.asc` bytes
/// plus the GPG passphrase that unlocks them, if any. Bundling both under
/// one SE-gated envelope means Job 2 (an actual DR drill) needs nothing but
/// Touch ID — the passphrase, if the key has one, is only ever typed once,
/// at enrollment.
struct EnrolledSecret: Codable {
    let ascData: Data
    let passphrase: String?
}

/// Orchestrates enrollment (Job 1) and decrypt (Job 2, added in a later
/// milestone). Owns the boundary between file I/O, the SE key store, and
/// the envelope wrapper — call sites never touch `SecureEnclaveKeyStore`,
/// `KeyWrapper`, or `EnrolledKeyStorage` directly.
enum UnsealerService {
    private static let decryptor: SnapDecrypting = ObjectivePGPDecryptor()

    static func isEnrolled() -> Bool {
        EnrolledKeyStorage.exists()
    }

    /// Generates a fresh SE key (overwriting any previously enrolled one),
    /// validates `passphrase` actually unlocks the key (fail fast on a
    /// wrong/missing passphrase rather than only discovering it mid-drill),
    /// and wraps both the `.asc` bytes and the passphrase together. The
    /// caller is responsible for the file's own security-scoped access.
    static func enrollKey(ascFileURL: URL, passphrase: String?) throws {
        let ascData: Data
        do {
            ascData = try Data(contentsOf: ascFileURL)
        } catch {
            throw UnsealerServiceError.fileReadFailed(error)
        }

        try decryptor.validatePassphrase(passphrase, forKeyData: ascData)

        let secret = EnrolledSecret(ascData: ascData, passphrase: passphrase)
        let secretData = try JSONEncoder().encode(secret)

        let seKey = try SecureEnclaveKeyStore.enroll()
        let blob = try KeyWrapper.wrap(secretData, using: seKey.publicKey)
        try EnrolledKeyStorage.save(blob)
    }

    /// Clears both the wrapped envelope and the SE key backing it, so a
    /// fresh `enrollKey` call starts clean.
    static func replaceEnrolledKey() {
        EnrolledKeyStorage.delete()
        SecureEnclaveKeyStore.deleteEnrolledKey()
    }

    /// Decrypts a `.snap.gpg` file to `outputURL`. Touch ID fires when the
    /// SE key is reloaded to unwrap the enrolled envelope. The unwrapped
    /// `.asc`+passphrase bytes live only in an `mlock`'d `SecureBuffer` for
    /// the duration of this call, zeroed immediately after
    /// `ObjectivePGPDecryptor` has consumed them — never written to disk.
    static func decryptSnapshot(inputURL: URL, outputURL: URL) throws {
        guard let blob = try EnrolledKeyStorage.load() else {
            throw UnsealerServiceError.notEnrolled
        }

        let seKey = try SecureEnclaveKeyStore.loadKeyAgreementKey()
        let unwrapped = try KeyWrapper.unwrap(blob, using: seKey)
        let secretBuffer = SecureBuffer(copying: unwrapped)
        defer { secretBuffer.zero() }

        let secret = try JSONDecoder().decode(EnrolledSecret.self, from: secretBuffer.dataNoCopy)

        let snapshotData: Data
        do {
            snapshotData = try Data(contentsOf: inputURL)
        } catch {
            throw UnsealerServiceError.fileReadFailed(error)
        }

        let decrypted = try decryptor.decrypt(
            snapshotData: snapshotData,
            privateKeyASC: secret.ascData,
            passphrase: secret.passphrase
        )

        do {
            try decrypted.write(to: outputURL, options: .atomic)
        } catch {
            throw UnsealerServiceError.fileWriteFailed(error)
        }
    }
}
