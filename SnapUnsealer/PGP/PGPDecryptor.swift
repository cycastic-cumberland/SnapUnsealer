//
//  PGPDecryptor.swift
//  SnapUnsealer
//

import Foundation
import ObjectivePGP

enum PGPDecryptorError: Error {
    case noKeysFound
    case decryptFailed(Error)
    case passphraseRequired
}

/// Narrow seam around the OpenPGP decrypt operation. Kept as a protocol
/// with one concrete implementation so a future hardening pass (e.g. moving
/// this call behind an XPC helper) only has to swap what's behind this
/// boundary, not touch call sites in `UnsealerService`.
protocol SnapDecrypting {
    /// Decrypts `snapshotData` (a `.snap.gpg` payload) using the raw OpenPGP
    /// private key bytes in `privateKeyASC` (armored or binary — ObjectivePGP
    /// accepts either). Both are `Data` in, `Data` out — never a file path —
    /// so the raw key material never has to exist as a file to be used here.
    /// `passphrase` unlocks the key if it's GPG-passphrase-protected; pass
    /// `nil` for an unprotected key.
    func decrypt(snapshotData: Data, privateKeyASC: Data, passphrase: String?) throws -> Data

    /// Confirms `passphrase` actually unlocks any passphrase-protected key
    /// found in `ascData`, without decrypting anything. Used at enrollment
    /// time to fail fast on a wrong/missing passphrase rather than only
    /// discovering it mid-drill during an actual decrypt.
    func validatePassphrase(_ passphrase: String?, forKeyData ascData: Data) throws
}

struct ObjectivePGPDecryptor: SnapDecrypting {
    func decrypt(snapshotData: Data, privateKeyASC: Data, passphrase: String?) throws -> Data {
        let keys = try readKeys(from: privateKeyASC)
        do {
            return try ObjectivePGP.decrypt(
                snapshotData,
                andVerifySignature: false,
                using: keys,
                passphraseForKey: passphrase.map { pass in { _ in pass } }
            )
        } catch {
            throw PGPDecryptorError.decryptFailed(error)
        }
    }

    func validatePassphrase(_ passphrase: String?, forKeyData ascData: Data) throws {
        let keys = try readKeys(from: ascData)
        for key in keys where key.isEncryptedWithPassword {
            guard let passphrase else {
                throw PGPDecryptorError.passphraseRequired
            }
            do {
                _ = try key.decrypted(withPassphrase: passphrase)
            } catch {
                throw PGPDecryptorError.decryptFailed(error)
            }
        }
    }

    private func readKeys(from data: Data) throws -> [Key] {
        let keys: [Key]
        do {
            keys = try ObjectivePGP.readKeys(from: data)
        } catch {
            throw PGPDecryptorError.decryptFailed(error)
        }
        guard !keys.isEmpty else {
            throw PGPDecryptorError.noKeysFound
        }
        return keys
    }
}
