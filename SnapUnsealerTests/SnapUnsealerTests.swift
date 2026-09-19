//
//  SnapUnsealerTests.swift
//  SnapUnsealerTests
//
//  Created by Nam Nguyen on 19/9/26.
//

import Testing
import CryptoKit
import Foundation
@testable import SnapUnsealer

struct SnapUnsealerTests {

    /// Wrap/unwrap round-trips byte-for-byte across a range of payload
    /// sizes. Uses a plain software P256 key rather than a real Secure
    /// Enclave key so this test never blocks on Touch ID — `KeyWrapper`
    /// treats both the same way via `KeyAgreementPrivateKey`.
    @Test(arguments: [0, 1, 32, 4096, 1 << 20])
    func keyWrapperRoundTrip(size: Int) throws {
        let privateKey = P256.KeyAgreement.PrivateKey()
        let plaintext = Data((0..<size).map { UInt8(truncatingIfNeeded: $0) })

        let blob = try KeyWrapper.wrap(plaintext, using: privateKey.publicKey)
        let recovered = try KeyWrapper.unwrap(blob, using: privateKey)

        #expect(recovered == plaintext)
    }

    /// Unwrapping with the wrong private key must fail, not silently
    /// return garbage plaintext — AES-GCM's tag check should catch this.
    @Test func keyWrapperRejectsWrongKey() throws {
        let correctKey = P256.KeyAgreement.PrivateKey()
        let wrongKey = P256.KeyAgreement.PrivateKey()
        let blob = try KeyWrapper.wrap(Data("secret".utf8), using: correctKey.publicKey)

        #expect(throws: (any Error).self) {
            _ = try KeyWrapper.unwrap(blob, using: wrongKey)
        }
    }

    /// `SecureBuffer` round-trips its contents, and `zero()` actually
    /// clears the underlying memory rather than being optimized away.
    @Test func secureBufferCopiesAndZeroes() {
        let original = Data("vault-restore-key-material".utf8)
        let buffer = SecureBuffer(copying: original)

        #expect(buffer.dataNoCopy == original)

        buffer.zero()

        let isAllZero = buffer.withUnsafeBytes { raw in
            raw.allSatisfy { $0 == 0 }
        }
        #expect(isAllZero)
    }

    /// `PGPDecryptor` against real fixtures (a generated test key + a real
    /// PGP-encrypted payload, both checked in under Fixtures/) — no
    /// Keychain/SE involved, this only exercises the ObjectivePGP-facing
    /// seam in isolation.
    @Test func pgpDecryptorDecryptsFixture() throws {
        let bundle = Bundle(for: BundleToken.self)
        let ascURL = try #require(bundle.url(forResource: "test-key", withExtension: "asc"))
        let snapURL = try #require(bundle.url(forResource: "test.snap", withExtension: "gpg"))
        let plaintextURL = try #require(bundle.url(forResource: "plaintext", withExtension: "txt"))

        let ascData = try Data(contentsOf: ascURL)
        let snapData = try Data(contentsOf: snapURL)
        let expectedPlaintext = try Data(contentsOf: plaintextURL)

        let decryptor = ObjectivePGPDecryptor()
        let decrypted = try decryptor.decrypt(snapshotData: snapData, privateKeyASC: ascData, passphrase: nil)

        #expect(decrypted == expectedPlaintext)
    }

    /// Decrypting with the wrong key must fail, not silently return garbage.
    @Test func pgpDecryptorRejectsGarbageKey() throws {
        let bundle = Bundle(for: BundleToken.self)
        let snapURL = try #require(bundle.url(forResource: "test.snap", withExtension: "gpg"))
        let snapData = try Data(contentsOf: snapURL)

        let decryptor = ObjectivePGPDecryptor()
        #expect(throws: (any Error).self) {
            _ = try decryptor.decrypt(snapshotData: snapData, privateKeyASC: Data("not a key".utf8), passphrase: nil)
        }
    }

    /// A passphrase-protected fixture: correct passphrase decrypts, wrong
    /// or missing passphrase fails cleanly instead of silently succeeding.
    @Test func pgpDecryptorHandlesPassphraseProtectedKey() throws {
        let bundle = Bundle(for: BundleToken.self)
        let ascURL = try #require(bundle.url(forResource: "test-key-passphrase", withExtension: "asc"))
        let snapURL = try #require(bundle.url(forResource: "test-passphrase.snap", withExtension: "gpg"))
        let plaintextURL = try #require(bundle.url(forResource: "plaintext-passphrase", withExtension: "txt"))

        let ascData = try Data(contentsOf: ascURL)
        let snapData = try Data(contentsOf: snapURL)
        let expectedPlaintext = try Data(contentsOf: plaintextURL)

        let decryptor = ObjectivePGPDecryptor()

        let decrypted = try decryptor.decrypt(
            snapshotData: snapData,
            privateKeyASC: ascData,
            passphrase: "milestone4-5-passphrase"
        )
        #expect(decrypted == expectedPlaintext)

        #expect(throws: (any Error).self) {
            _ = try decryptor.decrypt(snapshotData: snapData, privateKeyASC: ascData, passphrase: "wrong")
        }
        #expect(throws: (any Error).self) {
            _ = try decryptor.decrypt(snapshotData: snapData, privateKeyASC: ascData, passphrase: nil)
        }
    }

    /// `validatePassphrase` is the enrollment-time fail-fast check —
    /// correct passphrase passes silently, wrong/missing throws.
    @Test func validatePassphraseCatchesWrongOrMissing() throws {
        let bundle = Bundle(for: BundleToken.self)
        let ascURL = try #require(bundle.url(forResource: "test-key-passphrase", withExtension: "asc"))
        let ascData = try Data(contentsOf: ascURL)

        let decryptor = ObjectivePGPDecryptor()

        try decryptor.validatePassphrase("milestone4-5-passphrase", forKeyData: ascData)

        #expect(throws: (any Error).self) {
            try decryptor.validatePassphrase("wrong", forKeyData: ascData)
        }
        #expect(throws: (any Error).self) {
            try decryptor.validatePassphrase(nil, forKeyData: ascData)
        }
    }

}

/// Anchor class purely so `Bundle(for:)` can locate the test bundle
/// (and its bundled Fixtures/) from Swift Testing's struct-based tests.
private final class BundleToken {}
