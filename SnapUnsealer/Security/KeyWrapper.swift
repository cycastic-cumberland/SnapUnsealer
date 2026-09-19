//
//  KeyWrapper.swift
//  SnapUnsealer
//

import Foundation
import CryptoKit

/// Envelope-encrypted payload: a fresh ephemeral P-256 public key (the
/// sender side of one-shot ECDH) plus an AES-GCM sealed box.
struct WrappedBlob: Codable {
    let ephemeralPublicKey: Data
    let nonce: Data
    let ciphertext: Data
    let tag: Data
}

enum KeyWrapperError: Error {
    case sealFailed(Error)
    case openFailed(Error)
}

/// Common shape of `P256.KeyAgreement.PrivateKey` and
/// `SecureEnclave.P256.KeyAgreement.PrivateKey` (CryptoKit doesn't already
/// unify them). Lets `unwrap` be exercised in tests against a plain
/// software key, with production code passing the real Touch ID-gated SE
/// key through the exact same code path.
protocol KeyAgreementPrivateKey {
    func sharedSecretFromKeyAgreement(with publicKey: P256.KeyAgreement.PublicKey) throws -> SharedSecret
}

extension P256.KeyAgreement.PrivateKey: KeyAgreementPrivateKey {}
extension SecureEnclave.P256.KeyAgreement.PrivateKey: KeyAgreementPrivateKey {}

/// Envelope encryption over a non-exportable Secure-Enclave key-agreement
/// key. A non-exportable SE key can't do arbitrary reusable ECDH+wrap in a
/// single call, so every wrap generates a fresh ephemeral sender key,
/// performs ECDH against the SE key's public key, and derives a symmetric
/// key via HKDF to seal the payload with AES-GCM. Unwrap reverses this
/// using the SE private key's own ECDH against the stored ephemeral public
/// key — the operation that requires Touch ID, since it uses the
/// `.biometryCurrentSet`-gated private key.
enum KeyWrapper {
    private static let hkdfInfo = Data("SnapUnsealer.envelope.v1".utf8)

    static func wrap(_ plaintext: Data, using sePublicKey: P256.KeyAgreement.PublicKey) throws -> WrappedBlob {
        do {
            let ephemeral = P256.KeyAgreement.PrivateKey()
            let shared = try ephemeral.sharedSecretFromKeyAgreement(with: sePublicKey)
            let symmetricKey = shared.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data(),
                sharedInfo: hkdfInfo,
                outputByteCount: 32
            )
            let sealed = try AES.GCM.seal(plaintext, using: symmetricKey)
            let nonceData = sealed.nonce.withUnsafeBytes { Data($0) }
            return WrappedBlob(
                ephemeralPublicKey: ephemeral.publicKey.rawRepresentation,
                nonce: nonceData,
                ciphertext: sealed.ciphertext,
                tag: sealed.tag
            )
        } catch {
            throw KeyWrapperError.sealFailed(error)
        }
    }

    static func unwrap(
        _ blob: WrappedBlob,
        using privateKey: some KeyAgreementPrivateKey
    ) throws -> Data {
        do {
            let ephemeralPublicKey = try P256.KeyAgreement.PublicKey(rawRepresentation: blob.ephemeralPublicKey)
            let shared = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
            let symmetricKey = shared.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data(),
                sharedInfo: hkdfInfo,
                outputByteCount: 32
            )
            let nonce = try AES.GCM.Nonce(data: blob.nonce)
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: blob.ciphertext, tag: blob.tag)
            return try AES.GCM.open(sealedBox, using: symmetricKey)
        } catch {
            throw KeyWrapperError.openFailed(error)
        }
    }
}
