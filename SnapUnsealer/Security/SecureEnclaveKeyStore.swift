//
//  SecureEnclaveKeyStore.swift
//  SnapUnsealer
//

import Foundation
import CryptoKit
import Security
import LocalAuthentication

enum SecureEnclaveKeyStoreError: Error {
    case secureEnclaveUnavailable
    case accessControlCreationFailed(CFError?)
    case keychainWrite(OSStatus)
    case keychainRead(OSStatus)
    case keyNotFound
    case keyReconstructionFailed(Error)
}

/// Owns the Secure-Enclave-backed key-agreement identity used to gate the
/// wrapped vault-backup key. Keychain only ever stores the SE key's opaque
/// `dataRepresentation` token, never key material usable outside this
/// device's Secure Enclave.
enum SecureEnclaveKeyStore {
    private static let service = "net.cycastic.SnapUnsealer.seKey"
    private static let account = "vault-restore-se-key"

    /// Existence check only. Must not trigger a biometric prompt.
    static func hasEnrolledKey() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: false,
            kSecReturnAttributes as String: false,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    /// Generates a new Secure Enclave key-agreement key gated by the
    /// currently enrolled biometry set, and persists its opaque token
    /// representation in Keychain (overwriting any previously enrolled key).
    @discardableResult
    static func enroll() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        guard SecureEnclave.isAvailable else {
            throw SecureEnclaveKeyStoreError.secureEnclaveUnavailable
        }

        var accessControlError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &accessControlError
        ) else {
            throw SecureEnclaveKeyStoreError.accessControlCreationFailed(
                accessControlError?.takeRetainedValue()
            )
        }

        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        try persist(key.dataRepresentation)
        return key
    }

    /// Reloads the enrolled Secure Enclave key. Reconstruction and/or its
    /// first subsequent use is expected to prompt Touch ID, since the key
    /// was created with a `.biometryCurrentSet` access-control policy.
    static func loadKeyAgreementKey(
        context: LAContext = LAContext()
    ) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        guard let token = try readStoredToken() else {
            throw SecureEnclaveKeyStoreError.keyNotFound
        }
        do {
            return try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: token,
                authenticationContext: context
            )
        } catch {
            throw SecureEnclaveKeyStoreError.keyReconstructionFailed(error)
        }
    }

    static func deleteEnrolledKey() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
    }

    private static func persist(_ token: Data) throws {
        deleteEnrolledKey()
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: token,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SecureEnclaveKeyStoreError.keychainWrite(status)
        }
    }

    private static func readStoredToken() throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw SecureEnclaveKeyStoreError.keychainRead(status)
        }
        return result as? Data
    }
}
