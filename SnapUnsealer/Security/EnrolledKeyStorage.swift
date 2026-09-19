//
//  EnrolledKeyStorage.swift
//  SnapUnsealer
//

import Foundation
import Security

enum EnrolledKeyStorageError: Error {
    case encodingFailed(Error)
    case decodingFailed(Error)
    case keychainWrite(OSStatus)
    case keychainRead(OSStatus)
}

/// Keychain CRUD for the wrapped `.asc` envelope (`WrappedBlob`). This item
/// holds only ciphertext — AES-GCM sealed under a key derived from an SE
/// key-agreement operation — so its own Keychain protection is incidental;
/// the real boundary is the Secure Enclave key required to derive the
/// unwrap key, which `SecureEnclaveKeyStore` gates separately.
enum EnrolledKeyStorage {
    private static let service = "net.cycastic.SnapUnsealer.wrappedKey"
    private static let account = "vault-restore-key"

    /// Existence check only. Must not trigger a biometric prompt.
    static func exists() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: false,
            kSecReturnAttributes as String: false,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }

    static func save(_ blob: WrappedBlob) throws {
        let data: Data
        do {
            data = try JSONEncoder().encode(blob)
        } catch {
            throw EnrolledKeyStorageError.encodingFailed(error)
        }

        delete()
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw EnrolledKeyStorageError.keychainWrite(status)
        }
    }

    static func load() throws -> WrappedBlob? {
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
        guard status == errSecSuccess, let data = result as? Data else {
            throw EnrolledKeyStorageError.keychainRead(status)
        }
        do {
            return try JSONDecoder().decode(WrappedBlob.self, from: data)
        } catch {
            throw EnrolledKeyStorageError.decodingFailed(error)
        }
    }

    static func delete() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
    }
}
