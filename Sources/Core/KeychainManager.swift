//
//  KeychainManager.swift
//  iOS Security Framework Pro
//
//  Created by Muhittin Camdali
//  Copyright © 2024 Muhittin Camdali. All rights reserved.
//

import Foundation
import Security

/// Advanced keychain manager for iOS Security Framework Pro
public final class KeychainManager {
    
    // MARK: - Singleton
    public static let shared = KeychainManager()
    private init() {}
    
    // MARK: - Properties
    private let keychainQueue = DispatchQueue(label: "com.securityframework.keychain", qos: .userInitiated)
    private var keychainConfig: KeychainConfiguration?
    
    // MARK: - Keychain Configuration
    public struct KeychainConfiguration {
        public let accessibility: KeychainAccessibility
        public let synchronizable: Bool
        public let accessControl: SecAccessControl?
        public let encryptionLevel: EncryptionLevel
        
        public init(
            accessibility: KeychainAccessibility = .whenUnlockedThisDeviceOnly,
            synchronizable: Bool = false,
            accessControl: SecAccessControl? = nil,
            encryptionLevel: EncryptionLevel = .aes256
        ) {
            self.accessibility = accessibility
            self.synchronizable = synchronizable
            self.accessControl = accessControl
            self.encryptionLevel = encryptionLevel
        }
    }
    
    // MARK: - Keychain Accessibility
    public enum KeychainAccessibility {
        case whenUnlocked
        case whenUnlockedThisDeviceOnly
        case afterFirstUnlock
        case afterFirstUnlockThisDeviceOnly
        case always
        case alwaysThisDeviceOnly
        case whenPasscodeSetThisDeviceOnly
        
        public var cfString: CFString {
            switch self {
            case .whenUnlocked: return kSecAttrAccessibleWhenUnlocked
            case .whenUnlockedThisDeviceOnly: return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            case .afterFirstUnlock: return kSecAttrAccessibleAfterFirstUnlock
            case .afterFirstUnlockThisDeviceOnly: return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            case .always: return kSecAttrAccessibleAlways
            case .alwaysThisDeviceOnly: return kSecAttrAccessibleAlwaysThisDeviceOnly
            case .whenPasscodeSetThisDeviceOnly: return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
            }
        }
    }
    
    // MARK: - Encryption Level
    public enum EncryptionLevel {
        case aes128
        case aes256
        case chacha20
        case rsa2048
        case rsa4096
        
        public var keySize: Int {
            switch self {
            case .aes128: return 128
            case .aes256: return 256
            case .chacha20: return 256
            case .rsa2048: return 2048
            case .rsa4096: return 4096
            }
        }
    }
    
    // MARK: - Errors
    public enum KeychainError: Error, LocalizedError {
        case itemNotFound
        case duplicateItem
        case invalidItemFormat
        case userCanceled
        case authFailed
        case paramError
        case unsupportedError
        case unknown(OSStatus)
        
        public var errorDescription: String? {
            switch self {
            case .itemNotFound:
                return "Keychain item not found"
            case .duplicateItem:
                return "Keychain item already exists"
            case .invalidItemFormat:
                return "Invalid keychain item format"
            case .userCanceled:
                return "User canceled keychain operation"
            case .authFailed:
                return "Keychain authentication failed"
            case .paramError:
                return "Invalid keychain parameters"
            case .unsupportedError:
                return "Unsupported keychain operation"
            case .unknown(let status):
                return "Unknown keychain error: \(status)"
            }
        }
        
        public static func from(_ status: OSStatus) -> KeychainError {
            switch status {
            case errSecItemNotFound: return .itemNotFound
            case errSecDuplicateItem: return .duplicateItem
            case errSecParam: return .paramError
            case errSecUserCanceled: return .userCanceled
            case errSecAuthFailed: return .authFailed
            case errSecUnsupportedOperation: return .unsupportedError
            default: return .unknown(status)
            }
        }
    }
    
    // MARK: - Public Methods
    
    /// Initialize keychain manager with configuration
    /// - Parameter config: Keychain configuration
    /// - Throws: KeychainError if initialization fails
    public func initialize(with config: KeychainConfiguration) throws {
        keychainQueue.sync {
            self.keychainConfig = config
        }
    }
    
    /// Store data in keychain
    /// - Parameters:
    ///   - data: Data to store
    ///   - key: Key for the data
    ///   - service: Service identifier
    ///   - account: Account identifier
    ///   - completion: Completion handler with result
    public func store(
        data: Data,
        forKey key: String,
        service: String = "default",
        account: String? = nil,
        completion: @escaping (Result<Void, KeychainError>) -> Void
    ) {
        keychainQueue.async {
            do {
                try self.performStore(data: data, key: key, service: service, account: account)
                completion(.success(()))
            } catch let error as KeychainError {
                completion(.failure(error))
            } catch {
                completion(.failure(.unknown(errSecUnknown)))
            }
        }
    }
    
    /// Retrieve data from keychain
    /// - Parameters:
    ///   - key: Key for the data
    ///   - service: Service identifier
    ///   - account: Account identifier
    ///   - completion: Completion handler with result
    public func retrieve(
        forKey key: String,
        service: String = "default",
        account: String? = nil,
        completion: @escaping (Result<Data, KeychainError>) -> Void
    ) {
        keychainQueue.async {
            do {
                let data = try self.performRetrieve(key: key, service: service, account: account)
                completion(.success(data))
            } catch let error as KeychainError {
                completion(.failure(error))
            } catch {
                completion(.failure(.unknown(errSecUnknown)))
            }
        }
    }
    
    /// Update data in keychain
    /// - Parameters:
    ///   - data: New data
    ///   - key: Key for the data
    ///   - service: Service identifier
    ///   - account: Account identifier
    ///   - completion: Completion handler with result
    public func update(
        data: Data,
        forKey key: String,
        service: String = "default",
        account: String? = nil,
        completion: @escaping (Result<Void, KeychainError>) -> Void
    ) {
        keychainQueue.async {
            do {
                try self.performUpdate(data: data, key: key, service: service, account: account)
                completion(.success(()))
            } catch let error as KeychainError {
                completion(.failure(error))
            } catch {
                completion(.failure(.unknown(errSecUnknown)))
            }
        }
    }
    
    /// Delete data from keychain
    /// - Parameters:
    ///   - key: Key for the data
    ///   - service: Service identifier
    ///   - account: Account identifier
    ///   - completion: Completion handler with result
    public func delete(
        forKey key: String,
        service: String = "default",
        account: String? = nil,
        completion: @escaping (Result<Void, KeychainError>) -> Void
    ) {
        keychainQueue.async {
            do {
                try self.performDelete(key: key, service: service, account: account)
                completion(.success(()))
            } catch let error as KeychainError {
                completion(.failure(error))
            } catch {
                completion(.failure(.unknown(errSecUnknown)))
            }
        }
    }
    
    /// Check if keychain item exists
    /// - Parameters:
    ///   - key: Key to check
    ///   - service: Service identifier
    ///   - account: Account identifier
    ///   - completion: Completion handler with result
    public func exists(
        forKey key: String,
        service: String = "default",
        account: String? = nil,
        completion: @escaping (Result<Bool, KeychainError>) -> Void
    ) {
        keychainQueue.async {
            do {
                let exists = try self.performExists(key: key, service: service, account: account)
                completion(.success(exists))
            } catch let error as KeychainError {
                completion(.failure(error))
            } catch {
                completion(.failure(.unknown(errSecUnknown)))
            }
        }
    }
    
    /// Get all keys for a service
    /// - Parameters:
    ///   - service: Service identifier
    ///   - completion: Completion handler with result
    public func getAllKeys(
        forService service: String = "default",
        completion: @escaping (Result<[String], KeychainError>) -> Void
    ) {
        keychainQueue.async {
            do {
                let keys = try self.performGetAllKeys(service: service)
                completion(.success(keys))
            } catch let error as KeychainError {
                completion(.failure(error))
            } catch {
                completion(.failure(.unknown(errSecUnknown)))
            }
        }
    }
    
    /// Clear all items for a service
    /// - Parameters:
    ///   - service: Service identifier
    ///   - completion: Completion handler with result
    public func clearAll(
        forService service: String = "default",
        completion: @escaping (Result<Void, KeychainError>) -> Void
    ) {
        keychainQueue.async {
            do {
                try self.performClearAll(service: service)
                completion(.success(()))
            } catch let error as KeychainError {
                completion(.failure(error))
            } catch {
                completion(.failure(.unknown(errSecUnknown)))
            }
        }
    }
    
    /// Generate secure random key
    /// - Parameter length: Key length in bytes
    /// - Returns: Generated key data
    public func generateSecureKey(length: Int = 32) -> Data? {
        var key = Data(count: length)
        let result = key.withUnsafeMutableBytes { pointer in
            SecRandomCopyBytes(kSecRandomDefault, length, pointer.baseAddress!)
        }
        
        return result == errSecSuccess ? key : nil
    }
    
    // MARK: - Private Methods
    
    private func performStore(
        data: Data,
        key: String,
        service: String,
        account: String?
    ) throws {
        guard let config = keychainConfig else {
            throw KeychainError.paramError
        }
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: config.accessibility.cfString
        ]
        
        if let account = account {
            query[kSecAttrAccount as String] = account
        }
        
        if config.synchronizable {
            query[kSecAttrSynchronizable as String] = kCFBooleanTrue
        }
        
        if let accessControl = config.accessControl {
            query[kSecAttrAccessControl as String] = accessControl
        }
        
        let status = SecItemAdd(query as CFDictionary, nil)
        
        if status == errSecDuplicateItem {
            // Item already exists, update it
            try performUpdate(data: data, key: key, service: service, account: account)
        } else if status != errSecSuccess {
            throw KeychainError.from(status)
        }
    }
    
    private func performRetrieve(
        key: String,
        service: String,
        account: String?
    ) throws -> Data {
        guard let config = keychainConfig else {
            throw KeychainError.paramError
        }
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: kCFBooleanTrue,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        if let account = account {
            query[kSecAttrAccount as String] = account
        }
        
        if config.synchronizable {
            query[kSecAttrSynchronizable as String] = kCFBooleanTrue
        }
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            throw KeychainError.from(status)
        }
        
        guard let data = result as? Data else {
            throw KeychainError.invalidItemFormat
        }
        
        return data
    }
    
    private func performUpdate(
        data: Data,
        key: String,
        service: String,
        account: String?
    ) throws {
        guard let config = keychainConfig else {
            throw KeychainError.paramError
        }
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        
        if let account = account {
            query[kSecAttrAccount as String] = account
        }
        
        if config.synchronizable {
            query[kSecAttrSynchronizable as String] = kCFBooleanTrue
        }
        
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: config.accessibility.cfString
        ]
        
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        
        guard status == errSecSuccess else {
            throw KeychainError.from(status)
        }
    }
    
    private func performDelete(
        key: String,
        service: String,
        account: String?
    ) throws {
        guard let config = keychainConfig else {
            throw KeychainError.paramError
        }
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        
        if let account = account {
            query[kSecAttrAccount as String] = account
        }
        
        if config.synchronizable {
            query[kSecAttrSynchronizable as String] = kCFBooleanTrue
        }
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.from(status)
        }
    }
    
    private func performExists(
        key: String,
        service: String,
        account: String?
    ) throws -> Bool {
        guard let config = keychainConfig else {
            throw KeychainError.paramError
        }
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: kCFBooleanFalse,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        if let account = account {
            query[kSecAttrAccount as String] = account
        }
        
        if config.synchronizable {
            query[kSecAttrSynchronizable as String] = kCFBooleanTrue
        }
        
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        
        return status == errSecSuccess
    }
    
    private func performGetAllKeys(service: String) throws -> [String] {
        guard let config = keychainConfig else {
            throw KeychainError.paramError
        }
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: kCFBooleanTrue,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        if config.synchronizable {
            query[kSecAttrSynchronizable as String] = kCFBooleanTrue
        }
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            throw KeychainError.from(status)
        }
        
        guard let items = result as? [[String: Any]] else {
            return []
        }
        
        return items.compactMap { item in
            item[kSecAttrAccount as String] as? String
        }
    }
    
    private func performClearAll(service: String) throws {
        guard let config = keychainConfig else {
            throw KeychainError.paramError
        }
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        
        if config.synchronizable {
            query[kSecAttrSynchronizable as String] = kCFBooleanTrue
        }
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.from(status)
        }
    }
}

// MARK: - Keychain Manager Extensions
extension KeychainManager {
    
    /// Store string in keychain
    /// - Parameters:
    ///   - string: String to store
    ///   - key: Key for the string
    ///   - service: Service identifier
    ///   - account: Account identifier
    ///   - completion: Completion handler with result
    public func store(
        string: String,
        forKey key: String,
        service: String = "default",
        account: String? = nil,
        completion: @escaping (Result<Void, KeychainError>) -> Void
    ) {
        guard let data = string.data(using: .utf8) else {
            completion(.failure(.invalidItemFormat))
            return
        }
        
        store(data: data, forKey: key, service: service, account: account, completion: completion)
    }
    
    /// Retrieve string from keychain
    /// - Parameters:
    ///   - key: Key for the string
    ///   - service: Service identifier
    ///   - account: Account identifier
    ///   - completion: Completion handler with result
    public func retrieveString(
        forKey key: String,
        service: String = "default",
        account: String? = nil,
        completion: @escaping (Result<String, KeychainError>) -> Void
    ) {
        retrieve(forKey: key, service: service, account: account) { result in
            switch result {
            case .success(let data):
                guard let string = String(data: data, encoding: .utf8) else {
                    completion(.failure(.invalidItemFormat))
                    return
                }
                completion(.success(string))
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
} 