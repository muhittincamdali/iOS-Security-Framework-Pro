import Foundation
import Security

/**
 * KeychainManager - Secure Keychain Management Component
 * 
 * Handles secure storage and retrieval of sensitive data using iOS Keychain
 * with comprehensive error handling and security features.
 * 
 * - Features:
 *   - Secure data storage and retrieval
 *   - Multiple accessibility levels
 *   - Data encryption and protection
 *   - Error handling and logging
 *   - Keychain query optimization
 * 
 * - Example:
 * ```swift
 * let keychainManager = KeychainManager()
 * try keychainManager.store(data: sensitiveData, forKey: "user_token")
 * let retrievedData = try keychainManager.retrieve(forKey: "user_token")
 * ```
 */
public class KeychainManager {
    private let auditLogger = SecurityAuditLogger()
    
    public init() {}
    
    // MARK: - Data Storage
    
    /**
     * Store data securely in keychain
     * 
     * - Parameters:
     *   - data: Data to store
     *   - key: Unique key for data
     *   - accessibility: Keychain accessibility level
     * 
     * - Throws: SecurityError if storage fails
     */
    public func store(
        data: Data,
        forKey key: String,
        accessibility: CFString = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessibility,
            kSecAttrSynchronizable as String: false
        ]
        
        // Check if item already exists
        let status = SecItemAdd(query as CFDictionary, nil)
        
        if status == errSecDuplicateItem {
            // Item exists, update it
            let updateQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: key
            ]
            
            let updateAttributes: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrAccessible as String: accessibility
            ]
            
            let updateStatus = SecItemUpdate(updateQuery as CFDictionary, updateAttributes as CFDictionary)
            
            guard updateStatus == errSecSuccess else {
                auditLogger.logEvent(.dataStorageError, error: KeychainError.updateFailed(updateStatus))
                throw SecurityError.keychainError(KeychainError.updateFailed(updateStatus))
            }
        } else if status != errSecSuccess {
            auditLogger.logEvent(.dataStorageError, error: KeychainError.addFailed(status))
            throw SecurityError.keychainError(KeychainError.addFailed(status))
        }
        
        auditLogger.logEvent(.dataStored, metadata: ["key": key])
    }
    
    /**
     * Retrieve data from keychain
     * 
     * - Parameters:
     *   - key: Unique key for data
     * 
     * - Returns: Stored data
     * 
     * - Throws: SecurityError if retrieval fails
     */
    public func retrieve(forKey key: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            auditLogger.logEvent(.dataRetrievalError, error: KeychainError.retrieveFailed(status))
            throw SecurityError.keychainError(KeychainError.retrieveFailed(status))
        }
        
        guard let data = result as? Data else {
            auditLogger.logEvent(.dataRetrievalError, error: KeychainError.invalidData)
            throw SecurityError.keychainError(KeychainError.invalidData)
        }
        
        auditLogger.logEvent(.dataRetrieved, metadata: ["key": key])
        return data
    }
    
    /**
     * Delete data from keychain
     * 
     * - Parameters:
     *   - key: Unique key for data
     * 
     * - Throws: SecurityError if deletion fails
     */
    public func delete(forKey key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess || status == errSecItemNotFound else {
            auditLogger.logEvent(.dataDeletionError, error: KeychainError.deleteFailed(status))
            throw SecurityError.keychainError(KeychainError.deleteFailed(status))
        }
        
        auditLogger.logEvent(.dataDeleted, metadata: ["key": key])
    }
    
    // MARK: - Advanced Features
    
    /**
     * Store data with custom attributes
     * 
     * - Parameters:
     *   - data: Data to store
     *   - key: Unique key for data
     *   - attributes: Custom attributes for the keychain item
     *   - accessibility: Keychain accessibility level
     * 
     * - Throws: SecurityError if storage fails
     */
    public func store(
        data: Data,
        forKey key: String,
        attributes: [String: Any],
        accessibility: CFString = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessibility,
            kSecAttrSynchronizable as String: false
        ]
        
        // Add custom attributes
        for (attributeKey, attributeValue) in attributes {
            query[attributeKey] = attributeValue
        }
        
        let status = SecItemAdd(query as CFDictionary, nil)
        
        if status == errSecDuplicateItem {
            // Item exists, update it
            let updateQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: key
            ]
            
            var updateAttributes: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrAccessible as String: accessibility
            ]
            
            // Add custom attributes to update
            for (attributeKey, attributeValue) in attributes {
                updateAttributes[attributeKey] = attributeValue
            }
            
            let updateStatus = SecItemUpdate(updateQuery as CFDictionary, updateAttributes as CFDictionary)
            
            guard updateStatus == errSecSuccess else {
                auditLogger.logEvent(.dataStorageError, error: KeychainError.updateFailed(updateStatus))
                throw SecurityError.keychainError(KeychainError.updateFailed(updateStatus))
            }
        } else if status != errSecSuccess {
            auditLogger.logEvent(.dataStorageError, error: KeychainError.addFailed(status))
            throw SecurityError.keychainError(KeychainError.addFailed(status))
        }
        
        auditLogger.logEvent(.dataStored, metadata: ["key": key])
    }
    
    /**
     * Check if data exists in keychain
     * 
     * - Parameters:
     *   - key: Unique key for data
     * 
     * - Returns: Whether data exists
     */
    public func exists(forKey key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: false,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    /**
     * Get all stored keys
     * 
     * - Returns: Array of stored keys
     */
    public func getAllKeys() -> [String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let items = result as? [[String: Any]] else {
            return []
        }
        
        return items.compactMap { item in
            item[kSecAttrAccount as String] as? String
        }
    }
    
    /**
     * Clear all stored data
     * 
     * - Throws: SecurityError if clearing fails
     */
    public func clearAll() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess || status == errSecItemNotFound else {
            auditLogger.logEvent(.dataDeletionError, error: KeychainError.deleteFailed(status))
            throw SecurityError.keychainError(KeychainError.deleteFailed(status))
        }
        
        auditLogger.logEvent(.dataDeleted, metadata: ["action": "clear_all"])
    }
    
    // MARK: - Security Features
    
    /**
     * Set keychain accessibility level
     * 
     * - Parameters:
     *   - accessibility: Accessibility level
     *   - key: Key to update
     * 
     * - Throws: SecurityError if update fails
     */
    public func setAccessibility(
        _ accessibility: CFString,
        forKey key: String
    ) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        
        let attributes: [String: Any] = [
            kSecAttrAccessible as String: accessibility
        ]
        
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        
        guard status == errSecSuccess else {
            auditLogger.logEvent(.dataStorageError, error: KeychainError.updateFailed(status))
            throw SecurityError.keychainError(KeychainError.updateFailed(status))
        }
        
        auditLogger.logEvent(.dataUpdated, metadata: ["key": key, "accessibility": accessibility as String])
    }
    
    /**
     * Get keychain accessibility level
     * 
     * - Parameters:
     *   - key: Key to check
     * 
     * - Returns: Current accessibility level
     */
    public func getAccessibility(forKey key: String) -> CFString? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let attributes = result as? [String: Any] else {
            return nil
        }
        
        return attributes[kSecAttrAccessible as String] as? CFString
    }
}

// MARK: - Supporting Types

public enum KeychainError: Error, LocalizedError {
    case addFailed(OSStatus)
    case updateFailed(OSStatus)
    case retrieveFailed(OSStatus)
    case deleteFailed(OSStatus)
    case invalidData
    case itemNotFound
    
    public var errorDescription: String? {
        switch self {
        case .addFailed(let status):
            return "Failed to add item to keychain: \(status)"
        case .updateFailed(let status):
            return "Failed to update item in keychain: \(status)"
        case .retrieveFailed(let status):
            return "Failed to retrieve item from keychain: \(status)"
        case .deleteFailed(let status):
            return "Failed to delete item from keychain: \(status)"
        case .invalidData:
            return "Invalid data retrieved from keychain"
        case .itemNotFound:
            return "Item not found in keychain"
        }
    }
    
    public var statusCode: OSStatus {
        switch self {
        case .addFailed(let status):
            return status
        case .updateFailed(let status):
            return status
        case .retrieveFailed(let status):
            return status
        case .deleteFailed(let status):
            return status
        case .invalidData, .itemNotFound:
            return errSecItemNotFound
        }
    }
} 