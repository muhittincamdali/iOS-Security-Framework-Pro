//
//  SecureStorage.swift
//  iOS Security Framework Pro
//
//  Created by Muhittin Camdali
//  Copyright © 2024 Muhittin Camdali. All rights reserved.
//

import Foundation
import Security
import CryptoKit

/// Advanced secure storage manager for iOS Security Framework Pro
public final class SecureStorage {
    
    // MARK: - Singleton
    public static let shared = SecureStorage()
    private init() {}
    
    // MARK: - Properties
    private let storageQueue = DispatchQueue(label: "com.securityframework.storage", qos: .userInitiated)
    private var storageConfig: StorageConfiguration?
    private var encryptionManager: StorageEncryptionManager?
    private var keyManager: StorageKeyManager?
    
    // MARK: - Storage Configuration
    public struct StorageConfiguration {
        public let encryptionLevel: EncryptionLevel
        public let compressionEnabled: Bool
        public let backupEnabled: Bool
        public let maxStorageSize: UInt64
        public let autoCleanupEnabled: Bool
        
        public init(
            encryptionLevel: EncryptionLevel = .aes256,
            compressionEnabled: Bool = true,
            backupEnabled: Bool = true,
            maxStorageSize: UInt64 = 500 * 1024 * 1024, // 500MB
            autoCleanupEnabled: Bool = true
        ) {
            self.encryptionLevel = encryptionLevel
            self.compressionEnabled = compressionEnabled
            self.backupEnabled = backupEnabled
            self.maxStorageSize = maxStorageSize
            self.autoCleanupEnabled = autoCleanupEnabled
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
        
        public var description: String {
            switch self {
            case .aes128: return "AES-128"
            case .aes256: return "AES-256"
            case .chacha20: return "ChaCha20"
            case .rsa2048: return "RSA-2048"
            case .rsa4096: return "RSA-4096"
            }
        }
    }
    
    // MARK: - Storage Item
    public struct StorageItem {
        public let id: String
        public let key: String
        public let data: Data
        public let metadata: [String: Any]
        public let createdAt: Date
        public let expiresAt: Date?
        public let accessCount: Int
        
        public init(
            id: String = UUID().uuidString,
            key: String,
            data: Data,
            metadata: [String: Any] = [:],
            createdAt: Date = Date(),
            expiresAt: Date? = nil,
            accessCount: Int = 0
        ) {
            self.id = id
            self.key = key
            self.data = data
            self.metadata = metadata
            self.createdAt = createdAt
            self.expiresAt = expiresAt
            self.accessCount = accessCount
        }
    }
    
    // MARK: - Storage Statistics
    public struct StorageStatistics {
        public let totalItems: Int
        public let totalSize: UInt64
        public let encryptedItems: Int
        public let compressedItems: Int
        public let expiredItems: Int
        public let averageItemSize: UInt64
        
        public init(
            totalItems: Int = 0,
            totalSize: UInt64 = 0,
            encryptedItems: Int = 0,
            compressedItems: Int = 0,
            expiredItems: Int = 0,
            averageItemSize: UInt64 = 0
        ) {
            self.totalItems = totalItems
            self.totalSize = totalSize
            self.encryptedItems = encryptedItems
            self.compressedItems = compressedItems
            self.expiredItems = expiredItems
            self.averageItemSize = averageItemSize
        }
    }
    
    // MARK: - Errors
    public enum SecureStorageError: Error, LocalizedError {
        case initializationFailed
        case encryptionFailed
        case decryptionFailed
        case compressionFailed
        case decompressionFailed
        case storageFull
        case itemNotFound
        case itemExpired
        case invalidKey
        case backupFailed
        
        public var errorDescription: String? {
            switch self {
            case .initializationFailed:
                return "Secure storage initialization failed"
            case .encryptionFailed:
                return "Data encryption failed"
            case .decryptionFailed:
                return "Data decryption failed"
            case .compressionFailed:
                return "Data compression failed"
            case .decompressionFailed:
                return "Data decompression failed"
            case .storageFull:
                return "Storage is full"
            case .itemNotFound:
                return "Storage item not found"
            case .itemExpired:
                return "Storage item has expired"
            case .invalidKey:
                return "Invalid storage key"
            case .backupFailed:
                return "Storage backup failed"
            }
        }
    }
    
    // MARK: - Public Methods
    
    /// Initialize secure storage with configuration
    /// - Parameter config: Storage configuration
    /// - Throws: SecureStorageError if initialization fails
    public func initialize(with config: StorageConfiguration) throws {
        storageQueue.sync {
            self.storageConfig = config
            
            // Initialize encryption manager
            self.encryptionManager = StorageEncryptionManager()
            try self.encryptionManager?.initialize(with: config)
            
            // Initialize key manager
            self.keyManager = StorageKeyManager()
            try self.keyManager?.initialize(with: config)
            
            // Start storage monitoring
            startStorageMonitoring()
        }
    }
    
    /// Store data securely
    /// - Parameters:
    ///   - data: Data to store
    ///   - key: Storage key
    ///   - metadata: Additional metadata
    ///   - expiresAt: Expiration date
    ///   - completion: Completion handler with result
    public func store(
        data: Data,
        forKey key: String,
        metadata: [String: Any] = [:],
        expiresAt: Date? = nil,
        completion: @escaping (Result<Void, SecureStorageError>) -> Void
    ) {
        storageQueue.async {
            do {
                try self.performStore(data: data, key: key, metadata: metadata, expiresAt: expiresAt)
                completion(.success(()))
            } catch let error as SecureStorageError {
                completion(.failure(error))
            } catch {
                completion(.failure(.initializationFailed))
            }
        }
    }
    
    /// Retrieve data securely
    /// - Parameters:
    ///   - key: Storage key
    ///   - completion: Completion handler with result
    public func retrieve(
        forKey key: String,
        completion: @escaping (Result<Data, SecureStorageError>) -> Void
    ) {
        storageQueue.async {
            do {
                let data = try self.performRetrieve(key: key)
                completion(.success(data))
            } catch let error as SecureStorageError {
                completion(.failure(error))
            } catch {
                completion(.failure(.initializationFailed))
            }
        }
    }
    
    /// Update stored data
    /// - Parameters:
    ///   - data: New data
    ///   - key: Storage key
    ///   - metadata: Additional metadata
    ///   - completion: Completion handler with result
    public func update(
        data: Data,
        forKey key: String,
        metadata: [String: Any] = [:],
        completion: @escaping (Result<Void, SecureStorageError>) -> Void
    ) {
        storageQueue.async {
            do {
                try self.performUpdate(data: data, key: key, metadata: metadata)
                completion(.success(()))
            } catch let error as SecureStorageError {
                completion(.failure(error))
            } catch {
                completion(.failure(.initializationFailed))
            }
        }
    }
    
    /// Delete stored data
    /// - Parameters:
    ///   - key: Storage key
    ///   - completion: Completion handler with result
    public func delete(
        forKey key: String,
        completion: @escaping (Result<Void, SecureStorageError>) -> Void
    ) {
        storageQueue.async {
            do {
                try self.performDelete(key: key)
                completion(.success(()))
            } catch let error as SecureStorageError {
                completion(.failure(error))
            } catch {
                completion(.failure(.initializationFailed))
            }
        }
    }
    
    /// Check if item exists
    /// - Parameters:
    ///   - key: Storage key
    ///   - completion: Completion handler with result
    public func exists(
        forKey key: String,
        completion: @escaping (Result<Bool, SecureStorageError>) -> Void
    ) {
        storageQueue.async {
            do {
                let exists = try self.performExists(key: key)
                completion(.success(exists))
            } catch let error as SecureStorageError {
                completion(.failure(error))
            } catch {
                completion(.failure(.initializationFailed))
            }
        }
    }
    
    /// Get all storage keys
    /// - Parameter completion: Completion handler with result
    public func getAllKeys(
        completion: @escaping (Result<[String], SecureStorageError>) -> Void
    ) {
        storageQueue.async {
            do {
                let keys = try self.performGetAllKeys()
                completion(.success(keys))
            } catch let error as SecureStorageError {
                completion(.failure(error))
            } catch {
                completion(.failure(.initializationFailed))
            }
        }
    }
    
    /// Clear all stored data
    /// - Parameter completion: Completion handler with result
    public func clearAll(
        completion: @escaping (Result<Void, SecureStorageError>) -> Void
    ) {
        storageQueue.async {
            do {
                try self.performClearAll()
                completion(.success(()))
            } catch let error as SecureStorageError {
                completion(.failure(error))
            } catch {
                completion(.failure(.initializationFailed))
            }
        }
    }
    
    /// Get storage statistics
    /// - Returns: Storage statistics
    public func getStorageStatistics() -> StorageStatistics {
        return performGetStatistics()
    }
    
    /// Backup storage data
    /// - Parameter completion: Completion handler with result
    public func backup(
        completion: @escaping (Result<Void, SecureStorageError>) -> Void
    ) {
        storageQueue.async {
            do {
                try self.performBackup()
                completion(.success(()))
            } catch let error as SecureStorageError {
                completion(.failure(error))
            } catch {
                completion(.failure(.backupFailed))
            }
        }
    }
    
    /// Clean up expired items
    /// - Parameter completion: Completion handler with result
    public func cleanupExpiredItems(
        completion: @escaping (Result<Int, SecureStorageError>) -> Void
    ) {
        storageQueue.async {
            do {
                let count = try self.performCleanupExpiredItems()
                completion(.success(count))
            } catch let error as SecureStorageError {
                completion(.failure(error))
            } catch {
                completion(.failure(.initializationFailed))
            }
        }
    }
    
    // MARK: - Private Methods
    
    private func startStorageMonitoring() {
        // Start storage monitoring
    }
    
    private func performStore(
        data: Data,
        key: String,
        metadata: [String: Any],
        expiresAt: Date?
    ) throws {
        guard let config = storageConfig else {
            throw SecureStorageError.initializationFailed
        }
        
        // Check storage size
        let currentSize = getCurrentStorageSize()
        if currentSize + UInt64(data.count) > config.maxStorageSize {
            throw SecureStorageError.storageFull
        }
        
        // Encrypt data
        let encryptedData = try encryptionManager?.encrypt(data) ?? data
        
        // Compress if enabled
        let finalData = config.compressionEnabled ? 
            (try compressionManager?.compress(encryptedData) ?? encryptedData) : encryptedData
        
        // Store item
        let item = StorageItem(
            key: key,
            data: finalData,
            metadata: metadata,
            expiresAt: expiresAt
        )
        
        try storageManager?.storeItem(item)
    }
    
    private func performRetrieve(key: String) throws -> Data {
        guard let item = try storageManager?.getItem(forKey: key) else {
            throw SecureStorageError.itemNotFound
        }
        
        // Check expiration
        if let expiresAt = item.expiresAt, expiresAt < Date() {
            throw SecureStorageError.itemExpired
        }
        
        // Decompress if needed
        let decompressedData = storageConfig?.compressionEnabled == true ?
            (try compressionManager?.decompress(item.data) ?? item.data) : item.data
        
        // Decrypt data
        return try encryptionManager?.decrypt(decompressedData) ?? decompressedData
    }
    
    private func performUpdate(
        data: Data,
        key: String,
        metadata: [String: Any]
    ) throws {
        // Check if item exists
        guard try performExists(key: key) else {
            throw SecureStorageError.itemNotFound
        }
        
        // Store updated data
        try performStore(data: data, key: key, metadata: metadata, expiresAt: nil)
    }
    
    private func performDelete(key: String) throws {
        try storageManager?.deleteItem(forKey: key)
    }
    
    private func performExists(key: String) throws -> Bool {
        return try storageManager?.itemExists(forKey: key) ?? false
    }
    
    private func performGetAllKeys() throws -> [String] {
        return try storageManager?.getAllKeys() ?? []
    }
    
    private func performClearAll() throws {
        try storageManager?.clearAll()
    }
    
    private func performGetStatistics() -> StorageStatistics {
        return storageManager?.getStatistics() ?? StorageStatistics()
    }
    
    private func performBackup() throws {
        try storageManager?.backup()
    }
    
    private func performCleanupExpiredItems() throws -> Int {
        return try storageManager?.cleanupExpiredItems() ?? 0
    }
    
    private func getCurrentStorageSize() -> UInt64 {
        return storageManager?.getCurrentSize() ?? 0
    }
}

// MARK: - Supporting Classes (Placeholder implementations)
private class StorageEncryptionManager {
    func initialize(with config: SecureStorage.StorageConfiguration) throws {}
    func encrypt(_ data: Data) throws -> Data { return data }
    func decrypt(_ data: Data) throws -> Data { return data }
}

private class StorageKeyManager {
    func initialize(with config: SecureStorage.StorageConfiguration) throws {}
}

private class StorageManager {
    func storeItem(_ item: SecureStorage.StorageItem) throws {}
    func getItem(forKey key: String) throws -> SecureStorage.StorageItem? { return nil }
    func deleteItem(forKey key: String) throws {}
    func itemExists(forKey key: String) throws -> Bool { return false }
    func getAllKeys() throws -> [String] { return [] }
    func clearAll() throws {}
    func backup() throws {}
    func cleanupExpiredItems() throws -> Int { return 0 }
    func getCurrentSize() -> UInt64 { return 0 }
    func getStatistics() -> SecureStorage.StorageStatistics { return SecureStorage.StorageStatistics() }
}

private class CompressionManager {
    func compress(_ data: Data) throws -> Data { return data }
    func decompress(_ data: Data) throws -> Data { return data }
} 