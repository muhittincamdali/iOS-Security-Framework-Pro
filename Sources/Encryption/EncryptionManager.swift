//
//  EncryptionManager.swift
//  iOS Security Framework Pro
//
//  Created by Muhittin Camdali
//  Copyright © 2024 Muhittin Camdali. All rights reserved.
//

import Foundation
import Security
import CryptoKit

/// Advanced encryption manager for iOS Security Framework Pro
public final class EncryptionManager {
    
    // MARK: - Singleton
    public static let shared = EncryptionManager()
    private init() {}
    
    // MARK: - Properties
    private let encryptionQueue = DispatchQueue(label: "com.securityframework.encryption", qos: .userInitiated)
    private var encryptionConfig: EncryptionConfiguration?
    private var keyManager: KeyManager?
    
    // MARK: - Encryption Algorithms
    public enum EncryptionAlgorithm {
        case aes128
        case aes256
        case chacha20
        case rsa2048
        case rsa4096
        case hybrid
        
        public var keySize: Int {
            switch self {
            case .aes128: return 128
            case .aes256: return 256
            case .chacha20: return 256
            case .rsa2048: return 2048
            case .rsa4096: return 4096
            case .hybrid: return 256
            }
        }
        
        public var description: String {
            switch self {
            case .aes128: return "AES-128"
            case .aes256: return "AES-256"
            case .chacha20: return "ChaCha20"
            case .rsa2048: return "RSA-2048"
            case .rsa4096: return "RSA-4096"
            case .hybrid: return "Hybrid (AES-256 + RSA-4096)"
            }
        }
    }
    
    // MARK: - Encryption Configuration
    public struct EncryptionConfiguration {
        public let defaultAlgorithm: EncryptionAlgorithm
        public let keyRotationEnabled: Bool
        public let keyRotationInterval: TimeInterval
        public let hardwareAccelerationEnabled: Bool
        public let secureRandomEnabled: Bool
        
        public init(
            defaultAlgorithm: EncryptionAlgorithm = .aes256,
            keyRotationEnabled: Bool = true,
            keyRotationInterval: TimeInterval = 86400.0, // 24 hours
            hardwareAccelerationEnabled: Bool = true,
            secureRandomEnabled: Bool = true
        ) {
            self.defaultAlgorithm = defaultAlgorithm
            self.keyRotationEnabled = keyRotationEnabled
            self.keyRotationInterval = keyRotationInterval
            self.hardwareAccelerationEnabled = hardwareAccelerationEnabled
            self.secureRandomEnabled = secureRandomEnabled
        }
    }
    
    // MARK: - Encryption Result
    public struct EncryptionResult {
        public let encryptedData: Data
        public let algorithm: EncryptionAlgorithm
        public let keyIdentifier: String
        public let timestamp: Date
        public let metadata: [String: Any]
        
        public init(
            encryptedData: Data,
            algorithm: EncryptionAlgorithm,
            keyIdentifier: String,
            timestamp: Date = Date(),
            metadata: [String: Any] = [:]
        ) {
            self.encryptedData = encryptedData
            self.algorithm = algorithm
            self.keyIdentifier = keyIdentifier
            self.timestamp = timestamp
            self.metadata = metadata
        }
    }
    
    // MARK: - Decryption Result
    public struct DecryptionResult {
        public let decryptedData: Data
        public let algorithm: EncryptionAlgorithm
        public let keyIdentifier: String
        public let timestamp: Date
        public let metadata: [String: Any]
        
        public init(
            decryptedData: Data,
            algorithm: EncryptionAlgorithm,
            keyIdentifier: String,
            timestamp: Date = Date(),
            metadata: [String: Any] = [:]
        ) {
            self.decryptedData = decryptedData
            self.algorithm = algorithm
            self.keyIdentifier = keyIdentifier
            self.timestamp = timestamp
            self.metadata = metadata
        }
    }
    
    // MARK: - Errors
    public enum EncryptionError: Error, LocalizedError {
        case algorithmNotSupported
        case keyGenerationFailed
        case encryptionFailed
        case decryptionFailed
        case invalidKey
        case invalidData
        case hardwareAccelerationNotAvailable
        case keyRotationFailed
        
        public var errorDescription: String? {
            switch self {
            case .algorithmNotSupported:
                return "Encryption algorithm is not supported"
            case .keyGenerationFailed:
                return "Failed to generate encryption key"
            case .encryptionFailed:
                return "Data encryption failed"
            case .decryptionFailed:
                return "Data decryption failed"
            case .invalidKey:
                return "Invalid encryption key"
            case .invalidData:
                return "Invalid data for encryption/decryption"
            case .hardwareAccelerationNotAvailable:
                return "Hardware acceleration is not available"
            case .keyRotationFailed:
                return "Key rotation operation failed"
            }
        }
    }
    
    // MARK: - Public Methods
    
    /// Initialize encryption manager with configuration
    /// - Parameter config: Encryption configuration
    /// - Throws: EncryptionError if initialization fails
    public func initialize(with config: EncryptionConfiguration) throws {
        encryptionQueue.sync {
            self.encryptionConfig = config
            self.keyManager = KeyManager()
            
            // Initialize key manager
            try self.keyManager?.initialize(with: config)
            
            // Start key rotation if enabled
            if config.keyRotationEnabled {
                self.startKeyRotation()
            }
        }
    }
    
    /// Encrypt data with specified algorithm
    /// - Parameters:
    ///   - data: Data to encrypt
    ///   - algorithm: Encryption algorithm
    ///   - completion: Completion handler with result
    public func encrypt(
        data: Data,
        algorithm: EncryptionAlgorithm,
        completion: @escaping (Result<EncryptionResult, EncryptionError>) -> Void
    ) {
        encryptionQueue.async {
            do {
                let result = try self.performEncryption(data: data, algorithm: algorithm)
                completion(.success(result))
            } catch let error as EncryptionError {
                completion(.failure(error))
            } catch {
                completion(.failure(.encryptionFailed))
            }
        }
    }
    
    /// Encrypt data with default algorithm
    /// - Parameters:
    ///   - data: Data to encrypt
    ///   - completion: Completion handler with result
    public func encrypt(
        data: Data,
        completion: @escaping (Result<EncryptionResult, EncryptionError>) -> Void
    ) {
        guard let config = encryptionConfig else {
            completion(.failure(.algorithmNotSupported))
            return
        }
        
        encrypt(data: data, algorithm: config.defaultAlgorithm, completion: completion)
    }
    
    /// Decrypt data
    /// - Parameters:
    ///   - encryptedData: Encrypted data
    ///   - keyIdentifier: Key identifier
    ///   - completion: Completion handler with result
    public func decrypt(
        encryptedData: Data,
        keyIdentifier: String,
        completion: @escaping (Result<DecryptionResult, EncryptionError>) -> Void
    ) {
        encryptionQueue.async {
            do {
                let result = try self.performDecryption(encryptedData: encryptedData, keyIdentifier: keyIdentifier)
                completion(.success(result))
            } catch let error as EncryptionError {
                completion(.failure(error))
            } catch {
                completion(.failure(.decryptionFailed))
            }
        }
    }
    
    /// Generate encryption key
    /// - Parameters:
    ///   - algorithm: Encryption algorithm
    ///   - completion: Completion handler with key identifier
    public func generateKey(
        for algorithm: EncryptionAlgorithm,
        completion: @escaping (Result<String, EncryptionError>) -> Void
    ) {
        encryptionQueue.async {
            do {
                let keyIdentifier = try self.keyManager?.generateKey(for: algorithm) ?? ""
                completion(.success(keyIdentifier))
            } catch let error as EncryptionError {
                completion(.failure(error))
            } catch {
                completion(.failure(.keyGenerationFailed))
            }
        }
    }
    
    /// Rotate encryption keys
    /// - Parameter completion: Completion handler with result
    public func rotateKeys(completion: @escaping (Result<Void, EncryptionError>) -> Void) {
        encryptionQueue.async {
            do {
                try self.keyManager?.rotateKeys()
                completion(.success(()))
            } catch let error as EncryptionError {
                completion(.failure(error))
            } catch {
                completion(.failure(.keyRotationFailed))
            }
        }
    }
    
    /// Get supported algorithms
    /// - Returns: Array of supported algorithms
    public func getSupportedAlgorithms() -> [EncryptionAlgorithm] {
        return [.aes128, .aes256, .chacha20, .rsa2048, .rsa4096, .hybrid]
    }
    
    /// Check if hardware acceleration is available
    /// - Returns: True if available, false otherwise
    public func isHardwareAccelerationAvailable() -> Bool {
        // Check for Secure Enclave availability
        return SecureEnclave.isAvailable()
    }
    
    // MARK: - Private Methods
    
    private func performEncryption(data: Data, algorithm: EncryptionAlgorithm) throws -> EncryptionResult {
        guard let keyManager = keyManager else {
            throw EncryptionError.keyGenerationFailed
        }
        
        // Generate or get key for algorithm
        let keyIdentifier = try keyManager.getOrGenerateKey(for: algorithm)
        
        // Perform encryption based on algorithm
        let encryptedData: Data
        let metadata: [String: Any]
        
        switch algorithm {
        case .aes128, .aes256:
            (encryptedData, metadata) = try performAESEncryption(data: data, keyIdentifier: keyIdentifier)
            
        case .chacha20:
            (encryptedData, metadata) = try performChaCha20Encryption(data: data, keyIdentifier: keyIdentifier)
            
        case .rsa2048, .rsa4096:
            (encryptedData, metadata) = try performRSAEncryption(data: data, keyIdentifier: keyIdentifier)
            
        case .hybrid:
            (encryptedData, metadata) = try performHybridEncryption(data: data, keyIdentifier: keyIdentifier)
        }
        
        return EncryptionResult(
            encryptedData: encryptedData,
            algorithm: algorithm,
            keyIdentifier: keyIdentifier,
            metadata: metadata
        )
    }
    
    private func performDecryption(encryptedData: Data, keyIdentifier: String) throws -> DecryptionResult {
        guard let keyManager = keyManager else {
            throw EncryptionError.keyGenerationFailed
        }
        
        // Get key and algorithm from metadata
        let (algorithm, metadata) = try extractEncryptionMetadata(from: encryptedData)
        let key = try keyManager.getKey(identifier: keyIdentifier)
        
        // Perform decryption based on algorithm
        let decryptedData: Data
        
        switch algorithm {
        case .aes128, .aes256:
            decryptedData = try performAESDecryption(encryptedData: encryptedData, key: key)
            
        case .chacha20:
            decryptedData = try performChaCha20Decryption(encryptedData: encryptedData, key: key)
            
        case .rsa2048, .rsa4096:
            decryptedData = try performRSADecryption(encryptedData: encryptedData, key: key)
            
        case .hybrid:
            decryptedData = try performHybridDecryption(encryptedData: encryptedData, key: key)
        }
        
        return DecryptionResult(
            decryptedData: decryptedData,
            algorithm: algorithm,
            keyIdentifier: keyIdentifier,
            metadata: metadata
        )
    }
    
    private func performAESEncryption(data: Data, keyIdentifier: String) throws -> (Data, [String: Any]) {
        // Generate random IV
        let iv = try generateRandomIV(size: 16)
        
        // Get key
        guard let key = try keyManager?.getKey(identifier: keyIdentifier) else {
            throw EncryptionError.invalidKey
        }
        
        // Perform AES encryption
        let encryptedData = try AES.encrypt(data: data, key: key, iv: iv)
        
        let metadata: [String: Any] = [
            "algorithm": "AES",
            "iv": iv.base64EncodedString(),
            "keySize": 256
        ]
        
        return (encryptedData, metadata)
    }
    
    private func performAESDecryption(encryptedData: Data, key: Data) throws -> Data {
        // Extract IV from metadata
        let iv = try extractIV(from: encryptedData)
        
        // Perform AES decryption
        return try AES.decrypt(data: encryptedData, key: key, iv: iv)
    }
    
    private func performChaCha20Encryption(data: Data, keyIdentifier: String) throws -> (Data, [String: Any]) {
        // Generate random nonce
        let nonce = try generateRandomNonce(size: 12)
        
        // Get key
        guard let key = try keyManager?.getKey(identifier: keyIdentifier) else {
            throw EncryptionError.invalidKey
        }
        
        // Perform ChaCha20 encryption
        let encryptedData = try ChaCha20.encrypt(data: data, key: key, nonce: nonce)
        
        let metadata: [String: Any] = [
            "algorithm": "ChaCha20",
            "nonce": nonce.base64EncodedString(),
            "keySize": 256
        ]
        
        return (encryptedData, metadata)
    }
    
    private func performChaCha20Decryption(encryptedData: Data, key: Data) throws -> Data {
        // Extract nonce from metadata
        let nonce = try extractNonce(from: encryptedData)
        
        // Perform ChaCha20 decryption
        return try ChaCha20.decrypt(data: encryptedData, key: key, nonce: nonce)
    }
    
    private func performRSAEncryption(data: Data, keyIdentifier: String) throws -> (Data, [String: Any]) {
        // Get public key
        guard let publicKey = try keyManager?.getPublicKey(identifier: keyIdentifier) else {
            throw EncryptionError.invalidKey
        }
        
        // Perform RSA encryption
        let encryptedData = try RSA.encrypt(data: data, publicKey: publicKey)
        
        let metadata: [String: Any] = [
            "algorithm": "RSA",
            "keySize": 4096
        ]
        
        return (encryptedData, metadata)
    }
    
    private func performRSADecryption(encryptedData: Data, key: Data) throws -> Data {
        // Perform RSA decryption
        return try RSA.decrypt(data: encryptedData, privateKey: key)
    }
    
    private func performHybridEncryption(data: Data, keyIdentifier: String) throws -> (Data, [String: Any]) {
        // Generate symmetric key for data encryption
        let symmetricKey = try generateRandomKey(size: 32)
        
        // Encrypt data with symmetric key (AES)
        let iv = try generateRandomIV(size: 16)
        let encryptedData = try AES.encrypt(data: data, key: symmetricKey, iv: iv)
        
        // Encrypt symmetric key with RSA
        guard let publicKey = try keyManager?.getPublicKey(identifier: keyIdentifier) else {
            throw EncryptionError.invalidKey
        }
        let encryptedKey = try RSA.encrypt(data: symmetricKey, publicKey: publicKey)
        
        // Combine encrypted key and data
        var combinedData = Data()
        combinedData.append(encryptedKey)
        combinedData.append(encryptedData)
        
        let metadata: [String: Any] = [
            "algorithm": "Hybrid",
            "symmetricAlgorithm": "AES-256",
            "asymmetricAlgorithm": "RSA-4096",
            "iv": iv.base64EncodedString()
        ]
        
        return (combinedData, metadata)
    }
    
    private func performHybridDecryption(encryptedData: Data, key: Data) throws -> Data {
        // Extract encrypted key and data
        let (encryptedKey, encryptedData) = try extractHybridComponents(from: encryptedData)
        
        // Decrypt symmetric key with RSA
        let symmetricKey = try RSA.decrypt(data: encryptedKey, privateKey: key)
        
        // Decrypt data with symmetric key
        let iv = try extractIV(from: encryptedData)
        return try AES.decrypt(data: encryptedData, key: symmetricKey, iv: iv)
    }
    
    private func startKeyRotation() {
        guard let config = encryptionConfig else { return }
        
        Timer.scheduledTimer(withTimeInterval: config.keyRotationInterval, repeats: true) { _ in
            self.rotateKeys { _ in
                // Key rotation completed
            }
        }
    }
    
    // MARK: - Helper Methods
    
    private func generateRandomIV(size: Int) throws -> Data {
        var iv = Data(count: size)
        let result = iv.withUnsafeMutableBytes { pointer in
            SecRandomCopyBytes(kSecRandomDefault, size, pointer.baseAddress!)
        }
        
        guard result == errSecSuccess else {
            throw EncryptionError.keyGenerationFailed
        }
        
        return iv
    }
    
    private func generateRandomNonce(size: Int) throws -> Data {
        return try generateRandomIV(size: size)
    }
    
    private func generateRandomKey(size: Int) throws -> Data {
        return try generateRandomIV(size: size)
    }
    
    private func extractIV(from data: Data) throws -> Data {
        // Implementation depends on data format
        return Data()
    }
    
    private func extractNonce(from data: Data) throws -> Data {
        // Implementation depends on data format
        return Data()
    }
    
    private func extractEncryptionMetadata(from data: Data) throws -> (EncryptionAlgorithm, [String: Any]) {
        // Implementation depends on data format
        return (.aes256, [:])
    }
    
    private func extractHybridComponents(from data: Data) throws -> (Data, Data) {
        // Implementation depends on data format
        return (Data(), Data())
    }
}

// MARK: - Supporting Classes (Placeholder implementations)
private class KeyManager {
    func initialize(with config: EncryptionConfiguration) throws {}
    func generateKey(for algorithm: EncryptionAlgorithm) throws -> String { return "" }
    func getOrGenerateKey(for algorithm: EncryptionAlgorithm) throws -> String { return "" }
    func getKey(identifier: String) throws -> Data { return Data() }
    func getPublicKey(identifier: String) throws -> Data { return Data() }
    func rotateKeys() throws {}
}

private class SecureEnclave {
    static func isAvailable() -> Bool { return true }
}

private class AES {
    static func encrypt(data: Data, key: Data, iv: Data) throws -> Data { return Data() }
    static func decrypt(data: Data, key: Data, iv: Data) throws -> Data { return Data() }
}

private class ChaCha20 {
    static func encrypt(data: Data, key: Data, nonce: Data) throws -> Data { return Data() }
    static func decrypt(data: Data, key: Data, nonce: Data) throws -> Data { return Data() }
}

private class RSA {
    static func encrypt(data: Data, publicKey: Data) throws -> Data { return Data() }
    static func decrypt(data: Data, privateKey: Data) throws -> Data { return Data() }
} 