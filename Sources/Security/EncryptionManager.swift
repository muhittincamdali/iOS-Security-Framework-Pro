import Foundation
import CryptoKit
import Security

/// Advanced encryption management system for iOS applications.
///
/// This module provides comprehensive encryption utilities including
/// symmetric and asymmetric encryption, key management, and secure storage.
@available(iOS 13.0, *)
public class EncryptionManager {
    
    // MARK: - Properties
    
    /// Current encryption algorithm
    public var algorithm: EncryptionAlgorithm = .aes256
    
    /// Key derivation function
    public var keyDerivationFunction: KeyDerivationFunction = .pbkdf2
    
    /// Salt for key derivation
    private var salt: Data?
    
    /// Master key for encryption
    private var masterKey: SymmetricKey?
    
    /// Keychain manager
    private let keychainManager: KeychainManager
    
    /// Security analytics
    private var analytics: SecurityAnalytics?
    
    // MARK: - Initialization
    
    /// Creates a new encryption manager instance.
    ///
    /// - Parameters:
    ///   - keychainManager: Keychain manager instance
    ///   - analytics: Optional security analytics instance
    public init(keychainManager: KeychainManager, analytics: SecurityAnalytics? = nil) {
        self.keychainManager = keychainManager
        self.analytics = analytics
        setupEncryption()
    }
    
    // MARK: - Setup
    
    /// Sets up encryption with default parameters.
    private func setupEncryption() {
        generateSalt()
        setupMasterKey()
    }
    
    /// Generates a random salt for key derivation.
    private func generateSalt() {
        salt = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
    }
    
    /// Sets up the master key for encryption.
    private func setupMasterKey() {
        guard let salt = salt else { return }
        
        do {
            masterKey = try deriveKey(from: "master_key", salt: salt)
        } catch {
            analytics?.recordError(.keyDerivationFailed, error: error)
        }
    }
    
    // MARK: - Key Derivation
    
    /// Derives a key from a password and salt.
    ///
    /// - Parameters:
    ///   - password: Password for key derivation
    ///   - salt: Salt for key derivation
    /// - Returns: Derived symmetric key
    /// - Throws: EncryptionError if derivation fails
    public func deriveKey(from password: String, salt: Data) throws -> SymmetricKey {
        let hash = SHA256.hash(data: password.data(using: .utf8) ?? Data())
        let keyData = Data(hash)
        
        switch keyDerivationFunction {
        case .pbkdf2:
            return try deriveKeyWithPBKDF2(password: password, salt: salt)
        case .scrypt:
            return try deriveKeyWithScrypt(password: password, salt: salt)
        case .argon2:
            return try deriveKeyWithArgon2(password: password, salt: salt)
        }
    }
    
    /// Derives key using PBKDF2.
    private func deriveKeyWithPBKDF2(password: String, salt: Data) throws -> SymmetricKey {
        let rounds = 100_000
        let keyLength = algorithm.keyLength
        
        var derivedKeyData = Data(count: keyLength)
        let result = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationHmac(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    password,
                    password.count,
                    saltBytes.baseAddress,
                    salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    UInt32(rounds),
                    derivedKeyBytes.baseAddress,
                    keyLength
                )
            }
        }
        
        guard result == kCCSuccess else {
            throw EncryptionError.keyDerivationFailed
        }
        
        return SymmetricKey(data: derivedKeyData)
    }
    
    /// Derives key using Scrypt.
    private func deriveKeyWithScrypt(password: String, salt: Data) throws -> SymmetricKey {
        // Scrypt implementation would go here
        // For now, using PBKDF2 as fallback
        return try deriveKeyWithPBKDF2(password: password, salt: salt)
    }
    
    /// Derives key using Argon2.
    private func deriveKeyWithArgon2(password: String, salt: Data) throws -> SymmetricKey {
        // Argon2 implementation would go here
        // For now, using PBKDF2 as fallback
        return try deriveKeyWithPBKDF2(password: password, salt: salt)
    }
    
    // MARK: - Symmetric Encryption
    
    /// Encrypts data using symmetric encryption.
    ///
    /// - Parameters:
    ///   - data: Data to encrypt
    ///   - key: Optional encryption key (uses master key if nil)
    /// - Returns: Encrypted data
    /// - Throws: EncryptionError if encryption fails
    public func encrypt(_ data: Data, key: SymmetricKey? = nil) throws -> Data {
        let encryptionKey = key ?? masterKey ?? SymmetricKey(size: .bits256)
        
        switch algorithm {
        case .aes256:
            return try encryptWithAES(data: data, key: encryptionKey)
        case .aes128:
            return try encryptWithAES(data: data, key: encryptionKey)
        case .chacha20:
            return try encryptWithChaCha20(data: data, key: encryptionKey)
        }
    }
    
    /// Decrypts data using symmetric encryption.
    ///
    /// - Parameters:
    ///   - data: Data to decrypt
    ///   - key: Optional decryption key (uses master key if nil)
    /// - Returns: Decrypted data
    /// - Throws: EncryptionError if decryption fails
    public func decrypt(_ data: Data, key: SymmetricKey? = nil) throws -> Data {
        let decryptionKey = key ?? masterKey ?? SymmetricKey(size: .bits256)
        
        switch algorithm {
        case .aes256:
            return try decryptWithAES(data: data, key: decryptionKey)
        case .aes128:
            return try decryptWithAES(data: data, key: decryptionKey)
        case .chacha20:
            return try decryptWithChaCha20(data: data, key: decryptionKey)
        }
    }
    
    /// Encrypts data using AES.
    private func encryptWithAES(data: Data, key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.seal(data, using: key)
        return sealedBox.combined ?? Data()
    }
    
    /// Decrypts data using AES.
    private func decryptWithAES(data: Data, key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(sealedBox, using: key)
    }
    
    /// Encrypts data using ChaCha20.
    private func encryptWithChaCha20(data: Data, key: SymmetricKey) throws -> Data {
        let nonce = try AES.GCM.Nonce()
        let sealedBox = try ChaChaPoly.seal(data, using: key, nonce: nonce)
        return sealedBox.combined ?? Data()
    }
    
    /// Decrypts data using ChaCha20.
    private func decryptWithChaCha20(data: Data, key: SymmetricKey) throws -> Data {
        let sealedBox = try ChaChaPoly.SealedBox(combined: data)
        return try ChaChaPoly.open(sealedBox, using: key)
    }
    
    // MARK: - Asymmetric Encryption
    
    /// Generates a new key pair for asymmetric encryption.
    ///
    /// - Returns: Generated key pair
    /// - Throws: EncryptionError if generation fails
    public func generateKeyPair() throws -> KeyPair {
        let privateKey = try P256.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        
        return KeyPair(
            privateKey: privateKey,
            publicKey: publicKey
        )
    }
    
    /// Encrypts data using asymmetric encryption.
    ///
    /// - Parameters:
    ///   - data: Data to encrypt
    ///   - publicKey: Public key for encryption
    /// - Returns: Encrypted data
    /// - Throws: EncryptionError if encryption fails
    public func encryptAsymmetric(_ data: Data, publicKey: P256.KeyAgreement.PublicKey) throws -> Data {
        let ephemeralPrivateKey = try P256.KeyAgreement.PrivateKey()
        let ephemeralPublicKey = ephemeralPrivateKey.publicKey
        
        let sharedSecret = try ephemeralPrivateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: "encryption".data(using: .utf8) ?? Data(),
            sharedInfo: Data(),
            outputByteCount: 32
        )
        
        let sealedBox = try AES.GCM.seal(data, using: symmetricKey)
        let encryptedData = sealedBox.combined ?? Data()
        
        // Combine ephemeral public key with encrypted data
        var combinedData = Data()
        combinedData.append(ephemeralPublicKey.rawRepresentation)
        combinedData.append(encryptedData)
        
        return combinedData
    }
    
    /// Decrypts data using asymmetric encryption.
    ///
    /// - Parameters:
    ///   - data: Data to decrypt
    ///   - privateKey: Private key for decryption
    /// - Returns: Decrypted data
    /// - Throws: EncryptionError if decryption fails
    public func decryptAsymmetric(_ data: Data, privateKey: P256.KeyAgreement.PrivateKey) throws -> Data {
        guard data.count > 65 else { // Minimum size for ephemeral public key + some encrypted data
            throw EncryptionError.invalidData
        }
        
        let ephemeralPublicKeyData = data.prefix(65)
        let encryptedData = data.dropFirst(65)
        
        let ephemeralPublicKey = try P256.KeyAgreement.PublicKey(rawRepresentation: ephemeralPublicKeyData)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
        
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: "encryption".data(using: .utf8) ?? Data(),
            sharedInfo: Data(),
            outputByteCount: 32
        )
        
        let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
        return try AES.GCM.open(sealedBox, using: symmetricKey)
    }
    
    // MARK: - Secure Storage
    
    /// Securely stores encrypted data.
    ///
    /// - Parameters:
    ///   - data: Data to store
    ///   - key: Storage key
    /// - Throws: EncryptionError if storage fails
    public func secureStore(_ data: Data, key: String) throws {
        let encryptedData = try encrypt(data)
        try keychainManager.store(encryptedData, key: key)
        
        analytics?.recordSecureStorage(key: key, size: data.count)
    }
    
    /// Retrieves securely stored data.
    ///
    /// - Parameter key: Storage key
    /// - Returns: Retrieved data
    /// - Throws: EncryptionError if retrieval fails
    public func secureRetrieve(key: String) throws -> Data {
        let encryptedData = try keychainManager.retrieve(key: key)
        return try decrypt(encryptedData)
    }
    
    /// Removes securely stored data.
    ///
    /// - Parameter key: Storage key
    /// - Throws: EncryptionError if removal fails
    public func secureRemove(key: String) throws {
        try keychainManager.remove(key: key)
        analytics?.recordSecureRemoval(key: key)
    }
    
    // MARK: - Hash Functions
    
    /// Computes SHA-256 hash of data.
    ///
    /// - Parameter data: Data to hash
    /// - Returns: Hash value
    public func sha256(_ data: Data) -> Data {
        let hash = SHA256.hash(data: data)
        return Data(hash)
    }
    
    /// Computes SHA-512 hash of data.
    ///
    /// - Parameter data: Data to hash
    /// - Returns: Hash value
    public func sha512(_ data: Data) -> Data {
        let hash = SHA512.hash(data: data)
        return Data(hash)
    }
    
    /// Computes HMAC-SHA256 of data.
    ///
    /// - Parameters:
    ///   - data: Data to hash
    ///   - key: HMAC key
    /// - Returns: HMAC value
    public func hmacSHA256(_ data: Data, key: SymmetricKey) -> Data {
        let signature = HMAC<SHA256>.authenticationCode(for: data, using: key)
        return Data(signature)
    }
    
    // MARK: - Digital Signatures
    
    /// Signs data using a private key.
    ///
    /// - Parameters:
    ///   - data: Data to sign
    ///   - privateKey: Private key for signing
    /// - Returns: Digital signature
    /// - Throws: EncryptionError if signing fails
    public func sign(_ data: Data, privateKey: P256.Signing.PrivateKey) throws -> Data {
        let signature = try privateKey.signature(for: data)
        return signature.rawRepresentation
    }
    
    /// Verifies a digital signature.
    ///
    /// - Parameters:
    ///   - data: Original data
    ///   - signature: Digital signature
    ///   - publicKey: Public key for verification
    /// - Returns: True if signature is valid
    public func verify(_ data: Data, signature: Data, publicKey: P256.Signing.PublicKey) -> Bool {
        do {
            let signature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
            return publicKey.isValidSignature(signature, for: data)
        } catch {
            return false
        }
    }
    
    // MARK: - Security Analysis
    
    /// Analyzes encryption security.
    ///
    /// - Returns: Security analysis report
    public func analyzeSecurity() -> SecurityAnalysisReport {
        return SecurityAnalysisReport(
            algorithm: algorithm,
            keyDerivationFunction: keyDerivationFunction,
            keyLength: algorithm.keyLength,
            saltLength: salt?.count ?? 0,
            encryptionCount: analytics?.encryptionCount ?? 0,
            decryptionCount: analytics?.decryptionCount ?? 0
        )
    }
}

// MARK: - Supporting Types

/// Encryption algorithms.
@available(iOS 13.0, *)
public enum EncryptionAlgorithm {
    case aes256
    case aes128
    case chacha20
    
    var keyLength: Int {
        switch self {
        case .aes256:
            return 32
        case .aes128:
            return 16
        case .chacha20:
            return 32
        }
    }
}

/// Key derivation functions.
@available(iOS 13.0, *)
public enum KeyDerivationFunction {
    case pbkdf2
    case scrypt
    case argon2
}

/// Key pair for asymmetric encryption.
@available(iOS 13.0, *)
public struct KeyPair {
    public let privateKey: P256.KeyAgreement.PrivateKey
    public let publicKey: P256.KeyAgreement.PublicKey
}

/// Encryption errors.
@available(iOS 13.0, *)
public enum EncryptionError: Error {
    case keyDerivationFailed
    case encryptionFailed
    case decryptionFailed
    case invalidData
    case invalidKey
    case storageFailed
    case retrievalFailed
    case removalFailed
    case signingFailed
    case verificationFailed
}

/// Security analysis report.
@available(iOS 13.0, *)
public struct SecurityAnalysisReport {
    public let algorithm: EncryptionAlgorithm
    public let keyDerivationFunction: KeyDerivationFunction
    public let keyLength: Int
    public let saltLength: Int
    public let encryptionCount: Int
    public let decryptionCount: Int
    
    public var securityLevel: SecurityLevel {
        if keyLength >= 32 && saltLength >= 32 {
            return .high
        } else if keyLength >= 16 && saltLength >= 16 {
            return .medium
        } else {
            return .low
        }
    }
}

/// Security levels.
@available(iOS 13.0, *)
public enum SecurityLevel {
    case low
    case medium
    case high
}

// MARK: - Security Analytics

/// Security analytics protocol.
@available(iOS 13.0, *)
public protocol SecurityAnalytics {
    func recordError(_ error: EncryptionError, error: Error)
    func recordSecureStorage(key: String, size: Int)
    func recordSecureRemoval(key: String)
    
    var encryptionCount: Int { get }
    var decryptionCount: Int { get }
} 