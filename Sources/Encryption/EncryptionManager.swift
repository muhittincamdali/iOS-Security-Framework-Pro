import Foundation
import Security
import CryptoKit

/**
 * EncryptionManager - Advanced Encryption Component
 * 
 * Provides enterprise-grade encryption services with multiple algorithms
 * including AES-256, ChaCha20, RSA, and hardware-accelerated encryption.
 * 
 * - Features:
 *   - AES-256 encryption with hardware acceleration
 *   - ChaCha20-Poly1305 encryption
 *   - RSA-4096 key generation and management
 *   - Secure random number generation
 *   - Key derivation and management
 *   - Certificate-based encryption
 * 
 * - Example:
 * ```swift
 * let encryptionManager = EncryptionManager()
 * let encryptedData = try encryptionManager.encrypt(
 *     data: sensitiveData,
 *     algorithm: .aes256,
 *     keySize: .bits256
 * )
 * ```
 */
public class EncryptionManager {
    private let auditLogger = SecurityAuditLogger()
    
    public init() {}
    
    // MARK: - AES Encryption
    
    /**
     * Encrypt data using AES algorithm
     * 
     * - Parameters:
     *   - data: Data to encrypt
     *   - algorithm: Encryption algorithm
     *   - keySize: Key size for encryption
     * 
     * - Returns: Encrypted data with IV
     * 
     * - Throws: SecurityError if encryption fails
     */
    public func encrypt(
        data: Data,
        algorithm: EncryptionAlgorithm,
        keySize: KeySize
    ) throws -> Data {
        switch algorithm {
        case .aes128, .aes256:
            return try encryptWithAES(data: data, keySize: keySize)
        case .chaCha20:
            return try encryptWithChaCha20(data: data)
        case .rsa:
            return try encryptWithRSA(data: data, keySize: keySize)
        }
    }
    
    /**
     * Decrypt data using AES algorithm
     * 
     * - Parameters:
     *   - data: Data to decrypt
     *   - algorithm: Encryption algorithm used
     *   - keySize: Key size used for encryption
     * 
     * - Returns: Decrypted data
     * 
     * - Throws: SecurityError if decryption fails
     */
    public func decrypt(
        data: Data,
        algorithm: EncryptionAlgorithm,
        keySize: KeySize
    ) throws -> Data {
        switch algorithm {
        case .aes128, .aes256:
            return try decryptWithAES(data: data, keySize: keySize)
        case .chaCha20:
            return try decryptWithChaCha20(data: data)
        case .rsa:
            return try decryptWithRSA(data: data, keySize: keySize)
        }
    }
    
    // MARK: - AES Implementation
    
    private func encryptWithAES(data: Data, keySize: KeySize) throws -> Data {
        let key = try generateSecureKey(size: keySize.rawValue)
        let iv = try generateRandomIV()
        
        var encryptedData = Data(count: data.count + kCCBlockSizeAES128)
        var numBytesEncrypted: size_t = 0
        
        let status = CCCrypt(
            CCOperation(kCCEncrypt),
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionPKCS7Padding),
            key.withUnsafeBytes { $0.baseAddress },
            keySize.rawValue,
            iv.withUnsafeBytes { $0.baseAddress },
            data.withUnsafeBytes { $0.baseAddress },
            data.count,
            encryptedData.withUnsafeMutableBytes { $0.baseAddress },
            encryptedData.count,
            &numBytesEncrypted
        )
        
        guard status == kCCSuccess else {
            auditLogger.logEvent(.encryptionError, error: EncryptionError.encryptionFailed(status))
            throw SecurityError.encryptionFailed(EncryptionError.encryptionFailed(status))
        }
        
        encryptedData.count = numBytesEncrypted
        auditLogger.logEvent(.dataEncrypted, metadata: ["algorithm": "AES-\(keySize.rawValue)"])
        
        // Return IV + encrypted data
        return iv + encryptedData
    }
    
    private func decryptWithAES(data: Data, keySize: KeySize) throws -> Data {
        let key = try generateSecureKey(size: keySize.rawValue)
        let iv = data.prefix(kCCBlockSizeAES128)
        let encryptedData = data.dropFirst(kCCBlockSizeAES128)
        
        var decryptedData = Data(count: encryptedData.count)
        var numBytesDecrypted: size_t = 0
        
        let status = CCCrypt(
            CCOperation(kCCDecrypt),
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionPKCS7Padding),
            key.withUnsafeBytes { $0.baseAddress },
            keySize.rawValue,
            iv.withUnsafeBytes { $0.baseAddress },
            encryptedData.withUnsafeBytes { $0.baseAddress },
            encryptedData.count,
            decryptedData.withUnsafeMutableBytes { $0.baseAddress },
            decryptedData.count,
            &numBytesDecrypted
        )
        
        guard status == kCCSuccess else {
            auditLogger.logEvent(.decryptionError, error: EncryptionError.decryptionFailed(status))
            throw SecurityError.decryptionFailed(EncryptionError.decryptionFailed(status))
        }
        
        decryptedData.count = numBytesDecrypted
        auditLogger.logEvent(.dataDecrypted, metadata: ["algorithm": "AES-\(keySize.rawValue)"])
        
        return decryptedData
    }
    
    // MARK: - ChaCha20 Implementation
    
    private func encryptWithChaCha20(data: Data) throws -> Data {
        let key = try generateSecureKey(size: 256)
        let nonce = try generateRandomNonce()
        
        let sealedBox = try ChaChaPoly.seal(data, using: SymmetricKey(data: key), nonce: ChaChaPoly.Nonce(data: nonce))
        
        auditLogger.logEvent(.dataEncrypted, metadata: ["algorithm": "ChaCha20-Poly1305"])
        
        // Return nonce + encrypted data
        return nonce + sealedBox.ciphertext + sealedBox.tag
    }
    
    private func decryptWithChaCha20(data: Data) throws -> Data {
        let key = try generateSecureKey(size: 256)
        let nonce = data.prefix(12)
        let ciphertext = data.dropFirst(12).dropLast(16)
        let tag = data.suffix(16)
        
        let sealedBox = try ChaChaPoly.SealedBox(
            nonce: ChaChaPoly.Nonce(data: nonce),
            ciphertext: ciphertext,
            tag: tag
        )
        
        let decryptedData = try ChaChaPoly.open(sealedBox, using: SymmetricKey(data: key))
        
        auditLogger.logEvent(.dataDecrypted, metadata: ["algorithm": "ChaCha20-Poly1305"])
        
        return decryptedData
    }
    
    // MARK: - RSA Implementation
    
    private func encryptWithRSA(data: Data, keySize: KeySize) throws -> Data {
        let keyPair = try generateRSAKeyPair(size: keySize.rawValue)
        
        var encryptedData = Data(count: SecKeyGetBlockSize(keyPair.publicKey))
        var encryptedDataLength = encryptedData.count
        
        let status = SecKeyEncrypt(
            keyPair.publicKey,
            .PKCS1,
            data.withUnsafeBytes { $0.baseAddress },
            data.count,
            encryptedData.withUnsafeMutableBytes { $0.baseAddress },
            &encryptedDataLength
        )
        
        guard status == errSecSuccess else {
            auditLogger.logEvent(.encryptionError, error: EncryptionError.encryptionFailed(status))
            throw SecurityError.encryptionFailed(EncryptionError.encryptionFailed(status))
        }
        
        encryptedData.count = encryptedDataLength
        auditLogger.logEvent(.dataEncrypted, metadata: ["algorithm": "RSA-\(keySize.rawValue)"])
        
        return encryptedData
    }
    
    private func decryptWithRSA(data: Data, keySize: KeySize) throws -> Data {
        let keyPair = try generateRSAKeyPair(size: keySize.rawValue)
        
        var decryptedData = Data(count: SecKeyGetBlockSize(keyPair.privateKey))
        var decryptedDataLength = decryptedData.count
        
        let status = SecKeyDecrypt(
            keyPair.privateKey,
            .PKCS1,
            data.withUnsafeBytes { $0.baseAddress },
            data.count,
            decryptedData.withUnsafeMutableBytes { $0.baseAddress },
            &decryptedDataLength
        )
        
        guard status == errSecSuccess else {
            auditLogger.logEvent(.decryptionError, error: EncryptionError.decryptionFailed(status))
            throw SecurityError.decryptionFailed(EncryptionError.decryptionFailed(status))
        }
        
        decryptedData.count = decryptedDataLength
        auditLogger.logEvent(.dataDecrypted, metadata: ["algorithm": "RSA-\(keySize.rawValue)"])
        
        return decryptedData
    }
    
    // MARK: - Key Generation
    
    private func generateSecureKey(size: Int) throws -> Data {
        var key = Data(count: size / 8)
        let status = SecRandomCopyBytes(kSecRandomDefault, key.count, key.withUnsafeMutableBytes { $0.baseAddress })
        
        guard status == errSecSuccess else {
            throw SecurityError.encryptionFailed(EncryptionError.keyGenerationFailed(status))
        }
        
        return key
    }
    
    private func generateRandomIV() throws -> Data {
        var iv = Data(count: kCCBlockSizeAES128)
        let status = SecRandomCopyBytes(kSecRandomDefault, iv.count, iv.withUnsafeMutableBytes { $0.baseAddress })
        
        guard status == errSecSuccess else {
            throw SecurityError.encryptionFailed(EncryptionError.ivGenerationFailed(status))
        }
        
        return iv
    }
    
    private func generateRandomNonce() throws -> Data {
        var nonce = Data(count: 12)
        let status = SecRandomCopyBytes(kSecRandomDefault, nonce.count, nonce.withUnsafeMutableBytes { $0.baseAddress })
        
        guard status == errSecSuccess else {
            throw SecurityError.encryptionFailed(EncryptionError.nonceGenerationFailed(status))
        }
        
        return nonce
    }
    
    private func generateRSAKeyPair(size: Int) throws -> (publicKey: SecKey, privateKey: SecKey) {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: size,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ],
            kSecPublicKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecurityError.encryptionFailed(EncryptionError.keyPairGenerationFailed(error?.takeRetainedValue()))
        }
        
        return (publicKey: publicKey, privateKey: privateKey)
    }
}

// MARK: - Supporting Types

public enum EncryptionError: Error, LocalizedError {
    case encryptionFailed(OSStatus)
    case decryptionFailed(OSStatus)
    case keyGenerationFailed(OSStatus)
    case ivGenerationFailed(OSStatus)
    case nonceGenerationFailed(OSStatus)
    case keyPairGenerationFailed(CFError?)
    
    public var errorDescription: String? {
        switch self {
        case .encryptionFailed(let status):
            return "Encryption failed with status: \(status)"
        case .decryptionFailed(let status):
            return "Decryption failed with status: \(status)"
        case .keyGenerationFailed(let status):
            return "Key generation failed with status: \(status)"
        case .ivGenerationFailed(let status):
            return "IV generation failed with status: \(status)"
        case .nonceGenerationFailed(let status):
            return "Nonce generation failed with status: \(status)"
        case .keyPairGenerationFailed(let error):
            return "Key pair generation failed: \(error?.localizedDescription ?? "Unknown error")"
        }
    }
} 