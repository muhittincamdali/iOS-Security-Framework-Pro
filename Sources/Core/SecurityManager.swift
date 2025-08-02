import Foundation
import LocalAuthentication
import Security

/**
 * SecurityManager - Core Security Management Component
 * 
 * A comprehensive security manager that handles biometric authentication,
 * keychain management, encryption, and security monitoring.
 * 
 * - Features:
 *   - Biometric authentication (Face ID, Touch ID)
 *   - Keychain management for secure storage
 *   - Encryption and decryption services
 *   - Security audit logging
 *   - Threat detection and monitoring
 * 
 * - Example:
 * ```swift
 * let securityManager = SecurityManager()
 * let isAuthenticated = try await securityManager.authenticateUser()
 * ```
 */
public class SecurityManager: ObservableObject {
    private let biometricAuth = BiometricAuthenticator()
    private let keychainManager = KeychainManager()
    private let encryptionManager = EncryptionManager()
    private let auditLogger = SecurityAuditLogger()
    private let threatDetector = ThreatDetector()
    
    @Published public var isAuthenticated = false
    @Published public var securityLevel: SecurityLevel = .standard
    
    public enum SecurityLevel {
        case basic
        case standard
        case high
        case enterprise
    }
    
    public init() {
        setupSecurityMonitoring()
    }
    
    // MARK: - Biometric Authentication
    
    /**
     * Authenticate user using biometric authentication
     * 
     * - Parameters:
     *   - reason: Authentication reason for user
     *   - policy: Authentication policy to use
     * 
     * - Returns: Authentication result
     * 
     * - Throws: SecurityError if authentication fails
     */
    public func authenticateUser(
        reason: String = "Authenticate to access secure data",
        policy: LAPolicy = .deviceOwnerAuthenticationWithBiometrics
    ) async throws -> Bool {
        do {
            let result = try await biometricAuth.authenticate(reason: reason, policy: policy)
            isAuthenticated = result
            
            if result {
                auditLogger.logEvent(.authenticationSuccess)
                threatDetector.recordSuccessfulAuthentication()
            } else {
                auditLogger.logEvent(.authenticationFailure)
                threatDetector.recordFailedAuthentication()
            }
            
            return result
        } catch {
            auditLogger.logEvent(.authenticationError, error: error)
            throw SecurityError.authenticationFailed(error)
        }
    }
    
    /**
     * Check if biometric authentication is available
     * 
     * - Returns: Biometric availability status
     */
    public func isBiometricAvailable() -> BiometricAvailability {
        return biometricAuth.checkAvailability()
    }
    
    // MARK: - Keychain Management
    
    /**
     * Store sensitive data securely in keychain
     * 
     * - Parameters:
     *   - data: Data to store
     *   - key: Unique key for data
     *   - accessibility: Keychain accessibility level
     * 
     * - Throws: SecurityError if storage fails
     */
    public func storeSecureData(
        _ data: Data,
        forKey key: String,
        accessibility: CFString = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ) throws {
        do {
            try keychainManager.store(data: data, forKey: key, accessibility: accessibility)
            auditLogger.logEvent(.dataStored, metadata: ["key": key])
        } catch {
            auditLogger.logEvent(.dataStorageError, error: error)
            throw SecurityError.keychainError(error)
        }
    }
    
    /**
     * Retrieve secure data from keychain
     * 
     * - Parameters:
     *   - key: Unique key for data
     * 
     * - Returns: Stored data
     * 
     * - Throws: SecurityError if retrieval fails
     */
    public func retrieveSecureData(forKey key: String) throws -> Data {
        do {
            let data = try keychainManager.retrieve(forKey: key)
            auditLogger.logEvent(.dataRetrieved, metadata: ["key": key])
            return data
        } catch {
            auditLogger.logEvent(.dataRetrievalError, error: error)
            throw SecurityError.keychainError(error)
        }
    }
    
    /**
     * Delete secure data from keychain
     * 
     * - Parameters:
     *   - key: Unique key for data
     * 
     * - Throws: SecurityError if deletion fails
     */
    public func deleteSecureData(forKey key: String) throws {
        do {
            try keychainManager.delete(forKey: key)
            auditLogger.logEvent(.dataDeleted, metadata: ["key": key])
        } catch {
            auditLogger.logEvent(.dataDeletionError, error: error)
            throw SecurityError.keychainError(error)
        }
    }
    
    // MARK: - Encryption Services
    
    /**
     * Encrypt sensitive data
     * 
     * - Parameters:
     *   - data: Data to encrypt
     *   - algorithm: Encryption algorithm
     *   - keySize: Key size for encryption
     * 
     * - Returns: Encrypted data
     * 
     * - Throws: SecurityError if encryption fails
     */
    public func encryptSensitiveData(
        _ data: Data,
        algorithm: EncryptionAlgorithm = .aes256,
        keySize: KeySize = .bits256
    ) throws -> Data {
        do {
            let encryptedData = try encryptionManager.encrypt(
                data: data,
                algorithm: algorithm,
                keySize: keySize
            )
            auditLogger.logEvent(.dataEncrypted, metadata: ["algorithm": algorithm.rawValue])
            return encryptedData
        } catch {
            auditLogger.logEvent(.encryptionError, error: error)
            throw SecurityError.encryptionFailed(error)
        }
    }
    
    /**
     * Decrypt sensitive data
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
    public func decryptSensitiveData(
        _ data: Data,
        algorithm: EncryptionAlgorithm = .aes256,
        keySize: KeySize = .bits256
    ) throws -> Data {
        do {
            let decryptedData = try encryptionManager.decrypt(
                data: data,
                algorithm: algorithm,
                keySize: keySize
            )
            auditLogger.logEvent(.dataDecrypted, metadata: ["algorithm": algorithm.rawValue])
            return decryptedData
        } catch {
            auditLogger.logEvent(.decryptionError, error: error)
            throw SecurityError.decryptionFailed(error)
        }
    }
    
    // MARK: - Security Monitoring
    
    /**
     * Get current security status
     * 
     * - Returns: Security status information
     */
    public func getSecurityStatus() -> SecurityStatus {
        return SecurityStatus(
            isAuthenticated: isAuthenticated,
            biometricAvailable: isBiometricAvailable(),
            securityLevel: securityLevel,
            threatLevel: threatDetector.getCurrentThreatLevel(),
            lastAuditEvent: auditLogger.getLastEvent()
        )
    }
    
    /**
     * Get security audit log
     * 
     * - Returns: Array of audit events
     */
    public func getAuditLog() -> [SecurityAuditEvent] {
        return auditLogger.getAuditLog()
    }
    
    /**
     * Get threat detection report
     * 
     * - Returns: Threat detection report
     */
    public func getThreatReport() -> ThreatReport {
        return threatDetector.generateReport()
    }
    
    // MARK: - Private Methods
    
    private func setupSecurityMonitoring() {
        // Setup continuous security monitoring
        threatDetector.startMonitoring()
        auditLogger.startLogging()
    }
}

// MARK: - Supporting Types

public enum SecurityError: Error, LocalizedError {
    case authenticationFailed(Error)
    case keychainError(Error)
    case encryptionFailed(Error)
    case decryptionFailed(Error)
    case biometricNotAvailable
    case invalidSecurityLevel
    
    public var errorDescription: String? {
        switch self {
        case .authenticationFailed(let error):
            return "Authentication failed: \(error.localizedDescription)"
        case .keychainError(let error):
            return "Keychain error: \(error.localizedDescription)"
        case .encryptionFailed(let error):
            return "Encryption failed: \(error.localizedDescription)"
        case .decryptionFailed(let error):
            return "Decryption failed: \(error.localizedDescription)"
        case .biometricNotAvailable:
            return "Biometric authentication not available"
        case .invalidSecurityLevel:
            return "Invalid security level"
        }
    }
}

public enum EncryptionAlgorithm: String, CaseIterable {
    case aes128 = "AES-128"
    case aes256 = "AES-256"
    case chaCha20 = "ChaCha20"
    case rsa = "RSA"
}

public enum KeySize: Int, CaseIterable {
    case bits128 = 128
    case bits256 = 256
    case bits512 = 512
    case bits2048 = 2048
    case bits4096 = 4096
}

public struct SecurityStatus {
    public let isAuthenticated: Bool
    public let biometricAvailable: BiometricAvailability
    public let securityLevel: SecurityManager.SecurityLevel
    public let threatLevel: ThreatLevel
    public let lastAuditEvent: SecurityAuditEvent?
}

public enum ThreatLevel {
    case low
    case medium
    case high
    case critical
}

public struct ThreatReport {
    public let threatLevel: ThreatLevel
    public let detectedThreats: [SecurityThreat]
    public let recommendations: [String]
    public let timestamp: Date
}

public struct SecurityThreat {
    public let type: ThreatType
    public let severity: ThreatLevel
    public let description: String
    public let timestamp: Date
}

public enum ThreatType {
    case bruteForce
    case suspiciousActivity
    case unauthorizedAccess
    case dataBreach
    case malware
}

public struct SecurityAuditEvent {
    public let type: AuditEventType
    public let timestamp: Date
    public let metadata: [String: Any]?
    public let error: Error?
}

public enum AuditEventType {
    case authenticationSuccess
    case authenticationFailure
    case authenticationError
    case dataStored
    case dataRetrieved
    case dataDeleted
    case dataEncrypted
    case dataDecrypted
    case encryptionError
    case decryptionError
    case dataStorageError
    case dataRetrievalError
    case dataDeletionError
    case threatDetected
    case securityLevelChanged
} 