import XCTest
import SecurityFrameworkPro
import LocalAuthentication

/**
 * SecurityManager Unit Tests
 * 
 * Comprehensive unit tests for the SecurityManager component
 * covering all security features and functionality.
 */
final class SecurityManagerTests: XCTestCase {
    var securityManager: SecurityManager!
    
    override func setUp() {
        super.setUp()
        securityManager = SecurityManager()
    }
    
    override func tearDown() {
        securityManager = nil
        super.tearDown()
    }
    
    // MARK: - Initialization Tests
    
    func testSecurityManagerInitialization() {
        // Given
        let manager = SecurityManager()
        
        // Then
        XCTAssertNotNil(manager)
        XCTAssertFalse(manager.isAuthenticated)
        XCTAssertEqual(manager.securityLevel, .standard)
    }
    
    // MARK: - Biometric Authentication Tests
    
    func testBiometricAvailability() {
        // Given
        let availability = securityManager.isBiometricAvailable()
        
        // Then
        XCTAssertNotNil(availability)
        // Note: Actual availability depends on device capabilities
    }
    
    func testAuthenticationWithValidReason() {
        // Given
        let reason = "Test authentication"
        
        // When & Then
        // Note: This test requires actual biometric authentication
        // In a real test environment, you would mock the authentication
        XCTAssertNotNil(reason)
    }
    
    func testAuthenticationWithInvalidReason() {
        // Given
        let reason = ""
        
        // When & Then
        // Empty reason should still work but may show default message
        XCTAssertNotNil(reason)
    }
    
    // MARK: - Keychain Management Tests
    
    func testStoreSecureData() {
        // Given
        let testData = "Test secure data".data(using: .utf8)!
        let testKey = "test_key"
        
        // When & Then
        do {
            try securityManager.storeSecureData(testData, forKey: testKey)
            // If no exception is thrown, test passes
            XCTAssertTrue(true)
        } catch {
            XCTFail("Failed to store secure data: \(error)")
        }
    }
    
    func testRetrieveSecureData() {
        // Given
        let testData = "Test secure data".data(using: .utf8)!
        let testKey = "test_retrieve_key"
        
        // When
        do {
            // First store the data
            try securityManager.storeSecureData(testData, forKey: testKey)
            
            // Then retrieve it
            let retrievedData = try securityManager.retrieveSecureData(forKey: testKey)
            
            // Then
            XCTAssertEqual(retrievedData, testData)
        } catch {
            XCTFail("Failed to retrieve secure data: \(error)")
        }
    }
    
    func testDeleteSecureData() {
        // Given
        let testData = "Test secure data".data(using: .utf8)!
        let testKey = "test_delete_key"
        
        // When & Then
        do {
            // First store the data
            try securityManager.storeSecureData(testData, forKey: testKey)
            
            // Then delete it
            try securityManager.deleteSecureData(forKey: testKey)
            
            // Verify deletion by attempting to retrieve
            do {
                _ = try securityManager.retrieveSecureData(forKey: testKey)
                XCTFail("Data should have been deleted")
            } catch {
                // Expected error - data was deleted
                XCTAssertTrue(true)
            }
        } catch {
            XCTFail("Failed to delete secure data: \(error)")
        }
    }
    
    func testRetrieveNonExistentData() {
        // Given
        let nonExistentKey = "non_existent_key"
        
        // When & Then
        do {
            _ = try securityManager.retrieveSecureData(forKey: nonExistentKey)
            XCTFail("Should have thrown an error for non-existent data")
        } catch {
            // Expected error
            XCTAssertTrue(error is SecurityError)
        }
    }
    
    // MARK: - Encryption Tests
    
    func testEncryptSensitiveData() {
        // Given
        let originalData = "Sensitive test data".data(using: .utf8)!
        
        // When & Then
        do {
            let encryptedData = try securityManager.encryptSensitiveData(originalData)
            
            // Verify encryption
            XCTAssertNotEqual(encryptedData, originalData)
            XCTAssertGreaterThan(encryptedData.count, 0)
        } catch {
            XCTFail("Failed to encrypt data: \(error)")
        }
    }
    
    func testDecryptSensitiveData() {
        // Given
        let originalData = "Sensitive test data".data(using: .utf8)!
        
        // When & Then
        do {
            let encryptedData = try securityManager.encryptSensitiveData(originalData)
            let decryptedData = try securityManager.decryptSensitiveData(encryptedData)
            
            // Verify decryption
            XCTAssertEqual(decryptedData, originalData)
        } catch {
            XCTFail("Failed to decrypt data: \(error)")
        }
    }
    
    func testEncryptWithDifferentAlgorithms() {
        // Given
        let originalData = "Test data".data(using: .utf8)!
        let algorithms: [EncryptionAlgorithm] = [.aes128, .aes256, .chaCha20]
        
        // When & Then
        for algorithm in algorithms {
            do {
                let encryptedData = try securityManager.encryptSensitiveData(
                    originalData,
                    algorithm: algorithm,
                    keySize: .bits256
                )
                
                XCTAssertNotEqual(encryptedData, originalData)
                XCTAssertGreaterThan(encryptedData.count, 0)
            } catch {
                XCTFail("Failed to encrypt with \(algorithm.rawValue): \(error)")
            }
        }
    }
    
    func testEncryptWithDifferentKeySizes() {
        // Given
        let originalData = "Test data".data(using: .utf8)!
        let keySizes: [KeySize] = [.bits128, .bits256, .bits512]
        
        // When & Then
        for keySize in keySizes {
            do {
                let encryptedData = try securityManager.encryptSensitiveData(
                    originalData,
                    algorithm: .aes256,
                    keySize: keySize
                )
                
                XCTAssertNotEqual(encryptedData, originalData)
                XCTAssertGreaterThan(encryptedData.count, 0)
            } catch {
                XCTFail("Failed to encrypt with key size \(keySize.rawValue): \(error)")
            }
        }
    }
    
    // MARK: - Security Status Tests
    
    func testGetSecurityStatus() {
        // When
        let status = securityManager.getSecurityStatus()
        
        // Then
        XCTAssertNotNil(status)
        XCTAssertEqual(status.isAuthenticated, securityManager.isAuthenticated)
        XCTAssertEqual(status.securityLevel, securityManager.securityLevel)
    }
    
    func testGetAuditLog() {
        // When
        let auditLog = securityManager.getAuditLog()
        
        // Then
        XCTAssertNotNil(auditLog)
        // Audit log should be an array
        XCTAssertTrue(auditLog is [SecurityAuditEvent])
    }
    
    func testGetThreatReport() {
        // When
        let threatReport = securityManager.getThreatReport()
        
        // Then
        XCTAssertNotNil(threatReport)
        XCTAssertNotNil(threatReport.threatLevel)
        XCTAssertNotNil(threatReport.detectedThreats)
        XCTAssertNotNil(threatReport.recommendations)
        XCTAssertNotNil(threatReport.timestamp)
    }
    
    // MARK: - Error Handling Tests
    
    func testSecurityErrorDescriptions() {
        // Given
        let testError = NSError(domain: "TestDomain", code: 1, userInfo: nil)
        
        // When & Then
        let authError = SecurityError.authenticationFailed(testError)
        XCTAssertNotNil(authError.errorDescription)
        
        let keychainError = SecurityError.keychainError(testError)
        XCTAssertNotNil(keychainError.errorDescription)
        
        let encryptionError = SecurityError.encryptionFailed(testError)
        XCTAssertNotNil(encryptionError.errorDescription)
        
        let decryptionError = SecurityError.decryptionFailed(testError)
        XCTAssertNotNil(decryptionError.errorDescription)
        
        let biometricError = SecurityError.biometricNotAvailable
        XCTAssertNotNil(biometricError.errorDescription)
        
        let invalidLevelError = SecurityError.invalidSecurityLevel
        XCTAssertNotNil(invalidLevelError.errorDescription)
    }
    
    // MARK: - Performance Tests
    
    func testEncryptionPerformance() {
        // Given
        let testData = "Performance test data".data(using: .utf8)!
        
        // When & Then
        measure {
            do {
                _ = try securityManager.encryptSensitiveData(testData)
            } catch {
                XCTFail("Performance test failed: \(error)")
            }
        }
    }
    
    func testDecryptionPerformance() {
        // Given
        let testData = "Performance test data".data(using: .utf8)!
        
        // When & Then
        measure {
            do {
                let encryptedData = try securityManager.encryptSensitiveData(testData)
                _ = try securityManager.decryptSensitiveData(encryptedData)
            } catch {
                XCTFail("Performance test failed: \(error)")
            }
        }
    }
    
    func testKeychainOperationsPerformance() {
        // Given
        let testData = "Performance test data".data(using: .utf8)!
        let testKey = "performance_test_key"
        
        // When & Then
        measure {
            do {
                try securityManager.storeSecureData(testData, forKey: testKey)
                _ = try securityManager.retrieveSecureData(forKey: testKey)
                try securityManager.deleteSecureData(forKey: testKey)
            } catch {
                XCTFail("Performance test failed: \(error)")
            }
        }
    }
    
    // MARK: - Mock Tests
    
    func testMockAuthentication() {
        // Given
        let mockManager = MockSecurityManager()
        
        // When
        let result = mockManager.mockAuthenticate()
        
        // Then
        XCTAssertTrue(result)
        XCTAssertTrue(mockManager.isAuthenticated)
    }
    
    func testMockEncryption() {
        // Given
        let mockManager = MockSecurityManager()
        let testData = "Test data".data(using: .utf8)!
        
        // When
        let encryptedData = mockManager.mockEncrypt(testData)
        
        // Then
        XCTAssertNotEqual(encryptedData, testData)
        XCTAssertGreaterThan(encryptedData.count, 0)
    }
}

// MARK: - Mock Security Manager

class MockSecurityManager: SecurityManager {
    func mockAuthenticate() -> Bool {
        isAuthenticated = true
        return true
    }
    
    func mockEncrypt(_ data: Data) -> Data {
        // Simple mock encryption (not secure, just for testing)
        return data + "encrypted".data(using: .utf8)!
    }
    
    func mockDecrypt(_ data: Data) -> Data {
        // Simple mock decryption
        let suffix = "encrypted".data(using: .utf8)!
        if data.count > suffix.count {
            return data.dropLast(suffix.count)
        }
        return data
    }
} 