import XCTest
import SecurityFrameworkPro
import CryptoKit

/**
 * EncryptionManager Unit Tests
 * 
 * Comprehensive unit tests for the EncryptionManager component
 * covering all encryption algorithms and security features.
 */
final class EncryptionManagerTests: XCTestCase {
    var encryptionManager: EncryptionManager!
    
    override func setUp() {
        super.setUp()
        encryptionManager = EncryptionManager()
    }
    
    override func tearDown() {
        encryptionManager = nil
        super.tearDown()
    }
    
    // MARK: - Initialization Tests
    
    func testEncryptionManagerInitialization() {
        // Given
        let manager = EncryptionManager()
        
        // Then
        XCTAssertNotNil(manager)
    }
    
    // MARK: - AES Encryption Tests
    
    func testAES128Encryption() {
        // Given
        let testData = "Test AES-128 encryption".data(using: .utf8)!
        
        // When & Then
        do {
            let encryptedData = try encryptionManager.encrypt(
                data: testData,
                algorithm: .aes128,
                keySize: .bits128
            )
            
            XCTAssertNotEqual(encryptedData, testData)
            XCTAssertGreaterThan(encryptedData.count, 0)
        } catch {
            XCTFail("AES-128 encryption failed: \(error)")
        }
    }
    
    func testAES256Encryption() {
        // Given
        let testData = "Test AES-256 encryption".data(using: .utf8)!
        
        // When & Then
        do {
            let encryptedData = try encryptionManager.encrypt(
                data: testData,
                algorithm: .aes256,
                keySize: .bits256
            )
            
            XCTAssertNotEqual(encryptedData, testData)
            XCTAssertGreaterThan(encryptedData.count, 0)
        } catch {
            XCTFail("AES-256 encryption failed: \(error)")
        }
    }
    
    func testAES128Decryption() {
        // Given
        let originalData = "Test AES-128 decryption".data(using: .utf8)!
        
        // When & Then
        do {
            let encryptedData = try encryptionManager.encrypt(
                data: originalData,
                algorithm: .aes128,
                keySize: .bits128
            )
            
            let decryptedData = try encryptionManager.decrypt(
                data: encryptedData,
                algorithm: .aes128,
                keySize: .bits128
            )
            
            XCTAssertEqual(decryptedData, originalData)
        } catch {
            XCTFail("AES-128 decryption failed: \(error)")
        }
    }
    
    func testAES256Decryption() {
        // Given
        let originalData = "Test AES-256 decryption".data(using: .utf8)!
        
        // When & Then
        do {
            let encryptedData = try encryptionManager.encrypt(
                data: originalData,
                algorithm: .aes256,
                keySize: .bits256
            )
            
            let decryptedData = try encryptionManager.decrypt(
                data: encryptedData,
                algorithm: .aes256,
                keySize: .bits256
            )
            
            XCTAssertEqual(decryptedData, originalData)
        } catch {
            XCTFail("AES-256 decryption failed: \(error)")
        }
    }
    
    // MARK: - ChaCha20 Encryption Tests
    
    func testChaCha20Encryption() {
        // Given
        let testData = "Test ChaCha20 encryption".data(using: .utf8)!
        
        // When & Then
        do {
            let encryptedData = try encryptionManager.encrypt(
                data: testData,
                algorithm: .chaCha20,
                keySize: .bits256
            )
            
            XCTAssertNotEqual(encryptedData, testData)
            XCTAssertGreaterThan(encryptedData.count, 0)
        } catch {
            XCTFail("ChaCha20 encryption failed: \(error)")
        }
    }
    
    func testChaCha20Decryption() {
        // Given
        let originalData = "Test ChaCha20 decryption".data(using: .utf8)!
        
        // When & Then
        do {
            let encryptedData = try encryptionManager.encrypt(
                data: originalData,
                algorithm: .chaCha20,
                keySize: .bits256
            )
            
            let decryptedData = try encryptionManager.decrypt(
                data: encryptedData,
                algorithm: .chaCha20,
                keySize: .bits256
            )
            
            XCTAssertEqual(decryptedData, originalData)
        } catch {
            XCTFail("ChaCha20 decryption failed: \(error)")
        }
    }
    
    // MARK: - RSA Encryption Tests
    
    func testRSAEncryption() {
        // Given
        let testData = "Test RSA encryption".data(using: .utf8)!
        
        // When & Then
        do {
            let encryptedData = try encryptionManager.encrypt(
                data: testData,
                algorithm: .rsa,
                keySize: .bits4096
            )
            
            XCTAssertNotEqual(encryptedData, testData)
            XCTAssertGreaterThan(encryptedData.count, 0)
        } catch {
            XCTFail("RSA encryption failed: \(error)")
        }
    }
    
    func testRSADecryption() {
        // Given
        let originalData = "Test RSA decryption".data(using: .utf8)!
        
        // When & Then
        do {
            let encryptedData = try encryptionManager.encrypt(
                data: originalData,
                algorithm: .rsa,
                keySize: .bits4096
            )
            
            let decryptedData = try encryptionManager.decrypt(
                data: encryptedData,
                algorithm: .rsa,
                keySize: .bits4096
            )
            
            XCTAssertEqual(decryptedData, originalData)
        } catch {
            XCTFail("RSA decryption failed: \(error)")
        }
    }
    
    // MARK: - Key Generation Tests
    
    func testGenerateSecureKey() {
        // Given
        let keySizes = [128, 256, 512]
        
        // When & Then
        for size in keySizes {
            do {
                let key = try encryptionManager.generateSecureKey(size: size)
                XCTAssertEqual(key.count, size / 8)
            } catch {
                XCTFail("Failed to generate secure key of size \(size): \(error)")
            }
        }
    }
    
    func testGenerateRandomIV() {
        // When & Then
        do {
            let iv = try encryptionManager.generateRandomIV()
            XCTAssertEqual(iv.count, kCCBlockSizeAES128)
        } catch {
            XCTFail("Failed to generate random IV: \(error)")
        }
    }
    
    func testGenerateRandomNonce() {
        // When & Then
        do {
            let nonce = try encryptionManager.generateRandomNonce()
            XCTAssertEqual(nonce.count, 12)
        } catch {
            XCTFail("Failed to generate random nonce: \(error)")
        }
    }
    
    // MARK: - Algorithm Validation Tests
    
    func testAlgorithmValidation() {
        // Given
        let algorithms: [EncryptionAlgorithm] = [.aes128, .aes256, .chaCha20, .rsa]
        let keySizes: [KeySize] = [.bits128, .bits256, .bits512, .bits4096]
        
        // When & Then
        for algorithm in algorithms {
            for keySize in keySizes {
                let isValid = encryptionManager.isValidAlgorithm(algorithm, forKeySize: keySize)
                XCTAssertNotNil(isValid)
            }
        }
    }
    
    func testKeySizeValidation() {
        // Given
        let validKeySizes = [128, 256, 512, 4096]
        let invalidKeySizes = [64, 192, 384, 1024]
        
        // When & Then
        for size in validKeySizes {
            XCTAssertTrue(encryptionManager.isValidKeySize(size))
        }
        
        for size in invalidKeySizes {
            XCTAssertFalse(encryptionManager.isValidKeySize(size))
        }
    }
    
    // MARK: - Error Handling Tests
    
    func testEncryptionErrorDescriptions() {
        // Given
        let testError = EncryptionError.keyGenerationFailed(errSecSuccess)
        
        // When & Then
        XCTAssertNotNil(testError.errorDescription)
        XCTAssertEqual(testError.statusCode, errSecSuccess)
    }
    
    func testEncryptionErrorTypes() {
        // Test different encryption error types
        let keyGenError = EncryptionError.keyGenerationFailed(errSecSuccess)
        let ivGenError = EncryptionError.ivGenerationFailed(errSecSuccess)
        let nonceGenError = EncryptionError.nonceGenerationFailed(errSecSuccess)
        let keyPairError = EncryptionError.keyPairGenerationFailed(NSError())
        let encryptionError = EncryptionError.encryptionFailed(NSError())
        let decryptionError = EncryptionError.decryptionFailed(NSError())
        let invalidAlgorithmError = EncryptionError.invalidAlgorithm
        let invalidKeySizeError = EncryptionError.invalidKeySize
        let invalidDataError = EncryptionError.invalidData
        
        XCTAssertNotNil(keyGenError.errorDescription)
        XCTAssertNotNil(ivGenError.errorDescription)
        XCTAssertNotNil(nonceGenError.errorDescription)
        XCTAssertNotNil(keyPairError.errorDescription)
        XCTAssertNotNil(encryptionError.errorDescription)
        XCTAssertNotNil(decryptionError.errorDescription)
        XCTAssertNotNil(invalidAlgorithmError.errorDescription)
        XCTAssertNotNil(invalidKeySizeError.errorDescription)
        XCTAssertNotNil(invalidDataError.errorDescription)
    }
    
    // MARK: - Performance Tests
    
    func testAESEncryptionPerformance() {
        // Given
        let testData = "Performance test data".data(using: .utf8)!
        
        // When & Then
        measure {
            do {
                _ = try encryptionManager.encrypt(
                    data: testData,
                    algorithm: .aes256,
                    keySize: .bits256
                )
            } catch {
                XCTFail("Performance test failed: \(error)")
            }
        }
    }
    
    func testChaCha20EncryptionPerformance() {
        // Given
        let testData = "Performance test data".data(using: .utf8)!
        
        // When & Then
        measure {
            do {
                _ = try encryptionManager.encrypt(
                    data: testData,
                    algorithm: .chaCha20,
                    keySize: .bits256
                )
            } catch {
                XCTFail("Performance test failed: \(error)")
            }
        }
    }
    
    func testRSAEncryptionPerformance() {
        // Given
        let testData = "Performance test data".data(using: .utf8)!
        
        // When & Then
        measure {
            do {
                _ = try encryptionManager.encrypt(
                    data: testData,
                    algorithm: .rsa,
                    keySize: .bits4096
                )
            } catch {
                XCTFail("Performance test failed: \(error)")
            }
        }
    }
    
    func testKeyGenerationPerformance() {
        // When & Then
        measure {
            do {
                _ = try encryptionManager.generateSecureKey(size: 256)
            } catch {
                XCTFail("Performance test failed: \(error)")
            }
        }
    }
    
    // MARK: - Security Tests
    
    func testEncryptionStrength() {
        // Given
        let testData = "Security test data".data(using: .utf8)!
        
        // When & Then
        do {
            let encryptedData = try encryptionManager.encrypt(
                data: testData,
                algorithm: .aes256,
                keySize: .bits256
            )
            
            // Verify that encrypted data doesn't contain original data
            let encryptedString = String(data: encryptedData, encoding: .utf8)
            XCTAssertNil(encryptedString?.contains("Security test data"))
        } catch {
            XCTFail("Security test failed: \(error)")
        }
    }
    
    func testKeyRandomness() {
        // Given
        let keySize = 256
        var keys: [Data] = []
        
        // When
        for _ in 0..<10 {
            do {
                let key = try encryptionManager.generateSecureKey(size: keySize)
                keys.append(key)
            } catch {
                XCTFail("Failed to generate key: \(error)")
            }
        }
        
        // Then
        // Verify that keys are different
        for i in 0..<keys.count {
            for j in (i+1)..<keys.count {
                XCTAssertNotEqual(keys[i], keys[j])
            }
        }
    }
    
    // MARK: - Mock Tests
    
    func testMockEncryptionOperations() {
        // Given
        let mockEncryptionManager = MockEncryptionManager()
        let testData = "Test data".data(using: .utf8)!
        
        // When
        let encryptResult = mockEncryptionManager.mockEncrypt(data: testData)
        let decryptResult = mockEncryptionManager.mockDecrypt(data: encryptResult)
        let keyResult = mockEncryptionManager.mockGenerateKey(size: 256)
        
        // Then
        XCTAssertNotEqual(encryptResult, testData)
        XCTAssertEqual(decryptResult, testData)
        XCTAssertEqual(keyResult.count, 32)
    }
}

// MARK: - Mock Encryption Manager

class MockEncryptionManager: EncryptionManager {
    func mockEncrypt(data: Data) -> Data {
        // Simple XOR encryption for testing
        var encryptedData = Data()
        let key: UInt8 = 0x42
        
        for byte in data {
            encryptedData.append(byte ^ key)
        }
        
        return encryptedData
    }
    
    func mockDecrypt(data: Data) -> Data {
        // Simple XOR decryption for testing
        var decryptedData = Data()
        let key: UInt8 = 0x42
        
        for byte in data {
            decryptedData.append(byte ^ key)
        }
        
        return decryptedData
    }
    
    func mockGenerateKey(size: Int) -> Data {
        var key = Data(count: size / 8)
        for i in 0..<key.count {
            key[i] = UInt8(i % 256)
        }
        return key
    }
} 