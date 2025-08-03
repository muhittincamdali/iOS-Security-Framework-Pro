import XCTest
import SecurityFrameworkPro

/**
 * KeychainManager Unit Tests
 * 
 * Comprehensive unit tests for the KeychainManager component
 * covering all keychain operations and security features.
 */
final class KeychainManagerTests: XCTestCase {
    var keychainManager: KeychainManager!
    
    override func setUp() {
        super.setUp()
        keychainManager = KeychainManager()
    }
    
    override func tearDown() {
        keychainManager = nil
        super.tearDown()
    }
    
    // MARK: - Initialization Tests
    
    func testKeychainManagerInitialization() {
        // Given
        let manager = KeychainManager()
        
        // Then
        XCTAssertNotNil(manager)
    }
    
    // MARK: - Data Storage Tests
    
    func testStoreData() {
        // Given
        let testData = "Test data".data(using: .utf8)!
        let testKey = "test_key"
        
        // When & Then
        do {
            try keychainManager.store(data: testData, forKey: testKey)
            XCTAssertTrue(true)
        } catch {
            XCTFail("Failed to store data: \(error)")
        }
    }
    
    func testStoreDataWithCustomAccessibility() {
        // Given
        let testData = "Test data".data(using: .utf8)!
        let testKey = "test_custom_accessibility_key"
        
        // When & Then
        do {
            try keychainManager.store(
                data: testData,
                forKey: testKey,
                accessibility: kSecAttrAccessibleWhenUnlocked
            )
            XCTAssertTrue(true)
        } catch {
            XCTFail("Failed to store data with custom accessibility: \(error)")
        }
    }
    
    func testStoreDataWithAttributes() {
        // Given
        let testData = "Test data".data(using: .utf8)!
        let testKey = "test_attributes_key"
        let attributes = ["custom_attribute": "custom_value"]
        
        // When & Then
        do {
            try keychainManager.store(
                data: testData,
                forKey: testKey,
                attributes: attributes
            )
            XCTAssertTrue(true)
        } catch {
            XCTFail("Failed to store data with attributes: \(error)")
        }
    }
    
    // MARK: - Data Retrieval Tests
    
    func testRetrieveData() {
        // Given
        let testData = "Test data".data(using: .utf8)!
        let testKey = "test_retrieve_key"
        
        // When
        do {
            try keychainManager.store(data: testData, forKey: testKey)
            let retrievedData = try keychainManager.retrieve(forKey: testKey)
            
            // Then
            XCTAssertEqual(retrievedData, testData)
        } catch {
            XCTFail("Failed to retrieve data: \(error)")
        }
    }
    
    func testRetrieveNonExistentData() {
        // Given
        let nonExistentKey = "non_existent_key"
        
        // When & Then
        do {
            _ = try keychainManager.retrieve(forKey: nonExistentKey)
            XCTFail("Should have thrown an error for non-existent data")
        } catch {
            // Expected error
            XCTAssertTrue(error is SecurityError)
        }
    }
    
    // MARK: - Data Deletion Tests
    
    func testDeleteData() {
        // Given
        let testData = "Test data".data(using: .utf8)!
        let testKey = "test_delete_key"
        
        // When & Then
        do {
            try keychainManager.store(data: testData, forKey: testKey)
            try keychainManager.delete(forKey: testKey)
            
            // Verify deletion
            do {
                _ = try keychainManager.retrieve(forKey: testKey)
                XCTFail("Data should have been deleted")
            } catch {
                XCTAssertTrue(true)
            }
        } catch {
            XCTFail("Failed to delete data: \(error)")
        }
    }
    
    func testDeleteNonExistentData() {
        // Given
        let nonExistentKey = "non_existent_delete_key"
        
        // When & Then
        do {
            try keychainManager.delete(forKey: nonExistentKey)
            XCTAssertTrue(true)
        } catch {
            XCTFail("Failed to delete non-existent data: \(error)")
        }
    }
    
    // MARK: - Data Existence Tests
    
    func testExists() {
        // Given
        let testData = "Test data".data(using: .utf8)!
        let testKey = "test_exists_key"
        
        // When
        do {
            try keychainManager.store(data: testData, forKey: testKey)
            let exists = keychainManager.exists(forKey: testKey)
            
            // Then
            XCTAssertTrue(exists)
        } catch {
            XCTFail("Failed to test exists: \(error)")
        }
    }
    
    func testExistsForNonExistentData() {
        // Given
        let nonExistentKey = "non_existent_exists_key"
        
        // When
        let exists = keychainManager.exists(forKey: nonExistentKey)
        
        // Then
        XCTAssertFalse(exists)
    }
    
    // MARK: - Key Management Tests
    
    func testGetAllKeys() {
        // Given
        let testData = "Test data".data(using: .utf8)!
        let testKeys = ["key1", "key2", "key3"]
        
        // When
        do {
            for key in testKeys {
                try keychainManager.store(data: testData, forKey: key)
            }
            
            let allKeys = keychainManager.getAllKeys()
            
            // Then
            XCTAssertGreaterThanOrEqual(allKeys.count, testKeys.count)
        } catch {
            XCTFail("Failed to get all keys: \(error)")
        }
    }
    
    func testClearAll() {
        // Given
        let testData = "Test data".data(using: .utf8)!
        let testKeys = ["clear_key1", "clear_key2"]
        
        // When
        do {
            for key in testKeys {
                try keychainManager.store(data: testData, forKey: key)
            }
            
            try keychainManager.clearAll()
            
            // Then
            let allKeys = keychainManager.getAllKeys()
            XCTAssertEqual(allKeys.count, 0)
        } catch {
            XCTFail("Failed to clear all data: \(error)")
        }
    }
    
    // MARK: - Accessibility Tests
    
    func testSetAccessibility() {
        // Given
        let testData = "Test data".data(using: .utf8)!
        let testKey = "test_accessibility_key"
        
        // When
        do {
            try keychainManager.store(data: testData, forKey: testKey)
            try keychainManager.setAccessibility(kSecAttrAccessibleAlways, forKey: testKey)
            
            // Then
            let accessibility = keychainManager.getAccessibility(forKey: testKey)
            XCTAssertNotNil(accessibility)
        } catch {
            XCTFail("Failed to set accessibility: \(error)")
        }
    }
    
    func testGetAccessibility() {
        // Given
        let testData = "Test data".data(using: .utf8)!
        let testKey = "test_get_accessibility_key"
        
        // When
        do {
            try keychainManager.store(data: testData, forKey: testKey)
            let accessibility = keychainManager.getAccessibility(forKey: testKey)
            
            // Then
            XCTAssertNotNil(accessibility)
        } catch {
            XCTFail("Failed to get accessibility: \(error)")
        }
    }
    
    // MARK: - Error Handling Tests
    
    func testKeychainErrorDescriptions() {
        // Given
        let testError = KeychainError.addFailed(errSecDuplicateItem)
        
        // When & Then
        XCTAssertNotNil(testError.errorDescription)
        XCTAssertEqual(testError.statusCode, errSecDuplicateItem)
    }
    
    func testKeychainErrorTypes() {
        // Test different keychain error types
        let addError = KeychainError.addFailed(errSecSuccess)
        let updateError = KeychainError.updateFailed(errSecSuccess)
        let retrieveError = KeychainError.retrieveFailed(errSecSuccess)
        let deleteError = KeychainError.deleteFailed(errSecSuccess)
        let invalidDataError = KeychainError.invalidData
        let itemNotFoundError = KeychainError.itemNotFound
        
        XCTAssertNotNil(addError.errorDescription)
        XCTAssertNotNil(updateError.errorDescription)
        XCTAssertNotNil(retrieveError.errorDescription)
        XCTAssertNotNil(deleteError.errorDescription)
        XCTAssertNotNil(invalidDataError.errorDescription)
        XCTAssertNotNil(itemNotFoundError.errorDescription)
    }
    
    // MARK: - Performance Tests
    
    func testStorePerformance() {
        // Given
        let testData = "Performance test data".data(using: .utf8)!
        let testKey = "performance_test_key"
        
        // When & Then
        measure {
            do {
                try keychainManager.store(data: testData, forKey: testKey)
            } catch {
                XCTFail("Performance test failed: \(error)")
            }
        }
    }
    
    func testRetrievePerformance() {
        // Given
        let testData = "Performance test data".data(using: .utf8)!
        let testKey = "performance_retrieve_key"
        
        // When & Then
        measure {
            do {
                try keychainManager.store(data: testData, forKey: testKey)
                _ = try keychainManager.retrieve(forKey: testKey)
            } catch {
                XCTFail("Performance test failed: \(error)")
            }
        }
    }
    
    func testDeletePerformance() {
        // Given
        let testData = "Performance test data".data(using: .utf8)!
        let testKey = "performance_delete_key"
        
        // When & Then
        measure {
            do {
                try keychainManager.store(data: testData, forKey: testKey)
                try keychainManager.delete(forKey: testKey)
            } catch {
                XCTFail("Performance test failed: \(error)")
            }
        }
    }
    
    // MARK: - Mock Tests
    
    func testMockKeychainOperations() {
        // Given
        let mockKeychainManager = MockKeychainManager()
        let testData = "Test data".data(using: .utf8)!
        let testKey = "mock_test_key"
        
        // When
        let storeResult = mockKeychainManager.mockStore(data: testData, forKey: testKey)
        let retrieveResult = mockKeychainManager.mockRetrieve(forKey: testKey)
        let deleteResult = mockKeychainManager.mockDelete(forKey: testKey)
        
        // Then
        XCTAssertTrue(storeResult)
        XCTAssertEqual(retrieveResult, testData)
        XCTAssertTrue(deleteResult)
    }
}

// MARK: - Mock Keychain Manager

class MockKeychainManager: KeychainManager {
    private var storedData: [String: Data] = [:]
    
    func mockStore(data: Data, forKey key: String) -> Bool {
        storedData[key] = data
        return true
    }
    
    func mockRetrieve(forKey key: String) -> Data {
        return storedData[key] ?? Data()
    }
    
    func mockDelete(forKey key: String) -> Bool {
        storedData.removeValue(forKey: key)
        return true
    }
} 