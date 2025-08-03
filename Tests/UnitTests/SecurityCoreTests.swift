//
//  SecurityCoreTests.swift
//  iOS Security Framework Pro Tests
//
//  Created by Muhittin Camdali
//  Copyright © 2024 Muhittin Camdali. All rights reserved.
//

import XCTest
@testable import SecurityFrameworkPro

final class SecurityCoreTests: XCTestCase {
    
    var securityCore: SecurityCore!
    
    override func setUpWithError() throws {
        securityCore = SecurityCore.shared
    }
    
    override func tearDownWithError() throws {
        securityCore = nil
    }
    
    // MARK: - Initialization Tests
    
    func testInitializationWithValidConfiguration() throws {
        let config = SecurityCore.SecurityConfiguration(
            encryptionLevel: .aes256,
            biometricPolicy: .faceIDAndTouchID,
            keychainAccessibility: .whenUnlockedThisDeviceOnly,
            networkSecurityLevel: .high,
            threatDetectionEnabled: true,
            auditLoggingEnabled: true
        )
        
        XCTAssertNoThrow(try securityCore.initialize(with: config))
        XCTAssertTrue(securityCore.isInitialized())
    }
    
    func testInitializationWithInvalidConfiguration() throws {
        // Test with invalid configuration
        let invalidConfig = SecurityCore.SecurityConfiguration(
            encryptionLevel: .aes256,
            biometricPolicy: .none,
            keychainAccessibility: .whenUnlockedThisDeviceOnly,
            networkSecurityLevel: .high,
            threatDetectionEnabled: true,
            auditLoggingEnabled: true
        )
        
        XCTAssertThrowsError(try securityCore.initialize(with: invalidConfig))
    }
    
    // MARK: - Configuration Tests
    
    func testGetConfiguration() throws {
        let config = SecurityCore.SecurityConfiguration()
        try securityCore.initialize(with: config)
        
        let retrievedConfig = securityCore.getConfiguration()
        XCTAssertNotNil(retrievedConfig)
        XCTAssertEqual(retrievedConfig?.encryptionLevel, config.encryptionLevel)
        XCTAssertEqual(retrievedConfig?.biometricPolicy, config.biometricPolicy)
    }
    
    func testUpdateConfiguration() throws {
        let initialConfig = SecurityCore.SecurityConfiguration(
            encryptionLevel: .aes128,
            biometricPolicy: .faceID
        )
        try securityCore.initialize(with: initialConfig)
        
        let updatedConfig = SecurityCore.SecurityConfiguration(
            encryptionLevel: .aes256,
            biometricPolicy: .touchID
        )
        
        XCTAssertNoThrow(try securityCore.updateConfiguration(updatedConfig))
        
        let retrievedConfig = securityCore.getConfiguration()
        XCTAssertEqual(retrievedConfig?.encryptionLevel, updatedConfig.encryptionLevel)
        XCTAssertEqual(retrievedConfig?.biometricPolicy, updatedConfig.biometricPolicy)
    }
    
    // MARK: - Health Check Tests
    
    func testPerformSecurityHealthCheck() throws {
        let config = SecurityCore.SecurityConfiguration()
        try securityCore.initialize(with: config)
        
        let healthStatus = securityCore.performSecurityHealthCheck()
        
        XCTAssertNotNil(healthStatus)
        XCTAssertGreaterThanOrEqual(healthStatus.overallHealthScore, 0.0)
        XCTAssertLessThanOrEqual(healthStatus.overallHealthScore, 100.0)
    }
    
    func testHealthCheckWithoutInitialization() throws {
        let healthStatus = securityCore.performSecurityHealthCheck()
        
        XCTAssertNotNil(healthStatus)
        XCTAssertEqual(healthStatus.overallHealthScore, 0.0)
    }
    
    // MARK: - Encryption Level Tests
    
    func testEncryptionLevels() throws {
        let levels: [SecurityCore.EncryptionLevel] = [
            .aes128, .aes256, .chacha20, .rsa2048, .rsa4096, .hybrid
        ]
        
        for level in levels {
            let config = SecurityCore.SecurityConfiguration(encryptionLevel: level)
            XCTAssertNoThrow(try securityCore.initialize(with: config))
            
            let retrievedConfig = securityCore.getConfiguration()
            XCTAssertEqual(retrievedConfig?.encryptionLevel, level)
        }
    }
    
    // MARK: - Biometric Policy Tests
    
    func testBiometricPolicies() throws {
        let policies: [SecurityCore.BiometricPolicy] = [
            .faceID, .touchID, .faceIDAndTouchID, .none
        ]
        
        for policy in policies {
            let config = SecurityCore.SecurityConfiguration(biometricPolicy: policy)
            XCTAssertNoThrow(try securityCore.initialize(with: config))
            
            let retrievedConfig = securityCore.getConfiguration()
            XCTAssertEqual(retrievedConfig?.biometricPolicy, policy)
        }
    }
    
    // MARK: - Keychain Accessibility Tests
    
    func testKeychainAccessibilityLevels() throws {
        let accessibilityLevels: [SecurityCore.KeychainAccessibility] = [
            .whenUnlocked,
            .whenUnlockedThisDeviceOnly,
            .afterFirstUnlock,
            .afterFirstUnlockThisDeviceOnly,
            .always,
            .alwaysThisDeviceOnly,
            .whenPasscodeSetThisDeviceOnly
        ]
        
        for level in accessibilityLevels {
            let config = SecurityCore.SecurityConfiguration(keychainAccessibility: level)
            XCTAssertNoThrow(try securityCore.initialize(with: config))
            
            let retrievedConfig = securityCore.getConfiguration()
            XCTAssertEqual(retrievedConfig?.keychainAccessibility, level)
        }
    }
    
    // MARK: - Network Security Level Tests
    
    func testNetworkSecurityLevels() throws {
        let securityLevels: [SecurityCore.NetworkSecurityLevel] = [
            .low, .medium, .high, .maximum
        ]
        
        for level in securityLevels {
            let config = SecurityCore.SecurityConfiguration(networkSecurityLevel: level)
            XCTAssertNoThrow(try securityCore.initialize(with: config))
            
            let retrievedConfig = securityCore.getConfiguration()
            XCTAssertEqual(retrievedConfig?.networkSecurityLevel, level)
        }
    }
    
    // MARK: - Error Handling Tests
    
    func testSecurityErrorDescriptions() throws {
        let errors: [SecurityCore.SecurityError] = [
            .biometricNotAvailable,
            .encryptionFailed,
            .decryptionFailed,
            .keychainError(errSecSuccess),
            .configurationError,
            .threatDetected("Test threat"),
            .auditLoggingFailed
        ]
        
        for error in errors {
            XCTAssertNotNil(error.errorDescription)
            XCTAssertFalse(error.errorDescription?.isEmpty ?? true)
        }
    }
    
    // MARK: - Thread Safety Tests
    
    func testThreadSafety() throws {
        let config = SecurityCore.SecurityConfiguration()
        try securityCore.initialize(with: config)
        
        let expectation = XCTestExpectation(description: "Thread safety test")
        let queue = DispatchQueue(label: "test.queue", attributes: .concurrent)
        
        for i in 0..<10 {
            queue.async {
                let healthStatus = self.securityCore.performSecurityHealthCheck()
                XCTAssertNotNil(healthStatus)
                if i == 9 {
                    expectation.fulfill()
                }
            }
        }
        
        wait(for: [expectation], timeout: 5.0)
    }
    
    // MARK: - Performance Tests
    
    func testInitializationPerformance() throws {
        let config = SecurityCore.SecurityConfiguration()
        
        measure {
            try? securityCore.initialize(with: config)
        }
    }
    
    func testHealthCheckPerformance() throws {
        let config = SecurityCore.SecurityConfiguration()
        try securityCore.initialize(with: config)
        
        measure {
            _ = securityCore.performSecurityHealthCheck()
        }
    }
    
    // MARK: - Edge Cases
    
    func testMultipleInitializations() throws {
        let config1 = SecurityCore.SecurityConfiguration(encryptionLevel: .aes128)
        let config2 = SecurityCore.SecurityConfiguration(encryptionLevel: .aes256)
        
        XCTAssertNoThrow(try securityCore.initialize(with: config1))
        XCTAssertNoThrow(try securityCore.initialize(with: config2))
        
        let retrievedConfig = securityCore.getConfiguration()
        XCTAssertEqual(retrievedConfig?.encryptionLevel, .aes256)
    }
    
    func testConfigurationWithAllFeaturesDisabled() throws {
        let config = SecurityCore.SecurityConfiguration(
            threatDetectionEnabled: false,
            auditLoggingEnabled: false
        )
        
        XCTAssertNoThrow(try securityCore.initialize(with: config))
        XCTAssertTrue(securityCore.isInitialized())
    }
} 