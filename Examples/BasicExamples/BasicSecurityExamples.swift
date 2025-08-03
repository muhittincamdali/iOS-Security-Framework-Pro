import Foundation
import SecurityFrameworkPro

/**
 * Basic Security Examples
 * 
 * Simple examples demonstrating basic security features
 * of the iOS Security Framework Pro.
 */
class BasicSecurityExamples {
    
    // MARK: - Biometric Authentication Examples
    
    /**
     * Example: Check biometric availability
     */
    func checkBiometricAvailability() {
        let biometricAuth = BiometricAuthenticator()
        let availability = biometricAuth.checkAvailability()
        
        switch availability {
        case .faceID:
            print("✅ Face ID is available")
        case .touchID:
            print("✅ Touch ID is available")
        case .notAvailable(let reason):
            print("❌ Biometric not available: \(reason)")
        }
    }
    
    /**
     * Example: Perform biometric authentication
     */
    func performBiometricAuthentication() async {
        let biometricAuth = BiometricAuthenticator()
        
        do {
            let isAuthenticated = try await biometricAuth.authenticate(
                reason: "Access secure features",
                policy: .deviceOwnerAuthenticationWithBiometrics
            )
            
            if isAuthenticated {
                print("✅ Biometric authentication successful")
            } else {
                print("❌ Biometric authentication failed")
            }
        } catch {
            print("❌ Biometric authentication error: \(error)")
        }
    }
    
    // MARK: - Keychain Management Examples
    
    /**
     * Example: Store secure data in keychain
     */
    func storeSecureData() {
        let keychainManager = KeychainManager()
        let sensitiveData = "Sensitive information".data(using: .utf8)!
        let key = "secure_data_key"
        
        do {
            try keychainManager.store(
                data: sensitiveData,
                forKey: key,
                accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            )
            print("✅ Data stored securely in keychain")
        } catch {
            print("❌ Failed to store data: \(error)")
        }
    }
    
    /**
     * Example: Retrieve secure data from keychain
     */
    func retrieveSecureData() {
        let keychainManager = KeychainManager()
        let key = "secure_data_key"
        
        do {
            let retrievedData = try keychainManager.retrieve(forKey: key)
            let retrievedString = String(data: retrievedData, encoding: .utf8)
            print("✅ Retrieved data: \(retrievedString ?? "Unknown")")
        } catch {
            print("❌ Failed to retrieve data: \(error)")
        }
    }
    
    /**
     * Example: Delete secure data from keychain
     */
    func deleteSecureData() {
        let keychainManager = KeychainManager()
        let key = "secure_data_key"
        
        do {
            try keychainManager.delete(forKey: key)
            print("✅ Data deleted from keychain")
        } catch {
            print("❌ Failed to delete data: \(error)")
        }
    }
    
    // MARK: - Encryption Examples
    
    /**
     * Example: Encrypt sensitive data
     */
    func encryptSensitiveData() {
        let encryptionManager = EncryptionManager()
        let sensitiveData = "Highly sensitive information".data(using: .utf8)!
        
        do {
            let encryptedData = try encryptionManager.encrypt(
                data: sensitiveData,
                algorithm: .aes256,
                keySize: .bits256
            )
            print("✅ Data encrypted successfully")
            print("Original size: \(sensitiveData.count) bytes")
            print("Encrypted size: \(encryptedData.count) bytes")
        } catch {
            print("❌ Encryption failed: \(error)")
        }
    }
    
    /**
     * Example: Decrypt sensitive data
     */
    func decryptSensitiveData() {
        let encryptionManager = EncryptionManager()
        let sensitiveData = "Highly sensitive information".data(using: .utf8)!
        
        do {
            let encryptedData = try encryptionManager.encrypt(
                data: sensitiveData,
                algorithm: .aes256,
                keySize: .bits256
            )
            
            let decryptedData = try encryptionManager.decrypt(
                data: encryptedData,
                algorithm: .aes256,
                keySize: .bits256
            )
            
            let originalString = String(data: sensitiveData, encoding: .utf8)
            let decryptedString = String(data: decryptedData, encoding: .utf8)
            
            print("✅ Data decrypted successfully")
            print("Original: \(originalString ?? "Unknown")")
            print("Decrypted: \(decryptedString ?? "Unknown")")
        } catch {
            print("❌ Decryption failed: \(error)")
        }
    }
    
    // MARK: - Security Monitoring Examples
    
    /**
     * Example: Get security status
     */
    func getSecurityStatus() {
        let securityManager = SecurityManager()
        let status = securityManager.getSecurityStatus()
        
        print("🔒 Security Status:")
        print("- Biometric available: \(status.biometricAvailable)")
        print("- Authentication status: \(status.isAuthenticated)")
        print("- Security level: \(status.securityLevel)")
        print("- Last authentication: \(status.lastAuthenticationDate)")
    }
    
    /**
     * Example: Get audit log
     */
    func getAuditLog() {
        let auditLogger = SecurityAuditLogger()
        let events = auditLogger.getAuditEvents()
        
        print("📋 Audit Log:")
        for event in events {
            print("- \(event.timestamp): \(event.type) - \(event.description)")
        }
    }
    
    /**
     * Example: Get threat report
     */
    func getThreatReport() {
        let threatDetector = ThreatDetector()
        let report = threatDetector.generateReport()
        
        print("🚨 Threat Report:")
        print("- Threat level: \(report.threatLevel)")
        print("- Detected threats: \(report.detectedThreats.count)")
        print("- Suspicious activities: \(report.suspiciousActivities.count)")
        print("- Recommendations: \(report.recommendations.count)")
    }
    
    // MARK: - Network Security Examples
    
    /**
     * Example: Configure network security
     */
    func configureNetworkSecurity() {
        let networkSecurity = NetworkSecurityManager()
        
        // Configure with pinned certificates and allowed domains
        networkSecurity.configure(
            pinnedCertificates: [],
            allowedDomains: ["api.secureapp.com", "cdn.secureapp.com"],
            blockedIPs: ["192.168.1.100", "10.0.0.50"]
        )
        
        print("✅ Network security configured")
    }
    
    /**
     * Example: Make secure network request
     */
    func makeSecureNetworkRequest() async {
        let networkSecurity = NetworkSecurityManager()
        
        do {
            let request = try networkSecurity.createSecureRequest(
                url: "https://api.secureapp.com/data",
                method: .GET,
                headers: ["Authorization": "Bearer token"]
            )
            
            let response = try await networkSecurity.executeSecureRequest(request)
            
            print("✅ Secure network request successful")
            print("Status code: \(response.statusCode)")
            print("Response size: \(response.data.count) bytes")
        } catch {
            print("❌ Network request failed: \(error)")
        }
    }
    
    // MARK: - Complete Security Workflow Example
    
    /**
     * Example: Complete security workflow
     */
    func performCompleteSecurityWorkflow() async {
        print("🔄 Starting complete security workflow...")
        
        // Step 1: Check biometric availability
        checkBiometricAvailability()
        
        // Step 2: Perform biometric authentication
        await performBiometricAuthentication()
        
        // Step 3: Store sensitive data
        storeSecureData()
        
        // Step 4: Encrypt additional data
        encryptSensitiveData()
        
        // Step 5: Configure network security
        configureNetworkSecurity()
        
        // Step 6: Make secure network request
        await makeSecureNetworkRequest()
        
        // Step 7: Get security status
        getSecurityStatus()
        
        // Step 8: Get audit log
        getAuditLog()
        
        // Step 9: Get threat report
        getThreatReport()
        
        print("✅ Complete security workflow finished")
    }
    
    // MARK: - Error Handling Examples
    
    /**
     * Example: Handle security errors gracefully
     */
    func handleSecurityErrors() {
        let securityManager = SecurityManager()
        
        do {
            // Attempt to perform security operation
            try securityManager.storeSecureData(
                "Test data".data(using: .utf8)!,
                forKey: "test_key"
            )
        } catch SecurityError.authenticationFailed(let error) {
            print("❌ Authentication failed: \(error)")
            // Handle authentication failure
        } catch SecurityError.encryptionFailed(let error) {
            print("❌ Encryption failed: \(error)")
            // Handle encryption failure
        } catch SecurityError.keychainError(let error) {
            print("❌ Keychain error: \(error)")
            // Handle keychain error
        } catch {
            print("❌ Unknown security error: \(error)")
            // Handle unknown error
        }
    }
    
    // MARK: - Performance Examples
    
    /**
     * Example: Measure encryption performance
     */
    func measureEncryptionPerformance() {
        let encryptionManager = EncryptionManager()
        let testData = "Performance test data".data(using: .utf8)!
        
        let startTime = Date()
        
        do {
            _ = try encryptionManager.encrypt(
                data: testData,
                algorithm: .aes256,
                keySize: .bits256
            )
            
            let endTime = Date()
            let duration = endTime.timeIntervalSince(startTime)
            
            print("⚡ Encryption performance:")
            print("- Data size: \(testData.count) bytes")
            print("- Duration: \(duration * 1000) ms")
            print("- Speed: \(Double(testData.count) / duration / 1024) KB/s")
        } catch {
            print("❌ Performance test failed: \(error)")
        }
    }
    
    // MARK: - Utility Examples
    
    /**
     * Example: Generate secure random data
     */
    func generateSecureRandomData() {
        let encryptionManager = EncryptionManager()
        
        do {
            let randomKey = try encryptionManager.generateSecureKey(size: 256)
            let randomIV = try encryptionManager.generateRandomIV()
            let randomNonce = try encryptionManager.generateRandomNonce()
            
            print("🎲 Secure random data generated:")
            print("- Key size: \(randomKey.count) bytes")
            print("- IV size: \(randomIV.count) bytes")
            print("- Nonce size: \(randomNonce.count) bytes")
        } catch {
            print("❌ Failed to generate random data: \(error)")
        }
    }
    
    /**
     * Example: Validate security configuration
     */
    func validateSecurityConfiguration() {
        let securityManager = SecurityManager()
        let biometricAuth = BiometricAuthenticator()
        let keychainManager = KeychainManager()
        
        print("🔍 Security Configuration Validation:")
        
        // Check biometric availability
        let biometricAvailable = biometricAuth.checkAvailability()
        print("- Biometric available: \(biometricAvailable != .notAvailable(""))")
        
        // Check keychain accessibility
        let keychainAccessible = keychainManager.isKeychainAccessible()
        print("- Keychain accessible: \(keychainAccessible)")
        
        // Check security level
        let securityLevel = securityManager.getSecurityLevel()
        print("- Security level: \(securityLevel)")
        
        // Check encryption algorithms
        let algorithms = ["AES-128", "AES-256", "ChaCha20", "RSA-4096"]
        print("- Supported algorithms: \(algorithms.joined(separator: ", "))")
    }
}

// MARK: - Usage Examples

/**
 * Example usage of BasicSecurityExamples
 */
func demonstrateBasicSecurityExamples() async {
    let examples = BasicSecurityExamples()
    
    print("🚀 iOS Security Framework Pro - Basic Examples")
    print("=" * 50)
    
    // Run individual examples
    examples.checkBiometricAvailability()
    await examples.performBiometricAuthentication()
    examples.storeSecureData()
    examples.retrieveSecureData()
    examples.encryptSensitiveData()
    examples.decryptSensitiveData()
    examples.getSecurityStatus()
    examples.getAuditLog()
    examples.getThreatReport()
    examples.configureNetworkSecurity()
    await examples.makeSecureNetworkRequest()
    examples.handleSecurityErrors()
    examples.measureEncryptionPerformance()
    examples.generateSecureRandomData()
    examples.validateSecurityConfiguration()
    
    // Run complete workflow
    await examples.performCompleteSecurityWorkflow()
    
    print("✅ All basic security examples completed")
} 