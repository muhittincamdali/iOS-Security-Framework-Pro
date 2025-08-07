import Foundation
import SecurityFrameworkPro

/// Basic Security Example
/// This example demonstrates basic security features implementation
class BasicSecurityExample {
    
    // MARK: - Properties
    
    private let securityManager = SecurityManager()
    private let biometricAuth = BiometricAuthenticator()
    private let keychainManager = KeychainManager()
    private let encryptionManager = EncryptionManager()
    
    // MARK: - Initialization
    
    init() {
        setupSecurityManager()
    }
    
    // MARK: - Setup
    
    private func setupSecurityManager() {
        let config = SecurityConfiguration()
        config.enableBiometricAuth = true
        config.enableEncryption = true
        config.enableKeychainManagement = true
        
        securityManager.startServices(configuration: config)
    }
    
    // MARK: - Basic Authentication
    
    /// Demonstrates basic biometric authentication
    func demonstrateBasicAuthentication() async throws {
        print("🔐 Starting basic authentication demo...")
        
        // Check biometric availability
        let availability = biometricAuth.checkAvailability()
        print("Face ID available: \(availability.faceID)")
        print("Touch ID available: \(availability.touchID)")
        
        // Perform authentication
        let authResult = try await biometricAuth.authenticate(
            reason: "Access secure data"
        )
        
        if authResult.isAuthenticated {
            print("✅ Authentication successful")
            await demonstrateSecureOperations()
        } else {
            print("❌ Authentication failed: \(authResult.error)")
        }
    }
    
    // MARK: - Secure Operations
    
    /// Demonstrates secure operations after authentication
    private func demonstrateSecureOperations() async {
        print("🔒 Performing secure operations...")
        
        // Store secure data
        await demonstrateSecureStorage()
        
        // Encrypt sensitive data
        await demonstrateEncryption()
        
        // Retrieve secure data
        await demonstrateSecureRetrieval()
    }
    
    // MARK: - Secure Storage
    
    /// Demonstrates secure data storage using keychain
    private func demonstrateSecureStorage() async {
        print("💾 Demonstrating secure storage...")
        
        do {
            // Store password securely
            let password = "mySecurePassword123"
            let passwordData = password.data(using: .utf8)!
            
            try keychainManager.store(
                data: passwordData,
                forKey: "user_password",
                accessibility: .whenUnlocked
            )
            
            print("✅ Password stored securely")
            
            // Store API key securely
            let apiKey = "sk-1234567890abcdef"
            let apiKeyData = apiKey.data(using: .utf8)!
            
            try keychainManager.store(
                data: apiKeyData,
                forKey: "api_key",
                accessibility: .whenUnlocked
            )
            
            print("✅ API key stored securely")
            
        } catch {
            print("❌ Failed to store data: \(error)")
        }
    }
    
    // MARK: - Encryption
    
    /// Demonstrates data encryption and decryption
    private func demonstrateEncryption() async {
        print("🔐 Demonstrating encryption...")
        
        do {
            // Generate encryption key
            let encryptionKey = try encryptionManager.generateKey(
                algorithm: .aes256,
                keySize: .bits256
            )
            
            print("✅ Encryption key generated")
            
            // Encrypt sensitive data
            let sensitiveData = "This is sensitive information".data(using: .utf8)!
            let encryptedData = try encryptionManager.encrypt(
                data: sensitiveData,
                using: encryptionKey
            )
            
            print("✅ Data encrypted successfully")
            
            // Store encrypted data
            try keychainManager.store(
                data: encryptedData,
                forKey: "encrypted_sensitive_data",
                accessibility: .whenUnlocked
            )
            
            print("✅ Encrypted data stored securely")
            
        } catch {
            print("❌ Encryption failed: \(error)")
        }
    }
    
    // MARK: - Secure Retrieval
    
    /// Demonstrates secure data retrieval
    private func demonstrateSecureRetrieval() async {
        print("📤 Demonstrating secure retrieval...")
        
        do {
            // Retrieve stored password
            let passwordData = try keychainManager.retrieve(forKey: "user_password")
            let password = String(data: passwordData, encoding: .utf8)
            print("✅ Password retrieved: \(password ?? "nil")")
            
            // Retrieve and decrypt sensitive data
            let encryptedData = try keychainManager.retrieve(forKey: "encrypted_sensitive_data")
            
            // Generate the same key for decryption
            let encryptionKey = try encryptionManager.generateKey(
                algorithm: .aes256,
                keySize: .bits256
            )
            
            // Decrypt data
            let decryptedData = try encryptionManager.decrypt(
                data: encryptedData,
                using: encryptionKey
            )
            
            let decryptedString = String(data: decryptedData, encoding: .utf8)
            print("✅ Decrypted data: \(decryptedString ?? "nil")")
            
        } catch {
            print("❌ Retrieval failed: \(error)")
        }
    }
    
    // MARK: - Cleanup
    
    /// Cleans up stored data
    func cleanup() {
        print("🧹 Cleaning up stored data...")
        
        do {
            try keychainManager.delete(forKey: "user_password")
            try keychainManager.delete(forKey: "api_key")
            try keychainManager.delete(forKey: "encrypted_sensitive_data")
            
            print("✅ Cleanup completed")
        } catch {
            print("❌ Cleanup failed: \(error)")
        }
    }
}

// MARK: - Usage Example

/// Example usage of BasicSecurityExample
@main
struct BasicSecurityExampleApp {
    static func main() async {
        print("🚀 iOS Security Framework Pro - Basic Example")
        print("=============================================")
        
        let example = BasicSecurityExample()
        
        do {
            try await example.demonstrateBasicAuthentication()
        } catch {
            print("❌ Example failed: \(error)")
        }
        
        // Cleanup
        example.cleanup()
        
        print("✅ Basic security example completed")
    }
}
