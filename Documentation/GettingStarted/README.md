# 🚀 Getting Started with iOS Security Framework Pro

Welcome to the comprehensive guide for getting started with iOS Security Framework Pro. This guide will walk you through the installation, setup, and basic usage of our enterprise-grade security framework.

## 📋 Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Basic Usage](#basic-usage)
- [Advanced Features](#advanced-features)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## 🔧 Requirements

### System Requirements
- **iOS 15.0+**
- **Xcode 14.0+**
- **Swift 5.7+**
- **macOS 12.0+** (for development)

### Dependencies
- **LocalAuthentication framework** (built-in)
- **Security framework** (built-in)
- **CryptoKit framework** (built-in)

## 📦 Installation

### Swift Package Manager (Recommended)

1. **Add the package to your Xcode project:**
   ```swift
   // In your Xcode project, go to File > Add Package Dependencies
   // Enter the repository URL:
   https://github.com/muhittincamdali/iOS-Security-Framework-Pro
   ```

2. **Select the SecurityFrameworkPro package:**
   - Choose the latest version
   - Add to your target

3. **Import the framework:**
   ```swift
   import SecurityFrameworkPro
   ```

### Manual Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/muhittincamdali/iOS-Security-Framework-Pro.git
   ```

2. **Add to your project:**
   - Drag the `Sources` folder into your Xcode project
   - Ensure "Copy items if needed" is checked
   - Add to your target

## ⚡ Quick Start

### 1. Basic Setup

```swift
import SecurityFrameworkPro

class SecurityManager {
    private let securityManager = SecurityManager()
    
    func setupSecurity() {
        // Initialize security framework
        securityManager.configure()
    }
}
```

### 2. Biometric Authentication

```swift
func authenticateUser() async throws -> Bool {
    return try await securityManager.authenticateUser(
        reason: "Authenticate to access secure features"
    )
}
```

### 3. Secure Data Storage

```swift
func storeSecureData(_ data: Data, forKey key: String) throws {
    try securityManager.storeSecureData(data, forKey: key)
}

func retrieveSecureData(forKey key: String) throws -> Data {
    return try securityManager.retrieveSecureData(forKey: key)
}
```

### 4. Data Encryption

```swift
func encryptSensitiveData(_ data: Data) throws -> Data {
    return try securityManager.encryptSensitiveData(
        data,
        algorithm: .aes256,
        keySize: .bits256
    )
}
```

## 🔐 Basic Usage

### Biometric Authentication

```swift
class AuthenticationService {
    private let biometricAuth = BiometricAuthenticator()
    
    func checkBiometricAvailability() -> BiometricAvailability {
        return biometricAuth.checkAvailability()
    }
    
    func authenticateUser() async throws -> Bool {
        return try await biometricAuth.authenticate(
            reason: "Access secure data",
            policy: .deviceOwnerAuthenticationWithBiometrics
        )
    }
}
```

### Keychain Management

```swift
class SecureStorageService {
    private let keychainManager = KeychainManager()
    
    func storeSecureData(_ data: Data, forKey key: String) throws {
        try keychainManager.store(
            data: data,
            forKey: key,
            accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        )
    }
    
    func retrieveSecureData(forKey key: String) throws -> Data {
        return try keychainManager.retrieve(forKey: key)
    }
}
```

### Encryption Services

```swift
class EncryptionService {
    private let encryptionManager = EncryptionManager()
    
    func encryptData(_ data: Data) throws -> Data {
        return try encryptionManager.encrypt(
            data: data,
            algorithm: .aes256,
            keySize: .bits256
        )
    }
    
    func decryptData(_ data: Data) throws -> Data {
        return try encryptionManager.decrypt(
            data: data,
            algorithm: .aes256,
            keySize: .bits256
        )
    }
}
```

## 🛡️ Advanced Features

### Network Security

```swift
class NetworkSecurityService {
    private let networkSecurity = NetworkSecurityManager()
    
    func setupNetworkSecurity() {
        networkSecurity.configure(
            pinnedCertificates: loadPinnedCertificates(),
            allowedDomains: ["api.example.com", "secure.example.com"],
            blockedIPs: ["192.168.1.100"]
        )
    }
    
    func createSecureRequest(url: String) throws -> URLRequest {
        return try networkSecurity.createSecureRequest(
            url: url,
            method: .GET,
            headers: ["Authorization": "Bearer token"]
        )
    }
}
```

### Threat Detection

```swift
class ThreatDetectionService {
    private let threatDetector = ThreatDetector()
    
    func startMonitoring() {
        threatDetector.startMonitoring()
    }
    
    func getThreatReport() -> ThreatReport {
        return threatDetector.generateReport()
    }
}
```

### Security Audit Logging

```swift
class AuditLoggingService {
    private let auditLogger = SecurityAuditLogger()
    
    func logSecurityEvent(_ event: AuditEventType) {
        auditLogger.logEvent(event, severity: .medium)
    }
    
    func getAuditLog() -> [SecurityAuditEvent] {
        return auditLogger.getAuditLog()
    }
}
```

## 🎯 Best Practices

### 1. Security Configuration

```swift
// Always configure security settings early in app lifecycle
func configureSecurity() {
    let securityManager = SecurityManager()
    
    // Set appropriate security level
    securityManager.securityLevel = .enterprise
    
    // Configure audit logging
    securityManager.startLogging()
    
    // Start threat detection
    securityManager.startMonitoring()
}
```

### 2. Error Handling

```swift
func handleSecurityError(_ error: SecurityError) {
    switch error {
    case .authenticationFailed(let underlyingError):
        // Handle authentication failure
        print("Authentication failed: \(underlyingError.localizedDescription)")
        
    case .keychainError(let underlyingError):
        // Handle keychain error
        print("Keychain error: \(underlyingError.localizedDescription)")
        
    case .encryptionFailed(let underlyingError):
        // Handle encryption error
        print("Encryption failed: \(underlyingError.localizedDescription)")
        
    default:
        // Handle other security errors
        print("Security error: \(error.localizedDescription)")
    }
}
```

### 3. Data Protection

```swift
// Always use appropriate accessibility levels
func storeSensitiveData(_ data: Data, forKey key: String) throws {
    try keychainManager.store(
        data: data,
        forKey: key,
        accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    )
}

// Use strong encryption for sensitive data
func encryptSensitiveData(_ data: Data) throws -> Data {
    return try encryptionManager.encrypt(
        data: data,
        algorithm: .aes256,
        keySize: .bits256
    )
}
```

### 4. Network Security

```swift
// Always validate certificates
func validateCertificate(_ serverTrust: SecTrust) -> Bool {
    return certificatePinningManager.validateCertificate(
        serverTrust,
        pinnedCertificates: pinnedCertificates
    )
}

// Use secure network requests
func makeSecureRequest(_ url: String) async throws -> NetworkResponse {
    let request = try networkSecurity.createSecureRequest(
        url: url,
        method: .GET
    )
    
    return try await networkSecurity.executeSecureRequest(request)
}
```

## 🔧 Troubleshooting

### Common Issues

#### 1. Biometric Authentication Not Available

```swift
func checkBiometricSetup() {
    let availability = biometricAuth.checkAvailability()
    
    switch availability {
    case .faceID, .touchID:
        print("Biometric authentication available")
        
    case .notAvailable(let reason):
        print("Biometric not available: \(reason)")
        // Provide fallback authentication
    }
}
```

#### 2. Keychain Access Issues

```swift
func troubleshootKeychainAccess() {
    do {
        let testData = "test".data(using: .utf8)!
        try keychainManager.store(data: testData, forKey: "test_key")
        try keychainManager.delete(forKey: "test_key")
        print("Keychain access working correctly")
    } catch {
        print("Keychain access issue: \(error.localizedDescription)")
    }
}
```

#### 3. Encryption Errors

```swift
func troubleshootEncryption() {
    do {
        let testData = "test".data(using: .utf8)!
        let encryptedData = try encryptionManager.encrypt(
            data: testData,
            algorithm: .aes256,
            keySize: .bits256
        )
        let decryptedData = try encryptionManager.decrypt(
            data: encryptedData,
            algorithm: .aes256,
            keySize: .bits256
        )
        print("Encryption working correctly")
    } catch {
        print("Encryption error: \(error.localizedDescription)")
    }
}
```

### Debug Information

```swift
func getDebugInformation() -> [String: Any] {
    return [
        "biometricAvailable": biometricAuth.checkAvailability().isAvailable,
        "keychainAccessible": keychainManager.exists(forKey: "test_key"),
        "encryptionWorking": encryptionManager != nil,
        "securityLevel": securityManager.securityLevel,
        "threatLevel": threatDetector.getCurrentThreatLevel()
    ]
}
```

## 📚 Next Steps

After completing this getting started guide, explore:

1. **[Security Guide](Security/README.md)** - Advanced security features
2. **[Network Security](Network/README.md)** - Network security implementation
3. **[Authentication](Authentication/README.md)** - Authentication best practices
4. **[Encryption](Encryption/README.md)** - Encryption algorithms and usage
5. **[Testing](Testing/README.md)** - Security testing strategies

## 🤝 Support

- **Documentation**: [Full Documentation](../README.md)
- **Issues**: [GitHub Issues](https://github.com/muhittincamdali/iOS-Security-Framework-Pro/issues)
- **Discussions**: [GitHub Discussions](https://github.com/muhittincamdali/iOS-Security-Framework-Pro/discussions)

---

**🔒 Build secure iOS applications with confidence using iOS Security Framework Pro!** 