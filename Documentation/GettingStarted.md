# Getting Started Guide

## Overview

This guide will help you get started with the iOS Security Framework Pro. You'll learn how to integrate the framework into your iOS project and begin implementing enterprise-grade security features.

## Prerequisites

- iOS 15.0+
- Xcode 15.0+
- Swift 5.9+
- Basic understanding of iOS development and security concepts

## Installation

### Swift Package Manager

Add the framework to your project:

```swift
dependencies: [
    .package(url: "https://github.com/muhittincamdali/iOS-Security-Framework-Pro.git", from: "1.0.0")
]
```

### CocoaPods

Add to your Podfile:

```ruby
pod 'SecurityFrameworkPro', '~> 1.0.0'
```

## Quick Start

### 1. Import the Framework

```swift
import SecurityFrameworkPro
```

### 2. Initialize Security Manager

```swift
let securityManager = SecurityManager()
securityManager.enableBiometricAuth = true
securityManager.enableKeychainStorage = true
securityManager.enableEncryption = true
```

### 3. Configure Security Settings

```swift
let securityConfig = SecurityConfiguration()
securityConfig.biometricType = .faceID
securityConfig.encryptionAlgorithm = .aes256
securityConfig.keychainAccessibility = .whenUnlocked
```

### 4. Start Security Services

```swift
try securityManager.startServices(configuration: securityConfig)
```

## Basic Usage

### Biometric Authentication

```swift
let biometricAuth = BiometricAuthenticator()
let authResult = try await biometricAuth.authenticate(
    reason: "Access secure data",
    policy: .deviceOwnerAuthenticationWithBiometrics
)
```

### Keychain Management

```swift
let keychainManager = KeychainManager()
try keychainManager.store(
    data: secretData,
    forKey: "user_secret",
    accessibility: .whenUnlocked
)
```

### Encryption

```swift
let encryptionManager = EncryptionManager()
let encryptedData = try encryptionManager.encrypt(
    data: plaintextData,
    using: encryptionKey
)
```

## Next Steps

- Read the [Security Best Practices](SecurityBestPractices.md)
- Explore [Biometric Authentication](BiometricAuthenticationGuide.md)
- Learn about [Encryption](EncryptionGuide.md)
- Check out the [Examples](../Examples/) directory

## Support

For questions and support, please open an issue on GitHub or check the documentation. 