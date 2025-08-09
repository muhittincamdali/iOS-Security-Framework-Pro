# Encryption Examples

<!-- TOC START -->
## Table of Contents
- [Encryption Examples](#encryption-examples)
- [Examples](#examples)
- [Encryption Features](#encryption-features)
  - [AES Encryption](#aes-encryption)
  - [ChaCha20 Encryption](#chacha20-encryption)
  - [RSA Encryption](#rsa-encryption)
  - [Hybrid Encryption](#hybrid-encryption)
- [Requirements](#requirements)
- [Usage](#usage)
<!-- TOC END -->


This directory contains comprehensive examples demonstrating iOS Security Framework Pro encryption features.

## Examples

- **AESEncryption.swift** - AES-128/256 encryption
- **ChaCha20Encryption.swift** - ChaCha20 encryption
- **RSAEncryption.swift** - RSA-4096 encryption
- **HybridEncryption.swift** - Hybrid encryption
- **HardwareAcceleration.swift** - Hardware acceleration
- **KeyManagement.swift** - Key management

## Encryption Features

### AES Encryption
- AES-128 and AES-256
- Hardware acceleration
- Multiple modes (CBC, GCM)
- Key derivation

### ChaCha20 Encryption
- High-performance encryption
- Modern cipher
- Hardware acceleration
- Secure random generation

### RSA Encryption
- RSA-4096 implementation
- Asymmetric encryption
- Digital signatures
- Certificate management

### Hybrid Encryption
- Combined symmetric/asymmetric
- Optimal performance
- Secure key exchange
- Best of both worlds

## Requirements

- iOS 15.0+
- Xcode 15.0+
- Swift 5.9+

## Usage

```swift
import SecurityFrameworkPro

// Encryption example
let encryptionManager = EncryptionManager()
let encryptedData = try encryptionManager.encrypt(
    data: plaintextData,
    using: encryptionKey
)
``` 