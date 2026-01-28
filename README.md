# iOS Security Framework Pro

<p align="center">
  <a href="https://swift.org"><img src="https://img.shields.io/badge/Swift-5.9+-F05138?style=flat&logo=swift&logoColor=white" alt="Swift"></a>
  <a href="https://developer.apple.com/ios/"><img src="https://img.shields.io/badge/iOS-15.0+-000000?style=flat&logo=apple&logoColor=white" alt="iOS"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License"></a>
</p>

<p align="center">
  <b>Advanced security features: biometrics, encryption, secure networking, and threat detection.</b>
</p>

---

## Features

- **Biometric Auth** — Face ID, Touch ID, and device passcode
- **Encryption** — AES-256-GCM, RSA, and ECDH
- **SSL Pinning** — Certificate and public key pinning
- **Threat Detection** — Jailbreak, debugger, and tampering detection
- **Secure Storage** — Keychain with hardware backing

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/muhittincamdali/iOS-Security-Framework-Pro.git", from: "1.0.0")
]
```

## Quick Start

```swift
import SecurityPro

// Biometric authentication
let authenticated = try await Security.authenticateWithBiometrics(
    reason: "Access your account"
)

// Encrypt data
let encrypted = try Security.encrypt(sensitiveData, with: .aes256)

// SSL Pinning
let session = Security.createPinnedSession(
    certificates: ["sha256/..."]
)

// Threat detection
if Security.isDeviceCompromised {
    // Handle threat
}
```

## Requirements

- iOS 15.0+
- Xcode 15.0+
- Swift 5.9+

## License

MIT License. See [LICENSE](LICENSE).

## Author

**Muhittin Camdali** — [@muhittincamdali](https://github.com/muhittincamdali)
