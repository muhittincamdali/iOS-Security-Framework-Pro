# Network Security Examples

This directory contains comprehensive examples demonstrating iOS Security Framework Pro network security features.

## Examples

- **SSLPinning.swift** - SSL/TLS certificate pinning
- **JWTValidation.swift** - JWT authentication
- **OAuth2Flow.swift** - OAuth2 implementation
- **RateLimiting.swift** - Rate limiting
- **DDoSProtection.swift** - DDoS protection
- **APISecurity.swift** - API security

## Network Security Features

### SSL/TLS Pinning
- Certificate pinning
- Public key pinning
- Hostname validation
- Certificate revocation

### JWT Authentication
- JWT token validation
- Token refresh
- Claims verification
- Secure storage

### OAuth2 Implementation
- OAuth2 flow
- Authorization code
- Token management
- Secure redirects

### Rate Limiting
- Request throttling
- IP-based limiting
- User-based limiting
- Adaptive limits

## Requirements

- iOS 15.0+
- Xcode 15.0+
- Swift 5.9+

## Usage

```swift
import SecurityFrameworkPro

// SSL pinning example
let sslPinning = SSLPinningManager()
let isValid = try sslPinning.validateConnection(
    to: "https://api.example.com"
)
``` 