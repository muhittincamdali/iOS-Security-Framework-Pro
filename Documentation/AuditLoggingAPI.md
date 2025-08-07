# 🔐 Audit Logging API

## Overview

The Audit Logging API provides comprehensive logging capabilities for security events, compliance reporting, and forensic analysis. This API enables real-time event tracking, secure log storage, and automated compliance reporting.

## Core Components

### AuditLoggingManager

The main class for managing audit logging operations.

```swift
let auditLogger = AuditLoggingManager()
```

### Configuration

Configure audit logging settings:

```swift
let config = AuditLoggingConfiguration()
config.enableComprehensiveLogging = true
config.logRetentionDays = 365
config.encryptLogs = true
config.enableRealTimeAlerts = true
```

## API Reference

### Event Logging

Log security events with different severity levels:

```swift
// Log authentication events
auditLogger.logEvent(
    type: .authentication,
    severity: .info,
    message: "User authenticated successfully",
    metadata: ["user_id": "123", "method": "biometric"]
)

// Log threat detection events
auditLogger.logEvent(
    type: .threat_detected,
    severity: .high,
    message: "Brute force attack detected",
    metadata: ["source_ip": "192.168.1.100", "attempts": "15"]
)
```

### Compliance Reporting

Generate compliance reports for GDPR and HIPAA:

```swift
// Generate GDPR compliance report
let gdprReport = try auditLogger.generateGDPRReport()

// Generate HIPAA compliance report
let hipaaReport = try auditLogger.generateHIPAAReport()
```

### Log Export

Export logs in different formats:

```swift
// Export logs as JSON
let exportedLogs = try auditLogger.exportLogs(
    format: .json,
    dateRange: DateInterval(start: Date().addingTimeInterval(-86400), duration: 86400)
)
```

## Event Types

- `.authentication` - User authentication events
- `.threat_detected` - Security threat events
- `.encryption` - Encryption/decryption events
- `.keychain` - Keychain access events
- `.network` - Network security events
- `.compliance` - Compliance-related events

## Severity Levels

- `.low` - Informational events
- `.medium` - Warning events
- `.high` - Critical security events
- `.critical` - System-threatening events

## Best Practices

1. Always log security-critical events
2. Use appropriate severity levels
3. Include relevant metadata
4. Enable log encryption
5. Set up retention policies
6. Monitor log storage usage
7. Regular compliance audits
8. Secure log transmission
