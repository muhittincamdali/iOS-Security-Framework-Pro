import Foundation
import Security

/**
 * SecurityAuditLogger - Security Audit Logging Component
 * 
 * Provides comprehensive security audit logging with event tracking,
 * metadata storage, and security monitoring capabilities.
 */
public class SecurityAuditLogger {
    private let keychainManager = KeychainManager()
    private let encryptionManager = EncryptionManager()
    
    private var auditEvents: [SecurityAuditEvent] = []
    private let maxEventCount = 10000
    private let eventQueue = DispatchQueue(label: "com.securityframeworkpro.audit", qos: .utility)
    
    public init() {
        loadAuditEvents()
    }
    
    // MARK: - Event Logging
    
    public func logEvent(
        _ type: AuditEventType,
        metadata: [String: Any]? = nil,
        error: Error? = nil
    ) {
        let event = SecurityAuditEvent(
            type: type,
            timestamp: Date(),
            metadata: metadata,
            error: error,
            deviceInfo: DeviceInfo.current
        )
        
        eventQueue.async { [weak self] in
            self?.processEvent(event)
        }
    }
    
    public func logEvent(
        _ type: AuditEventType,
        severity: SecuritySeverity,
        metadata: [String: Any]? = nil,
        error: Error? = nil
    ) {
        let event = SecurityAuditEvent(
            type: type,
            timestamp: Date(),
            severity: severity,
            metadata: metadata,
            error: error,
            deviceInfo: DeviceInfo.current
        )
        
        eventQueue.async { [weak self] in
            self?.processEvent(event)
        }
    }
    
    // MARK: - Event Retrieval
    
    public func getAuditLog() -> [SecurityAuditEvent] {
        return eventQueue.sync {
            return auditEvents
        }
    }
    
    public func getAuditEvents(of type: AuditEventType) -> [SecurityAuditEvent] {
        return eventQueue.sync {
            return auditEvents.filter { $0.type == type }
        }
    }
    
    public func getLastEvent() -> SecurityAuditEvent? {
        return eventQueue.sync {
            return auditEvents.last
        }
    }
    
    // MARK: - Private Methods
    
    private func processEvent(_ event: SecurityAuditEvent) {
        auditEvents.append(event)
        
        if auditEvents.count > maxEventCount {
            auditEvents.removeFirst(auditEvents.count - maxEventCount)
        }
        
        saveAuditEvents()
    }
    
    private func saveAuditEvents() {
        do {
            let eventData = try JSONEncoder().encode(auditEvents)
            let encryptedData = try encryptionManager.encrypt(
                data: eventData,
                algorithm: .aes256,
                keySize: .bits256
            )
            
            try keychainManager.store(
                data: encryptedData,
                forKey: "audit_log",
                accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            )
        } catch {
            print("Failed to save audit events: \(error)")
        }
    }
    
    private func loadAuditEvents() {
        do {
            let encryptedData = try keychainManager.retrieve(forKey: "audit_log")
            let eventData = try encryptionManager.decrypt(
                data: encryptedData,
                algorithm: .aes256,
                keySize: .bits256
            )
            
            let events = try JSONDecoder().decode([SecurityAuditEvent].self, from: eventData)
            auditEvents = events
        } catch {
            auditEvents = []
        }
    }
    
    public func startLogging() {
        schedulePeriodicCleanup()
    }
    
    private func schedulePeriodicCleanup() {
        Timer.scheduledTimer(withTimeInterval: 3600, repeats: true) { [weak self] _ in
            self?.cleanupOldEvents()
        }
    }
    
    private func cleanupOldEvents() {
        let thirtyDaysAgo = Date().addingTimeInterval(-30 * 24 * 60 * 60)
        auditEvents.removeAll { $0.timestamp < thirtyDaysAgo }
        saveAuditEvents()
    }
}

// MARK: - Supporting Types

public struct SecurityAuditEvent: Codable {
    public let type: AuditEventType
    public let timestamp: Date
    public let severity: SecuritySeverity
    public let metadata: [String: Any]?
    public let error: Error?
    public let deviceInfo: DeviceInfo
    
    public init(
        type: AuditEventType,
        timestamp: Date = Date(),
        severity: SecuritySeverity = .medium,
        metadata: [String: Any]? = nil,
        error: Error? = nil,
        deviceInfo: DeviceInfo = DeviceInfo.current
    ) {
        self.type = type
        self.timestamp = timestamp
        self.severity = severity
        self.metadata = metadata
        self.error = error
        self.deviceInfo = deviceInfo
    }
}

public enum SecuritySeverity: String, Codable, CaseIterable {
    case low = "low"
    case medium = "medium"
    case high = "high"
    case critical = "critical"
}

public struct DeviceInfo: Codable {
    public let deviceName: String
    public let systemVersion: String
    public let appVersion: String
    public let deviceIdentifier: String
    
    public static var current: DeviceInfo {
        return DeviceInfo(
            deviceName: UIDevice.current.name,
            systemVersion: UIDevice.current.systemVersion,
            appVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "Unknown",
            deviceIdentifier: UIDevice.current.identifierForVendor?.uuidString ?? "Unknown"
        )
    }
} 