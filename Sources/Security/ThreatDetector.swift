import Foundation
import Security

/**
 * ThreatDetector - Real-time Threat Detection Component
 * 
 * Provides comprehensive threat detection and monitoring capabilities
 * with behavioral analysis and security threat identification.
 */
public class ThreatDetector {
    private let auditLogger = SecurityAuditLogger()
    
    private var threatLevel: ThreatLevel = .low
    private var detectedThreats: [SecurityThreat] = []
    private var authenticationAttempts: [AuthenticationAttempt] = []
    private var suspiciousActivities: [SuspiciousActivity] = []
    
    public init() {}
    
    // MARK: - Threat Detection
    
    public func startMonitoring() {
        // Start continuous threat monitoring
        scheduleThreatAnalysis()
    }
    
    public func getCurrentThreatLevel() -> ThreatLevel {
        return threatLevel
    }
    
    public func generateReport() -> ThreatReport {
        return ThreatReport(
            threatLevel: threatLevel,
            detectedThreats: detectedThreats,
            recommendations: generateRecommendations(),
            timestamp: Date()
        )
    }
    
    // MARK: - Authentication Monitoring
    
    public func recordSuccessfulAuthentication() {
        let attempt = AuthenticationAttempt(
            timestamp: Date(),
            success: true,
            biometricType: getCurrentBiometricType()
        )
        
        authenticationAttempts.append(attempt)
        analyzeAuthenticationPatterns()
    }
    
    public func recordFailedAuthentication() {
        let attempt = AuthenticationAttempt(
            timestamp: Date(),
            success: false,
            biometricType: getCurrentBiometricType()
        )
        
        authenticationAttempts.append(attempt)
        analyzeAuthenticationPatterns()
        
        // Check for brute force attempts
        checkForBruteForceAttempts()
    }
    
    // MARK: - Activity Monitoring
    
    public func recordSuspiciousActivity(_ activity: SuspiciousActivity) {
        suspiciousActivities.append(activity)
        
        if activity.severity == .critical {
            threatLevel = .critical
            auditLogger.logEvent(.threatDetected, severity: .critical, metadata: [
                "activity": activity.description,
                "severity": activity.severity.rawValue
            ])
        } else if activity.severity == .high && threatLevel != .critical {
            threatLevel = .high
        }
        
        detectedThreats.append(SecurityThreat(
            type: .suspiciousActivity,
            severity: activity.severity,
            description: activity.description,
            timestamp: Date()
        ))
    }
    
    // MARK: - Private Methods
    
    private func scheduleThreatAnalysis() {
        Timer.scheduledTimer(withTimeInterval: 300, repeats: true) { [weak self] _ in
            self?.performThreatAnalysis()
        }
    }
    
    private func performThreatAnalysis() {
        // Analyze recent activities for threats
        analyzeAuthenticationPatterns()
        analyzeSuspiciousActivities()
        updateThreatLevel()
    }
    
    private func analyzeAuthenticationPatterns() {
        let recentAttempts = authenticationAttempts.filter {
            $0.timestamp.timeIntervalSinceNow > -3600 // Last hour
        }
        
        let failedAttempts = recentAttempts.filter { !$0.success }
        
        if failedAttempts.count > 5 {
            let threat = SecurityThreat(
                type: .bruteForce,
                severity: .high,
                description: "Multiple failed authentication attempts detected",
                timestamp: Date()
            )
            
            detectedThreats.append(threat)
            threatLevel = .high
            
            auditLogger.logEvent(.threatDetected, severity: .high, metadata: [
                "failedAttempts": failedAttempts.count,
                "timeWindow": "1 hour"
            ])
        }
    }
    
    private func checkForBruteForceAttempts() {
        let recentFailedAttempts = authenticationAttempts.filter {
            $0.timestamp.timeIntervalSinceNow > -300 && !$0.success // Last 5 minutes
        }
        
        if recentFailedAttempts.count > 3 {
            threatLevel = .critical
            
            let threat = SecurityThreat(
                type: .bruteForce,
                severity: .critical,
                description: "Rapid failed authentication attempts - possible brute force attack",
                timestamp: Date()
            )
            
            detectedThreats.append(threat)
            
            auditLogger.logEvent(.threatDetected, severity: .critical, metadata: [
                "failedAttempts": recentFailedAttempts.count,
                "timeWindow": "5 minutes"
            ])
        }
    }
    
    private func analyzeSuspiciousActivities() {
        let criticalActivities = suspiciousActivities.filter {
            $0.severity == .critical && $0.timestamp.timeIntervalSinceNow > -3600
        }
        
        if !criticalActivities.isEmpty {
            threatLevel = .critical
        }
    }
    
    private func updateThreatLevel() {
        // Reset threat level if no recent threats
        let recentThreats = detectedThreats.filter {
            $0.timestamp.timeIntervalSinceNow > -3600
        }
        
        if recentThreats.isEmpty {
            threatLevel = .low
        }
    }
    
    private func generateRecommendations() -> [String] {
        var recommendations: [String] = []
        
        if threatLevel == .critical {
            recommendations.append("Immediate action required: Critical security threats detected")
            recommendations.append("Enable additional security measures")
            recommendations.append("Review recent authentication attempts")
        } else if threatLevel == .high {
            recommendations.append("Monitor authentication patterns closely")
            recommendations.append("Consider implementing rate limiting")
        } else if threatLevel == .medium {
            recommendations.append("Continue monitoring for suspicious activities")
        } else {
            recommendations.append("Security status is normal")
        }
        
        return recommendations
    }
    
    private func getCurrentBiometricType() -> String {
        // This would typically get the current biometric type
        return "Face ID"
    }
}

// MARK: - Supporting Types

public struct AuthenticationAttempt {
    public let timestamp: Date
    public let success: Bool
    public let biometricType: String
}

public struct SuspiciousActivity {
    public let description: String
    public let severity: SecuritySeverity
    public let timestamp: Date
    public let metadata: [String: Any]?
} 