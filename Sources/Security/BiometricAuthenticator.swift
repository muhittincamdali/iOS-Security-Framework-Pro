import Foundation
import LocalAuthentication
import Security

/**
 * BiometricAuthenticator - Biometric Authentication Component
 * 
 * Handles Face ID, Touch ID, and other biometric authentication methods
 * with comprehensive error handling and security features.
 * 
 * - Features:
 *   - Face ID and Touch ID support
 *   - Biometric availability checking
 *   - Authentication policy management
 *   - Secure authentication flow
 *   - Error handling and logging
 * 
 * - Example:
 * ```swift
 * let authenticator = BiometricAuthenticator()
 * let isAvailable = authenticator.checkAvailability()
 * let isAuthenticated = try await authenticator.authenticate(reason: "Access secure data")
 * ```
 */
public class BiometricAuthenticator {
    private let context = LAContext()
    private let auditLogger = SecurityAuditLogger()
    
    public init() {}
    
    // MARK: - Authentication
    
    /**
     * Authenticate user using biometric authentication
     * 
     * - Parameters:
     *   - reason: Authentication reason for user
     *   - policy: Authentication policy to use
     * 
     * - Returns: Authentication result
     * 
     * - Throws: SecurityError if authentication fails
     */
    public func authenticate(
        reason: String,
        policy: LAPolicy = .deviceOwnerAuthenticationWithBiometrics
    ) async throws -> Bool {
        var error: NSError?
        
        // Check if biometric authentication is available
        guard context.canEvaluatePolicy(policy, error: &error) else {
            auditLogger.logEvent(.authenticationError, error: error)
            throw SecurityError.biometricNotAvailable
        }
        
        // Perform authentication
        do {
            let result = try await context.evaluatePolicy(policy, localizedReason: reason)
            
            if result {
                auditLogger.logEvent(.authenticationSuccess)
            } else {
                auditLogger.logEvent(.authenticationFailure)
            }
            
            return result
        } catch {
            auditLogger.logEvent(.authenticationError, error: error)
            throw SecurityError.authenticationFailed(error)
        }
    }
    
    /**
     * Check biometric authentication availability
     * 
     * - Returns: Biometric availability status
     */
    public func checkAvailability() -> BiometricAvailability {
        var error: NSError?
        
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return .notAvailable(error?.localizedDescription ?? "Unknown error")
        }
        
        switch context.biometryType {
        case .faceID:
            return .faceID
        case .touchID:
            return .touchID
        case .none:
            return .notAvailable("No biometric authentication available")
        @unknown default:
            return .notAvailable("Unknown biometric type")
        }
    }
    
    /**
     * Check if biometric authentication is enrolled
     * 
     * - Returns: Enrollment status
     */
    public func isBiometricEnrolled() -> Bool {
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }
    
    /**
     * Get biometric type
     * 
     * - Returns: Biometric type
     */
    public func getBiometricType() -> LABiometryType {
        return context.biometryType
    }
    
    // MARK: - Policy Management
    
    /**
     * Check if specific policy is available
     * 
     * - Parameters:
     *   - policy: Policy to check
     * 
     * - Returns: Policy availability
     */
    public func isPolicyAvailable(_ policy: LAPolicy) -> Bool {
        var error: NSError?
        return context.canEvaluatePolicy(policy, error: &error)
    }
    
    /**
     * Get available policies
     * 
     * - Returns: Array of available policies
     */
    public func getAvailablePolicies() -> [LAPolicy] {
        let policies: [LAPolicy] = [
            .deviceOwnerAuthentication,
            .deviceOwnerAuthenticationWithBiometrics,
            .deviceOwnerAuthenticationWithWatch
        ]
        
        return policies.filter { isPolicyAvailable($0) }
    }
    
    // MARK: - Security Features
    
    /**
     * Invalidate biometric authentication
     * 
     * This method invalidates the current biometric authentication
     * and forces re-authentication on next attempt.
     */
    public func invalidateAuthentication() {
        context.invalidate()
        auditLogger.logEvent(.authenticationInvalidated)
    }
    
    /**
     * Set authentication timeout
     * 
     * - Parameters:
     *   - timeout: Timeout duration in seconds
     */
    public func setAuthenticationTimeout(_ timeout: TimeInterval) {
        context.touchIDAuthenticationAllowableReuseDuration = timeout
    }
    
    /**
     * Get authentication reuse duration
     * 
     * - Returns: Current reuse duration
     */
    public func getAuthenticationReuseDuration() -> TimeInterval {
        return context.touchIDAuthenticationAllowableReuseDuration
    }
    
    // MARK: - Error Handling
    
    /**
     * Get detailed error information
     * 
     * - Parameters:
     *   - error: Authentication error
     * 
     * - Returns: Detailed error information
     */
    public func getErrorDetails(_ error: Error) -> BiometricErrorDetails {
        let laError = error as? LAError ?? LAError(.invalidContext)
        
        return BiometricErrorDetails(
            code: laError.code,
            description: laError.localizedDescription,
            recoverySuggestion: laError.localizedRecoverySuggestion,
            failureReason: laError.localizedFailureReason
        )
    }
    
    /**
     * Check if error is recoverable
     * 
     * - Parameters:
     *   - error: Authentication error
     * 
     * - Returns: Whether error is recoverable
     */
    public func isErrorRecoverable(_ error: Error) -> Bool {
        let laError = error as? LAError ?? LAError(.invalidContext)
        
        switch laError.code {
        case .userCancel, .userFallback, .systemCancel, .appCancel:
            return true
        case .authenticationFailed, .userLockout, .invalidContext:
            return false
        default:
            return false
        }
    }
}

// MARK: - Supporting Types

public enum BiometricAvailability {
    case faceID
    case touchID
    case notAvailable(String)
    
    public var isAvailable: Bool {
        switch self {
        case .faceID, .touchID:
            return true
        case .notAvailable:
            return false
        }
    }
    
    public var description: String {
        switch self {
        case .faceID:
            return "Face ID"
        case .touchID:
            return "Touch ID"
        case .notAvailable(let reason):
            return "Not Available: \(reason)"
        }
    }
}

public struct BiometricErrorDetails {
    public let code: LAError.Code
    public let description: String
    public let recoverySuggestion: String?
    public let failureReason: String?
    
    public var isRecoverable: Bool {
        switch code {
        case .userCancel, .userFallback, .systemCancel, .appCancel:
            return true
        case .authenticationFailed, .userLockout, .invalidContext:
            return false
        default:
            return false
        }
    }
}

// MARK: - Security Error Extension

extension SecurityError {
    public static func biometricNotAvailable(_ reason: String? = nil) -> SecurityError {
        return .biometricNotAvailable
    }
    
    public static func authenticationFailed(_ error: Error) -> SecurityError {
        return .authenticationFailed(error)
    }
} 