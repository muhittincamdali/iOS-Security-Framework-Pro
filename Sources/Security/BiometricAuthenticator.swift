//
//  BiometricAuthenticator.swift
//  iOS Security Framework Pro
//
//  Created by Muhittin Camdali
//  Copyright © 2024 Muhittin Camdali. All rights reserved.
//

import Foundation
import LocalAuthentication
import Security

/// Advanced biometric authentication manager for iOS Security Framework Pro
public final class BiometricAuthenticator {
    
    // MARK: - Singleton
    public static let shared = BiometricAuthenticator()
    private init() {}
    
    // MARK: - Properties
    private let context = LAContext()
    private let biometricQueue = DispatchQueue(label: "com.securityframework.biometric", qos: .userInitiated)
    private var authenticationPolicies: [String: BiometricPolicy] = [:]
    private var authenticationAttempts: [String: Int] = [:]
    private let maxAttempts = 5
    
    // MARK: - Biometric Types
    public enum BiometricType {
        case faceID
        case touchID
        case none
        
        public var description: String {
            switch self {
            case .faceID: return "Face ID"
            case .touchID: return "Touch ID"
            case .none: return "None"
            }
        }
    }
    
    // MARK: - Authentication Policies
    public struct BiometricPolicy {
        public let biometricType: BiometricType
        public let fallbackEnabled: Bool
        public let fallbackTitle: String?
        public let cancelTitle: String?
        public let reason: String
        public let maxAttempts: Int
        public let lockoutDuration: TimeInterval
        
        public init(
            biometricType: BiometricType = .faceID,
            fallbackEnabled: Bool = true,
            fallbackTitle: String? = "Enter Passcode",
            cancelTitle: String? = "Cancel",
            reason: String = "Authenticate to continue",
            maxAttempts: Int = 5,
            lockoutDuration: TimeInterval = 300.0
        ) {
            self.biometricType = biometricType
            self.fallbackEnabled = fallbackEnabled
            self.fallbackTitle = fallbackTitle
            self.cancelTitle = cancelTitle
            self.reason = reason
            self.maxAttempts = maxAttempts
            self.lockoutDuration = lockoutDuration
        }
    }
    
    // MARK: - Authentication Result
    public enum AuthenticationResult {
        case success
        case failure(Error)
        case cancelled
        case lockedOut
        case notAvailable
    }
    
    // MARK: - Errors
    public enum BiometricError: Error, LocalizedError {
        case notAvailable
        case notEnrolled
        case lockedOut
        case cancelled
        case invalidPolicy
        case tooManyAttempts
        case systemError(LAError)
        
        public var errorDescription: String? {
            switch self {
            case .notAvailable:
                return "Biometric authentication is not available"
            case .notEnrolled:
                return "No biometric data is enrolled"
            case .lockedOut:
                return "Biometric authentication is locked out"
            case .cancelled:
                return "Authentication was cancelled"
            case .invalidPolicy:
                return "Invalid authentication policy"
            case .tooManyAttempts:
                return "Too many authentication attempts"
            case .systemError(let error):
                return "System error: \(error.localizedDescription)"
            }
        }
    }
    
    // MARK: - Public Methods
    
    /// Check biometric availability
    /// - Returns: Available biometric types
    public func checkAvailability() -> [BiometricType] {
        var availableTypes: [BiometricType] = []
        
        let context = LAContext()
        var error: NSError?
        
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            switch context.biometryType {
            case .faceID:
                availableTypes.append(.faceID)
            case .touchID:
                availableTypes.append(.touchID)
            case .none:
                break
            @unknown default:
                break
            }
        }
        
        return availableTypes
    }
    
    /// Get current biometric type
    /// - Returns: Current biometric type
    public func getCurrentBiometricType() -> BiometricType {
        let context = LAContext()
        var error: NSError?
        
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return .none
        }
        
        switch context.biometryType {
        case .faceID:
            return .faceID
        case .touchID:
            return .touchID
        case .none:
            return .none
        @unknown default:
            return .none
        }
    }
    
    /// Register authentication policy for a specific operation
    /// - Parameters:
    ///   - operation: Operation identifier
    ///   - policy: Authentication policy
    public func registerPolicy(for operation: String, policy: BiometricPolicy) {
        biometricQueue.sync {
            authenticationPolicies[operation] = policy
        }
    }
    
    /// Remove authentication policy for a specific operation
    /// - Parameter operation: Operation identifier
    public func removePolicy(for operation: String) {
        biometricQueue.sync {
            authenticationPolicies.removeValue(forKey: operation)
            authenticationAttempts.removeValue(forKey: operation)
        }
    }
    
    /// Authenticate with biometrics
    /// - Parameters:
    ///   - operation: Operation identifier
    ///   - completion: Completion handler with result
    public func authenticate(operation: String, completion: @escaping (AuthenticationResult) -> Void) {
        biometricQueue.async {
            // Check if operation is locked out
            if self.isLockedOut(for: operation) {
                completion(.lockedOut)
                return
            }
            
            // Get policy for operation
            guard let policy = self.authenticationPolicies[operation] else {
                completion(.failure(BiometricError.invalidPolicy))
                return
            }
            
            // Check biometric availability
            guard self.isBiometricAvailable(for: policy.biometricType) else {
                completion(.notAvailable)
                return
            }
            
            // Perform authentication
            self.performAuthentication(with: policy, operation: operation, completion: completion)
        }
    }
    
    /// Authenticate with default policy
    /// - Parameter completion: Completion handler with result
    public func authenticate(completion: @escaping (AuthenticationResult) -> Void) {
        let defaultPolicy = BiometricPolicy()
        authenticate(operation: "default", completion: completion)
    }
    
    /// Reset authentication attempts for an operation
    /// - Parameter operation: Operation identifier
    public func resetAttempts(for operation: String) {
        biometricQueue.sync {
            authenticationAttempts.removeValue(forKey: operation)
        }
    }
    
    /// Check if operation is locked out
    /// - Parameter operation: Operation identifier
    /// - Returns: True if locked out, false otherwise
    public func isLockedOut(for operation: String) -> Bool {
        guard let attempts = authenticationAttempts[operation],
              let policy = authenticationPolicies[operation] else {
            return false
        }
        
        return attempts >= policy.maxAttempts
    }
    
    /// Get remaining attempts for an operation
    /// - Parameter operation: Operation identifier
    /// - Returns: Remaining attempts count
    public func getRemainingAttempts(for operation: String) -> Int {
        guard let attempts = authenticationAttempts[operation],
              let policy = authenticationPolicies[operation] else {
            return 5 // Default max attempts
        }
        
        return max(0, policy.maxAttempts - attempts)
    }
    
    // MARK: - Private Methods
    
    private func isBiometricAvailable(for type: BiometricType) -> Bool {
        let context = LAContext()
        var error: NSError?
        
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return false
        }
        
        switch type {
        case .faceID:
            return context.biometryType == .faceID
        case .touchID:
            return context.biometryType == .touchID
        case .none:
            return false
        }
    }
    
    private func performAuthentication(
        with policy: BiometricPolicy,
        operation: String,
        completion: @escaping (AuthenticationResult) -> Void
    ) {
        let context = LAContext()
        
        // Configure context
        if let fallbackTitle = policy.fallbackTitle {
            context.localizedFallbackTitle = fallbackTitle
        }
        
        if let cancelTitle = policy.cancelTitle {
            context.localizedCancelTitle = cancelTitle
        }
        
        // Evaluate policy
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: policy.reason) { success, error in
            DispatchQueue.main.async {
                if success {
                    // Reset attempts on success
                    self.resetAttempts(for: operation)
                    completion(.success)
                } else {
                    // Handle error
                    self.handleAuthenticationError(error, operation: operation, completion: completion)
                }
            }
        }
    }
    
    private func handleAuthenticationError(
        _ error: Error?,
        operation: String,
        completion: @escaping (AuthenticationResult) -> Void
    ) {
        guard let error = error as? LAError else {
            completion(.failure(BiometricError.systemError(LAError(.appCancel))))
            return
        }
        
        switch error.code {
        case .userCancel, .appCancel:
            completion(.cancelled)
            
        case .userFallback:
            // Handle fallback authentication
            handleFallbackAuthentication(operation: operation, completion: completion)
            
        case .biometryNotAvailable:
            completion(.notAvailable)
            
        case .biometryNotEnrolled:
            completion(.failure(BiometricError.notEnrolled))
            
        case .biometryLockout:
            completion(.lockedOut)
            
        case .invalidContext:
            completion(.failure(BiometricError.systemError(error)))
            
        default:
            // Increment attempts
            incrementAttempts(for: operation)
            
            if isLockedOut(for: operation) {
                completion(.lockedOut)
            } else {
                completion(.failure(BiometricError.systemError(error)))
            }
        }
    }
    
    private func handleFallbackAuthentication(
        operation: String,
        completion: @escaping (AuthenticationResult) -> Void
    ) {
        guard let policy = authenticationPolicies[operation],
              policy.fallbackEnabled else {
            completion(.failure(BiometricError.invalidPolicy))
            return
        }
        
        // Implement fallback authentication (e.g., passcode)
        // For now, we'll just return failure
        completion(.failure(BiometricError.invalidPolicy))
    }
    
    private func incrementAttempts(for operation: String) {
        biometricQueue.sync {
            let currentAttempts = authenticationAttempts[operation] ?? 0
            authenticationAttempts[operation] = currentAttempts + 1
        }
    }
}

// MARK: - Biometric Authentication Extensions
extension BiometricAuthenticator {
    
    /// Create Face ID policy
    /// - Parameter reason: Authentication reason
    /// - Returns: Face ID policy
    public static func faceIDPolicy(reason: String = "Authenticate with Face ID") -> BiometricPolicy {
        return BiometricPolicy(
            biometricType: .faceID,
            reason: reason
        )
    }
    
    /// Create Touch ID policy
    /// - Parameter reason: Authentication reason
    /// - Returns: Touch ID policy
    public static func touchIDPolicy(reason: String = "Authenticate with Touch ID") -> BiometricPolicy {
        return BiometricPolicy(
            biometricType: .touchID,
            reason: reason
        )
    }
    
    /// Create strict policy with no fallback
    /// - Parameter reason: Authentication reason
    /// - Returns: Strict policy
    public static func strictPolicy(reason: String = "Authenticate to continue") -> BiometricPolicy {
        return BiometricPolicy(
            fallbackEnabled: false,
            reason: reason
        )
    }
} 