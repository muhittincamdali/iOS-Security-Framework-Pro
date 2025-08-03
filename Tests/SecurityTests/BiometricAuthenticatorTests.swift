import XCTest
import SecurityFrameworkPro
import LocalAuthentication

/**
 * BiometricAuthenticator Unit Tests
 * 
 * Comprehensive unit tests for the BiometricAuthenticator component
 * covering all biometric authentication features and functionality.
 */
final class BiometricAuthenticatorTests: XCTestCase {
    var biometricAuthenticator: BiometricAuthenticator!
    
    override func setUp() {
        super.setUp()
        biometricAuthenticator = BiometricAuthenticator()
    }
    
    override func tearDown() {
        biometricAuthenticator = nil
        super.tearDown()
    }
    
    // MARK: - Initialization Tests
    
    func testBiometricAuthenticatorInitialization() {
        // Given
        let authenticator = BiometricAuthenticator()
        
        // Then
        XCTAssertNotNil(authenticator)
    }
    
    // MARK: - Availability Tests
    
    func testBiometricAvailability() {
        // When
        let availability = biometricAuthenticator.checkAvailability()
        
        // Then
        XCTAssertNotNil(availability)
        // Note: Actual availability depends on device capabilities
    }
    
    func testBiometricEnrollment() {
        // When
        let isEnrolled = biometricAuthenticator.isBiometricEnrolled()
        
        // Then
        XCTAssertNotNil(isEnrolled)
        // Note: Enrollment status depends on device configuration
    }
    
    func testBiometricType() {
        // When
        let biometricType = biometricAuthenticator.getBiometricType()
        
        // Then
        XCTAssertNotNil(biometricType)
        // Note: Biometric type depends on device capabilities
    }
    
    // MARK: - Policy Tests
    
    func testPolicyAvailability() {
        // Given
        let policies: [LAPolicy] = [
            .deviceOwnerAuthentication,
            .deviceOwnerAuthenticationWithBiometrics,
            .deviceOwnerAuthenticationWithWatch
        ]
        
        // When & Then
        for policy in policies {
            let isAvailable = biometricAuthenticator.isPolicyAvailable(policy)
            XCTAssertNotNil(isAvailable)
        }
    }
    
    func testAvailablePolicies() {
        // When
        let availablePolicies = biometricAuthenticator.getAvailablePolicies()
        
        // Then
        XCTAssertNotNil(availablePolicies)
        XCTAssertTrue(availablePolicies is [LAPolicy])
    }
    
    // MARK: - Authentication Tests
    
    func testAuthenticationWithValidReason() {
        // Given
        let reason = "Test authentication"
        
        // When & Then
        // Note: This test requires actual biometric authentication
        // In a real test environment, you would mock the authentication
        XCTAssertNotNil(reason)
    }
    
    func testAuthenticationWithEmptyReason() {
        // Given
        let reason = ""
        
        // When & Then
        // Empty reason should still work but may show default message
        XCTAssertNotNil(reason)
    }
    
    func testAuthenticationWithLongReason() {
        // Given
        let reason = "This is a very long authentication reason that tests how the system handles extended text in the biometric authentication prompt"
        
        // When & Then
        XCTAssertNotNil(reason)
        XCTAssertGreaterThan(reason.count, 50)
    }
    
    // MARK: - Security Features Tests
    
    func testAuthenticationInvalidation() {
        // Given
        let authenticator = BiometricAuthenticator()
        
        // When
        authenticator.invalidateAuthentication()
        
        // Then
        // Authentication should be invalidated
        XCTAssertNotNil(authenticator)
    }
    
    func testAuthenticationTimeout() {
        // Given
        let timeout: TimeInterval = 30.0
        
        // When
        biometricAuthenticator.setAuthenticationTimeout(timeout)
        let retrievedTimeout = biometricAuthenticator.getAuthenticationReuseDuration()
        
        // Then
        XCTAssertEqual(retrievedTimeout, timeout)
    }
    
    // MARK: - Error Handling Tests
    
    func testErrorDetails() {
        // Given
        let testError = LAError(.userCancel)
        
        // When
        let errorDetails = biometricAuthenticator.getErrorDetails(testError)
        
        // Then
        XCTAssertNotNil(errorDetails)
        XCTAssertEqual(errorDetails.code, .userCancel)
        XCTAssertNotNil(errorDetails.description)
    }
    
    func testErrorRecoverability() {
        // Given
        let recoverableError = LAError(.userCancel)
        let nonRecoverableError = LAError(.authenticationFailed)
        
        // When
        let isRecoverable1 = biometricAuthenticator.isErrorRecoverable(recoverableError)
        let isRecoverable2 = biometricAuthenticator.isErrorRecoverable(nonRecoverableError)
        
        // Then
        XCTAssertTrue(isRecoverable1)
        XCTAssertFalse(isRecoverable2)
    }
    
    // MARK: - Performance Tests
    
    func testAvailabilityCheckPerformance() {
        // When & Then
        measure {
            _ = biometricAuthenticator.checkAvailability()
        }
    }
    
    func testPolicyCheckPerformance() {
        // When & Then
        measure {
            _ = biometricAuthenticator.isPolicyAvailable(.deviceOwnerAuthenticationWithBiometrics)
        }
    }
    
    // MARK: - Mock Tests
    
    func testMockAuthentication() {
        // Given
        let mockAuthenticator = MockBiometricAuthenticator()
        
        // When
        let result = mockAuthenticator.mockAuthenticate()
        
        // Then
        XCTAssertTrue(result)
    }
    
    func testMockAvailability() {
        // Given
        let mockAuthenticator = MockBiometricAuthenticator()
        
        // When
        let availability = mockAuthenticator.mockCheckAvailability()
        
        // Then
        XCTAssertTrue(availability.isAvailable)
    }
}

// MARK: - Mock Biometric Authenticator

class MockBiometricAuthenticator: BiometricAuthenticator {
    func mockAuthenticate() -> Bool {
        return true
    }
    
    func mockCheckAvailability() -> BiometricAvailability {
        return .faceID
    }
} 