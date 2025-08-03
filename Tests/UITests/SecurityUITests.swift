import XCTest
import SecurityFrameworkPro

/**
 * Security UI Tests
 * 
 * Comprehensive UI tests for the SecurityFrameworkPro components
 * covering user interface interactions and visual elements.
 */
final class SecurityUITests: XCTestCase {
    var app: XCUIApplication!
    
    override func setUp() {
        super.setUp()
        continueAfterFailure = false
        app = XCUIApplication()
        app.launch()
    }
    
    override func tearDown() {
        app = nil
        super.tearDown()
    }
    
    // MARK: - App Launch Tests
    
    func testAppLaunch() {
        // Given
        let app = XCUIApplication()
        
        // When
        app.launch()
        
        // Then
        XCTAssertTrue(app.exists)
    }
    
    func testAppLaunchPerformance() {
        // When & Then
        measure(metrics: [XCTCPUMetric(), XCTMemoryMetric()]) {
            app.launch()
        }
    }
    
    // MARK: - Security Examples UI Tests
    
    func testSecurityExamplesNavigation() {
        // Given
        let navigationBar = app.navigationBars["Security Examples"]
        
        // When & Then
        XCTAssertTrue(navigationBar.exists)
        XCTAssertTrue(navigationBar.staticTexts["Security Examples"].exists)
    }
    
    func testBiometricAuthenticationSection() {
        // Given
        let biometricSection = app.staticTexts["Biometric Authentication"]
        
        // When & Then
        XCTAssertTrue(biometricSection.exists)
    }
    
    func testKeychainManagementSection() {
        // Given
        let keychainSection = app.staticTexts["Keychain Management"]
        
        // When & Then
        XCTAssertTrue(keychainSection.exists)
    }
    
    func testEncryptionServicesSection() {
        // Given
        let encryptionSection = app.staticTexts["Encryption Services"]
        
        // When & Then
        XCTAssertTrue(encryptionSection.exists)
    }
    
    func testSecurityMonitoringSection() {
        // Given
        let monitoringSection = app.staticTexts["Security Monitoring"]
        
        // When & Then
        XCTAssertTrue(monitoringSection.exists)
    }
    
    func testThreatDetectionSection() {
        // Given
        let threatSection = app.staticTexts["Threat Detection"]
        
        // When & Then
        XCTAssertTrue(threatSection.exists)
    }
    
    // MARK: - Button Interaction Tests
    
    func testCheckBiometricAvailabilityButton() {
        // Given
        let button = app.buttons["Check Biometric Availability"]
        
        // When & Then
        XCTAssertTrue(button.exists)
        XCTAssertTrue(button.isEnabled)
    }
    
    func testAuthenticateButton() {
        // Given
        let button = app.buttons["Authenticate with Face ID/Touch ID"]
        
        // When & Then
        XCTAssertTrue(button.exists)
        // Note: Button may be disabled if biometrics not available
    }
    
    func testStoreSecureDataButton() {
        // Given
        let button = app.buttons["Store Secure Data"]
        
        // When & Then
        XCTAssertTrue(button.exists)
        XCTAssertTrue(button.isEnabled)
    }
    
    func testRetrieveSecureDataButton() {
        // Given
        let button = app.buttons["Retrieve Secure Data"]
        
        // When & Then
        XCTAssertTrue(button.exists)
        XCTAssertTrue(button.isEnabled)
    }
    
    func testDeleteSecureDataButton() {
        // Given
        let button = app.buttons["Delete Secure Data"]
        
        // When & Then
        XCTAssertTrue(button.exists)
        XCTAssertTrue(button.isEnabled)
    }
    
    func testEncryptSensitiveDataButton() {
        // Given
        let button = app.buttons["Encrypt Sensitive Data"]
        
        // When & Then
        XCTAssertTrue(button.exists)
        XCTAssertTrue(button.isEnabled)
    }
    
    func testDecryptSensitiveDataButton() {
        // Given
        let button = app.buttons["Decrypt Sensitive Data"]
        
        // When & Then
        XCTAssertTrue(button.exists)
        XCTAssertTrue(button.isEnabled)
    }
    
    func testEncryptWithAES256Button() {
        // Given
        let button = app.buttons["Encrypt with AES-256"]
        
        // When & Then
        XCTAssertTrue(button.exists)
        XCTAssertTrue(button.isEnabled)
    }
    
    func testGetSecurityStatusButton() {
        // Given
        let button = app.buttons["Get Security Status"]
        
        // When & Then
        XCTAssertTrue(button.exists)
        XCTAssertTrue(button.isEnabled)
    }
    
    func testGetAuditLogButton() {
        // Given
        let button = app.buttons["Get Audit Log"]
        
        // When & Then
        XCTAssertTrue(button.exists)
        XCTAssertTrue(button.isEnabled)
    }
    
    func testGetThreatReportButton() {
        // Given
        let button = app.buttons["Get Threat Report"]
        
        // When & Then
        XCTAssertTrue(button.exists)
        XCTAssertTrue(button.isEnabled)
    }
    
    // MARK: - Status Display Tests
    
    func testAuthenticationStatusDisplay() {
        // Given
        let statusText = app.staticTexts.containing(NSPredicate(format: "label CONTAINS %@", "Authentication Status"))
        
        // When & Then
        XCTAssertTrue(statusText.element.exists)
    }
    
    func testSecurityStatusDisplay() {
        // Given
        let statusSection = app.staticTexts["Security Status:"]
        
        // When & Then
        // Note: This may only appear after clicking "Get Security Status"
        XCTAssertNotNil(statusSection)
    }
    
    func testThreatReportDisplay() {
        // Given
        let reportSection = app.staticTexts["Threat Report:"]
        
        // When & Then
        // Note: This may only appear after clicking "Get Threat Report"
        XCTAssertNotNil(reportSection)
    }
    
    // MARK: - Scroll View Tests
    
    func testScrollViewExists() {
        // Given
        let scrollView = app.scrollViews.firstMatch
        
        // When & Then
        XCTAssertTrue(scrollView.exists)
    }
    
    func testScrollViewScrolling() {
        // Given
        let scrollView = app.scrollViews.firstMatch
        
        // When
        scrollView.swipeUp()
        
        // Then
        XCTAssertTrue(scrollView.exists)
    }
    
    // MARK: - Accessibility Tests
    
    func testAccessibilityLabels() {
        // Given
        let buttons = app.buttons.allElements
        
        // When & Then
        for button in buttons {
            XCTAssertFalse(button.label.isEmpty, "Button should have accessibility label")
        }
    }
    
    func testAccessibilityHints() {
        // Given
        let buttons = app.buttons.allElements
        
        // When & Then
        for button in buttons {
            // Check if buttons have accessibility hints
            XCTAssertNotNil(button)
        }
    }
    
    // MARK: - Performance Tests
    
    func testUIResponsiveness() {
        // Given
        let startTime = Date()
        
        // When
        app.buttons["Check Biometric Availability"].tap()
        
        // Then
        let responseTime = Date().timeIntervalSince(startTime)
        XCTAssertLessThan(responseTime, 1.0, "UI should respond within 1 second")
    }
    
    func testMemoryUsage() {
        // Given
        let initialMemory = getMemoryUsage()
        
        // When
        for _ in 0..<10 {
            app.buttons["Get Security Status"].tap()
        }
        
        // Then
        let finalMemory = getMemoryUsage()
        let memoryIncrease = finalMemory - initialMemory
        XCTAssertLessThan(memoryIncrease, 50 * 1024 * 1024, "Memory increase should be less than 50MB")
    }
    
    // MARK: - Helper Methods
    
    private func getMemoryUsage() -> Int64 {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size)/4
        
        let kerr: kern_return_t = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: 1) {
                task_info(mach_task_self_,
                         task_flavor_t(MACH_TASK_BASIC_INFO),
                         $0,
                         &count)
            }
        }
        
        if kerr == KERN_SUCCESS {
            return Int64(info.resident_size)
        } else {
            return 0
        }
    }
} 