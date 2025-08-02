import SwiftUI
import SecurityFrameworkPro

/**
 * Security Examples
 * 
 * Comprehensive examples showing how to use SecurityManager component
 * with different security features and configurations.
 */
struct SecurityExamples: View {
    @StateObject private var securityManager = SecurityManager()
    @State private var isAuthenticated = false
    @State private var securityStatus: SecurityStatus?
    @State private var auditLog: [SecurityAuditEvent] = []
    @State private var threatReport: ThreatReport?
    
    var body: some View {
        ScrollView {
            VStack(spacing: 30) {
                // Biometric Authentication
                biometricAuthenticationSection
                
                // Keychain Management
                keychainManagementSection
                
                // Encryption Services
                encryptionServicesSection
                
                // Security Monitoring
                securityMonitoringSection
                
                // Threat Detection
                threatDetectionSection
            }
            .padding()
        }
        .navigationTitle("Security Examples")
        .onAppear {
            loadSecurityStatus()
        }
    }
    
    // MARK: - Biometric Authentication
    private var biometricAuthenticationSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Biometric Authentication")
                .font(.title2)
                .fontWeight(.bold)
            
            VStack(spacing: 12) {
                // Check Biometric Availability
                Button("Check Biometric Availability") {
                    checkBiometricAvailability()
                }
                .buttonStyle(.borderedProminent)
                
                // Authenticate User
                Button("Authenticate with Face ID/Touch ID") {
                    authenticateUser()
                }
                .buttonStyle(.borderedProminent)
                .disabled(!securityManager.isBiometricAvailable().isAvailable)
                
                // Authentication Status
                HStack {
                    Text("Authentication Status:")
                    Spacer()
                    Text(isAuthenticated ? "✅ Authenticated" : "❌ Not Authenticated")
                        .foregroundColor(isAuthenticated ? .green : .red)
                }
                .padding(.horizontal)
            }
        }
    }
    
    // MARK: - Keychain Management
    private var keychainManagementSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Keychain Management")
                .font(.title2)
                .fontWeight(.bold)
            
            VStack(spacing: 12) {
                // Store Secure Data
                Button("Store Secure Data") {
                    storeSecureData()
                }
                .buttonStyle(.borderedProminent)
                
                // Retrieve Secure Data
                Button("Retrieve Secure Data") {
                    retrieveSecureData()
                }
                .buttonStyle(.borderedProminent)
                
                // Delete Secure Data
                Button("Delete Secure Data") {
                    deleteSecureData()
                }
                .buttonStyle(.borderedProminent)
                .foregroundColor(.red)
            }
        }
    }
    
    // MARK: - Encryption Services
    private var encryptionServicesSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Encryption Services")
                .font(.title2)
                .fontWeight(.bold)
            
            VStack(spacing: 12) {
                // Encrypt Data
                Button("Encrypt Sensitive Data") {
                    encryptData()
                }
                .buttonStyle(.borderedProminent)
                
                // Decrypt Data
                Button("Decrypt Sensitive Data") {
                    decryptData()
                }
                .buttonStyle(.borderedProminent)
                
                // Different Algorithms
                Button("Encrypt with AES-256") {
                    encryptWithAES256()
                }
                .buttonStyle(.borderedProminent)
            }
        }
    }
    
    // MARK: - Security Monitoring
    private var securityMonitoringSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Security Monitoring")
                .font(.title2)
                .fontWeight(.bold)
            
            VStack(spacing: 12) {
                // Get Security Status
                Button("Get Security Status") {
                    getSecurityStatus()
                }
                .buttonStyle(.borderedProminent)
                
                // Get Audit Log
                Button("Get Audit Log") {
                    getAuditLog()
                }
                .buttonStyle(.borderedProminent)
                
                // Security Status Display
                if let status = securityStatus {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Security Status:")
                            .font(.headline)
                        
                        Text("• Authenticated: \(status.isAuthenticated ? "Yes" : "No")")
                        Text("• Biometric: \(status.biometricAvailable.description)")
                        Text("• Security Level: \(status.securityLevel)")
                        Text("• Threat Level: \(status.threatLevel)")
                    }
                    .padding()
                    .background(Color(.systemGray6))
                    .cornerRadius(8)
                }
            }
        }
    }
    
    // MARK: - Threat Detection
    private var threatDetectionSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Threat Detection")
                .font(.title2)
                .fontWeight(.bold)
            
            VStack(spacing: 12) {
                // Get Threat Report
                Button("Get Threat Report") {
                    getThreatReport()
                }
                .buttonStyle(.borderedProminent)
                
                // Threat Report Display
                if let report = threatReport {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Threat Report:")
                            .font(.headline)
                        
                        Text("• Threat Level: \(report.threatLevel)")
                        Text("• Detected Threats: \(report.detectedThreats.count)")
                        Text("• Recommendations: \(report.recommendations.count)")
                        Text("• Timestamp: \(report.timestamp)")
                    }
                    .padding()
                    .background(Color(.systemGray6))
                    .cornerRadius(8)
                }
            }
        }
    }
    
    // MARK: - Helper Methods
    
    private func checkBiometricAvailability() {
        let availability = securityManager.isBiometricAvailable()
        print("Biometric Availability: \(availability.description)")
    }
    
    private func authenticateUser() {
        Task {
            do {
                let result = try await securityManager.authenticateUser(
                    reason: "Authenticate to access secure features"
                )
                await MainActor.run {
                    isAuthenticated = result
                }
            } catch {
                print("Authentication failed: \(error.localizedDescription)")
            }
        }
    }
    
    private func storeSecureData() {
        do {
            let sensitiveData = "Super secret data".data(using: .utf8)!
            try securityManager.storeSecureData(sensitiveData, forKey: "user_secret")
            print("Secure data stored successfully")
        } catch {
            print("Failed to store secure data: \(error.localizedDescription)")
        }
    }
    
    private func retrieveSecureData() {
        do {
            let data = try securityManager.retrieveSecureData(forKey: "user_secret")
            let string = String(data: data, encoding: .utf8)
            print("Retrieved secure data: \(string ?? "Invalid data")")
        } catch {
            print("Failed to retrieve secure data: \(error.localizedDescription)")
        }
    }
    
    private func deleteSecureData() {
        do {
            try securityManager.deleteSecureData(forKey: "user_secret")
            print("Secure data deleted successfully")
        } catch {
            print("Failed to delete secure data: \(error.localizedDescription)")
        }
    }
    
    private func encryptData() {
        do {
            let originalData = "Sensitive information".data(using: .utf8)!
            let encryptedData = try securityManager.encryptSensitiveData(originalData)
            print("Data encrypted successfully: \(encryptedData.count) bytes")
        } catch {
            print("Failed to encrypt data: \(error.localizedDescription)")
        }
    }
    
    private func decryptData() {
        do {
            let originalData = "Sensitive information".data(using: .utf8)!
            let encryptedData = try securityManager.encryptSensitiveData(originalData)
            let decryptedData = try securityManager.decryptSensitiveData(encryptedData)
            let string = String(data: decryptedData, encoding: .utf8)
            print("Data decrypted successfully: \(string ?? "Invalid data")")
        } catch {
            print("Failed to decrypt data: \(error.localizedDescription)")
        }
    }
    
    private func encryptWithAES256() {
        do {
            let originalData = "High-security data".data(using: .utf8)!
            let encryptedData = try securityManager.encryptSensitiveData(
                originalData,
                algorithm: .aes256,
                keySize: .bits256
            )
            print("AES-256 encryption successful: \(encryptedData.count) bytes")
        } catch {
            print("Failed to encrypt with AES-256: \(error.localizedDescription)")
        }
    }
    
    private func getSecurityStatus() {
        securityStatus = securityManager.getSecurityStatus()
    }
    
    private func getAuditLog() {
        auditLog = securityManager.getAuditLog()
        print("Audit log retrieved: \(auditLog.count) events")
    }
    
    private func getThreatReport() {
        threatReport = securityManager.getThreatReport()
    }
    
    private func loadSecurityStatus() {
        securityStatus = securityManager.getSecurityStatus()
    }
}

// MARK: - Previews
struct SecurityExamples_Previews: PreviewProvider {
    static var previews: some View {
        NavigationView {
            SecurityExamples()
        }
    }
} 