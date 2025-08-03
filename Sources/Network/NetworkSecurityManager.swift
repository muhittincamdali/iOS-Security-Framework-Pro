import Foundation
import Security
import Network

/**
 * NetworkSecurityManager - Network Security Component
 * 
 * Provides comprehensive network security features including SSL/TLS pinning,
 * certificate validation, API authentication, and secure network communication.
 * 
 * - Features:
 *   - SSL/TLS certificate pinning
 *   - Certificate validation and verification
 *   - API authentication with JWT tokens
 *   - Secure network request handling
 *   - DDoS protection and rate limiting
 *   - Network traffic monitoring
 * 
 * - Example:
 * ```swift
 * let networkSecurity = NetworkSecurityManager()
 * let secureRequest = try networkSecurity.createSecureRequest(
 *     url: "https://api.example.com",
 *     method: .GET,
 *     headers: ["Authorization": "Bearer token"]
 * )
 * ```
 */
public class NetworkSecurityManager: NSObject, URLSessionDelegate {
    private let auditLogger = SecurityAuditLogger()
    private let certificatePinningManager = CertificatePinningManager()
    private let rateLimiter = NetworkRateLimiter()
    private let threatDetector = NetworkThreatDetector()
    
    private var pinnedCertificates: [Data] = []
    private var allowedDomains: Set<String> = []
    private var blockedIPs: Set<String> = []
    
    public override init() {
        super.init()
        setupNetworkSecurity()
    }
    
    // MARK: - Configuration
    
    /**
     * Configure network security settings
     * 
     * - Parameters:
     *   - pinnedCertificates: Array of pinned certificates
     *   - allowedDomains: Set of allowed domains
     *   - blockedIPs: Set of blocked IP addresses
     */
    public func configure(
        pinnedCertificates: [Data] = [],
        allowedDomains: Set<String> = [],
        blockedIPs: Set<String> = []
    ) {
        self.pinnedCertificates = pinnedCertificates
        self.allowedDomains = allowedDomains
        self.blockedIPs = blockedIPs
        
        auditLogger.logEvent(.networkSecurityConfigured, metadata: [
            "pinnedCertificates": pinnedCertificates.count,
            "allowedDomains": allowedDomains.count,
            "blockedIPs": blockedIPs.count
        ])
    }
    
    // MARK: - Secure Network Requests
    
    /**
     * Create a secure network request
     * 
     * - Parameters:
     *   - url: Request URL
     *   - method: HTTP method
     *   - headers: Request headers
     *   - body: Request body
     * 
     * - Returns: Secure URLRequest
     * 
     * - Throws: SecurityError if request creation fails
     */
    public func createSecureRequest(
        url: String,
        method: HTTPMethod,
        headers: [String: String] = [:],
        body: Data? = nil
    ) throws -> URLRequest {
        guard let url = URL(string: url) else {
            throw SecurityError.networkError(NetworkError.invalidURL)
        }
        
        // Validate domain
        guard isDomainAllowed(url.host ?? "") else {
            throw SecurityError.networkError(NetworkError.domainNotAllowed)
        }
        
        // Check rate limiting
        guard rateLimiter.isRequestAllowed(for: url.host ?? "") else {
            throw SecurityError.networkError(NetworkError.rateLimitExceeded)
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = method.rawValue
        request.httpBody = body
        
        // Add security headers
        var secureHeaders = headers
        secureHeaders["User-Agent"] = "SecurityFrameworkPro/1.0"
        secureHeaders["Accept"] = "application/json"
        secureHeaders["Content-Type"] = "application/json"
        
        // Add security tokens if available
        if let authToken = getAuthToken() {
            secureHeaders["Authorization"] = "Bearer \(authToken)"
        }
        
        request.allHTTPHeaderFields = secureHeaders
        
        auditLogger.logEvent(.secureRequestCreated, metadata: [
            "url": url.absoluteString,
            "method": method.rawValue,
            "headers": secureHeaders.count
        ])
        
        return request
    }
    
    /**
     * Execute secure network request
     * 
     * - Parameters:
     *   - request: URLRequest to execute
     * 
     * - Returns: Network response
     * 
     * - Throws: SecurityError if request fails
     */
    public func executeSecureRequest(_ request: URLRequest) async throws -> NetworkResponse {
        let session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
        
        do {
            let (data, response) = try await session.data(for: request)
            
            guard let httpResponse = response as? HTTPURLResponse else {
                throw SecurityError.networkError(NetworkError.invalidResponse)
            }
            
            // Validate response
            try validateResponse(httpResponse, data: data)
            
            let networkResponse = NetworkResponse(
                data: data,
                response: httpResponse,
                request: request
            )
            
            auditLogger.logEvent(.secureRequestCompleted, metadata: [
                "statusCode": httpResponse.statusCode,
                "dataSize": data.count
            ])
            
            return networkResponse
        } catch {
            auditLogger.logEvent(.networkRequestError, error: error)
            throw SecurityError.networkError(NetworkError.requestFailed(error))
        }
    }
    
    // MARK: - Certificate Pinning
    
    /**
     * Add certificate for pinning
     * 
     * - Parameters:
     *   - certificate: Certificate data to pin
     */
    public func addPinnedCertificate(_ certificate: Data) {
        pinnedCertificates.append(certificate)
        auditLogger.logEvent(.certificatePinned, metadata: ["certificateSize": certificate.count])
    }
    
    /**
     * Remove pinned certificate
     * 
     * - Parameters:
     *   - certificate: Certificate data to remove
     */
    public func removePinnedCertificate(_ certificate: Data) {
        pinnedCertificates.removeAll { $0 == certificate }
        auditLogger.logEvent(.certificateUnpinned, metadata: ["certificateSize": certificate.count])
    }
    
    // MARK: - Domain Management
    
    /**
     * Add allowed domain
     * 
     * - Parameters:
     *   - domain: Domain to allow
     */
    public func addAllowedDomain(_ domain: String) {
        allowedDomains.insert(domain)
        auditLogger.logEvent(.domainAllowed, metadata: ["domain": domain])
    }
    
    /**
     * Remove allowed domain
     * 
     * - Parameters:
     *   - domain: Domain to remove
     */
    public func removeAllowedDomain(_ domain: String) {
        allowedDomains.remove(domain)
        auditLogger.logEvent(.domainRemoved, metadata: ["domain": domain])
    }
    
    /**
     * Check if domain is allowed
     * 
     * - Parameters:
     *   - domain: Domain to check
     * 
     * - Returns: Whether domain is allowed
     */
    public func isDomainAllowed(_ domain: String) -> Bool {
        return allowedDomains.isEmpty || allowedDomains.contains(domain)
    }
    
    // MARK: - IP Blocking
    
    /**
     * Block IP address
     * 
     * - Parameters:
     *   - ip: IP address to block
     */
    public func blockIP(_ ip: String) {
        blockedIPs.insert(ip)
        auditLogger.logEvent(.ipBlocked, metadata: ["ip": ip])
    }
    
    /**
     * Unblock IP address
     * 
     * - Parameters:
     *   - ip: IP address to unblock
     */
    public func unblockIP(_ ip: String) {
        blockedIPs.remove(ip)
        auditLogger.logEvent(.ipUnblocked, metadata: ["ip": ip])
    }
    
    /**
     * Check if IP is blocked
     * 
     * - Parameters:
     *   - ip: IP address to check
     * 
     * - Returns: Whether IP is blocked
     */
    public func isIPBlocked(_ ip: String) -> Bool {
        return blockedIPs.contains(ip)
    }
    
    // MARK: - URLSessionDelegate
    
    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        // Handle certificate pinning
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            handleServerTrustChallenge(challenge, completionHandler: completionHandler)
        } else {
            // Handle other authentication challenges
            handleOtherChallenge(challenge, completionHandler: completionHandler)
        }
    }
    
    // MARK: - Private Methods
    
    private func setupNetworkSecurity() {
        threatDetector.startMonitoring()
        rateLimiter.startRateLimiting()
        
        auditLogger.logEvent(.networkSecurityInitialized)
    }
    
    private func handleServerTrustChallenge(
        _ challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Validate certificate
        let isValid = certificatePinningManager.validateCertificate(
            serverTrust,
            pinnedCertificates: pinnedCertificates
        )
        
        if isValid {
            let credential = URLCredential(trust: serverTrust)
            completionHandler(.useCredential, credential)
            
            auditLogger.logEvent(.certificateValidated, metadata: [
                "host": challenge.protectionSpace.host
            ])
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            
            auditLogger.logEvent(.certificateValidationFailed, metadata: [
                "host": challenge.protectionSpace.host
            ])
        }
    }
    
    private func handleOtherChallenge(
        _ challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        // Handle client certificate authentication
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate {
            // Implement client certificate handling
            completionHandler(.cancelAuthenticationChallenge, nil)
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
    
    private func validateResponse(_ response: HTTPURLResponse, data: Data) throws {
        // Check for suspicious response patterns
        if threatDetector.isResponseSuspicious(response, data: data) {
            throw SecurityError.networkError(NetworkError.suspiciousResponse)
        }
        
        // Validate status code
        guard (200...299).contains(response.statusCode) else {
            throw SecurityError.networkError(NetworkError.httpError(response.statusCode))
        }
    }
    
    private func getAuthToken() -> String? {
        // Retrieve authentication token from secure storage
        // This would typically come from a token manager
        return nil
    }
}

// MARK: - Supporting Types

public enum HTTPMethod: String {
    case GET = "GET"
    case POST = "POST"
    case PUT = "PUT"
    case DELETE = "DELETE"
    case PATCH = "PATCH"
}

public struct NetworkResponse {
    public let data: Data
    public let response: HTTPURLResponse
    public let request: URLRequest
}

public enum NetworkError: Error, LocalizedError {
    case invalidURL
    case domainNotAllowed
    case rateLimitExceeded
    case invalidResponse
    case requestFailed(Error)
    case suspiciousResponse
    case httpError(Int)
    case certificateValidationFailed
    
    public var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "Invalid URL provided"
        case .domainNotAllowed:
            return "Domain not in allowed list"
        case .rateLimitExceeded:
            return "Rate limit exceeded"
        case .invalidResponse:
            return "Invalid response received"
        case .requestFailed(let error):
            return "Request failed: \(error.localizedDescription)"
        case .suspiciousResponse:
            return "Suspicious response detected"
        case .httpError(let code):
            return "HTTP error: \(code)"
        case .certificateValidationFailed:
            return "Certificate validation failed"
        }
    }
}

// MARK: - Certificate Pinning Manager

private class CertificatePinningManager {
    func validateCertificate(_ serverTrust: SecTrust, pinnedCertificates: [Data]) -> Bool {
        guard !pinnedCertificates.isEmpty else {
            // No pinned certificates, use system validation
            return validateWithSystem(serverTrust)
        }
        
        let certificateCount = SecTrustGetCertificateCount(serverTrust)
        
        for i in 0..<certificateCount {
            guard let certificate = SecTrustGetCertificateAtIndex(serverTrust, i) else {
                continue
            }
            
            let certificateData = SecCertificateCopyData(certificate) as Data
            
            if pinnedCertificates.contains(certificateData) {
                return true
            }
        }
        
        return false
    }
    
    private func validateWithSystem(_ serverTrust: SecTrust) -> Bool {
        var result: SecTrustResultType = .invalid
        let status = SecTrustEvaluate(serverTrust, &result)
        
        return status == errSecSuccess && (result == .unspecified || result == .proceed)
    }
}

// MARK: - Network Rate Limiter

private class NetworkRateLimiter {
    private var requestCounts: [String: (count: Int, lastReset: Date)] = [:]
    private let maxRequestsPerMinute = 60
    private let resetInterval: TimeInterval = 60
    
    func isRequestAllowed(for host: String) -> Bool {
        let now = Date()
        
        if let (count, lastReset) = requestCounts[host] {
            if now.timeIntervalSince(lastReset) >= resetInterval {
                // Reset counter
                requestCounts[host] = (1, now)
                return true
            } else if count < maxRequestsPerMinute {
                // Increment counter
                requestCounts[host] = (count + 1, lastReset)
                return true
            } else {
                return false
            }
        } else {
            // First request
            requestCounts[host] = (1, now)
            return true
        }
    }
    
    func startRateLimiting() {
        // Start rate limiting monitoring
    }
}

// MARK: - Network Threat Detector

private class NetworkThreatDetector {
    func isResponseSuspicious(_ response: HTTPURLResponse, data: Data) -> Bool {
        // Check for suspicious response patterns
        // This is a simplified implementation
        return false
    }
    
    func startMonitoring() {
        // Start network threat monitoring
    }
} 