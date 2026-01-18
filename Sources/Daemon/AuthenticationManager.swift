import Foundation

/// Manages authentication with the central server on boot
public final class AuthenticationManager {

    public static let shared = AuthenticationManager()

    private let secureStorage = SecureStorage.shared
    private let auditLogger = AuditLogger.shared
    private let session: URLSession

    private var sessionToken: String?
    private var tokenExpiresAt: Date?
    private var refreshTimer: Timer?

    public var isAuthenticated: Bool {
        guard let token = sessionToken, let expiresAt = tokenExpiresAt else {
            return false
        }
        return !token.isEmpty && expiresAt > Date()
    }

    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        self.session = URLSession(configuration: config)
    }

    // MARK: - Public API

    /// Authenticate with server using stored credentials
    public func authenticate() async throws -> String {
        let machineID = try secureStorage.getMachineIdentifier()

        // Try to get stored credentials
        let apiKey: String
        let serverURL: String

        do {
            apiKey = try secureStorage.retrieveAPIKey()
            serverURL = try secureStorage.retrieveServerURL()
        } catch {
            auditLogger.logAuthFailure(reason: "No credentials configured")
            throw AuthenticationError.noCredentials
        }

        // Make authentication request
        let token = try await performAuthentication(
            serverURL: serverURL,
            apiKey: apiKey,
            machineID: machineID
        )

        // Store session token
        self.sessionToken = token
        self.tokenExpiresAt = Date().addingTimeInterval(3600) // 1 hour default
        try secureStorage.storeSessionToken(token)

        auditLogger.logAuthSuccess(machineID: machineID)

        // Start token refresh timer
        startRefreshTimer()

        return token
    }

    /// Authenticate with provided credentials (for initial setup)
    public func authenticate(serverURL: String, apiKey: String) async throws -> String {
        // Store credentials
        try secureStorage.storeCredentials(apiKey: apiKey, serverURL: serverURL)

        // Perform authentication
        return try await authenticate()
    }

    /// Refresh the session token
    public func refreshToken() async throws {
        guard let currentToken = sessionToken else {
            throw AuthenticationError.notAuthenticated
        }

        let serverURL = try secureStorage.retrieveServerURL()

        let token = try await performTokenRefresh(
            serverURL: serverURL,
            currentToken: currentToken
        )

        self.sessionToken = token
        self.tokenExpiresAt = Date().addingTimeInterval(3600)
        try secureStorage.storeSessionToken(token)
    }

    /// Logout and clear credentials
    public func logout() throws {
        refreshTimer?.invalidate()
        refreshTimer = nil
        sessionToken = nil
        tokenExpiresAt = nil
        try secureStorage.clearSessionToken()

        auditLogger.log(
            eventType: .authSuccess,
            severity: .info,
            source: "AuthManager",
            message: "Logged out successfully"
        )
    }

    /// Get current session token
    public func getSessionToken() throws -> String {
        guard let token = sessionToken, isAuthenticated else {
            throw AuthenticationError.notAuthenticated
        }
        return token
    }

    // MARK: - Private Methods

    private func performAuthentication(serverURL: String, apiKey: String, machineID: String) async throws -> String {
        guard let url = URL(string: "\(serverURL)/api/v1/auth/machine") else {
            throw AuthenticationError.invalidServerURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")

        let body = AuthenticationRequest(
            machineID: machineID,
            hostname: Host.current().localizedName ?? "unknown",
            osVersion: ProcessInfo.processInfo.operatingSystemVersionString,
            agentVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0"
        )

        request.httpBody = try JSONEncoder().encode(body)

        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw AuthenticationError.invalidResponse
        }

        switch httpResponse.statusCode {
        case 200...299:
            let authResponse = try JSONDecoder().decode(AuthenticationResponse.self, from: data)
            return authResponse.token

        case 401:
            auditLogger.logAuthFailure(reason: "Invalid API key")
            throw AuthenticationError.invalidCredentials

        case 403:
            auditLogger.logAuthFailure(reason: "Machine not authorized")
            throw AuthenticationError.machineNotAuthorized

        default:
            auditLogger.logAuthFailure(reason: "Server error: \(httpResponse.statusCode)")
            throw AuthenticationError.serverError(statusCode: httpResponse.statusCode)
        }
    }

    private func performTokenRefresh(serverURL: String, currentToken: String) async throws -> String {
        guard let url = URL(string: "\(serverURL)/api/v1/auth/refresh") else {
            throw AuthenticationError.invalidServerURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(currentToken)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw AuthenticationError.invalidResponse
        }

        guard httpResponse.statusCode == 200 else {
            throw AuthenticationError.tokenRefreshFailed
        }

        let refreshResponse = try JSONDecoder().decode(AuthenticationResponse.self, from: data)
        return refreshResponse.token
    }

    private func startRefreshTimer() {
        refreshTimer?.invalidate()

        // Refresh 5 minutes before expiry
        let refreshInterval: TimeInterval = 55 * 60 // 55 minutes

        refreshTimer = Timer.scheduledTimer(withTimeInterval: refreshInterval, repeats: true) { [weak self] _ in
            Task {
                do {
                    try await self?.refreshToken()
                } catch {
                    self?.auditLogger.logError(error, source: "AuthManager", context: "Token refresh failed")
                }
            }
        }
    }
}

// MARK: - Request/Response Models

private struct AuthenticationRequest: Codable {
    let machineID: String
    let hostname: String
    let osVersion: String
    let agentVersion: String

    enum CodingKeys: String, CodingKey {
        case machineID = "machine_id"
        case hostname
        case osVersion = "os_version"
        case agentVersion = "agent_version"
    }
}

private struct AuthenticationResponse: Codable {
    let token: String
    let expiresIn: Int?
    let machineID: String?

    enum CodingKeys: String, CodingKey {
        case token
        case expiresIn = "expires_in"
        case machineID = "machine_id"
    }
}

// MARK: - Errors

public enum AuthenticationError: Error, LocalizedError {
    case noCredentials
    case invalidServerURL
    case invalidCredentials
    case machineNotAuthorized
    case notAuthenticated
    case tokenRefreshFailed
    case invalidResponse
    case serverError(statusCode: Int)

    public var errorDescription: String? {
        switch self {
        case .noCredentials:
            return "No authentication credentials configured"
        case .invalidServerURL:
            return "Invalid server URL"
        case .invalidCredentials:
            return "Invalid API key or credentials"
        case .machineNotAuthorized:
            return "This machine is not authorized to connect"
        case .notAuthenticated:
            return "Not authenticated - please authenticate first"
        case .tokenRefreshFailed:
            return "Failed to refresh authentication token"
        case .invalidResponse:
            return "Invalid response from server"
        case .serverError(let statusCode):
            return "Server error: HTTP \(statusCode)"
        }
    }
}
