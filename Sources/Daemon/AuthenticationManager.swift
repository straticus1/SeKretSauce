import Foundation
import Common

/// Manages authentication with the central server on boot
@MainActor
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

        let endpoint = try secureEndpoint(serverURL)
        let response = try await performAuthentication(
            endpoint: endpoint,
            apiKey: apiKey,
            machineID: machineID
        )

        try establishSession(response, machineID: machineID)
        return response.token
    }

    /// Authenticate with provided credentials (for initial setup)
    public func authenticate(serverURL: String, apiKey: String) async throws -> String {
        guard !apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw AuthenticationError.invalidCredentials
        }

        let endpoint = try secureEndpoint(serverURL)
        let machineID = try secureStorage.getMachineIdentifier()
        let response = try await performAuthentication(
            endpoint: endpoint,
            apiKey: apiKey,
            machineID: machineID
        )

        try secureStorage.storeCredentials(
            apiKey: apiKey,
            serverURL: endpoint.baseURL.absoluteString
        )
        try establishSession(response, machineID: machineID)
        return response.token
    }

    /// Refresh the session token
    public func refreshToken() async throws {
        guard let currentToken = sessionToken else {
            throw AuthenticationError.notAuthenticated
        }

        let serverURL = try secureStorage.retrieveServerURL()

        let response = try await performTokenRefresh(
            endpoint: try secureEndpoint(serverURL),
            currentToken: currentToken
        )

        sessionToken = response.token
        tokenExpiresAt = expirationDate(for: response)
        try secureStorage.storeSessionToken(response.token)
        startRefreshTimer()
    }

    /// Logout and clear credentials
    public func logout() throws {
        refreshTimer?.invalidate()
        refreshTimer = nil
        sessionToken = nil
        tokenExpiresAt = nil
        try secureStorage.clearSessionToken()

        auditLogger.log(
            eventType: .authLogout,
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

    private func performAuthentication(
        endpoint: SecureServerEndpoint,
        apiKey: String,
        machineID: String
    ) async throws -> AuthenticationResponse {
        let url = endpoint.appending(path: "/api/v1/auth/machine")
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
            guard !authResponse.token.isEmpty else {
                throw AuthenticationError.invalidResponse
            }
            return authResponse

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

    private func performTokenRefresh(
        endpoint: SecureServerEndpoint,
        currentToken: String
    ) async throws -> AuthenticationResponse {
        let url = endpoint.appending(path: "/api/v1/auth/refresh")
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
        guard !refreshResponse.token.isEmpty else {
            throw AuthenticationError.invalidResponse
        }
        return refreshResponse
    }

    private func startRefreshTimer() {
        refreshTimer?.invalidate()

        guard let tokenExpiresAt else { return }
        let refreshInterval = max(30, tokenExpiresAt.timeIntervalSinceNow - 300)

        refreshTimer = Timer.scheduledTimer(withTimeInterval: refreshInterval, repeats: false) { [weak self] _ in
            Task {
                do {
                    try await self?.refreshToken()
                } catch {
                    self?.auditLogger.logError(error, source: "AuthManager", context: "Token refresh failed")
                }
            }
        }
    }

    private func secureEndpoint(_ value: String) throws -> SecureServerEndpoint {
        do {
            return try SecureServerEndpoint(value)
        } catch {
            throw AuthenticationError.invalidServerURL
        }
    }

    private func establishSession(
        _ response: AuthenticationResponse,
        machineID: String
    ) throws {
        sessionToken = response.token
        tokenExpiresAt = expirationDate(for: response)
        try secureStorage.storeSessionToken(response.token)
        auditLogger.logAuthSuccess(machineID: machineID)
        startRefreshTimer()
    }

    private func expirationDate(for response: AuthenticationResponse) -> Date {
        let lifetime = min(max(response.expiresIn ?? 3600, 60), 86_400)
        return Date().addingTimeInterval(TimeInterval(lifetime))
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
