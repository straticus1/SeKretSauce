import Foundation
import Security

/// Secure storage manager using macOS Keychain
public final class SecureStorage: @unchecked Sendable {

    public static let shared = SecureStorage()

    private let serviceName = "com.sekretsauce.agent"
    private let accessGroup: String? = nil // Set for app groups if needed

    private init() {}

    // MARK: - Credential Storage

    /// Store credentials securely in Keychain
    public func storeCredentials(apiKey: String, serverURL: String) throws {
        let previousAPIKey = try? retrieve(key: "api_key")
        let previousServerURL = try? retrieve(key: "server_url")
        do {
            try store(key: "api_key", value: apiKey)
            try store(key: "server_url", value: serverURL)
        } catch {
            restore(key: "api_key", value: previousAPIKey)
            restore(key: "server_url", value: previousServerURL)
            throw error
        }
    }

    /// Retrieve stored API key
    public func retrieveAPIKey() throws -> String {
        return try retrieve(key: "api_key")
    }

    /// Retrieve stored server URL
    public func retrieveServerURL() throws -> String {
        return try retrieve(key: "server_url")
    }

    /// Store session token
    public func storeSessionToken(_ token: String) throws {
        try store(key: "session_token", value: token)
    }

    /// Retrieve session token
    public func retrieveSessionToken() throws -> String {
        return try retrieve(key: "session_token")
    }

    /// Clear session token (logout)
    public func clearSessionToken() throws {
        try delete(key: "session_token")
    }

    // MARK: - Generic Keychain Operations

    public func store(key: String, value: String) throws {
        guard let data = value.data(using: .utf8) else {
            throw SecureStorageError.encodingFailed
        }

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key
        ]
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        let updateStatus = SecItemUpdate(
            query as CFDictionary,
            [kSecValueData as String: data] as CFDictionary
        )
        if updateStatus == errSecSuccess {
            return
        }
        guard updateStatus == errSecItemNotFound else {
            throw SecureStorageError.keychainError(status: updateStatus)
        }

        query.merge([
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]) { _, new in new }

        let status = SecItemAdd(query as CFDictionary, nil)

        guard status == errSecSuccess else {
            throw SecureStorageError.keychainError(status: status)
        }
    }

    private func restore(key: String, value: String?) {
        if let value {
            try? store(key: key, value: value)
        } else {
            try? delete(key: key)
        }
    }

    public func retrieve(key: String) throws -> String {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                throw SecureStorageError.itemNotFound
            }
            throw SecureStorageError.keychainError(status: status)
        }

        guard let data = result as? Data,
              let value = String(data: data, encoding: .utf8) else {
            throw SecureStorageError.decodingFailed
        }

        return value
    }

    public func delete(key: String) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key
        ]

        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        let status = SecItemDelete(query as CFDictionary)

        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecureStorageError.keychainError(status: status)
        }
    }

    public func exists(key: String) -> Bool {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecReturnData as String: false
        ]

        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    // MARK: - Configuration Storage

    public func storeConfiguration(_ config: AgentConfiguration) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(config)
        guard let jsonString = String(data: data, encoding: .utf8) else {
            throw SecureStorageError.encodingFailed
        }
        try store(key: "agent_config", value: jsonString)
    }

    public func retrieveConfiguration() throws -> AgentConfiguration {
        let jsonString = try retrieve(key: "agent_config")
        guard let data = jsonString.data(using: .utf8) else {
            throw SecureStorageError.decodingFailed
        }
        let decoder = JSONDecoder()
        return try decoder.decode(AgentConfiguration.self, from: data)
    }

    // MARK: - Machine Identity

    /// Get or create a unique machine identifier
    public func getMachineIdentifier() throws -> String {
        if let existingID = try? retrieve(key: "machine_id") {
            return existingID
        }

        // Generate new machine ID based on hardware UUID + random component
        let hardwareUUID = getHardwareUUID() ?? UUID().uuidString
        let machineID = "\(hardwareUUID)-\(UUID().uuidString.prefix(8))"
        try store(key: "machine_id", value: machineID)
        return machineID
    }

    private func getHardwareUUID() -> String? {
        let platformExpert = IOServiceGetMatchingService(
            kIOMainPortDefault,
            IOServiceMatching("IOPlatformExpertDevice")
        )

        guard platformExpert != 0 else { return nil }
        defer { IOObjectRelease(platformExpert) }

        guard let uuid = IORegistryEntryCreateCFProperty(
            platformExpert,
            kIOPlatformUUIDKey as CFString,
            kCFAllocatorDefault,
            0
        )?.takeRetainedValue() as? String else {
            return nil
        }

        return uuid
    }
}

// MARK: - Errors

public enum SecureStorageError: Error, LocalizedError {
    case encodingFailed
    case decodingFailed
    case itemNotFound
    case keychainError(status: OSStatus)

    public var errorDescription: String? {
        switch self {
        case .encodingFailed:
            return "Failed to encode data for storage"
        case .decodingFailed:
            return "Failed to decode stored data"
        case .itemNotFound:
            return "Item not found in secure storage"
        case .keychainError(let status):
            return "Keychain error: \(status) - \(SecCopyErrorMessageString(status, nil) as String? ?? "Unknown")"
        }
    }
}
