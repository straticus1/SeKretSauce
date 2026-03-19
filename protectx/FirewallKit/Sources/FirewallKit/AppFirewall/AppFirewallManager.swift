// AppFirewallManager - macOS Application Firewall management
// Wraps /usr/libexec/ApplicationFirewall/socketfilterfw

import Foundation

public final class AppFirewallManager {

    // MARK: - Properties

    public private(set) var isEnabled: Bool = false
    public private(set) var stealthMode: Bool = false
    public private(set) var blockAll: Bool = false
    public private(set) var allowSigned: Bool = true
    public private(set) var allowDownloadedSigned: Bool = true
    public private(set) var apps: [AppFirewallRule] = []

    private let socketFilterFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"

    public init() {
        refresh()
    }

    // MARK: - Status

    /// Refresh status from system
    public func refresh() {
        isEnabled = getGlobalState()
        stealthMode = getStealthMode()
        blockAll = getBlockAll()
        allowSigned = getAllowSigned()
        allowDownloadedSigned = getAllowSignedDownloaded()
        apps = listApps()
    }

    // MARK: - Global Controls

    /// Enable the application firewall
    public func enable() throws {
        try requireRoot()
        let result = shell("\(socketFilterFW) --setglobalstate on")
        if result.contains("enabled") || result.contains("already") {
            isEnabled = true
        } else {
            throw AppFirewallError.enableFailed(result)
        }
    }

    /// Disable the application firewall
    public func disable() throws {
        try requireRoot()
        let result = shell("\(socketFilterFW) --setglobalstate off")
        if result.contains("disabled") || result.contains("already") {
            isEnabled = false
        } else {
            throw AppFirewallError.disableFailed(result)
        }
    }

    /// Set stealth mode (don't respond to pings/probes)
    public func setStealthMode(_ enabled: Bool) throws {
        try requireRoot()
        let flag = enabled ? "on" : "off"
        let result = shell("\(socketFilterFW) --setstealthmode \(flag)")
        if result.contains("enabled") || result.contains("disabled") || result.contains("already") {
            stealthMode = enabled
        } else {
            throw AppFirewallError.stealthModeFailed(result)
        }
    }

    /// Block all incoming connections
    public func setBlockAll(_ enabled: Bool) throws {
        try requireRoot()
        let flag = enabled ? "on" : "off"
        let result = shell("\(socketFilterFW) --setblockall \(flag)")
        if result.contains("enabled") || result.contains("disabled") || result.contains("already") {
            blockAll = enabled
        } else {
            throw AppFirewallError.blockAllFailed(result)
        }
    }

    /// Allow signed applications automatically
    public func setAllowSigned(_ enabled: Bool) throws {
        try requireRoot()
        let flag = enabled ? "on" : "off"
        let result = shell("\(socketFilterFW) --setallowsigned \(flag)")
        allowSigned = enabled
    }

    /// Allow downloaded signed applications automatically
    public func setAllowSignedDownloaded(_ enabled: Bool) throws {
        try requireRoot()
        let flag = enabled ? "on" : "off"
        let result = shell("\(socketFilterFW) --setallowsignedapp \(flag)")
        allowDownloadedSigned = enabled
    }

    // MARK: - App Rules

    /// Add a rule for an application
    public func addRule(_ rule: AppFirewallRule) throws {
        try requireRoot()
        let flag = rule.allowed ? "--add" : "--blockapp"
        let result = shell("\(socketFilterFW) \(flag) \"\(rule.path)\"")
        if result.contains("added") || result.contains("already") {
            refresh()
        } else {
            throw AppFirewallError.addRuleFailed(result)
        }
    }

    /// Remove a rule for an application
    public func removeRule(for path: String) throws {
        try requireRoot()
        let result = shell("\(socketFilterFW) --remove \"\(path)\"")
        if result.contains("removed") || result.contains("not found") {
            refresh()
        } else {
            throw AppFirewallError.removeRuleFailed(result)
        }
    }

    /// Allow an application
    public func allowApp(at path: String) throws {
        try addRule(.allow(path: path))
    }

    /// Block an application
    public func blockApp(at path: String) throws {
        try addRule(.block(path: path))
    }

    // MARK: - Status Display

    public func statusDescription() -> String {
        """
        Application Firewall Status
        ===========================
        Enabled:              \(isEnabled ? "YES" : "NO")
        Stealth Mode:         \(stealthMode ? "ON" : "OFF")
        Block All:            \(blockAll ? "ON" : "OFF")
        Allow Signed:         \(allowSigned ? "YES" : "NO")
        Allow Downloaded:     \(allowDownloadedSigned ? "YES" : "NO")
        Managed Apps:         \(apps.count)
        """
    }

    public func appsDescription() -> String {
        if apps.isEmpty {
            return "No application rules configured"
        }
        return apps.enumerated().map { index, rule in
            let status = rule.allowed ? "✅ ALLOW" : "🚫 BLOCK"
            return "[\(index)] \(status) \(rule.name) (\(rule.path))"
        }.joined(separator: "\n")
    }

    // MARK: - Private Helpers

    private func getGlobalState() -> Bool {
        let result = shell("\(socketFilterFW) --getglobalstate")
        return result.contains("enabled")
    }

    private func getStealthMode() -> Bool {
        let result = shell("\(socketFilterFW) --getstealthmode")
        return result.contains("enabled")
    }

    private func getBlockAll() -> Bool {
        let result = shell("\(socketFilterFW) --getblockall")
        return result.contains("enabled") && !result.contains("DISABLED")
    }

    private func getAllowSigned() -> Bool {
        let result = shell("\(socketFilterFW) --getallowsigned")
        return result.contains("enabled") || result.contains("ENABLED")
    }

    private func getAllowSignedDownloaded() -> Bool {
        let result = shell("\(socketFilterFW) --getallowsignedapp")
        return result.contains("enabled") || result.contains("ENABLED")
    }

    private func listApps() -> [AppFirewallRule] {
        let result = shell("\(socketFilterFW) --listapps")
        var rules: [AppFirewallRule] = []

        // Parse output format:
        // ALF: total number of apps = N
        // 1: /path/to/app.app
        //    ( Allow incoming connections )
        //    or
        //    ( Block incoming connections )

        let lines = result.split(separator: "\n").map(String.init)
        var currentPath: String?

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            // Check for app path (starts with number and colon)
            if let colonIndex = trimmed.firstIndex(of: ":") {
                let prefix = trimmed[..<colonIndex]
                if Int(prefix) != nil {
                    currentPath = String(trimmed[trimmed.index(after: colonIndex)...])
                        .trimmingCharacters(in: .whitespaces)
                }
            }

            // Check for permission line
            if let path = currentPath {
                if trimmed.contains("Allow incoming") {
                    let name = (path as NSString).lastPathComponent
                    rules.append(AppFirewallRule(path: path, name: name, allowed: true))
                    currentPath = nil
                } else if trimmed.contains("Block incoming") {
                    let name = (path as NSString).lastPathComponent
                    rules.append(AppFirewallRule(path: path, name: name, allowed: false))
                    currentPath = nil
                }
            }
        }

        return rules
    }

    private func requireRoot() throws {
        if getuid() != 0 {
            throw AppFirewallError.requiresRoot
        }
    }

    private func shell(_ command: String) -> String {
        let task = Process()
        let pipe = Pipe()

        task.standardOutput = pipe
        task.standardError = pipe
        task.arguments = ["-c", command]
        task.launchPath = "/bin/sh"

        do {
            try task.run()
            task.waitUntilExit()
        } catch {
            return ""
        }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }
}

// MARK: - App Rule

public struct AppFirewallRule: Identifiable, Equatable {
    public let id: UUID
    public var path: String
    public var name: String
    public var allowed: Bool

    public init(id: UUID = UUID(), path: String, name: String? = nil, allowed: Bool) {
        self.id = id
        self.path = path
        self.name = name ?? (path as NSString).lastPathComponent
        self.allowed = allowed
    }

    public static func allow(path: String) -> AppFirewallRule {
        AppFirewallRule(path: path, allowed: true)
    }

    public static func block(path: String) -> AppFirewallRule {
        AppFirewallRule(path: path, allowed: false)
    }
}

// MARK: - Errors

public enum AppFirewallError: Error, LocalizedError {
    case requiresRoot
    case enableFailed(String)
    case disableFailed(String)
    case stealthModeFailed(String)
    case blockAllFailed(String)
    case addRuleFailed(String)
    case removeRuleFailed(String)

    public var errorDescription: String? {
        switch self {
        case .requiresRoot:
            return "This operation requires root privileges"
        case .enableFailed(let msg):
            return "Failed to enable Application Firewall: \(msg)"
        case .disableFailed(let msg):
            return "Failed to disable Application Firewall: \(msg)"
        case .stealthModeFailed(let msg):
            return "Failed to set stealth mode: \(msg)"
        case .blockAllFailed(let msg):
            return "Failed to set block all: \(msg)"
        case .addRuleFailed(let msg):
            return "Failed to add app rule: \(msg)"
        case .removeRuleFailed(let msg):
            return "Failed to remove app rule: \(msg)"
        }
    }
}
