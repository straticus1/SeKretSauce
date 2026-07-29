// AppFirewallManager - macOS Application Firewall management
// Wraps /usr/libexec/ApplicationFirewall/socketfilterfw

import Foundation

enum AppFirewallCommand {
    private static let executable = "/usr/libexec/ApplicationFirewall/socketfilterfw"

    static func command(_ arguments: [String]) -> CommandInvocation {
        CommandInvocation(executable: executable, arguments: arguments)
    }

    static func add(path: String) -> CommandInvocation {
        command(["--add", path])
    }

    static func remove(path: String) -> CommandInvocation {
        command(["--remove", path])
    }

    static func allow(path: String) -> CommandInvocation {
        command(["--unblockapp", path])
    }

    static func block(path: String) -> CommandInvocation {
        command(["--blockapp", path])
    }
}

public final class AppFirewallManager {

    // MARK: - Properties

    public private(set) var isEnabled: Bool = false
    public private(set) var stealthMode: Bool = false
    public private(set) var blockAll: Bool = false
    public private(set) var allowSigned: Bool = true
    public private(set) var allowDownloadedSigned: Bool = true
    public private(set) var apps: [AppFirewallRule] = []

    private let runner: SystemCommandRunning

    public init() {
        self.runner = SystemCommandRunner()
        refresh()
    }

    init(runner: SystemCommandRunning) {
        self.runner = runner
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
        _ = try run(["--setglobalstate", "on"])
        isEnabled = true
    }

    /// Disable the application firewall
    public func disable() throws {
        try requireRoot()
        _ = try run(["--setglobalstate", "off"])
        isEnabled = false
    }

    /// Set stealth mode (don't respond to pings/probes)
    public func setStealthMode(_ enabled: Bool) throws {
        try requireRoot()
        let flag = enabled ? "on" : "off"
        _ = try run(["--setstealthmode", flag])
        stealthMode = enabled
    }

    /// Block all incoming connections
    public func setBlockAll(_ enabled: Bool) throws {
        try requireRoot()
        let flag = enabled ? "on" : "off"
        _ = try run(["--setblockall", flag])
        blockAll = enabled
    }

    /// Allow signed applications automatically
    public func setAllowSigned(_ enabled: Bool) throws {
        try requireRoot()
        let flag = enabled ? "on" : "off"
        _ = try run(["--setallowsigned", flag])
        allowSigned = enabled
    }

    /// Allow downloaded signed applications automatically
    public func setAllowSignedDownloaded(_ enabled: Bool) throws {
        try requireRoot()
        let flag = enabled ? "on" : "off"
        _ = try run(["--setallowsignedapp", flag])
        allowDownloadedSigned = enabled
    }

    // MARK: - App Rules

    /// Add a rule for an application
    public func addRule(_ rule: AppFirewallRule) throws {
        try requireRoot()
        let path = try validatedApplicationPath(rule.path)
        _ = try runner.runChecked(AppFirewallCommand.add(path: path))
        _ = try runner.runChecked(
            rule.allowed ? AppFirewallCommand.allow(path: path) : AppFirewallCommand.block(path: path)
        )
        refresh()
    }

    /// Remove a rule for an application
    public func removeRule(for path: String) throws {
        try requireRoot()
        let validatedPath = try validatedApplicationPath(path)
        _ = try runner.runChecked(AppFirewallCommand.remove(path: validatedPath))
        refresh()
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
        let result = (try? run(["--getglobalstate"])) ?? ""
        return result.contains("enabled")
    }

    private func getStealthMode() -> Bool {
        let result = (try? run(["--getstealthmode"])) ?? ""
        return result.contains("enabled")
    }

    private func getBlockAll() -> Bool {
        let result = (try? run(["--getblockall"])) ?? ""
        return result.contains("enabled") && !result.contains("DISABLED")
    }

    private func getAllowSigned() -> Bool {
        let result = (try? run(["--getallowsigned"])) ?? ""
        return result.contains("enabled") || result.contains("ENABLED")
    }

    private func getAllowSignedDownloaded() -> Bool {
        let result = (try? run(["--getallowsignedapp"])) ?? ""
        return result.contains("enabled") || result.contains("ENABLED")
    }

    private func listApps() -> [AppFirewallRule] {
        let result = (try? run(["--listapps"])) ?? ""
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

    private func run(_ arguments: [String]) throws -> String {
        try runner.runChecked(AppFirewallCommand.command(arguments))
    }

    private func validatedApplicationPath(_ path: String) throws -> String {
        guard path.hasPrefix("/"),
              !path.contains("\0"),
              !path.contains("\n"),
              !path.contains("\r"),
              FileManager.default.fileExists(atPath: path) else {
            throw AppFirewallError.invalidApplicationPath
        }
        return URL(fileURLWithPath: path).standardizedFileURL.path
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
    case invalidApplicationPath

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
        case .invalidApplicationPath:
            return "Application path must be an existing absolute path"
        }
    }
}
