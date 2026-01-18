// PFManager - Packet Filter management for macOS
// Wraps pfctl and pf.conf parsing/generation

import Foundation

public final class PFManager {

    // MARK: - Properties

    public private(set) var isEnabled: Bool = false
    public private(set) var rules: [PFRule] = []

    private let pfctlPath = "/sbin/pfctl"
    private let pfConfPath = "/etc/pf.conf"

    public init() {
        refresh()
    }

    // MARK: - Status

    /// Refresh status from system
    public func refresh() {
        isEnabled = checkEnabled()
        rules = parseCurrentRules()
    }

    private func checkEnabled() -> Bool {
        let output = shell("\(pfctlPath) -s info 2>/dev/null")
        return output.contains("Status: Enabled")
    }

    // MARK: - Control

    /// Enable packet filter
    public func enable() throws {
        try requireRoot()
        let result = shell("\(pfctlPath) -e 2>&1")
        if result.contains("pf enabled") || result.contains("already enabled") {
            isEnabled = true
        } else {
            throw PFError.enableFailed(result)
        }
    }

    /// Disable packet filter
    public func disable() throws {
        try requireRoot()
        let result = shell("\(pfctlPath) -d 2>&1")
        if result.contains("pf disabled") || result.contains("already disabled") {
            isEnabled = false
        } else {
            throw PFError.disableFailed(result)
        }
    }

    /// Reload rules from pf.conf
    public func reload() throws {
        try requireRoot()
        let result = shell("\(pfctlPath) -f \(pfConfPath) 2>&1")
        if !result.isEmpty && !result.contains("rules loaded") {
            throw PFError.reloadFailed(result)
        }
        refresh()
    }

    // MARK: - Rules

    /// Add a rule to pf
    public func addRule(_ rule: PFRule) throws {
        try requireRoot()
        rules.append(rule)
        try writeRules()
        try reload()
    }

    /// Remove a rule from pf
    public func removeRule(at index: Int) throws {
        try requireRoot()
        guard index >= 0 && index < rules.count else {
            throw PFError.invalidRuleIndex
        }
        rules.remove(at: index)
        try writeRules()
        try reload()
    }

    /// Get current rules as human-readable text
    public func rulesDescription() -> String {
        if rules.isEmpty {
            return "No rules configured"
        }
        return rules.enumerated().map { index, rule in
            "[\(index)] \(rule.description)"
        }.joined(separator: "\n")
    }

    // MARK: - Parsing

    private func parseCurrentRules() -> [PFRule] {
        let output = shell("\(pfctlPath) -s rules 2>/dev/null")
        return output
            .split(separator: "\n")
            .compactMap { PFRule.parse(String($0)) }
    }

    // MARK: - Writing

    private func writeRules() throws {
        // Generate pf.conf content
        var content = """
        # Rampart - Managed pf.conf
        # Do not edit manually - use Rampart CLI or GUI

        # Default policies
        set block-policy drop
        set skip on lo0

        # Scrub incoming
        scrub in all

        # Rules managed by Rampart
        """

        for rule in rules {
            content += "\n\(rule.toPFSyntax())"
        }

        content += "\n"

        // Write to temp file, then move (atomic)
        let tempPath = "/tmp/pf.conf.rampart"
        try content.write(toFile: tempPath, atomically: true, encoding: .utf8)

        let result = shell("sudo mv \(tempPath) \(pfConfPath)")
        if !result.isEmpty {
            throw PFError.writeFailed(result)
        }
    }

    // MARK: - Helpers

    private func requireRoot() throws {
        if getuid() != 0 {
            throw PFError.requiresRoot
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

// MARK: - Errors

public enum PFError: Error, LocalizedError {
    case requiresRoot
    case enableFailed(String)
    case disableFailed(String)
    case reloadFailed(String)
    case writeFailed(String)
    case parseFailed(String)
    case invalidRuleIndex

    public var errorDescription: String? {
        switch self {
        case .requiresRoot:
            return "This operation requires root privileges"
        case .enableFailed(let msg):
            return "Failed to enable pf: \(msg)"
        case .disableFailed(let msg):
            return "Failed to disable pf: \(msg)"
        case .reloadFailed(let msg):
            return "Failed to reload pf rules: \(msg)"
        case .writeFailed(let msg):
            return "Failed to write pf.conf: \(msg)"
        case .parseFailed(let msg):
            return "Failed to parse pf rule: \(msg)"
        case .invalidRuleIndex:
            return "Invalid rule index"
        }
    }
}
