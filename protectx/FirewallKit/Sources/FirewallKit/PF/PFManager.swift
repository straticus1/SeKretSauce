// PFManager - Packet Filter management for macOS
// Manages ProtectX rules in a dedicated PF anchor without replacing pf.conf.

import Foundation
import Darwin

public final class PFManager {
    public private(set) var isEnabled = false
    public private(set) var rules: [PFRule] = []

    private let pfctlPath = "/sbin/pfctl"
    private let pfConfPath = "/etc/pf.conf"
    private let runner: SystemCommandRunning

    public init() {
        self.runner = SystemCommandRunner()
        refresh()
    }

    init(runner: SystemCommandRunning) {
        self.runner = runner
        refresh()
    }

    public func refresh() {
        isEnabled = checkEnabled()
        rules = parseCurrentRules()
    }

    public func enable() throws {
        try requireRoot()
        _ = try run(["-e"])
        isEnabled = true
    }

    public func disable() throws {
        try requireRoot()
        _ = try run(["-d"])
        isEnabled = false
    }

    public func reload() throws {
        try requireRoot()
        _ = try run(["-f", pfConfPath])
        refresh()
    }

    public func addRule(_ rule: PFRule) throws {
        try requireRoot()
        try rule.validate()

        let updatedRules = rules + [rule]
        try installManagedAnchorIfNeeded()
        try writeAndLoadManagedRules(updatedRules)
        rules = updatedRules
    }

    public func removeRule(at index: Int) throws {
        try requireRoot()
        guard rules.indices.contains(index) else {
            throw PFError.invalidRuleIndex
        }

        var updatedRules = rules
        updatedRules.remove(at: index)
        try installManagedAnchorIfNeeded()
        try writeAndLoadManagedRules(updatedRules)
        rules = updatedRules
    }

    public func rulesDescription() -> String {
        guard !rules.isEmpty else {
            return "No ProtectX-managed rules configured"
        }
        return rules.enumerated().map { index, rule in
            "[\(index)] \(rule.description)"
        }.joined(separator: "\n")
    }

    private func checkEnabled() -> Bool {
        guard let output = try? run(["-s", "info"]) else {
            return false
        }
        return output.contains("Status: Enabled")
    }

    private func parseCurrentRules() -> [PFRule] {
        guard let output = try? run([
            "-a", ManagedPFConfiguration.anchorName,
            "-s", "rules"
        ]) else {
            return []
        }
        return output.split(separator: "\n").compactMap { PFRule.parse(String($0)) }
    }

    private func installManagedAnchorIfNeeded() throws {
        let existing: String
        do {
            existing = try String(contentsOfFile: pfConfPath, encoding: .utf8)
        } catch {
            throw PFError.configurationFailed("Could not read \(pfConfPath): \(error.localizedDescription)")
        }

        let updated = ManagedPFConfiguration.installAnchorReferences(in: existing)
        guard updated != existing else {
            return
        }

        let temporaryPath = try SecureAtomicFile.createSibling(
            of: pfConfPath,
            contents: Data(updated.utf8),
            mode: 0o644
        )

        do {
            _ = try run(["-n", "-f", temporaryPath])
            try SecureAtomicFile.commit(temporaryPath: temporaryPath, destinationPath: pfConfPath)
            _ = try run(["-f", pfConfPath])
        } catch {
            SecureAtomicFile.removeIfPresent(temporaryPath)
            throw PFError.configurationFailed(error.localizedDescription)
        }
    }

    private func writeAndLoadManagedRules(_ rules: [PFRule]) throws {
        for rule in rules {
            try rule.validate()
        }

        let content = rules.map { $0.toPFSyntax() }.joined(separator: "\n") + "\n"
        let temporaryPath = try SecureAtomicFile.createSibling(
            of: ManagedPFConfiguration.anchorPath,
            contents: Data(content.utf8),
            mode: 0o600
        )

        do {
            _ = try run([
                "-n",
                "-a", ManagedPFConfiguration.anchorName,
                "-f", temporaryPath
            ])
            try SecureAtomicFile.commit(
                temporaryPath: temporaryPath,
                destinationPath: ManagedPFConfiguration.anchorPath
            )
            _ = try run([
                "-a", ManagedPFConfiguration.anchorName,
                "-f", ManagedPFConfiguration.anchorPath
            ])
        } catch {
            SecureAtomicFile.removeIfPresent(temporaryPath)
            throw PFError.writeFailed(error.localizedDescription)
        }
    }

    private func run(_ arguments: [String]) throws -> String {
        try runner.runChecked(CommandInvocation(executable: pfctlPath, arguments: arguments))
    }

    private func requireRoot() throws {
        guard getuid() == 0 else {
            throw PFError.requiresRoot
        }
    }
}

private enum SecureAtomicFile {
    static func createSibling(of destinationPath: String, contents: Data, mode: mode_t) throws -> String {
        let directory = (destinationPath as NSString).deletingLastPathComponent
        let name = (destinationPath as NSString).lastPathComponent
        let temporaryPath = "\(directory)/.\(name).protectx-\(UUID().uuidString)"

        let descriptor = open(
            temporaryPath,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
            mode
        )
        guard descriptor >= 0 else {
            throw PFError.writeFailed(String(cString: strerror(errno)))
        }

        var shouldRemove = true
        defer {
            close(descriptor)
            if shouldRemove {
                unlink(temporaryPath)
            }
        }

        try contents.withUnsafeBytes { bytes in
            guard var pointer = bytes.baseAddress else {
                return
            }
            var remaining = bytes.count
            while remaining > 0 {
                let written = Darwin.write(descriptor, pointer, remaining)
                guard written > 0 else {
                    throw PFError.writeFailed(String(cString: strerror(errno)))
                }
                pointer = pointer.advanced(by: written)
                remaining -= written
            }
        }

        guard fchmod(descriptor, mode) == 0, fsync(descriptor) == 0 else {
            throw PFError.writeFailed(String(cString: strerror(errno)))
        }

        shouldRemove = false
        return temporaryPath
    }

    static func commit(temporaryPath: String, destinationPath: String) throws {
        guard rename(temporaryPath, destinationPath) == 0 else {
            let message = String(cString: strerror(errno))
            removeIfPresent(temporaryPath)
            throw PFError.writeFailed(message)
        }
    }

    static func removeIfPresent(_ path: String) {
        unlink(path)
    }
}

public enum PFError: Error, LocalizedError {
    case requiresRoot
    case enableFailed(String)
    case disableFailed(String)
    case reloadFailed(String)
    case writeFailed(String)
    case parseFailed(String)
    case configurationFailed(String)
    case invalidRuleIndex

    public var errorDescription: String? {
        switch self {
        case .requiresRoot:
            return "This operation requires root privileges"
        case .enableFailed(let message):
            return "Failed to enable PF: \(message)"
        case .disableFailed(let message):
            return "Failed to disable PF: \(message)"
        case .reloadFailed(let message):
            return "Failed to reload PF rules: \(message)"
        case .writeFailed(let message):
            return "Failed to write PF rules: \(message)"
        case .parseFailed(let message):
            return "Failed to parse PF rule: \(message)"
        case .configurationFailed(let message):
            return "Failed to configure ProtectX PF anchor: \(message)"
        case .invalidRuleIndex:
            return "Invalid rule index"
        }
    }
}
