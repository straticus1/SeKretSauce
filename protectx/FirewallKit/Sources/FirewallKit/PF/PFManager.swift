import Darwin
import Foundation

public struct PFPolicySnapshot: Codable {
    public let schemaVersion: Int
    public let revision: Int
    public let rules: [PFRulePayload]
}

/// The structured policy owns editable rules. Kernel text is never reconstructed
/// into the policy, and a journal makes interrupted disk/kernel changes recoverable.
public final class PFManager {
    public private(set) var isEnabled = false
    public private(set) var rules: [PFRule] = []
    public private(set) var revision = 0
    public private(set) var lastError: String?
    private let pfConfPath: String
    private let anchorPath: String
    private var policyPath: String { anchorPath + ".json" }
    private var journalPath: String { anchorPath + ".journal" }
    private let runner: SystemCommandRunning
    private let authorize: () throws -> Void
    private let lock = NSRecursiveLock()

    public convenience init() {
        self.init(runner: SystemCommandRunner())
    }
    init(
        runner: SystemCommandRunning, pfConfPath: String = "/etc/pf.conf",
        anchorPath: String = ManagedPFConfiguration.anchorPath,
        authorize: @escaping () throws -> Void = { if getuid() != 0 { throw PFError.requiresRoot } }
    ) {
        self.runner = runner
        self.pfConfPath = pfConfPath
        self.anchorPath = anchorPath
        self.authorize = authorize
        do {
            if try readOptional(journalPath) != nil { try withPolicyLock { try recover() } }
        } catch {
            lastError = "Startup recovery required: \(error.localizedDescription)"
            return
        }
        refresh()
    }

    public func refresh() {
        lock.lock()
        defer { lock.unlock() }
        do {
            let policy = try loadPolicy()
            let enabled = try run(["-s", "info"]).contains("Status: Enabled")
            rules = try policy.rules.map { try $0.toPFRule() }
            revision = policy.revision
            isEnabled = enabled
            lastError = nil
        } catch { lastError = error.localizedDescription }
    }

    public func snapshot() throws -> PFPolicySnapshot {
        lock.lock()
        defer { lock.unlock() }
        let policy = try loadPolicy()
        guard try readOptional(journalPath) == nil else {
            throw PFError.configurationFailed("Interrupted update requires recovery")
        }
        return policy
    }

    public func enable() throws {
        try authorize()
        _ = try run(["-e"])
        refresh()
    }
    public func disable() throws {
        try authorize()
        _ = try run(["-d"])
        refresh()
    }
    public func reload() throws {
        try withPolicyLock {
            try recover()
            let policy = try loadPolicy()
            // Reload our anchor only; preserve unrelated dynamic system rules.
            if try readOptional(anchorPath) != nil {
                _ = try run(["-a", ManagedPFConfiguration.anchorName, "-f", anchorPath])
            }
            rules = try policy.rules.map { try $0.toPFRule() }
            revision = policy.revision
        }
    }

    public func addRule(_ rule: PFRule) throws {
        try withPolicyLock {
            try recover()
            let policy = try loadPolicy()
            try applyLocked(policy.rules.map { try $0.toPFRule() } + [rule], previous: policy)
        }
    }
    public func removeRule(at index: Int) throws {
        try withPolicyLock {
            try recover()
            let policy = try loadPolicy()
            var current = try policy.rules.map { try $0.toPFRule() }
            guard current.indices.contains(index) else { throw PFError.invalidRuleIndex }
            current.remove(at: index)
            try applyLocked(current, previous: policy)
        }
    }
    public func apply(_ proposed: [PFRule], expectedRevision: Int) throws {
        try withPolicyLock {
            try recover()
            let policy = try loadPolicy()
            guard policy.revision == expectedRevision else {
                throw PFError.configurationFailed("Policy changed; refresh before applying your edit")
            }
            try applyLocked(proposed, previous: policy)
        }
    }
    public func rulesDescription() -> String {
        if let lastError { return "Policy unavailable: \(lastError)" }
        return rules.isEmpty
            ? "No ProtectX-managed rules configured"
            : rules.enumerated().map { "[\($0.offset)] \($0.element.description)" }.joined(
                separator: "\n")
    }

    private func loadPolicy() throws -> PFPolicySnapshot {
        if try readOptional(journalPath) != nil {
            throw PFError.configurationFailed("Interrupted update requires recovery")
        }
        if let data = try readOptional(policyPath) {
            let policy = try JSONDecoder().decode(PFPolicySnapshot.self, from: data)
            guard policy.schemaVersion == 1, policy.revision >= 0 else {
                throw PFError.parseFailed("Unsupported policy version")
            }
            let current = try policy.rules.map { try $0.toPFRule() }
            guard Set(current.map(\.id)).count == current.count else {
                throw PFError.parseFailed("Duplicate rule identities")
            }
            guard try readOptional(anchorPath) == render(current) else {
                throw PFError.configurationFailed(
                    "Managed anchor changed outside ProtectX; reconcile before editing")
            }
            return policy
        }
        var imported: [PFRule] = []
        if let data = try readOptional(anchorPath) {
            guard let source = String(data: data, encoding: .utf8) else {
                throw PFError.parseFailed("Invalid anchor encoding")
            }
            for line in source.split(separator: "\n") {
                let text = line.trimmingCharacters(in: .whitespaces)
                if text.isEmpty || text.hasPrefix("#") { continue }
                guard let rule = PFRule.parse(text) else {
                    throw PFError.parseFailed("Unsupported existing anchor rule; refusing a lossy import")
                }
                imported.append(rule)
            }
        }
        return PFPolicySnapshot(schemaVersion: 1, revision: 0, rules: imported.map(PFRulePayload.init))
    }

    private struct Journal: Codable {
        let configuration: Data
        let anchor: Data?
        let policy: Data?
        let mainChanged: Bool
    }
    private func applyLocked(_ proposed: [PFRule], previous: PFPolicySnapshot) throws {
        for rule in proposed { try rule.validate() }
        guard Set(proposed.map(\.id)).count == proposed.count else {
            throw PFError.parseFailed("Duplicate rule identities")
        }
        guard let oldConfig = try readOptional(pfConfPath),
            let configuration = String(data: oldConfig, encoding: .utf8)
        else { throw PFError.configurationFailed("Cannot read pf.conf") }
        let updated = ManagedPFConfiguration.installAnchorReferences(in: configuration)
            .replacingOccurrences(of: ManagedPFConfiguration.anchorPath, with: anchorPath)
        let journal = Journal(
            configuration: oldConfig, anchor: try readOptional(anchorPath),
            policy: try readOptional(policyPath), mainChanged: Data(updated.utf8) != oldConfig)
        let stagedAnchor = try SecureAtomicFile.createSibling(
            of: anchorPath, contents: render(proposed), mode: 0o600)
        defer { SecureAtomicFile.removeIfPresent(stagedAnchor) }
        // Every referenced file exists before validating the complete configuration.
        let stagedConfig = try SecureAtomicFile.createSibling(
            of: pfConfPath,
            contents: Data(updated.replacingOccurrences(of: anchorPath, with: stagedAnchor).utf8),
            mode: 0o600)
        defer { SecureAtomicFile.removeIfPresent(stagedConfig) }
        _ = try run(["-n", "-a", ManagedPFConfiguration.anchorName, "-f", stagedAnchor])
        if journal.mainChanged { _ = try run(["-n", "-f", stagedConfig]) }
        try write(JSONEncoder().encode(journal), to: journalPath)
        do {
            try write(render(proposed), to: anchorPath)
            if journal.mainChanged {
                try write(Data(updated.utf8), to: pfConfPath, mode: 0o644)
                _ = try run(["-f", pfConfPath])
            } else {
                _ = try run(["-a", ManagedPFConfiguration.anchorName, "-f", anchorPath])
            }
            let next = PFPolicySnapshot(
                schemaVersion: 1, revision: previous.revision + 1, rules: proposed.map(PFRulePayload.init))
            try write(JSONEncoder().encode(next), to: policyPath)
            // Commit point. If the journal remains after a crash, recovery rolls back.
            guard unlink(journalPath) == 0 else {
                throw PFError.writeFailed("Cannot commit transaction journal")
            }
            try SecureAtomicFile.syncDirectory(of: journalPath)
            rules = proposed
            revision = next.revision
            lastError = nil
        } catch {
            let original = error
            do { try recover() } catch {
                lastError = "Apply and rollback failed; recovery required: \(error.localizedDescription)"
                throw PFError.configurationFailed(lastError!)
            }
            throw original
        }
    }

    private func recover() throws {
        guard let data = try readOptional(journalPath) else { return }
        let journal = try JSONDecoder().decode(Journal.self, from: data)
        try restore(journal.anchor, to: anchorPath)
        try restore(journal.policy, to: policyPath)
        if journal.mainChanged {
            try write(journal.configuration, to: pfConfPath, mode: 0o644)
            _ = try run(["-f", pfConfPath])
        }
        if journal.anchor != nil {
            _ = try run(["-a", ManagedPFConfiguration.anchorName, "-f", anchorPath])
        } else {
            _ = try run(["-a", ManagedPFConfiguration.anchorName, "-F", "rules"])
        }
        guard unlink(journalPath) == 0 else { throw PFError.writeFailed("Cannot finish rollback") }
        try SecureAtomicFile.syncDirectory(of: journalPath)
    }
    private func restore(_ data: Data?, to path: String) throws {
        if let data {
            try write(data, to: path)
        } else {
            if unlink(path) != 0 && errno != ENOENT {
                throw PFError.writeFailed("Cannot restore \(path)")
            }
            try SecureAtomicFile.syncDirectory(of: path)
        }
    }
    private func render(_ rules: [PFRule]) -> Data {
        Data((rules.map { $0.toPFSyntax() }.joined(separator: "\n") + "\n").utf8)
    }
    private func readOptional(_ path: String) throws -> Data? {
        let fd = open(path, O_RDONLY | O_NOFOLLOW)
        if fd < 0 {
            if errno == ENOENT { return nil }
            throw PFError.configurationFailed("Cannot read \(path)")
        }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_size <= 4 * 1024 * 1024
        else { throw PFError.parseFailed("Invalid policy file") }
        return try handle.readToEnd() ?? Data()
    }
    private func write(_ data: Data, to path: String, mode: mode_t = 0o600) throws {
        let temporary = try SecureAtomicFile.createSibling(of: path, contents: data, mode: mode)
        try SecureAtomicFile.commit(temporaryPath: temporary, destinationPath: path)
    }
    private func withPolicyLock<T>(_ operation: () throws -> T) throws -> T {
        try authorize()
        lock.lock()
        defer { lock.unlock() }
        let fd = open(anchorPath + ".lock", O_RDWR | O_CREAT | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw PFError.configurationFailed("Cannot lock policy") }
        defer { close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { throw PFError.configurationFailed("Cannot lock policy") }
        defer { flock(fd, LOCK_UN) }
        return try operation()
    }
    private func run(_ arguments: [String]) throws -> String {
        try runner.runChecked(CommandInvocation(executable: "/sbin/pfctl", arguments: arguments))
    }
}
private enum SecureAtomicFile {
    static func createSibling(of destinationPath: String, contents: Data, mode: mode_t) throws
        -> String
    {
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
        try syncDirectory(of: destinationPath)
    }

    static func syncDirectory(of path: String) throws {
        let fd = open((path as NSString).deletingLastPathComponent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard fd >= 0 else { throw PFError.writeFailed("Cannot open policy directory") }
        defer { close(fd) }
        guard fsync(fd) == 0 else { throw PFError.writeFailed("Cannot sync policy directory") }
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
