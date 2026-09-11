import Common
import Darwin
import Foundation
import ThreatDetection

struct ExecutionIdentity {
    let auditToken: audit_token_t
    var values: [UInt32] { withUnsafeBytes(of: auditToken) { Array($0.bindMemory(to: UInt32.self)) } }
    var pid: Int32 { Int32(bitPattern: auditToken.val.5) }
    var ownerUID: UInt32 { auditToken.val.3 }
    private static let bootID: String = {
        var length = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &length, nil, 0) == 0, length > 0, length < 1024
        else { return UUID().uuidString }
        var bytes = [CChar](repeating: 0, count: length)
        guard sysctlbyname("kern.bootsessionuuid", &bytes, &length, nil, 0) == 0 else {
            return UUID().uuidString
        }
        return String(cString: bytes)
    }()
    var key: String { Self.bootID + ":" + values.map(String.init).joined(separator: ":") }
}

protocol TaskControlling {
    func suspend(_ identity: ExecutionIdentity) throws -> mach_port_t
    func resume(_ token: mach_port_t) throws
}

/// Holds a task-specific suspension token; never resumes an arbitrary PID.
private final class MachTaskController: TaskControlling {
    func suspend(_ identity: ExecutionIdentity) throws -> mach_port_t {
        var task: mach_port_t = 0
        let acquired = task_for_pid(mach_task_self_, identity.pid, &task)
        guard acquired == KERN_SUCCESS else {
            throw ControlError.unavailable("Task access denied (\(acquired)); process was not suspended")
        }
        defer { mach_port_deallocate(mach_task_self_, task) }
        try verify(task, identity)
        var token: task_suspension_token_t = 0
        let result = task_suspend2(task, &token)
        guard result == KERN_SUCCESS else {
            throw ControlError.unavailable("Task suspension failed (\(result))")
        }
        do { try verify(task, identity) } catch {
            _ = task_resume2(token)
            throw error
        }
        return token
    }
    func resume(_ token: mach_port_t) throws {
        let result = task_resume2(token)
        guard result == KERN_SUCCESS else {
            throw ControlError.unavailable("Task resume failed (\(result)); verify process state")
        }
    }
    private func verify(_ task: mach_port_t, _ identity: ExecutionIdentity) throws {
        var token = audit_token_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<audit_token_t>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &token) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(task, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        guard result == KERN_SUCCESS, ExecutionIdentity(auditToken: token).values == identity.values
        else {
            throw ControlError.unavailable("Process execution changed; response refused")
        }
    }
}

final class IncidentResponse: @unchecked Sendable {
    static let shared = IncidentResponse(
        directory: URL(fileURLWithPath: "/Library/Application Support/SeKretSauce/incidents"),
        controller: MachTaskController(),
        automaticResponseEnabled: IncidentControl.automaticResponseEnabled)
    private let lock = NSRecursiveLock()
    private let directory: URL
    private let controller: TaskControlling
    private let automaticResponseEnabled: Bool
    private var records: [IncidentRecord] = []
    private var tokens: [UUID: mach_port_t] = [:]
    private var loaded = false

    init(directory: URL, controller: TaskControlling, automaticResponseEnabled: Bool = true) {
        self.directory = directory
        self.controller = controller
        self.automaticResponseEnabled = automaticResponseEnabled
    }

    func observe(_ verdict: ThreatVerdict, identity: ExecutionIdentity, path: String) throws
        -> IncidentRecord
    {
        lock.lock()
        defer { lock.unlock() }
        try load()
        let index: Int
        if let existing = records.firstIndex(where: { $0.executionID == identity.key }) {
            index = existing
        } else {
            if records.count >= 500,
                let oldest = records.firstIndex(where: {
                    !["applied", "pending"].contains($0.responseState)
                })
            {
                records.remove(at: oldest)
            }
            guard records.count < 500 else {
                throw ControlError.unavailable("Incident store is full; response requires review")
            }
            records.append(
                IncidentRecord(
                    executionID: identity.key, pid: identity.pid, ownerUID: identity.ownerUID,
                    processPath: path, score: verdict.score, reasons: verdict.reasons,
                    recommendedAction: verdict.action.rawValue))
            index = records.count - 1
        }
        records[index].lastSeenAt = Date()
        records[index].score = verdict.score
        records[index].reasons = verdict.reasons
        records[index].recommendedAction = verdict.action.rawValue
        guard verdict.action == .suspend, records[index].responseState == "observed" else {
            try persist()
            return records[index]
        }
        guard automaticResponseEnabled else {
            records[index].responseError =
                "Automatic containment is disabled pending signed macOS validation"
            try persist()
            return records[index]
        }
        records[index].responseState = "pending"
        try persist()  // Never act without a durable intent record.
        do {
            let token = try controller.suspend(identity)
            tokens[records[index].id] = token
            records[index].responseState = "applied"
            do { try persist() } catch {
                // Keep the token available if rollback itself fails.
                do {
                    try controller.resume(token)
                    tokens.removeValue(forKey: records[index].id)
                } catch {
                    records[index].responseState = "applied"
                    records[index].responseError = "Persistence failed; suspension still needs review"
                    throw error
                }
                records[index].responseState = "failed"
                throw error
            }
        } catch {
            if tokens[records[index].id] == nil { records[index].responseState = "failed" }
            records[index].responseError = error.localizedDescription
            try persist()
        }
        return records[index]
    }

    func list(uid: UInt32) throws -> [IncidentRecord] {
        lock.lock()
        defer { lock.unlock() }
        try load()
        return records.filter { uid == 0 || $0.ownerUID == uid }.sorted {
            $0.lastSeenAt > $1.lastSeenAt
        }
    }
    func resume(id: UUID, uid: UInt32) throws {
        lock.lock()
        defer { lock.unlock() }
        try load()
        guard let index = records.firstIndex(where: { $0.id == id }),
            uid == 0 || records[index].ownerUID == uid
        else { throw ControlError.unavailable("Incident unavailable for this user") }
        if records[index].responseState == "resumed" { return }
        guard records[index].responseState == "applied", let token = tokens[id] else {
            throw ControlError.unavailable("No live suspension token; process state requires review")
        }
        try controller.resume(token)
        tokens.removeValue(forKey: id)
        records[index].responseState = "resumed"
        records[index].responseError = nil
        try persist()
    }
    private struct Store: Codable {
        var schemaVersion = 1
        let records: [IncidentRecord]
    }
    private func load() throws {
        guard !loaded else { return }
        let directoryFD = try openDirectory()
        defer { close(directoryFD) }
        let fd = openat(directoryFD, "incidents.json", O_RDONLY | O_NOFOLLOW)
        if fd < 0 {
            if errno == ENOENT {
                loaded = true
                return
            }
            throw ControlError.unavailable("Cannot read incident store")
        }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == getuid(),
            info.st_size <= 4 * 1024 * 1024
        else { throw ControlError.unavailable("Invalid incident store") }
        let store = try JSONDecoder().decode(Store.self, from: file.readToEnd() ?? Data())
        guard store.schemaVersion == 1 else {
            throw ControlError.unavailable("Unsupported incident store")
        }
        records = store.records
        // Tokens belong to one daemon lifetime. Never recreate a response from a stored PID.
        for index in records.indices
        where ["pending", "applied"].contains(records[index].responseState) {
            records[index].responseState = "interrupted"
            records[index].responseError =
                "Daemon restarted; no live suspension token. Verify process state."
        }
        try persist()
        loaded = true
    }
    private func persist() throws {
        let directoryFD = try openDirectory()
        defer { close(directoryFD) }
        let name = ".pending-" + UUID().uuidString
        let fd = openat(directoryFD, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw ControlError.unavailable("Cannot write incident store") }
        defer {
            close(fd)
            unlinkat(directoryFD, name, 0)
        }
        let data = try JSONEncoder().encode(Store(records: records))
        try data.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let n = Darwin.write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if n < 0 && errno == EINTR { continue }
                guard n > 0 else { throw ControlError.unavailable("Cannot write incident record") }
                offset += n
            }
        }
        guard fsync(fd) == 0, renameat(directoryFD, name, directoryFD, "incidents.json") == 0,
            fsync(directoryFD) == 0
        else { throw ControlError.unavailable("Cannot commit incident record") }
    }
    private func openDirectory() throws -> Int32 {
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let fd = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard fd >= 0 else { throw ControlError.unavailable("Invalid incident directory") }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == getuid(), fchmod(fd, 0o700) == 0 else {
            close(fd)
            throw ControlError.unavailable("Invalid incident directory owner")
        }
        return fd
    }
}

public enum IncidentControl {
    /// Explicit deployment opt-in after validating task suspension on the target macOS build.
    public static let automaticResponseEnabled =
        ProcessInfo.processInfo.environment["SEKRETSAUCE_ENABLE_TASK_RESPONSE"] == "1"
    public static func list(uid: UInt32) throws -> [IncidentRecord] {
        try IncidentResponse.shared.list(uid: uid)
    }
    public static func resume(id: UUID, uid: UInt32) throws {
        try IncidentResponse.shared.resume(id: id, uid: uid)
    }
}
