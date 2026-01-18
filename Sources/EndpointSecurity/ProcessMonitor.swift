import Foundation
import EndpointSecurity
import os.log

/// Process Monitor using Endpoint Security Framework
/// Monitors process execution, file access, and network activity
/// Note: Requires com.apple.developer.endpoint-security.client entitlement
public final class ProcessMonitor {

    public static let shared = ProcessMonitor()

    private let log = OSLog(subsystem: "com.sekretsauce.agent", category: "processmonitor")
    private let auditLogger = AuditLogger.shared
    private let tunnelDetector = TunnelDetectionEngine.shared
    private let cloudflareDetector = CloudflareTunnelDetector.shared

    private var client: OpaquePointer?
    private var isRunning = false

    private init() {}

    // MARK: - Lifecycle

    /// Start the process monitor
    public func start() throws {
        guard !isRunning else {
            os_log(.info, log: log, "Process monitor already running")
            return
        }

        os_log(.info, log: log, "Starting process monitor...")

        var newClient: OpaquePointer?

        let result = es_new_client(&newClient) { [weak self] client, message in
            self?.handleEvent(message)
        }

        switch result {
        case ES_NEW_CLIENT_RESULT_SUCCESS:
            self.client = newClient
            os_log(.info, log: log, "Endpoint Security client created successfully")

        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            os_log(.error, log: log, "Missing Endpoint Security entitlement")
            throw ProcessMonitorError.notEntitled

        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            os_log(.error, log: log, "Endpoint Security not permitted - check System Preferences")
            throw ProcessMonitorError.notPermitted

        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            os_log(.error, log: log, "Must run as root for Endpoint Security")
            throw ProcessMonitorError.notPrivileged

        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            os_log(.error, log: log, "Too many Endpoint Security clients")
            throw ProcessMonitorError.tooManyClients

        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
            os_log(.error, log: log, "Invalid argument for Endpoint Security")
            throw ProcessMonitorError.invalidArgument

        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
            os_log(.error, log: log, "Internal Endpoint Security error")
            throw ProcessMonitorError.internalError

        default:
            os_log(.error, log: log, "Unknown Endpoint Security error: %d", result.rawValue)
            throw ProcessMonitorError.unknownError(Int(result.rawValue))
        }

        // Subscribe to events
        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_NOTIFY_EXEC,           // Process execution
            ES_EVENT_TYPE_NOTIFY_FORK,           // Process fork
            ES_EVENT_TYPE_NOTIFY_EXIT,           // Process exit
            ES_EVENT_TYPE_NOTIFY_OPEN,           // File open
            ES_EVENT_TYPE_NOTIFY_WRITE,          // File write
            ES_EVENT_TYPE_NOTIFY_RENAME,         // File rename
            ES_EVENT_TYPE_NOTIFY_SIGNAL,         // Signal delivery
            ES_EVENT_TYPE_NOTIFY_KEXTLOAD,       // Kernel extension load
            ES_EVENT_TYPE_NOTIFY_MOUNT,          // Filesystem mount
        ]

        let subscribeResult = es_subscribe(newClient!, events, UInt32(events.count))
        guard subscribeResult == ES_RETURN_SUCCESS else {
            es_delete_client(newClient)
            os_log(.error, log: log, "Failed to subscribe to events")
            throw ProcessMonitorError.subscriptionFailed
        }

        isRunning = true
        os_log(.info, log: log, "Process monitor started, subscribed to %d event types", events.count)

        auditLogger.log(
            eventType: .systemStart,
            severity: .info,
            source: "ProcessMonitor",
            message: "Endpoint Security monitor started"
        )
    }

    /// Stop the process monitor
    public func stop() {
        guard isRunning, let client = client else { return }

        os_log(.info, log: log, "Stopping process monitor...")

        es_unsubscribe_all(client)
        es_delete_client(client)

        self.client = nil
        isRunning = false

        auditLogger.log(
            eventType: .systemStop,
            severity: .info,
            source: "ProcessMonitor",
            message: "Endpoint Security monitor stopped"
        )
    }

    // MARK: - Event Handling

    private func handleEvent(_ message: UnsafePointer<es_message_t>) {
        let eventType = message.pointee.event_type

        switch eventType {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            handleExecEvent(message)

        case ES_EVENT_TYPE_NOTIFY_FORK:
            handleForkEvent(message)

        case ES_EVENT_TYPE_NOTIFY_EXIT:
            handleExitEvent(message)

        case ES_EVENT_TYPE_NOTIFY_OPEN:
            handleOpenEvent(message)

        case ES_EVENT_TYPE_NOTIFY_WRITE:
            handleWriteEvent(message)

        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
            handleKextLoadEvent(message)

        default:
            break
        }
    }

    // MARK: - Exec Event

    private func handleExecEvent(_ message: UnsafePointer<es_message_t>) {
        let event = message.pointee.event.exec
        let process = message.pointee.process.pointee

        // Get process details
        let pid = audit_token_to_pid(process.audit_token)
        let ppid = process.ppid
        let path = getString(from: event.target.pointee.executable.pointee.path)
        let user = getUsername(uid: audit_token_to_euid(process.audit_token))

        // Get arguments
        var arguments: [String] = []
        let argCount = es_exec_arg_count(&event)
        for i in 0..<argCount {
            if let arg = es_exec_arg(&event, i) {
                arguments.append(getString(from: arg.pointee))
            }
        }

        // Create process metadata
        let processInfo = ProcessMetadata(
            pid: pid,
            ppid: ppid,
            path: path,
            arguments: arguments,
            user: user
        )

        // Check for tunnel processes
        checkForTunnelProcess(processInfo)

        // Log the execution
        auditLogger.logProcessExec(processInfo)
    }

    private func checkForTunnelProcess(_ process: ProcessMetadata) {
        // Check with main tunnel detector
        let result = tunnelDetector.analyzeProcess(
            path: process.path,
            arguments: process.arguments,
            pid: process.pid,
            user: process.user
        )

        if let alert = result.alert {
            var alertWithProcess = TunnelAlert(
                id: alert.id,
                type: alert.type,
                evidence: alert.evidence,
                severity: alert.severity,
                timestamp: alert.timestamp,
                processInfo: process,
                networkInfo: alert.networkInfo
            )
            auditLogger.logTunnelAlert(alertWithProcess)
        }

        // Check specifically for Cloudflare
        if let cfAlert = cloudflareDetector.detectProcess(
            path: process.path,
            arguments: process.arguments
        ) {
            var alertWithProcess = TunnelAlert(
                id: cfAlert.id,
                type: cfAlert.type,
                evidence: cfAlert.evidence,
                severity: cfAlert.severity,
                timestamp: cfAlert.timestamp,
                processInfo: process,
                networkInfo: cfAlert.networkInfo
            )
            auditLogger.logTunnelAlert(alertWithProcess)
        }
    }

    // MARK: - Fork Event

    private func handleForkEvent(_ message: UnsafePointer<es_message_t>) {
        // Fork events can be used to track process genealogy
        // Useful for detecting process injection or suspicious spawning
    }

    // MARK: - Exit Event

    private func handleExitEvent(_ message: UnsafePointer<es_message_t>) {
        // Track process exits for session recording correlation
    }

    // MARK: - File Events

    private func handleOpenEvent(_ message: UnsafePointer<es_message_t>) {
        let event = message.pointee.event.open
        let path = getString(from: event.file.pointee.path)

        // Check for Cloudflare config files
        if let alert = cloudflareDetector.detectConfigFile(path: path) {
            auditLogger.logTunnelAlert(alert)
        }

        // Check for other sensitive file access
        checkSensitiveFileAccess(path: path, message: message)
    }

    private func handleWriteEvent(_ message: UnsafePointer<es_message_t>) {
        // Monitor writes to sensitive files
    }

    private func checkSensitiveFileAccess(path: String, message: UnsafePointer<es_message_t>) {
        let sensitivePatterns = [
            "/.ssh/",
            "/etc/ssh/",
            "/.cloudflared/",
            "/.ngrok",
            "/tailscale/",
            "/.wireguard/",
            "/openvpn/",
            "/.frp"
        ]

        for pattern in sensitivePatterns {
            if path.lowercased().contains(pattern) {
                let process = message.pointee.process.pointee
                let pid = audit_token_to_pid(process.audit_token)
                let execPath = getString(from: process.executable.pointee.path)

                auditLogger.log(
                    eventType: .networkConnection,
                    severity: .medium,
                    source: "ProcessMonitor",
                    message: "Sensitive file accessed: \(path)",
                    metadata: [
                        "path": path,
                        "pid": String(pid),
                        "process": execPath
                    ]
                )
                break
            }
        }
    }

    // MARK: - Kext Event

    private func handleKextLoadEvent(_ message: UnsafePointer<es_message_t>) {
        let event = message.pointee.event.kextload
        let identifier = getString(from: event.identifier)

        auditLogger.log(
            eventType: .systemStart,
            severity: .high,
            source: "ProcessMonitor",
            message: "Kernel extension loaded: \(identifier)",
            metadata: ["kext": identifier]
        )
    }

    // MARK: - Helpers

    private func getString(from token: es_string_token_t) -> String {
        if let data = token.data {
            return String(cString: data)
        }
        return ""
    }

    private func getUsername(uid: uid_t) -> String {
        if let pwd = getpwuid(uid) {
            return String(cString: pwd.pointee.pw_name)
        }
        return String(uid)
    }
}

// MARK: - Errors

public enum ProcessMonitorError: Error, LocalizedError {
    case notEntitled
    case notPermitted
    case notPrivileged
    case tooManyClients
    case invalidArgument
    case internalError
    case subscriptionFailed
    case unknownError(Int)

    public var errorDescription: String? {
        switch self {
        case .notEntitled:
            return "Missing Endpoint Security entitlement"
        case .notPermitted:
            return "Endpoint Security not permitted - grant access in System Preferences > Security & Privacy > Privacy > Full Disk Access"
        case .notPrivileged:
            return "Must run as root"
        case .tooManyClients:
            return "Too many Endpoint Security clients"
        case .invalidArgument:
            return "Invalid argument"
        case .internalError:
            return "Internal Endpoint Security error"
        case .subscriptionFailed:
            return "Failed to subscribe to events"
        case .unknownError(let code):
            return "Unknown error: \(code)"
        }
    }
}

// MARK: - C Helpers

private func audit_token_to_pid(_ token: audit_token_t) -> Int32 {
    var t = token
    return withUnsafePointer(to: &t) { ptr in
        let raw = UnsafeRawPointer(ptr)
        let val = raw.load(fromByteOffset: 20, as: Int32.self)
        return val
    }
}

private func audit_token_to_euid(_ token: audit_token_t) -> uid_t {
    var t = token
    return withUnsafePointer(to: &t) { ptr in
        let raw = UnsafeRawPointer(ptr)
        let val = raw.load(fromByteOffset: 4, as: uid_t.self)
        return val
    }
}
