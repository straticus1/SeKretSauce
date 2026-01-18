import Foundation
import os.log

/// Centralized audit logging system for compliance and security monitoring
public final class AuditLogger {

    public static let shared = AuditLogger()

    private let osLog = OSLog(subsystem: "com.sekretsauce.agent", category: "audit")
    private let logDirectory: URL
    private let fileManager = FileManager.default
    private let encoder = JSONEncoder()
    private let dateFormatter: DateFormatter
    private let queue = DispatchQueue(label: "com.sekretsauce.auditlogger", qos: .utility)

    private var currentLogFile: FileHandle?
    private var currentLogDate: String?
    private var logLevel: LogLevel = .info

    private init() {
        // Set up log directory
        let appSupport = fileManager.urls(for: .applicationSupportDirectory, in: .localDomainMask).first!
        logDirectory = appSupport.appendingPathComponent("SeKretSauce/logs", isDirectory: true)

        // Create directory if needed
        try? fileManager.createDirectory(at: logDirectory, withIntermediateDirectories: true)

        // Set up date formatter
        dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd"

        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
    }

    // MARK: - Configuration

    public func setLogLevel(_ level: LogLevel) {
        queue.async { [weak self] in
            self?.logLevel = level
        }
    }

    // MARK: - Event Logging

    public func log(_ event: AuditEvent) {
        queue.async { [weak self] in
            self?.writeEvent(event)
        }
    }

    public func log(
        eventType: AuditEventType,
        severity: AlertSeverity,
        source: String,
        message: String,
        metadata: [String: String] = [:]
    ) {
        let event = AuditEvent(
            eventType: eventType,
            severity: severity,
            source: source,
            message: message,
            metadata: metadata
        )
        log(event)
    }

    // MARK: - Convenience Methods

    public func logSystemStart() {
        log(
            eventType: .systemStart,
            severity: .info,
            source: "Daemon",
            message: "SeKretSauce security agent started",
            metadata: [
                "version": Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown",
                "build": Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "unknown"
            ]
        )
    }

    public func logSystemStop() {
        log(
            eventType: .systemStop,
            severity: .info,
            source: "Daemon",
            message: "SeKretSauce security agent stopped"
        )
    }

    public func logAuthSuccess(machineID: String) {
        log(
            eventType: .authSuccess,
            severity: .info,
            source: "AuthManager",
            message: "Successfully authenticated with server",
            metadata: ["machine_id": machineID]
        )
    }

    public func logAuthFailure(reason: String) {
        log(
            eventType: .authFailure,
            severity: .high,
            source: "AuthManager",
            message: "Authentication failed: \(reason)"
        )
    }

    public func logSSHSession(_ session: SSHSession, started: Bool) {
        let eventType: AuditEventType = started ? .sshSessionStart : .sshSessionEnd
        var metadata: [String: String] = [
            "session_id": session.id.uuidString,
            "user": session.user,
            "destination": "\(session.destinationHost):\(session.destinationPort)",
            "arguments": session.arguments.joined(separator: " ")
        ]

        if let recordingPath = session.recordingPath {
            metadata["recording"] = recordingPath
        }

        if !session.tunnelFlags.isEmpty {
            metadata["tunnel_flags"] = session.tunnelFlags.map { $0.type.rawValue }.joined(separator: ", ")
        }

        log(
            eventType: eventType,
            severity: session.tunnelFlags.isEmpty ? .info : .high,
            source: "SSHRecorder",
            message: started ? "SSH session started" : "SSH session ended",
            metadata: metadata
        )
    }

    public func logTunnelAlert(_ alert: TunnelAlert) {
        var metadata: [String: String] = [
            "alert_id": alert.id.uuidString,
            "tunnel_type": alert.type.rawValue,
            "evidence": alert.evidence
        ]

        if let processInfo = alert.processInfo {
            metadata["process_path"] = processInfo.path
            metadata["process_pid"] = String(processInfo.pid)
            metadata["process_user"] = processInfo.user
        }

        if let networkInfo = alert.networkInfo {
            if let destIP = networkInfo.destinationIP {
                metadata["dest_ip"] = destIP
            }
            if let destPort = networkInfo.destinationPort {
                metadata["dest_port"] = String(destPort)
            }
        }

        log(
            eventType: .tunnelAlertRaised,
            severity: alert.severity,
            source: "TunnelDetection",
            message: "Tunnel detected: \(alert.type.rawValue)",
            metadata: metadata
        )
    }

    public func logDNSQuery(_ query: DNSQuery) {
        let eventType: AuditEventType = query.blocked ? .dnsBlocked : .dnsQuery
        var metadata: [String: String] = [
            "query_name": query.queryName,
            "query_type": String(query.queryType.rawValue)
        ]

        if let app = query.sourceApp {
            metadata["source_app"] = app
        }

        if let suspicion = query.tunnelSuspicion {
            metadata["tunnel_suspicion"] = String(format: "%.2f", suspicion)
        }

        if query.blocked {
            metadata["action"] = "BLOCKED"
        }

        log(
            eventType: eventType,
            severity: query.blocked ? .medium : .info,
            source: "DNSProxy",
            message: query.blocked ? "DNS query blocked: \(query.queryName)" : "DNS query: \(query.queryName)",
            metadata: metadata
        )
    }

    public func logProcessExec(_ process: ProcessMetadata) {
        log(
            eventType: .processExec,
            severity: .info,
            source: "ProcessMonitor",
            message: "Process executed: \(process.path)",
            metadata: [
                "pid": String(process.pid),
                "ppid": String(process.ppid),
                "path": process.path,
                "user": process.user,
                "arguments": process.arguments.joined(separator: " ")
            ]
        )
    }

    public func logError(_ error: Error, source: String, context: String? = nil) {
        var metadata: [String: String] = [
            "error": error.localizedDescription
        ]
        if let context = context {
            metadata["context"] = context
        }

        log(
            eventType: .error,
            severity: .high,
            source: source,
            message: "Error occurred: \(error.localizedDescription)",
            metadata: metadata
        )
    }

    // MARK: - File Operations

    private func writeEvent(_ event: AuditEvent) {
        // Check log level
        guard event.severity >= logLevel else { return }

        // Also log to system log
        logToOSLog(event)

        // Write to file
        do {
            let handle = try getLogFileHandle()
            var eventData = try encoder.encode(event)
            eventData.append(contentsOf: [0x0A]) // newline
            handle.write(eventData)
        } catch {
            os_log(.error, log: osLog, "Failed to write audit event: %{public}@", error.localizedDescription)
        }
    }

    private func getLogFileHandle() throws -> FileHandle {
        let today = dateFormatter.string(from: Date())

        // Check if we need a new log file
        if currentLogDate != today {
            currentLogFile?.closeFile()
            currentLogFile = nil
            currentLogDate = today
        }

        if let handle = currentLogFile {
            return handle
        }

        // Create new log file
        let logPath = logDirectory.appendingPathComponent("audit-\(today).jsonl")

        if !fileManager.fileExists(atPath: logPath.path) {
            fileManager.createFile(atPath: logPath.path, contents: nil)
        }

        let handle = try FileHandle(forWritingTo: logPath)
        handle.seekToEndOfFile()
        currentLogFile = handle

        return handle
    }

    private func logToOSLog(_ event: AuditEvent) {
        let type: OSLogType
        switch event.severity {
        case .info: type = .info
        case .low: type = .default
        case .medium: type = .default
        case .high: type = .error
        case .critical: type = .fault
        }

        os_log(type, log: osLog, "[%{public}@] %{public}@: %{public}@",
               event.eventType.rawValue,
               event.source,
               event.message)
    }

    // MARK: - Log Management

    /// Get all log files
    public func getLogFiles() -> [URL] {
        let files = try? fileManager.contentsOfDirectory(
            at: logDirectory,
            includingPropertiesForKeys: [.creationDateKey],
            options: .skipsHiddenFiles
        )
        return files?.filter { $0.pathExtension == "jsonl" } ?? []
    }

    /// Read events from a log file
    public func readEvents(from file: URL) throws -> [AuditEvent] {
        let data = try Data(contentsOf: file)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        var events: [AuditEvent] = []
        let lines = data.split(separator: 0x0A)

        for line in lines {
            if let event = try? decoder.decode(AuditEvent.self, from: Data(line)) {
                events.append(event)
            }
        }

        return events
    }

    /// Cleanup old log files
    public func cleanupOldLogs(retentionDays: Int) {
        queue.async { [weak self] in
            guard let self = self else { return }

            let cutoffDate = Calendar.current.date(byAdding: .day, value: -retentionDays, to: Date())!

            for file in self.getLogFiles() {
                guard let attrs = try? self.fileManager.attributesOfItem(atPath: file.path),
                      let creationDate = attrs[.creationDate] as? Date else {
                    continue
                }

                if creationDate < cutoffDate {
                    try? self.fileManager.removeItem(at: file)
                    os_log(.info, log: self.osLog, "Cleaned up old log file: %{public}@", file.lastPathComponent)
                }
            }
        }
    }

    /// Export logs for compliance
    public func exportLogs(from startDate: Date, to endDate: Date) throws -> Data {
        var allEvents: [AuditEvent] = []

        for file in getLogFiles() {
            // Check if file is in date range based on filename
            let filename = file.deletingPathExtension().lastPathComponent
            guard filename.hasPrefix("audit-") else { continue }

            let dateString = String(filename.dropFirst(6))
            guard let fileDate = dateFormatter.date(from: dateString) else { continue }

            if fileDate >= startDate && fileDate <= endDate {
                let events = try readEvents(from: file)
                allEvents.append(contentsOf: events)
            }
        }

        // Sort by timestamp
        allEvents.sort { $0.timestamp < $1.timestamp }

        let exportEncoder = JSONEncoder()
        exportEncoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        exportEncoder.dateEncodingStrategy = .iso8601

        return try exportEncoder.encode(allEvents)
    }

    deinit {
        currentLogFile?.closeFile()
    }
}

// MARK: - Debug Logging Extension

extension AuditLogger {
    public func debug(_ message: String, source: String = "Debug") {
        guard logLevel == .debug else { return }
        log(
            eventType: .error, // Using error as generic type
            severity: .info,
            source: source,
            message: "[DEBUG] \(message)"
        )
    }
}
