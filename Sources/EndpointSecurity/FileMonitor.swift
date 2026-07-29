import Foundation
import os.log
import Common

/// File system monitoring for sensitive configuration and credential files
/// Complements Endpoint Security with targeted file watching
public final class FileMonitor: @unchecked Sendable {

    public static let shared = FileMonitor()

    private let log = OSLog(subsystem: "com.sekretsauce.agent", category: "filemonitor")
    private let auditLogger = AuditLogger.shared

    private var monitoredPaths: [String: DispatchSourceFileSystemObject] = [:]
    private let queue = DispatchQueue(label: "com.sekretsauce.filemonitor", qos: .utility)

    // Paths to monitor
    private let sensitiveDirectories = [
        "~/.ssh",
        "~/.cloudflared",
        "~/.ngrok2",
        "~/.config/ngrok",
        "~/.config/cloudflared",
        "/etc/ssh",
        "/etc/wireguard",
        "/etc/openvpn",
        "~/.tailscale"
    ]

    private let sensitiveFiles = [
        "~/.ssh/config",
        "~/.ssh/authorized_keys",
        "~/.ssh/known_hosts",
        "~/.cloudflared/config.yml",
        "~/.cloudflared/cert.pem",
        "~/.ngrok2/ngrok.yml"
    ]

    private init() {}

    // MARK: - Lifecycle

    /// Start monitoring sensitive paths
    public func start() {
        queue.sync {
            startOnQueue()
        }
    }

    private func startOnQueue() {
        os_log(.info, log: log, "Starting file monitor...")

        // Expand home directory paths
        let homeDir = FileManager.default.homeDirectoryForCurrentUser.path

        // Monitor directories
        for dirPath in sensitiveDirectories {
            let expandedPath = dirPath.replacingOccurrences(of: "~", with: homeDir)
            monitorPath(expandedPath, isDirectory: true)
        }

        // Monitor specific files
        for filePath in sensitiveFiles {
            let expandedPath = filePath.replacingOccurrences(of: "~", with: homeDir)
            monitorPath(expandedPath, isDirectory: false)
        }

        auditLogger.log(
            eventType: .systemStart,
            severity: .info,
            source: "FileMonitor",
            message: "File monitor started with \(monitoredPaths.count) watched paths"
        )
    }

    /// Stop all file monitoring
    public func stop() {
        queue.sync {
            stopOnQueue()
        }
    }

    private func stopOnQueue() {
        os_log(.info, log: log, "Stopping file monitor...")

        for (_, source) in monitoredPaths {
            source.cancel()
        }
        monitoredPaths.removeAll()

        auditLogger.log(
            eventType: .systemStop,
            severity: .info,
            source: "FileMonitor",
            message: "File monitor stopped"
        )
    }

    /// Add a custom path to monitor
    public func addMonitoredPath(_ path: String) {
        queue.sync {
            let expandedPath = (path as NSString).expandingTildeInPath
            let isDirectory = FileManager.default.fileExists(atPath: expandedPath, isDirectory: nil)
            monitorPath(expandedPath, isDirectory: isDirectory)
        }
    }

    // MARK: - Path Monitoring

    private func monitorPath(_ path: String, isDirectory: Bool) {
        guard monitoredPaths[path] == nil else { return }

        // Check if path exists
        guard FileManager.default.fileExists(atPath: path) else {
            // Try to monitor parent directory for creation
            let parentPath = (path as NSString).deletingLastPathComponent
            if FileManager.default.fileExists(atPath: parentPath) {
                monitorForCreation(path: path, in: parentPath)
            }
            return
        }

        // Open file descriptor for monitoring
        let fd = open(path, O_EVTONLY)
        guard fd >= 0 else {
            os_log(.default, log: log, "Failed to open path for monitoring: %{public}@", path)
            return
        }

        // Create dispatch source
        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .delete, .rename, .attrib, .extend],
            queue: queue
        )

        source.setEventHandler { [weak self] in
            self?.handleFileEvent(path: path, source: source)
        }

        source.setCancelHandler {
            close(fd)
        }

        source.resume()
        monitoredPaths[path] = source

        os_log(.debug, log: log, "Now monitoring: %{public}@", path)
    }

    private func monitorForCreation(path: String, in parentPath: String) {
        // Monitor parent directory for the file to be created
        let fd = open(parentPath, O_EVTONLY)
        guard fd >= 0 else { return }

        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write],
            queue: queue
        )

        source.setEventHandler { [weak self] in
            if FileManager.default.fileExists(atPath: path) {
                source.cancel()
                self?.monitorPath(path, isDirectory: false)

                self?.auditLogger.log(
                    eventType: .configChange,
                    severity: .medium,
                    source: "FileMonitor",
                    message: "Sensitive file created: \(path)"
                )
            }
        }

        source.setCancelHandler {
            close(fd)
        }

        source.resume()
    }

    private func handleFileEvent(path: String, source: DispatchSourceFileSystemObject) {
        let event = source.data

        var eventTypes: [String] = []

        if event.contains(.write) {
            eventTypes.append("modified")
        }
        if event.contains(.delete) {
            eventTypes.append("deleted")
        }
        if event.contains(.rename) {
            eventTypes.append("renamed")
        }
        if event.contains(.attrib) {
            eventTypes.append("attributes changed")
        }
        if event.contains(.extend) {
            eventTypes.append("extended")
        }

        let eventDescription = eventTypes.joined(separator: ", ")

        // Determine severity based on path
        let severity: AlertSeverity
        if path.contains(".ssh") || path.contains("cloudflared") {
            severity = .high
        } else {
            severity = .medium
        }

        auditLogger.log(
            eventType: .configChange,
            severity: severity,
            source: "FileMonitor",
            message: "Sensitive file \(eventDescription): \(path)",
            metadata: [
                "path": path,
                "events": eventDescription
            ]
        )

        // Check if file was deleted - need to re-monitor
        if event.contains(.delete) {
            source.cancel()
            monitoredPaths.removeValue(forKey: path)

            // Start monitoring for recreation
            let parentPath = (path as NSString).deletingLastPathComponent
            monitorForCreation(path: path, in: parentPath)
        }
    }
}
