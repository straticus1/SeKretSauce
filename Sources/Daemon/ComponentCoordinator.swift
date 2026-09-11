import Common
import CryptoKit
import EndpointSecurityMonitor
import Foundation
import TunnelDetection
import os.log

/// Coordinates all security agent components
@MainActor
public final class ComponentCoordinator {

    public static let shared = ComponentCoordinator()

    private let log = OSLog(subsystem: "com.sekretsauce.agent", category: "coordinator")
    private let auditLogger = AuditLogger.shared
    private let authManager = AuthenticationManager.shared

    // Component status
    private var isRunning = false
    private var sshWrapperInstalled = false
    private var networkExtensionActive = false
    private var processMonitorActive = false
    private var processMonitorError: String?

    private init() {}

    // MARK: - Lifecycle

    /// Start all components
    public func start() async throws {
        guard !isRunning else {
            os_log(.info, log: log, "Coordinator already running")
            return
        }

        os_log(.info, log: log, "Starting SeKretSauce security agent...")
        auditLogger.logSystemStart()

        do {
            AgentControlService.shared.start()
            let config = try loadConfiguration()

            if SecureStorage.shared.exists(key: "api_key") {
                do {
                    os_log(.info, log: log, "Authenticating with server...")
                    _ = try await authManager.authenticate()
                    os_log(.info, log: log, "Authentication successful")
                } catch {
                    auditLogger.logAuthFailure(reason: error.localizedDescription)
                    os_log(
                        .error, log: log, "Remote authentication unavailable; local protection will continue")
                }
            } else {
                os_log(.info, log: log, "No remote credentials configured; starting in local-only mode")
            }

            if config.enableSSHRecording {
                do {
                    try installSSHWrapper()
                } catch {
                    auditLogger.logError(error, source: "Coordinator", context: "SSH recording unavailable")
                }
            }

            if config.enableDNSMonitoring {
                do {
                    try await activateNetworkExtension()
                } catch {
                    auditLogger.logError(
                        error, source: "Coordinator", context: "Network extension unavailable")
                }
            }

            if config.enableProcessMonitoring {
                do {
                    try startProcessMonitor(tunnelDetectionEnabled: config.enableTunnelDetection)
                } catch {
                    processMonitorError = error.localizedDescription
                    auditLogger.logError(
                        error, source: "Coordinator", context: "Process monitoring unavailable")
                }
            }

            // 4. Start log sync
            startLogSync(intervalSeconds: config.syncIntervalSeconds)

            // 5. Schedule log cleanup
            scheduleLogCleanup(retentionDays: config.maxLogRetentionDays)

            isRunning = true
            os_log(.info, log: log, "All components started successfully")

        } catch {
            auditLogger.logError(error, source: "Coordinator", context: "Failed to start components")
            throw error
        }
    }

    /// Stop all components
    public func stop() {
        guard isRunning else { return }

        os_log(.info, log: log, "Stopping SeKretSauce security agent...")

        // Stop components in reverse order
        stopProcessMonitor()
        deactivateNetworkExtension()
        uninstallSSHWrapper()
        logSyncTimer?.invalidate()
        logSyncTimer = nil
        logCleanupTimer?.invalidate()
        logCleanupTimer = nil

        auditLogger.logSystemStop()
        isRunning = false

        os_log(.info, log: log, "All components stopped")
    }

    public func health(for uid: uid_t) -> AgentHealth {
        let telemetry = ProcessMonitor.shared.telemetry
        let canaries = CanaryManager.installed(for: uid)
        let sensorState =
            processMonitorActive ? (telemetry.dropped > 0 ? "degraded" : "active") : "unavailable"
        return AgentHealth(
            components: [
                ComponentHealth(
                    id: "containment",
                    state: IncidentControl.automaticResponseEnabled ? "enabled" : "unavailable",
                    reason: IncidentControl.automaticResponseEnabled
                        ? "Task response enabled; individual attempts may fail"
                        : "Automatic containment awaits signed macOS validation"),
                ComponentHealth(
                    id: "sensor", state: sensorState,
                    reason: processMonitorError
                        ?? (processMonitorActive ? "" : "Behavioral monitoring is not running")),
                ComponentHealth(
                    id: "canaries",
                    state: canaries ? (processMonitorActive ? "active" : "degraded") : "notInstalled",
                    reason: canaries
                        ? "Canary files installed; protection depends on the sensor"
                        : "Install canaries to enable this signal"),
                ComponentHealth(
                    id: "networkProxy", state: "unavailable", reason: "No upstream relay is implemented"),
                ComponentHealth(
                    id: "remoteSync", state: authManager.isAuthenticated ? "active" : "unavailable",
                    reason: authManager.isAuthenticated
                        ? "" : "Local protection operates independently of remote sync"),
            ], eventsReceived: telemetry.received, eventsDropped: telemetry.dropped,
            lastEventAt: telemetry.lastEvent)
    }

    // MARK: - Configuration

    private func loadConfiguration() throws -> AgentConfiguration {
        do {
            return try SecureStorage.shared.retrieveConfiguration()
        } catch SecureStorageError.itemNotFound {
            // Return default configuration
            let defaultConfig = AgentConfiguration()
            os_log(.info, log: log, "Using default configuration")
            return defaultConfig
        }
    }

    public func updateConfiguration(_ config: AgentConfiguration) throws {
        try SecureStorage.shared.storeConfiguration(config)

        auditLogger.log(
            eventType: .configChange,
            severity: .info,
            source: "Coordinator",
            message: "Configuration updated"
        )

        guard isRunning else { return }

        if config.enableProcessMonitoring && !processMonitorActive {
            try startProcessMonitor(tunnelDetectionEnabled: config.enableTunnelDetection)
        } else if !config.enableProcessMonitoring && processMonitorActive {
            stopProcessMonitor()
        } else if processMonitorActive {
            ProcessMonitor.shared.setTunnelDetectionEnabled(config.enableTunnelDetection)
        }
    }

    // MARK: - SSH Wrapper

    private func installSSHWrapper() throws {
        os_log(.info, log: log, "Checking SSH wrapper availability...")

        let candidatePaths = [
            "/Library/Application Support/SeKretSauce/ssh-wrapper",
            "/usr/local/bin/ssh-wrapper",
        ]
        let fileManager = FileManager.default

        guard
            let wrapperPath = candidatePaths.first(where: {
                fileManager.isExecutableFile(atPath: $0)
            })
        else {
            os_log(.error, log: log, "SSH wrapper binary not found")
            throw ComponentError.sshWrapperNotFound
        }

        sshWrapperInstalled = true
        os_log(
            .info, log: log,
            "SSH wrapper available at %{public}@; users must invoke or alias it explicitly", wrapperPath)
    }

    private func uninstallSSHWrapper() {
        guard sshWrapperInstalled else { return }

        os_log(.info, log: log, "SSH wrapper availability state cleared")
        sshWrapperInstalled = false
    }

    // MARK: - Network Extension

    private func activateNetworkExtension() async throws {
        os_log(.info, log: log, "Activating network extension...")

        networkExtensionActive = false
        throw ComponentError.networkExtensionNotInstalled
    }

    private func deactivateNetworkExtension() {
        guard networkExtensionActive else { return }

        os_log(.info, log: log, "Deactivating network extension")
        // In production: disable the network extension
        networkExtensionActive = false
    }

    // MARK: - Process Monitor

    private func startProcessMonitor(tunnelDetectionEnabled: Bool = true) throws {
        os_log(.info, log: log, "Starting process monitor...")

        try ProcessMonitor.shared.start(tunnelDetectionEnabled: tunnelDetectionEnabled)
        FileMonitor.shared.start()
        processMonitorActive = true
        processMonitorError = nil
        os_log(.info, log: log, "Process and file monitors activated")
    }

    private func stopProcessMonitor() {
        guard processMonitorActive else { return }

        os_log(.info, log: log, "Stopping process monitor")
        ProcessMonitor.shared.stop()
        FileMonitor.shared.stop()
        processMonitorActive = false
    }

    // MARK: - Log Sync

    private var logSyncTimer: Timer?
    private var logCleanupTimer: Timer?

    private func startLogSync(intervalSeconds: Int) {
        logSyncTimer?.invalidate()
        let safeInterval = min(max(intervalSeconds, 30), 86_400)

        logSyncTimer = Timer.scheduledTimer(withTimeInterval: TimeInterval(safeInterval), repeats: true) {
            [weak self] _ in
            Task {
                await self?.syncLogs()
            }
        }

        os_log(.info, log: log, "Log sync scheduled every %d seconds", safeInterval)
    }

    private func syncLogs() async {
        guard authManager.isAuthenticated else {
            os_log(.default, log: log, "Cannot sync logs - not authenticated")
            return
        }

        do {
            let token = try authManager.getSessionToken()
            let serverURL = try SecureStorage.shared.retrieveServerURL()
            var manifest = loadLogSyncManifest()

            // Get unsync'd log files
            let logFiles = auditLogger.getLogFiles()

            for file in logFiles.suffix(5) {  // Sync last 5 days max at a time
                let data = try readLogFile(file)
                let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
                guard manifest[file.lastPathComponent] != digest else { continue }
                try await uploadLogData(
                    data,
                    digest: digest,
                    serverURL: serverURL,
                    token: token
                )
                manifest[file.lastPathComponent] = digest
                try saveLogSyncManifest(manifest)
            }

        } catch {
            os_log(.error, log: log, "Log sync failed: %{public}@", error.localizedDescription)
        }
    }

    private func uploadLogData(
        _ logData: Data,
        digest: String,
        serverURL: String,
        token: String
    ) async throws {
        guard let endpoint = try? SecureServerEndpoint(serverURL) else {
            throw ComponentError.invalidServerURL
        }

        var request = URLRequest(url: endpoint.appending(path: "/api/v1/logs/upload"))
        request.httpMethod = "POST"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/x-ndjson", forHTTPHeaderField: "Content-Type")
        request.setValue(digest, forHTTPHeaderField: "Idempotency-Key")
        request.httpBody = logData

        let (_, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse,
            (200...299).contains(httpResponse.statusCode)
        else {
            throw ComponentError.logUploadFailed
        }
    }

    private func readLogFile(_ file: URL) throws -> Data {
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        let size = (attributes[.size] as? NSNumber)?.intValue ?? 0
        guard size <= 10 * 1024 * 1024 else {
            throw ComponentError.logFileTooLarge
        }
        return try Data(contentsOf: file, options: [.mappedIfSafe])
    }

    private func loadLogSyncManifest() -> [String: String] {
        guard let json = try? SecureStorage.shared.retrieve(key: "log_sync_manifest"),
            let data = json.data(using: .utf8),
            let manifest = try? JSONDecoder().decode([String: String].self, from: data)
        else {
            return [:]
        }
        return manifest
    }

    private func saveLogSyncManifest(_ manifest: [String: String]) throws {
        let data = try JSONEncoder().encode(manifest)
        guard let json = String(data: data, encoding: .utf8) else {
            throw ComponentError.logUploadFailed
        }
        try SecureStorage.shared.store(key: "log_sync_manifest", value: json)
    }

    // MARK: - Log Cleanup

    private func scheduleLogCleanup(retentionDays: Int) {
        // Run cleanup daily
        logCleanupTimer?.invalidate()
        logCleanupTimer = Timer.scheduledTimer(withTimeInterval: 86400, repeats: true) {
            [weak self] _ in
            self?.auditLogger.cleanupOldLogs(retentionDays: min(max(retentionDays, 1), 3_650))
        }

        // Also run immediately
        auditLogger.cleanupOldLogs(retentionDays: min(max(retentionDays, 1), 3_650))
    }

    // MARK: - Status

    public struct Status {
        public let isRunning: Bool
        public let isAuthenticated: Bool
        public let sshWrapperInstalled: Bool
        public let networkExtensionActive: Bool
        public let processMonitorActive: Bool
    }

    public func getStatus() -> Status {
        return Status(
            isRunning: isRunning,
            isAuthenticated: authManager.isAuthenticated,
            sshWrapperInstalled: sshWrapperInstalled,
            networkExtensionActive: networkExtensionActive,
            processMonitorActive: processMonitorActive
        )
    }
}

// MARK: - Errors

public enum ComponentError: Error, LocalizedError {
    case sshWrapperNotFound
    case networkExtensionNotInstalled
    case processMonitorFailed
    case invalidServerURL
    case logUploadFailed
    case logFileTooLarge

    public var errorDescription: String? {
        switch self {
        case .sshWrapperNotFound:
            return "SSH wrapper binary not found"
        case .networkExtensionNotInstalled:
            return "Network extension is not installed"
        case .processMonitorFailed:
            return "Failed to start process monitor"
        case .invalidServerURL:
            return "Invalid server URL configured"
        case .logUploadFailed:
            return "Failed to upload logs to server"
        case .logFileTooLarge:
            return "Audit log exceeds the 10 MiB upload limit"
        }
    }
}
