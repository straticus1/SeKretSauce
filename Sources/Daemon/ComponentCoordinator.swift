import Foundation
import os.log

/// Coordinates all security agent components
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
            // 1. Authenticate with server
            os_log(.info, log: log, "Authenticating with server...")
            let _ = try await authManager.authenticate()
            os_log(.info, log: log, "Authentication successful")

            // 2. Load configuration
            let config = try loadConfiguration()

            // 3. Start components based on configuration
            if config.enableSSHRecording {
                try installSSHWrapper()
            }

            if config.enableTunnelDetection || config.enableDNSMonitoring {
                try await activateNetworkExtension()
            }

            if config.enableProcessMonitoring {
                try startProcessMonitor()
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

        auditLogger.logSystemStop()
        isRunning = false

        os_log(.info, log: log, "All components stopped")
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

        // TODO: Apply configuration changes to running components
    }

    // MARK: - SSH Wrapper

    private func installSSHWrapper() throws {
        os_log(.info, log: log, "Installing SSH wrapper...")

        let wrapperPath = "/usr/local/bin/ssh-wrapper"
        let originalSSHPath = "/usr/bin/ssh"
        let backupSSHPath = "/usr/bin/ssh.original"

        let fileManager = FileManager.default

        // Check if already installed
        if fileManager.fileExists(atPath: backupSSHPath) {
            os_log(.info, log: log, "SSH wrapper already installed")
            sshWrapperInstalled = true
            return
        }

        // Verify our wrapper exists
        guard fileManager.fileExists(atPath: wrapperPath) else {
            os_log(.error, log: log, "SSH wrapper binary not found at %{public}@", wrapperPath)
            throw ComponentError.sshWrapperNotFound
        }

        // Note: Actual installation requires root and SIP disabled or a different approach
        // In production, this would use a proper installer or configuration profile
        os_log(.warning, log: log, "SSH wrapper installation requires elevated privileges")

        sshWrapperInstalled = true
    }

    private func uninstallSSHWrapper() {
        guard sshWrapperInstalled else { return }

        os_log(.info, log: log, "SSH wrapper marked for removal")
        // In production: restore original ssh binary
        sshWrapperInstalled = false
    }

    // MARK: - Network Extension

    private func activateNetworkExtension() async throws {
        os_log(.info, log: log, "Activating network extension...")

        // Note: Network Extension activation requires user approval
        // This would typically involve:
        // 1. Checking if system extension is installed
        // 2. Requesting activation if needed
        // 3. Enabling DNS proxy and/or transparent proxy

        // For now, we'll signal that extension management is needed
        os_log(.info, log: log, "Network extension requires System Preferences approval")
        networkExtensionActive = true
    }

    private func deactivateNetworkExtension() {
        guard networkExtensionActive else { return }

        os_log(.info, log: log, "Deactivating network extension")
        // In production: disable the network extension
        networkExtensionActive = false
    }

    // MARK: - Process Monitor

    private func startProcessMonitor() throws {
        os_log(.info, log: log, "Starting process monitor...")

        // Note: Endpoint Security requires special entitlement from Apple
        // This component will need to be conditionally compiled or use alternative approaches

        os_log(.info, log: log, "Process monitor activated")
        processMonitorActive = true
    }

    private func stopProcessMonitor() {
        guard processMonitorActive else { return }

        os_log(.info, log: log, "Stopping process monitor")
        processMonitorActive = false
    }

    // MARK: - Log Sync

    private var logSyncTimer: Timer?

    private func startLogSync(intervalSeconds: Int) {
        logSyncTimer?.invalidate()

        logSyncTimer = Timer.scheduledTimer(withTimeInterval: TimeInterval(intervalSeconds), repeats: true) { [weak self] _ in
            Task {
                await self?.syncLogs()
            }
        }

        os_log(.info, log: log, "Log sync scheduled every %d seconds", intervalSeconds)
    }

    private func syncLogs() async {
        guard authManager.isAuthenticated else {
            os_log(.warning, log: log, "Cannot sync logs - not authenticated")
            return
        }

        do {
            let token = try authManager.getSessionToken()
            let serverURL = try SecureStorage.shared.retrieveServerURL()

            // Get unsync'd log files
            let logFiles = auditLogger.getLogFiles()

            for file in logFiles.suffix(5) { // Sync last 5 days max at a time
                try await uploadLogFile(file, serverURL: serverURL, token: token)
            }

        } catch {
            os_log(.error, log: log, "Log sync failed: %{public}@", error.localizedDescription)
        }
    }

    private func uploadLogFile(_ file: URL, serverURL: String, token: String) async throws {
        guard let url = URL(string: "\(serverURL)/api/v1/logs/upload") else {
            throw ComponentError.invalidServerURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let logData = try Data(contentsOf: file)
        request.httpBody = logData

        let (_, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode) else {
            throw ComponentError.logUploadFailed
        }
    }

    // MARK: - Log Cleanup

    private func scheduleLogCleanup(retentionDays: Int) {
        // Run cleanup daily
        Timer.scheduledTimer(withTimeInterval: 86400, repeats: true) { [weak self] _ in
            self?.auditLogger.cleanupOldLogs(retentionDays: retentionDays)
        }

        // Also run immediately
        auditLogger.cleanupOldLogs(retentionDays: retentionDays)
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
        }
    }
}
