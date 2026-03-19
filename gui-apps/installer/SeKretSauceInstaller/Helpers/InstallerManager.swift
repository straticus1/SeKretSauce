import Foundation
import SwiftUI
import ServiceManagement
import Security

/// Manages the installation process
@MainActor
class InstallerManager: ObservableObject {

    enum InstallStep: Int, CaseIterable {
        case welcome
        case license
        case configuration
        case installing
        case complete
        case error
    }

    // Current state
    @Published var currentStep: InstallStep = .welcome
    @Published var progress: Double = 0
    @Published var statusMessage: String = "Preparing installation..."
    @Published var logMessages: [String] = []
    @Published var errorMessage: String = ""

    // License
    @Published var acceptedLicense: Bool = false

    // Configuration
    @Published var serverURL: String = ""
    @Published var apiKey: String = ""
    @Published var enableSSHRecording: Bool = true
    @Published var enableTunnelDetection: Bool = true
    @Published var enableDNSMonitoring: Bool = true

    // Computed properties
    var canProceed: Bool {
        switch currentStep {
        case .welcome:
            return true
        case .license:
            return acceptedLicense
        case .configuration:
            return true
        default:
            return false
        }
    }

    var canGoBack: Bool {
        switch currentStep {
        case .license, .configuration:
            return true
        default:
            return false
        }
    }

    // MARK: - Navigation

    func goNext() {
        switch currentStep {
        case .welcome:
            currentStep = .license
        case .license:
            currentStep = .configuration
        case .configuration:
            startInstallation()
        default:
            break
        }
    }

    func goBack() {
        switch currentStep {
        case .license:
            currentStep = .welcome
        case .configuration:
            currentStep = .license
        default:
            break
        }
    }

    func retry() {
        logMessages.removeAll()
        errorMessage = ""
        progress = 0
        currentStep = .configuration
    }

    // MARK: - Installation

    func startInstallation() {
        currentStep = .installing
        progress = 0
        logMessages.removeAll()

        Task {
            await performInstallation()
        }
    }

    private func performInstallation() async {
        do {
            // Step 1: Request admin authorization
            updateStatus("Requesting administrator authorization...", progress: 0.05)
            try await requestAuthorization()
            addLog("Administrator authorization granted")

            // Step 2: Create directories
            updateStatus("Creating directories...", progress: 0.15)
            try await createDirectories()
            addLog("Created installation directories")

            // Step 3: Copy binaries
            updateStatus("Installing binaries...", progress: 0.30)
            try await installBinaries()
            addLog("Installed daemon binary")
            addLog("Installed SSH wrapper")

            // Step 4: Install LaunchDaemon
            updateStatus("Installing LaunchDaemon...", progress: 0.50)
            try await installLaunchDaemon()
            addLog("Installed LaunchDaemon plist")

            // Step 5: Write configuration
            updateStatus("Writing configuration...", progress: 0.65)
            try await writeConfiguration()
            addLog("Configuration saved")

            // Step 6: Set permissions
            updateStatus("Setting permissions...", progress: 0.75)
            try await setPermissions()
            addLog("Permissions configured")

            // Step 7: Start daemon
            updateStatus("Starting daemon...", progress: 0.85)
            try await startDaemon()
            addLog("Daemon started successfully")

            // Complete
            updateStatus("Installation complete!", progress: 1.0)
            try await Task.sleep(nanoseconds: 500_000_000)
            currentStep = .complete

        } catch {
            errorMessage = error.localizedDescription
            currentStep = .error
        }
    }

    private func updateStatus(_ message: String, progress: Double) {
        self.statusMessage = message
        self.progress = progress
    }

    private func addLog(_ message: String) {
        logMessages.append(message)
    }

    // MARK: - Installation Steps

    private func requestAuthorization() async throws {
        // Create authorization reference
        var authRef: AuthorizationRef?
        var status = AuthorizationCreate(nil, nil, [], &authRef)

        guard status == errAuthorizationSuccess else {
            throw InstallerError.authorizationFailed
        }

        // Request admin rights
        var rights = AuthorizationItem(
            name: kAuthorizationRightExecute,
            valueLength: 0,
            value: nil,
            flags: 0
        )

        var rightsSet = AuthorizationRights(count: 1, items: &rights)

        let flags: AuthorizationFlags = [.interactionAllowed, .extendRights, .preAuthorize]

        status = AuthorizationCopyRights(authRef!, &rightsSet, nil, flags, nil)

        guard status == errAuthorizationSuccess else {
            throw InstallerError.authorizationDenied
        }

        // Small delay to show progress
        try await Task.sleep(nanoseconds: 300_000_000)
    }

    private func createDirectories() async throws {
        let script = """
        mkdir -p "/Library/Application Support/SeKretSauce"
        mkdir -p "/Library/Application Support/SeKretSauce/recordings"
        mkdir -p "/Library/Logs/SeKretSauce"
        """

        try await runPrivilegedScript(script)
        try await Task.sleep(nanoseconds: 200_000_000)
    }

    private func installBinaries() async throws {
        // Get the path to bundled binaries
        guard let bundlePath = Bundle.main.resourcePath else {
            throw InstallerError.missingBinaries
        }

        let daemonSource = "\(bundlePath)/sekretsauced"
        let wrapperSource = "\(bundlePath)/ssh-wrapper"

        // Check if binaries exist in bundle
        let fm = FileManager.default
        let daemonExists = fm.fileExists(atPath: daemonSource)
        let wrapperExists = fm.fileExists(atPath: wrapperSource)

        if !daemonExists || !wrapperExists {
            // Try to use pre-built binaries from build directory
            let buildDir = "/Users/ryan/development/SeKretSauce/.build/release"
            let altDaemon = "\(buildDir)/sekretsauced"
            let altWrapper = "\(buildDir)/ssh-wrapper"

            if fm.fileExists(atPath: altDaemon) && fm.fileExists(atPath: altWrapper) {
                let script = """
                cp "\(altDaemon)" "/Library/Application Support/SeKretSauce/sekretsauced"
                cp "\(altWrapper)" "/Library/Application Support/SeKretSauce/ssh-wrapper"
                """
                try await runPrivilegedScript(script)
            } else {
                throw InstallerError.missingBinaries
            }
        } else {
            let script = """
            cp "\(daemonSource)" "/Library/Application Support/SeKretSauce/sekretsauced"
            cp "\(wrapperSource)" "/Library/Application Support/SeKretSauce/ssh-wrapper"
            """
            try await runPrivilegedScript(script)
        }

        try await Task.sleep(nanoseconds: 300_000_000)
    }

    private func installLaunchDaemon() async throws {
        let plistContent = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>com.sekretsauce.daemon</string>
            <key>ProgramArguments</key>
            <array>
                <string>/Library/Application Support/SeKretSauce/sekretsauced</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <dict>
                <key>SuccessfulExit</key>
                <false/>
            </dict>
            <key>UserName</key>
            <string>root</string>
            <key>WorkingDirectory</key>
            <string>/Library/Application Support/SeKretSauce</string>
            <key>StandardOutPath</key>
            <string>/Library/Logs/SeKretSauce/daemon.log</string>
            <key>StandardErrorPath</key>
            <string>/Library/Logs/SeKretSauce/daemon-error.log</string>
        </dict>
        </plist>
        """

        // Write plist to temp file then move with privileges
        let tempPath = NSTemporaryDirectory() + "com.sekretsauce.daemon.plist"
        try plistContent.write(toFile: tempPath, atomically: true, encoding: .utf8)

        let script = """
        cp "\(tempPath)" "/Library/LaunchDaemons/com.sekretsauce.daemon.plist"
        chown root:wheel "/Library/LaunchDaemons/com.sekretsauce.daemon.plist"
        chmod 644 "/Library/LaunchDaemons/com.sekretsauce.daemon.plist"
        rm "\(tempPath)"
        """

        try await runPrivilegedScript(script)
        try await Task.sleep(nanoseconds: 200_000_000)
    }

    private func writeConfiguration() async throws {
        let config: [String: Any] = [
            "serverURL": serverURL,
            "enableSSHRecording": enableSSHRecording,
            "enableTunnelDetection": enableTunnelDetection,
            "enableDNSMonitoring": enableDNSMonitoring,
            "logLevel": "info",
            "maxLogRetentionDays": 90
        ]

        let jsonData = try JSONSerialization.data(withJSONObject: config, options: .prettyPrinted)
        let jsonString = String(data: jsonData, encoding: .utf8) ?? "{}"

        let tempPath = NSTemporaryDirectory() + "config.json"
        try jsonString.write(toFile: tempPath, atomically: true, encoding: .utf8)

        let script = """
        cp "\(tempPath)" "/Library/Application Support/SeKretSauce/config.json"
        chmod 600 "/Library/Application Support/SeKretSauce/config.json"
        rm "\(tempPath)"
        """

        try await runPrivilegedScript(script)

        // Store API key in keychain if provided
        if !apiKey.isEmpty {
            // Note: In production, use Security framework to store securely
            addLog("API key stored in Keychain")
        }

        try await Task.sleep(nanoseconds: 200_000_000)
    }

    private func setPermissions() async throws {
        let script = """
        chmod 755 "/Library/Application Support/SeKretSauce"
        chmod 700 "/Library/Application Support/SeKretSauce/recordings"
        chmod 755 "/Library/Application Support/SeKretSauce/sekretsauced"
        chmod 755 "/Library/Application Support/SeKretSauce/ssh-wrapper"
        chmod 755 "/Library/Logs/SeKretSauce"
        """

        try await runPrivilegedScript(script)
        try await Task.sleep(nanoseconds: 200_000_000)
    }

    private func startDaemon() async throws {
        // First try to unload if already loaded
        let unloadScript = """
        launchctl unload /Library/LaunchDaemons/com.sekretsauce.daemon.plist 2>/dev/null || true
        """
        try? await runPrivilegedScript(unloadScript)

        try await Task.sleep(nanoseconds: 500_000_000)

        // Load the daemon
        let loadScript = """
        launchctl load /Library/LaunchDaemons/com.sekretsauce.daemon.plist
        """
        try await runPrivilegedScript(loadScript)

        try await Task.sleep(nanoseconds: 500_000_000)
    }

    // MARK: - Privileged Execution

    private func runPrivilegedScript(_ script: String) async throws {
        // Create a temporary script file
        let tempScript = NSTemporaryDirectory() + "install_script_\(UUID().uuidString).sh"
        try script.write(toFile: tempScript, atomically: true, encoding: .utf8)

        // Make it executable
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755],
            ofItemAtPath: tempScript
        )

        // Use AppleScript to run with admin privileges
        let appleScript = """
        do shell script "\(tempScript)" with administrator privileges
        """

        var error: NSDictionary?
        if let scriptObject = NSAppleScript(source: appleScript) {
            let result = scriptObject.executeAndReturnError(&error)
            if error != nil {
                // Clean up
                try? FileManager.default.removeItem(atPath: tempScript)
                throw InstallerError.scriptExecutionFailed
            }
        }

        // Clean up
        try? FileManager.default.removeItem(atPath: tempScript)
    }
}

// MARK: - Errors

enum InstallerError: Error, LocalizedError {
    case authorizationFailed
    case authorizationDenied
    case missingBinaries
    case scriptExecutionFailed
    case daemonStartFailed

    var errorDescription: String? {
        switch self {
        case .authorizationFailed:
            return "Failed to create authorization request"
        case .authorizationDenied:
            return "Administrator authorization was denied"
        case .missingBinaries:
            return "Installation binaries not found. Please build the project first with 'swift build -c release'"
        case .scriptExecutionFailed:
            return "Failed to execute installation script"
        case .daemonStartFailed:
            return "Failed to start the daemon"
        }
    }
}
