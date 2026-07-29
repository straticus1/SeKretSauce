import Foundation
import SwiftUI
import ServiceManagement
import Security
import InstallerSupport

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
    private var installerTeamIdentifier: String?

    // Configuration
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
            // Step 1: Verify the installer before crossing the privilege boundary.
            updateStatus("Verifying installer signature...", progress: 0.05)
            try verifyInstallerSignature()
            addLog("Installer signature verified")

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

            // Step 5: Set permissions. Remote credentials are configured later
            // in a root-owned terminal so they never cross a command-line or
            // AppleScript privilege boundary.
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

    private func verifyInstallerSignature() throws {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(Bundle.main.bundleURL as CFURL, [], &code) == errSecSuccess,
              let code else {
            throw InstallerError.invalidSignature
        }

        let flags = SecCSFlags(
            rawValue: UInt32(kSecCSStrictValidate | kSecCSCheckAllArchitectures)
        )
        guard SecStaticCodeCheckValidity(code, flags, nil) == errSecSuccess else {
            throw InstallerError.invalidSignature
        }

        var signingInformation: CFDictionary?
        guard SecCodeCopySigningInformation(code, [], &signingInformation) == errSecSuccess,
              let information = signingInformation as? [String: Any],
              let teamIdentifier = information[kSecCodeInfoTeamIdentifier as String] as? String,
              !teamIdentifier.isEmpty else {
            throw InstallerError.invalidSignature
        }
        installerTeamIdentifier = teamIdentifier
    }

    private func createDirectories() async throws {
        try runPrivileged(
            PrivilegedCommand(
                executable: "/bin/mkdir",
                arguments: [
                    "-p",
                    "/Library/Application Support/SeKretSauce",
                    "/Library/Application Support/SeKretSauce/recordings",
                    "/Library/Logs/SeKretSauce"
                ]
            )
        )
        try await Task.sleep(nanoseconds: 200_000_000)
    }

    private func installBinaries() async throws {
        // Get the path to bundled binaries
        guard let bundlePath = Bundle.main.resourcePath else {
            throw InstallerError.missingBinaries
        }

        let daemonSource = "\(bundlePath)/sekretsauced"
        let wrapperSource = "\(bundlePath)/ssh-wrapper"

        let fm = FileManager.default
        guard fm.fileExists(atPath: daemonSource),
              fm.fileExists(atPath: wrapperSource) else {
            throw InstallerError.missingBinaries
        }

        try installSignedBinary(
            from: daemonSource,
            to: "/Library/Application Support/SeKretSauce/sekretsauced"
        )
        try installSignedBinary(
            from: wrapperSource,
            to: "/Library/Application Support/SeKretSauce/ssh-wrapper"
        )

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

        try writePrivilegedFile(
            Data(plistContent.utf8),
            to: "/Library/LaunchDaemons/com.sekretsauce.daemon.plist",
            permissions: "0644"
        )
        try await Task.sleep(nanoseconds: 200_000_000)
    }

    private func setPermissions() async throws {
        try runPrivileged(
            PrivilegedCommand(
                executable: "/bin/chmod",
                arguments: [
                    "0755",
                    "/Library/Application Support/SeKretSauce"
                ]
            )
        )
        try runPrivileged(
            PrivilegedCommand(
                executable: "/bin/chmod",
                arguments: [
                    "0700",
                    "/Library/Application Support/SeKretSauce/recordings",
                    "/Library/Logs/SeKretSauce"
                ]
            )
        )
        try runPrivileged(
            PrivilegedCommand(
                executable: "/bin/chmod",
                arguments: [
                    "0755",
                    "/Library/Application Support/SeKretSauce/sekretsauced",
                    "/Library/Application Support/SeKretSauce/ssh-wrapper"
                ]
            )
        )
        try await Task.sleep(nanoseconds: 200_000_000)
    }

    private func startDaemon() async throws {
        // First try to unload if already loaded
        try? runPrivileged(
            PrivilegedCommand(
                executable: "/bin/launchctl",
                arguments: ["bootout", "system/com.sekretsauce.daemon"]
            )
        )

        try await Task.sleep(nanoseconds: 500_000_000)

        // Load the daemon
        try runPrivileged(
            PrivilegedCommand(
                executable: "/bin/launchctl",
                arguments: [
                    "bootstrap",
                    "system",
                    "/Library/LaunchDaemons/com.sekretsauce.daemon.plist"
                ]
            )
        )

        try await Task.sleep(nanoseconds: 500_000_000)
    }

    // MARK: - Privileged Execution

    private func runPrivileged(_ command: PrivilegedCommand) throws {
        var error: NSDictionary?
        guard let scriptObject = NSAppleScript(source: command.appleScriptSource) else {
            throw InstallerError.scriptExecutionFailed("Could not create authorization request")
        }
        _ = scriptObject.executeAndReturnError(&error)

        if let error {
            let message = error[NSAppleScript.errorMessage] as? String
                ?? "Administrator operation failed"
            throw InstallerError.scriptExecutionFailed(message)
        }
    }

    private func installSignedBinary(from source: String, to destination: String) throws {
        guard let installerTeamIdentifier else {
            throw InstallerError.invalidSignature
        }
        try verifyBinary(at: source, expectedTeamIdentifier: installerTeamIdentifier)
        try runPrivileged(
            PrivilegedCommand(
                executable: "/usr/bin/install",
                arguments: ["-o", "root", "-g", "wheel", "-m", "0755", source, destination]
            )
        )
        do {
            try verifyBinary(at: destination, expectedTeamIdentifier: installerTeamIdentifier)
        } catch {
            try? runPrivileged(
                PrivilegedCommand(executable: "/bin/rm", arguments: ["-f", destination])
            )
            throw error
        }
    }

    private func verifyBinary(at path: String, expectedTeamIdentifier: String) throws {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code else {
            throw InstallerError.invalidBundledBinary
        }
        let flags = SecCSFlags(rawValue: UInt32(kSecCSStrictValidate | kSecCSCheckAllArchitectures))
        guard SecStaticCodeCheckValidity(code, flags, nil) == errSecSuccess else {
            throw InstallerError.invalidBundledBinary
        }
        var signingInformation: CFDictionary?
        guard SecCodeCopySigningInformation(code, [], &signingInformation) == errSecSuccess,
              let information = signingInformation as? [String: Any],
              let teamIdentifier = information[kSecCodeInfoTeamIdentifier as String] as? String,
              teamIdentifier == expectedTeamIdentifier else {
            throw InstallerError.invalidBundledBinary
        }
    }

    private func writePrivilegedFile(
        _ data: Data,
        to destination: String,
        permissions: String
    ) throws {
        let encoded = data.base64EncodedString()
        let quotedEncoded = ShellEscaping.quote(encoded)
        let quotedDestination = ShellEscaping.quote(destination)
        let command = """
        set -e
        umask 077
        /usr/bin/printf '%s' \(quotedEncoded) | /usr/bin/base64 -D > \(quotedDestination)
        /usr/sbin/chown root:wheel \(quotedDestination)
        /bin/chmod \(ShellEscaping.quote(permissions)) \(quotedDestination)
        """
        try runPrivileged(
            PrivilegedCommand(executable: "/bin/sh", arguments: ["-c", command])
        )
    }
}

// MARK: - Errors

enum InstallerError: Error, LocalizedError {
    case authorizationFailed
    case authorizationDenied
    case invalidSignature
    case invalidBundledBinary
    case missingBinaries
    case scriptExecutionFailed(String)
    case daemonStartFailed

    var errorDescription: String? {
        switch self {
        case .authorizationFailed:
            return "Failed to create authorization request"
        case .authorizationDenied:
            return "Administrator authorization was denied"
        case .invalidSignature:
            return "The installer is not signed by a trusted development team"
        case .invalidBundledBinary:
            return "A bundled binary is unsigned, invalid, or signed by a different development team"
        case .missingBinaries:
            return "Installation binaries not found. Please build the project first with 'swift build -c release'"
        case .scriptExecutionFailed(let message):
            return "Failed to perform privileged installation: \(message)"
        case .daemonStartFailed:
            return "Failed to start the daemon"
        }
    }
}
