import Foundation
import os.log

/// SeKretSauce Security Agent - Launch Daemon Entry Point
/// This daemon runs at boot with root privileges to monitor and secure the system

let log = OSLog(subsystem: "com.sekretsauce.agent", category: "main")

// MARK: - Signal Handling

func setupSignalHandlers() {
    signal(SIGTERM) { _ in
        os_log(.info, log: log, "Received SIGTERM, shutting down...")
        ComponentCoordinator.shared.stop()
        exit(0)
    }

    signal(SIGINT) { _ in
        os_log(.info, log: log, "Received SIGINT, shutting down...")
        ComponentCoordinator.shared.stop()
        exit(0)
    }

    signal(SIGHUP) { _ in
        os_log(.info, log: log, "Received SIGHUP, reloading configuration...")
        // Reload configuration
        Task {
            do {
                let config = try SecureStorage.shared.retrieveConfiguration()
                try ComponentCoordinator.shared.updateConfiguration(config)
            } catch {
                os_log(.error, log: log, "Failed to reload configuration: %{public}@", error.localizedDescription)
            }
        }
    }
}

// MARK: - Main Entry Point

@main
struct SeKretSauceDaemon {
    static func main() async {
        os_log(.info, log: log, "SeKretSauce Security Agent starting...")
        os_log(.info, log: log, "PID: %d, UID: %d", getpid(), getuid())

        // Verify running as root
        guard getuid() == 0 else {
            os_log(.fault, log: log, "ERROR: Must run as root (current UID: %d)", getuid())
            fputs("Error: SeKretSauce daemon must run as root\n", stderr)
            exit(1)
        }

        // Setup signal handlers
        setupSignalHandlers()

        // Check for command line arguments
        let args = CommandLine.arguments

        if args.contains("--setup") {
            await runSetup()
            return
        }

        if args.contains("--status") {
            printStatus()
            return
        }

        if args.contains("--version") {
            printVersion()
            return
        }

        // Start the coordinator
        do {
            try await ComponentCoordinator.shared.start()
        } catch {
            os_log(.fault, log: log, "Failed to start coordinator: %{public}@", error.localizedDescription)
            AuditLogger.shared.logError(error, source: "Main", context: "Startup failure")
            exit(1)
        }

        // Keep the daemon running
        os_log(.info, log: log, "Daemon running, entering run loop...")
        RunLoop.main.run()
    }
}

// MARK: - Commands

func runSetup() async {
    print("SeKretSauce Security Agent Setup")
    print("================================")
    print()

    // Check if already configured
    if SecureStorage.shared.exists(key: "api_key") {
        print("Warning: Credentials already configured.")
        print("Do you want to reconfigure? (y/N): ", terminator: "")

        guard let response = readLine()?.lowercased(), response == "y" else {
            print("Setup cancelled.")
            return
        }
    }

    // Get server URL
    print("Enter server URL (e.g., https://api.yourcompany.com): ", terminator: "")
    guard let serverURL = readLine(), !serverURL.isEmpty else {
        print("Error: Server URL is required")
        exit(1)
    }

    // Validate URL
    guard URL(string: serverURL) != nil else {
        print("Error: Invalid URL format")
        exit(1)
    }

    // Get API key
    print("Enter API key: ", terminator: "")
    guard let apiKey = readLine(), !apiKey.isEmpty else {
        print("Error: API key is required")
        exit(1)
    }

    // Test authentication
    print("\nTesting authentication...")
    do {
        let _ = try await AuthenticationManager.shared.authenticate(
            serverURL: serverURL,
            apiKey: apiKey
        )
        print("Authentication successful!")

        let machineID = try SecureStorage.shared.getMachineIdentifier()
        print("Machine ID: \(machineID)")

    } catch {
        print("Authentication failed: \(error.localizedDescription)")
        exit(1)
    }

    print("\nSetup complete!")
    print("The daemon will authenticate automatically on next start.")
}

func printStatus() {
    let status = ComponentCoordinator.shared.getStatus()

    print("SeKretSauce Security Agent Status")
    print("==================================")
    print("Running:              \(status.isRunning ? "Yes" : "No")")
    print("Authenticated:        \(status.isAuthenticated ? "Yes" : "No")")
    print("SSH Wrapper:          \(status.sshWrapperInstalled ? "Installed" : "Not Installed")")
    print("Network Extension:    \(status.networkExtensionActive ? "Active" : "Inactive")")
    print("Process Monitor:      \(status.processMonitorActive ? "Active" : "Inactive")")

    if let machineID = try? SecureStorage.shared.getMachineIdentifier() {
        print("Machine ID:           \(machineID)")
    }

    let logFiles = AuditLogger.shared.getLogFiles()
    print("Log Files:            \(logFiles.count)")
}

func printVersion() {
    let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0"
    let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"
    print("SeKretSauce Security Agent v\(version) (build \(build))")
}
