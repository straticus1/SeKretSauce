import Foundation
import os.log
import Common

/// SeKretSauce Security Agent - Launch Daemon Entry Point
/// This daemon runs at boot with root privileges to monitor and secure the system

// MARK: - Signal Handling

@MainActor
private enum SignalController {
    private static var sources: [DispatchSourceSignal] = []

    static func install() {
        for signalNumber in [SIGTERM, SIGINT, SIGHUP] {
            signal(signalNumber, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: .main)
            source.setEventHandler {
                if signalNumber == SIGHUP {
                    reloadConfiguration()
                } else {
                    os_log(.info, log: SeKretSauceDaemon.log, "Received shutdown signal")
                    ComponentCoordinator.shared.stop()
                    exit(0)
                }
            }
            source.resume()
            sources.append(source)
        }
    }

    private static func reloadConfiguration() {
        os_log(.info, log: SeKretSauceDaemon.log, "Received SIGHUP, reloading configuration...")
        do {
            let config = try SecureStorage.shared.retrieveConfiguration()
            try ComponentCoordinator.shared.updateConfiguration(config)
        } catch {
            os_log(.error, log: SeKretSauceDaemon.log, "Failed to reload configuration: %{public}@", error.localizedDescription)
        }
    }
}

// MARK: - Main Entry Point

@main
struct SeKretSauceDaemon {
    fileprivate static let log = OSLog(subsystem: "com.sekretsauce.agent", category: "main")

    static func main() async {
        os_log(.info, log: Self.log, "SeKretSauce Security Agent starting...")
        os_log(.info, log: Self.log, "PID: %d, UID: %d", getpid(), getuid())

        // Verify running as root
        guard getuid() == 0 else {
            os_log(.fault, log: Self.log, "ERROR: Must run as root (current UID: %d)", getuid())
            fputs("Error: SeKretSauce daemon must run as root\n", stderr)
            exit(1)
        }

        // Setup signal handlers
        SignalController.install()

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
            os_log(.fault, log: Self.log, "Failed to start coordinator: %{public}@", error.localizedDescription)
            AuditLogger.shared.logError(error, source: "Main", context: "Startup failure")
            exit(1)
        }

        os_log(.info, log: Self.log, "Daemon running")
        while !Task.isCancelled {
            try? await Task.sleep(nanoseconds: 3_600_000_000_000)
        }
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
    guard (try? SecureServerEndpoint(serverURL)) != nil else {
        print("Error: Server URL must use HTTPS and include a valid host")
        exit(1)
    }

    // Get API key
    guard let apiKey = readSecret(prompt: "Enter API key: "), !apiKey.isEmpty else {
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

private func readSecret(prompt: String) -> String? {
    print(prompt, terminator: "")
    fflush(stdout)

    var original = termios()
    guard tcgetattr(STDIN_FILENO, &original) == 0 else {
        return readLine()
    }
    var hidden = original
    hidden.c_lflag &= ~tcflag_t(ECHO)
    guard tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) == 0 else {
        return readLine()
    }
    defer {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &original)
        print()
    }
    return readLine()
}

@MainActor
func printStatus() {
    print("SeKretSauce Security Agent Status")
    print("==================================")
    print("Launch daemon loaded: \(isLaunchDaemonLoaded() ? "Yes" : "No")")
    print("Remote configured:    \(SecureStorage.shared.exists(key: "api_key") ? "Yes" : "No")")
    print("Network proxy:        Disabled (no upstream relay)")
    print("Live component state: See audit and launch-daemon logs")

    if let machineID = try? SecureStorage.shared.retrieve(key: "machine_id") {
        print("Machine ID:           \(machineID)")
    }

    let logFiles = AuditLogger.shared.getLogFiles()
    print("Log Files:            \(logFiles.count)")
}

private func isLaunchDaemonLoaded() -> Bool {
    let process = Process()
    let output = Pipe()
    process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
    process.arguments = ["print", "system/com.sekretsauce.daemon"]
    process.standardOutput = output
    process.standardError = output
    do {
        try process.run()
        _ = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return process.terminationReason == .exit && process.terminationStatus == 0
    } catch {
        return false
    }
}

func printVersion() {
    let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0"
    let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"
    print("SeKretSauce Security Agent v\(version) (build \(build))")
}
