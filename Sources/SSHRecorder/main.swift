import Foundation

/// SSH Wrapper - Intercepts SSH commands for recording and tunnel detection
/// This binary should be installed as /usr/local/bin/ssh-wrapper
/// and the original /usr/bin/ssh moved to /usr/bin/ssh.original

let auditLogger = AuditLogger.shared

// MARK: - Main Entry Point

@main
struct SSHWrapper {
    static func main() {
        let args = CommandLine.arguments

        // Parse SSH arguments
        let parser = SSHArgumentParser()
        guard let parsed = parser.parse(args) else {
            // Can't parse, just forward to real SSH
            executeRealSSH(args: Array(args.dropFirst()))
            exit(1)
        }

        // Check for tunnel flags - this is a security concern
        if !parsed.tunnels.isEmpty {
            handleTunnelDetection(parsed)
        }

        // Create session record
        let currentUser = ProcessInfo.processInfo.environment["USER"] ?? "unknown"
        let hostname = Host.current().localizedName ?? "localhost"

        let session = SSHSession(
            user: parsed.user ?? currentUser,
            sourceHost: hostname,
            destinationHost: parsed.host,
            destinationPort: parsed.port,
            command: args.first ?? "ssh",
            arguments: args,
            tunnelFlags: parsed.tunnels
        )

        // Check if recording is enabled
        let shouldRecord = shouldRecordSession(parsed)

        if shouldRecord {
            recordAndExecute(session: session, parsed: parsed)
        } else {
            // Just log and execute
            auditLogger.logSSHSession(session, started: true)
            executeRealSSH(args: Array(args.dropFirst()))
        }
    }
}

// MARK: - Tunnel Detection

func handleTunnelDetection(_ parsed: SSHArgumentParser.ParsedSSHCommand) {
    for tunnel in parsed.tunnels {
        let alert = TunnelAlert(
            type: .sshTunnel,
            evidence: "SSH tunnel detected: \(tunnel.type.rawValue) on port \(tunnel.bindPort)",
            severity: .high,
            processInfo: ProcessMetadata(
                pid: getpid(),
                ppid: getppid(),
                path: CommandLine.arguments[0],
                arguments: CommandLine.arguments,
                user: ProcessInfo.processInfo.environment["USER"] ?? "unknown"
            ),
            networkInfo: NetworkMetadata(
                destinationIP: parsed.host,
                destinationPort: parsed.port,
                protocol: .tcp
            )
        )

        auditLogger.logTunnelAlert(alert)
    }

    // Check for suspicious tunnel services
    let suspiciousDomains = [
        "serveo.net",
        "localhost.run",
        "ngrok.io",
        "bore.pub"
    ]

    for domain in suspiciousDomains {
        if parsed.host.contains(domain) {
            let alert = TunnelAlert(
                type: .sshTunnel,
                evidence: "SSH connection to known tunnel service: \(parsed.host)",
                severity: .critical,
                processInfo: ProcessMetadata(
                    pid: getpid(),
                    ppid: getppid(),
                    path: CommandLine.arguments[0],
                    arguments: CommandLine.arguments,
                    user: ProcessInfo.processInfo.environment["USER"] ?? "unknown"
                ),
                networkInfo: NetworkMetadata(
                    destinationIP: parsed.host,
                    destinationPort: parsed.port,
                    protocol: .tcp
                )
            )

            auditLogger.logTunnelAlert(alert)
        }
    }
}

// MARK: - Recording

func shouldRecordSession(_ parsed: SSHArgumentParser.ParsedSSHCommand) -> Bool {
    // Check configuration
    do {
        let config = try SecureStorage.shared.retrieveConfiguration()
        return config.enableSSHRecording
    } catch {
        // Default to recording if no config
        return true
    }
}

func recordAndExecute(session: SSHSession, parsed: SSHArgumentParser.ParsedSSHCommand) {
    // Get recording directory
    let recordingDirectory = getRecordingDirectory()

    // Ensure directory exists
    try? FileManager.default.createDirectory(at: recordingDirectory, withIntermediateDirectories: true)

    do {
        // Update session with recording path
        var recordedSession = session
        let recorder = try SessionRecorder(session: session, recordingDirectory: recordingDirectory)
        recordedSession = SSHSession(
            id: session.id,
            startTime: session.startTime,
            endTime: nil,
            user: session.user,
            sourceHost: session.sourceHost,
            destinationHost: session.destinationHost,
            destinationPort: session.destinationPort,
            command: session.command,
            arguments: session.arguments,
            recordingPath: recorder.recordingPath.path,
            tunnelFlags: session.tunnelFlags
        )

        // Start recording and execute SSH
        let sshPath = getRealSSHPath()
        let _ = try recorder.start(sshPath: sshPath)

        // Wait for completion
        let exitCode = recorder.wait()
        exit(exitCode)

    } catch {
        auditLogger.logError(error, source: "SSHWrapper", context: "Recording failed, falling back to direct execution")
        // Fall back to direct execution
        executeRealSSH(args: Array(CommandLine.arguments.dropFirst()))
    }
}

func getRecordingDirectory() -> URL {
    let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .localDomainMask).first!
    return appSupport.appendingPathComponent("SeKretSauce/recordings", isDirectory: true)
}

func getRealSSHPath() -> String {
    // Check for moved original
    if FileManager.default.fileExists(atPath: "/usr/bin/ssh.original") {
        return "/usr/bin/ssh.original"
    }
    // Fall back to standard location
    return "/usr/bin/ssh"
}

// MARK: - Direct Execution

func executeRealSSH(args: [String]) {
    let sshPath = getRealSSHPath()
    var fullArgs = [sshPath] + args
    let cArgs = fullArgs.map { strdup($0) } + [nil]
    execv(sshPath, cArgs)

    // If we get here, exec failed
    perror("execv")
    exit(127)
}
