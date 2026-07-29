import Foundation
import Darwin
import Common

/// Records SSH sessions with full I/O capture using pseudo-terminals
public final class SessionRecorder: @unchecked Sendable {

    private let session: SSHSession
    private let asciicastWriter: AsciicastWriter
    private let auditLogger = AuditLogger.shared

    private var masterFD: Int32 = -1
    private var slaveFD: Int32 = -1
    private var childProcess: Process?
    private var isRecording = false
    private let stateLock = NSLock()
    private let pumpGroup = DispatchGroup()

    public init(session: SSHSession, recordingDirectory: URL) throws {
        self.session = session

        // Create recording file path
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd_HH-mm-ss"
        let timestamp = formatter.string(from: session.startTime)
        let safeHost = session.destinationHost.map { character in
            character.isLetter || character.isNumber || character == "." || character == "-"
                ? character
                : "_"
        }
        let filename = "ssh_\(String(safeHost).prefix(255))_\(timestamp).cast"
        let filePath = recordingDirectory.appendingPathComponent(filename)

        // Get terminal size
        var winSize = winsize()
        _ = ioctl(STDOUT_FILENO, TIOCGWINSZ, &winSize)
        let width = Int(winSize.ws_col > 0 ? winSize.ws_col : 120)
        let height = Int(winSize.ws_row > 0 ? winSize.ws_row : 40)

        // Initialize asciicast writer
        self.asciicastWriter = try AsciicastWriter(
            filePath: filePath,
            width: width,
            height: height,
            title: "SSH to \(session.destinationHost)",
            command: SensitiveDataRedactor.redact(arguments: session.arguments).joined(separator: " "),
            recordInput: false
        )
    }

    /// Start recording and execute SSH
    public func start(sshPath: String = "/usr/bin/ssh") throws -> Int32 {
        // Create pseudo-terminal pair
        var master: Int32 = 0
        var slave: Int32 = 0

        guard openpty(&master, &slave, nil, nil, nil) == 0 else {
            throw RecorderError.ptyCreationFailed
        }

        masterFD = master
        slaveFD = slave

        // Set non-blocking on master
        let flags = fcntl(masterFD, F_GETFL)
        _ = fcntl(masterFD, F_SETFL, flags | O_NONBLOCK)

        let process = Process()
        let slaveHandle = FileHandle(fileDescriptor: slaveFD, closeOnDealloc: false)
        process.executableURL = URL(fileURLWithPath: sshPath)
        process.arguments = Array(session.arguments.dropFirst())
        process.standardInput = slaveHandle
        process.standardOutput = slaveHandle
        process.standardError = slaveHandle

        do {
            try process.run()
        } catch {
            close(masterFD)
            close(slaveFD)
            masterFD = -1
            slaveFD = -1
            throw RecorderError.processLaunchFailed(error.localizedDescription)
        }

        // Parent process
        close(slaveFD)
        slaveFD = -1
        childProcess = process
        setRecording(true)

        // Log session start
        auditLogger.logSSHSession(session, started: true)

        // Start I/O pump in background
        startIOPump()

        return process.processIdentifier
    }

    /// Wait for the SSH process to complete
    public func wait() -> Int32 {
        guard let childProcess else {
            return -1
        }
        childProcess.waitUntilExit()

        setRecording(false)
        pumpGroup.wait()
        if masterFD >= 0 {
            close(masterFD)
            masterFD = -1
        }
        asciicastWriter.close()

        // Update session with end time
        var endedSession = session
        endedSession.endTime = Date()
        auditLogger.logSSHSession(endedSession, started: false)

        return childProcess.terminationReason == .exit
            ? childProcess.terminationStatus
            : -1
    }

    /// Pump I/O between terminal and PTY while recording
    private func startIOPump() {
        // Handle terminal input -> PTY master (and record)
        let inputThread = Thread { [weak self] in
            defer { self?.pumpGroup.leave() }
            self?.pumpInput()
        }
        pumpGroup.enter()
        inputThread.start()

        // Handle PTY master output -> terminal (and record)
        let outputThread = Thread { [weak self] in
            defer { self?.pumpGroup.leave() }
            self?.pumpOutput()
        }
        pumpGroup.enter()
        outputThread.start()
    }

    private func pumpInput() {
        // Save original terminal settings
        var originalTermios = termios()
        tcgetattr(STDIN_FILENO, &originalTermios)

        // Set raw mode
        var rawTermios = originalTermios
        cfmakeraw(&rawTermios)
        tcsetattr(STDIN_FILENO, TCSANOW, &rawTermios)

        defer {
            // Restore terminal settings
            tcsetattr(STDIN_FILENO, TCSANOW, &originalTermios)
        }

        var buffer = [UInt8](repeating: 0, count: 1024)

        while recordingState {
            var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
            let pollResult = poll(&descriptor, 1, 100)
            if pollResult == 0 {
                continue
            }
            if pollResult < 0 {
                if errno == EINTR { continue }
                break
            }

            let n = read(STDIN_FILENO, &buffer, buffer.count)
            if n > 0 {
                // Forward to PTY
                _ = write(masterFD, buffer, n)
            } else if n == 0 || (n < 0 && errno != EAGAIN) {
                break
            }
        }
    }

    private func pumpOutput() {
        var buffer = [UInt8](repeating: 0, count: 4096)

        while true {
            let n = read(masterFD, &buffer, buffer.count)
            if n > 0 {
                let data = Data(bytes: buffer, count: n)

                // Record output
                asciicastWriter.writeOutput(data)

                // Forward to terminal
                _ = write(STDOUT_FILENO, buffer, n)
            } else if n == 0 {
                break
            } else if errno != EAGAIN {
                break
            } else {
                if !recordingState {
                    usleep(10_000)
                }
                // EAGAIN - no data available, small sleep
                usleep(1000)
            }
        }
    }

    private var recordingState: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return isRecording
    }

    private func setRecording(_ value: Bool) {
        stateLock.lock()
        isRecording = value
        stateLock.unlock()
    }

    /// Get the recording file path
    public var recordingPath: URL {
        return asciicastWriter.filePath
    }
}

// MARK: - Errors

public enum RecorderError: Error, LocalizedError {
    case ptyCreationFailed
    case forkFailed
    case execFailed
    case processLaunchFailed(String)

    public var errorDescription: String? {
        switch self {
        case .ptyCreationFailed:
            return "Failed to create pseudo-terminal"
        case .forkFailed:
            return "Failed to fork process"
        case .execFailed:
            return "Failed to execute SSH"
        case .processLaunchFailed(let message):
            return "Failed to execute SSH: \(message)"
        }
    }
}
