import Foundation
import Darwin

/// Records SSH sessions with full I/O capture using pseudo-terminals
public final class SessionRecorder {

    private let session: SSHSession
    private let asciicastWriter: AsciicastWriter
    private let auditLogger = AuditLogger.shared

    private var masterFD: Int32 = -1
    private var slaveFD: Int32 = -1
    private var childPID: pid_t = -1
    private var isRecording = false

    public init(session: SSHSession, recordingDirectory: URL) throws {
        self.session = session

        // Create recording file path
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd_HH-mm-ss"
        let timestamp = formatter.string(from: session.startTime)
        let filename = "ssh_\(session.destinationHost)_\(timestamp).cast"
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
            command: session.arguments.joined(separator: " ")
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

        // Fork process
        let pid = fork()

        if pid == -1 {
            throw RecorderError.forkFailed
        }

        if pid == 0 {
            // Child process
            close(masterFD)

            // Create new session
            _ = setsid()

            // Set controlling terminal
            _ = ioctl(slaveFD, TIOCSCTTY, 0)

            // Redirect stdio to slave pty
            dup2(slaveFD, STDIN_FILENO)
            dup2(slaveFD, STDOUT_FILENO)
            dup2(slaveFD, STDERR_FILENO)

            if slaveFD > STDERR_FILENO {
                close(slaveFD)
            }

            // Execute SSH
            var args = [sshPath] + session.arguments.dropFirst() // Remove wrapper name
            let cArgs = args.map { strdup($0) } + [nil]
            execv(sshPath, cArgs)

            // If exec fails
            perror("execv")
            _exit(127)
        }

        // Parent process
        close(slaveFD)
        childPID = pid
        isRecording = true

        // Log session start
        auditLogger.logSSHSession(session, started: true)

        // Start I/O pump in background
        startIOPump()

        return pid
    }

    /// Wait for the SSH process to complete
    public func wait() -> Int32 {
        var status: Int32 = 0
        waitpid(childPID, &status, 0)

        isRecording = false
        asciicastWriter.close()

        // Update session with end time
        var endedSession = session
        endedSession.endTime = Date()
        auditLogger.logSSHSession(endedSession, started: false)

        if WIFEXITED(status) {
            return WEXITSTATUS(status)
        }
        return -1
    }

    /// Pump I/O between terminal and PTY while recording
    private func startIOPump() {
        // Handle terminal input -> PTY master (and record)
        let inputThread = Thread { [weak self] in
            self?.pumpInput()
        }
        inputThread.start()

        // Handle PTY master output -> terminal (and record)
        let outputThread = Thread { [weak self] in
            self?.pumpOutput()
        }
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

        while isRecording {
            let n = read(STDIN_FILENO, &buffer, buffer.count)
            if n > 0 {
                let data = Data(bytes: buffer, count: n)

                // Record input
                asciicastWriter.writeInput(data)

                // Forward to PTY
                _ = write(masterFD, buffer, n)
            } else if n == 0 || (n < 0 && errno != EAGAIN) {
                break
            }
        }
    }

    private func pumpOutput() {
        var buffer = [UInt8](repeating: 0, count: 4096)

        while isRecording {
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
                // EAGAIN - no data available, small sleep
                usleep(1000)
            }
        }
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

    public var errorDescription: String? {
        switch self {
        case .ptyCreationFailed:
            return "Failed to create pseudo-terminal"
        case .forkFailed:
            return "Failed to fork process"
        case .execFailed:
            return "Failed to execute SSH"
        }
    }
}

// MARK: - C Helpers

private func WIFEXITED(_ status: Int32) -> Bool {
    return (status & 0x7f) == 0
}

private func WEXITSTATUS(_ status: Int32) -> Int32 {
    return (status >> 8) & 0xff
}
