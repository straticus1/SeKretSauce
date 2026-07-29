import Foundation
import Darwin

/// Writes SSH session recordings in Asciicast v2 format
/// Compatible with asciinema player for playback
public final class AsciicastWriter: @unchecked Sendable {

    private let fileHandle: FileHandle
    private let startTime: Date
    private let encoder = JSONEncoder()
    private let queue = DispatchQueue(label: "com.sekretsauce.asciicast")
    private let queueKey = DispatchSpecificKey<UInt8>()
    private let recordInput: Bool
    private var isClosed = false

    public let filePath: URL

    /// Initialize with a file path for the recording
    public init(
        filePath: URL,
        width: Int = 120,
        height: Int = 40,
        title: String? = nil,
        command: String? = nil,
        recordInput: Bool = false
    ) throws {
        self.filePath = filePath
        self.startTime = Date()
        self.recordInput = recordInput

        let descriptor = open(
            filePath.path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
            0o600
        )
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        self.fileHandle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        self.queue.setSpecific(key: queueKey, value: 1)

        // Write header
        let header = AsciicastHeader(
            version: 2,
            width: width,
            height: height,
            timestamp: Int(startTime.timeIntervalSince1970),
            title: title,
            command: command,
            env: AsciicastEnv(
                shell: ProcessInfo.processInfo.environment["SHELL"] ?? "/bin/zsh",
                term: ProcessInfo.processInfo.environment["TERM"] ?? "xterm-256color"
            )
        )

        let headerData = try JSONEncoder().encode(header)
        fileHandle.write(headerData)
        fileHandle.write(Data([0x0A])) // newline
    }

    /// Write output event (data from SSH server to terminal)
    public func writeOutput(_ data: Data) {
        queue.async { [weak self] in
            self?.writeEvent(type: "o", data: data)
        }
    }

    /// Write input event (data from user to SSH server)
    public func writeInput(_ data: Data) {
        guard recordInput else {
            return
        }
        queue.async { [weak self] in
            self?.writeEvent(type: "i", data: data)
        }
    }

    private func writeEvent(type: String, data: Data) {
        let elapsed = Date().timeIntervalSince(startTime)

        let event: [Any] = [
            Double(String(format: "%.6f", elapsed)) ?? elapsed,
            type,
            String(decoding: data, as: UTF8.self)
        ]
        if let eventData = try? JSONSerialization.data(withJSONObject: event) {
            fileHandle.write(eventData)
            fileHandle.write(Data([0x0A])) // newline
        }
    }

    /// Close the recording file
    public func close() {
        if DispatchQueue.getSpecific(key: queueKey) != nil {
            closeOnQueue()
        } else {
            queue.sync {
                closeOnQueue()
            }
        }
    }

    private func closeOnQueue() {
        guard !isClosed else { return }
        isClosed = true
        fileHandle.synchronizeFile()
        fileHandle.closeFile()
    }

    deinit {
        close()
    }
}

// MARK: - Asciicast v2 Models

private struct AsciicastHeader: Codable {
    let version: Int
    let width: Int
    let height: Int
    let timestamp: Int
    let title: String?
    let command: String?
    let env: AsciicastEnv?
}

private struct AsciicastEnv: Codable {
    let shell: String
    let term: String

    enum CodingKeys: String, CodingKey {
        case shell = "SHELL"
        case term = "TERM"
    }
}
