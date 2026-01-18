import Foundation

/// Writes SSH session recordings in Asciicast v2 format
/// Compatible with asciinema player for playback
public final class AsciicastWriter {

    private let fileHandle: FileHandle
    private let startTime: Date
    private let encoder = JSONEncoder()
    private let queue = DispatchQueue(label: "com.sekretsauce.asciicast")

    public let filePath: URL

    /// Initialize with a file path for the recording
    public init(filePath: URL, width: Int = 120, height: Int = 40, title: String? = nil, command: String? = nil) throws {
        self.filePath = filePath
        self.startTime = Date()

        // Create the file
        FileManager.default.createFile(atPath: filePath.path, contents: nil)
        self.fileHandle = try FileHandle(forWritingTo: filePath)

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
        queue.async { [weak self] in
            self?.writeEvent(type: "i", data: data)
        }
    }

    private func writeEvent(type: String, data: Data) {
        let elapsed = Date().timeIntervalSince(startTime)

        // Convert data to string, escaping control characters
        let text = escapeForJSON(data)

        // Asciicast v2 event format: [time, type, data]
        let event = "[\(String(format: "%.6f", elapsed)), \"\(type)\", \(text)]"

        if let eventData = event.data(using: .utf8) {
            fileHandle.write(eventData)
            fileHandle.write(Data([0x0A])) // newline
        }
    }

    /// Escape binary data for JSON string
    private func escapeForJSON(_ data: Data) -> String {
        var result = "\""
        for byte in data {
            switch byte {
            case 0x08: result += "\\b"
            case 0x09: result += "\\t"
            case 0x0A: result += "\\n"
            case 0x0C: result += "\\f"
            case 0x0D: result += "\\r"
            case 0x22: result += "\\\""
            case 0x5C: result += "\\\\"
            case 0x00...0x1F, 0x7F:
                result += String(format: "\\u%04x", byte)
            default:
                if let char = String(bytes: [byte], encoding: .utf8) {
                    result += char
                } else {
                    result += String(format: "\\u%04x", byte)
                }
            }
        }
        result += "\""
        return result
    }

    /// Close the recording file
    public func close() {
        queue.sync {
            fileHandle.synchronizeFile()
            fileHandle.closeFile()
        }
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
