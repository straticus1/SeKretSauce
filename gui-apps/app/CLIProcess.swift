import Darwin
import Foundation

/// A bounded subprocess reader. stdout is JSON; diagnostics never contaminate it.
enum CLIProcess {
    private final class Cancellation: @unchecked Sendable {
        private let lock = NSLock()
        private var value = false
        func cancel() {
            lock.lock()
            value = true
            lock.unlock()
        }
        var cancelled: Bool {
            lock.lock()
            defer { lock.unlock() }
            return value
        }
    }

    static func run(path: String, arguments: [String], timeout: TimeInterval = 300) async throws
        -> Data
    {
        let cancellation = Cancellation()
        return try await withTaskCancellationHandler {
            try await Task.detached {
                let process = Process()
                let pipe = Pipe()
                process.executableURL = URL(fileURLWithPath: path)
                process.arguments = arguments
                process.standardOutput = pipe
                process.standardError = FileHandle.nullDevice
                if cancellation.cancelled { throw CancellationError() }
                try process.run()
                let fd = pipe.fileHandleForReading.fileDescriptor
                _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
                defer {
                    if process.isRunning { process.terminate() }
                    try? pipe.fileHandleForReading.close()
                    try? pipe.fileHandleForWriting.close()
                }
                let deadline = ProcessInfo.processInfo.systemUptime + timeout
                var data = Data()
                var buffer = [UInt8](repeating: 0, count: 16_384)
                while true {
                    if cancellation.cancelled { throw CancellationError() }
                    if ProcessInfo.processInfo.systemUptime >= deadline { throw CLIError.timeout }
                    let count = Darwin.read(fd, &buffer, buffer.count)
                    if count > 0 {
                        guard data.count + count <= 32 * 1024 * 1024 else { throw CLIError.invalidResponse }
                        data.append(contentsOf: buffer.prefix(count))
                        continue
                    }
                    if count < 0 && errno != EAGAIN && errno != EINTR { throw CLIError.invalidResponse }
                    if !process.isRunning { break }
                    var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                    _ = poll(&descriptor, 1, 100)
                }
                process.waitUntilExit()
                guard process.terminationReason == .exit else {
                    throw CLIError.failed(process.terminationStatus)
                }
                if process.terminationStatus == 2 {
                    let report = try ScanReport.decode(data)
                    guard report.status == "partial" || report.status == "failed" else {
                        throw CLIError.invalidResponse
                    }
                } else if process.terminationStatus != 0 {
                    throw CLIError.failed(process.terminationStatus)
                }
                return data
            }.value
        } onCancel: {
            cancellation.cancel()
        }
    }
}
