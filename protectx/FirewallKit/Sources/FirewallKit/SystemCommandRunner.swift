import Foundation

struct CommandInvocation: Equatable {
    let executable: String
    let arguments: [String]
}

struct CommandResult {
    let output: String
    let terminationStatus: Int32
}

protocol SystemCommandRunning {
    func run(_ invocation: CommandInvocation) throws -> CommandResult
}

struct SystemCommandError: Error, LocalizedError {
    let invocation: CommandInvocation
    let terminationStatus: Int32
    let output: String

    var errorDescription: String? {
        let detail = output.trimmingCharacters(in: .whitespacesAndNewlines)
        return detail.isEmpty
            ? "\(invocation.executable) exited with status \(terminationStatus)"
            : detail
    }
}

final class SystemCommandRunner: SystemCommandRunning {
    func run(_ invocation: CommandInvocation) throws -> CommandResult {
        let process = Process()
        let outputPipe = Pipe()

        process.executableURL = URL(fileURLWithPath: invocation.executable)
        process.arguments = invocation.arguments
        process.standardOutput = outputPipe
        process.standardError = outputPipe

        try process.run()
        let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        return CommandResult(
            output: String(data: data, encoding: .utf8) ?? "",
            terminationStatus: process.terminationStatus
        )
    }
}

extension SystemCommandRunning {
    @discardableResult
    func runChecked(_ invocation: CommandInvocation) throws -> String {
        let result = try run(invocation)
        guard result.terminationStatus == 0 else {
            throw SystemCommandError(
                invocation: invocation,
                terminationStatus: result.terminationStatus,
                output: result.output
            )
        }
        return result.output
    }
}
