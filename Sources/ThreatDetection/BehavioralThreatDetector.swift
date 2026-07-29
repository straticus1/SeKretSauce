import Foundation

public enum ThreatAction: String, Codable, Sendable {
    case allow
    case observe
    case suspend
}

public struct ThreatVerdict: Codable, Sendable, Equatable {
    public let score: Int
    public let action: ThreatAction
    public let reasons: [String]

    public init(score: Int, action: ThreatAction, reasons: [String]) {
        self.score = min(max(score, 0), 100)
        self.action = action
        self.reasons = reasons
    }

    public static let clean = ThreatVerdict(score: 0, action: .allow, reasons: [])
}

public struct ProcessObservation: Sendable {
    public let pid: Int32
    public let path: String
    public let arguments: [String]
    public let isPlatformBinary: Bool
    public let isCodeSigned: Bool

    public init(
        pid: Int32,
        path: String,
        arguments: [String],
        isPlatformBinary: Bool,
        isCodeSigned: Bool
    ) {
        self.pid = pid
        self.path = path
        self.arguments = arguments
        self.isPlatformBinary = isPlatformBinary
        self.isCodeSigned = isCodeSigned
    }
}

public enum FileMutationKind: String, Sendable {
    case write
    case rename
    case create
    case delete
}

public struct FileMutationObservation: Sendable {
    public let pid: Int32
    public let processPath: String
    public let targetPath: String
    public let kind: FileMutationKind
    public let timestamp: Date

    public init(
        pid: Int32,
        processPath: String,
        targetPath: String,
        kind: FileMutationKind,
        timestamp: Date = Date()
    ) {
        self.pid = pid
        self.processPath = processPath
        self.targetPath = targetPath
        self.kind = kind
        self.timestamp = timestamp
    }
}

/// Stateful, local-only behavior scoring. It makes no cloud reputation calls and
/// only recommends containment when multiple high-confidence signals correlate.
public final class BehavioralThreatDetector: @unchecked Sendable {
    private struct ProcessState {
        var score = 0
        var reasons = Set<String>()
        var mutations: [(path: String, date: Date)] = []
    }

    private let lock = NSLock()
    private var states: [Int32: ProcessState] = [:]
    private let ransomwareWindow: TimeInterval
    private let ransomwareFileThreshold: Int

    private let documentExtensions: Set<String> = [
        "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "rtf",
        "jpg", "jpeg", "png", "heic", "mov", "mp4", "zip", "sqlite"
    ]
    private let ransomwareExtensions: Set<String> = [
        "encrypted", "locked", "crypted", "crypto", "enc", "lockbit"
    ]

    public init(ransomwareWindow: TimeInterval = 10, ransomwareFileThreshold: Int = 12) {
        self.ransomwareWindow = max(1, ransomwareWindow)
        self.ransomwareFileThreshold = max(3, ransomwareFileThreshold)
    }

    public func observeProcess(_ observation: ProcessObservation) -> ThreatVerdict {
        return withState(for: observation.pid) { state in
            let normalizedPath = observation.path.lowercased()
            let commandLine = observation.arguments.joined(separator: " ").lowercased()

            if !observation.isPlatformBinary && !observation.isCodeSigned {
                add(20, "unsigned executable", to: &state)
            }
            if isUserWritableExecutionPath(normalizedPath) {
                add(25, "execution from a user-writable or temporary directory", to: &state)
            }
            if containsObfuscatedInterpreterCommand(commandLine) {
                add(30, "encoded or obfuscated interpreter command", to: &state)
            }
            if commandLine.contains("curl ") && (commandLine.contains("| sh") || commandLine.contains("| bash")) {
                add(35, "download piped directly to a shell", to: &state)
            }
            if normalizedPath.contains("/launchagents/") || normalizedPath.contains("/launchdaemons/") {
                add(25, "execution from a persistence directory", to: &state)
            }

            return verdict(for: state)
        }
    }

    public func observeFileMutation(_ observation: FileMutationObservation) -> ThreatVerdict {
        guard !isTrustedSystemProcess(observation.processPath) else { return .clean }

        return withState(for: observation.pid) { state in
            let path = observation.targetPath.lowercased()
            let now = observation.timestamp

            if isPersistencePath(path) {
                add(40, "modified a persistence location", to: &state)
            }
            if isCredentialPath(path) {
                add(35, "modified credential or key material", to: &state)
            }
            if isSecurityControlPath(path) {
                add(50, "modified a security control", to: &state)
            }
            if isCanaryPath(path) {
                add(100, "modified a ransomware canary", to: &state)
            }
            if ransomwareExtensions.contains(URL(fileURLWithPath: path).pathExtension) {
                add(45, "created a common ransomware extension", to: &state)
            }

            if documentExtensions.contains(URL(fileURLWithPath: path).pathExtension) {
                state.mutations.append((path, now))
                let cutoff = now.addingTimeInterval(-ransomwareWindow)
                state.mutations.removeAll { $0.date < cutoff }
                let uniqueFiles = Set(state.mutations.map(\.path)).count
                if uniqueFiles >= ransomwareFileThreshold {
                    // A bulk edit by a signed productivity tool is not enough
                    // to stop a process. This becomes containment-worthy only
                    // when correlated with execution or extension indicators.
                    add(60, "rapidly modified \(uniqueFiles) user documents", to: &state)
                }
            }

            return verdict(for: state)
        }
    }

    public func processExited(pid: Int32) {
        lock.lock()
        states.removeValue(forKey: pid)
        lock.unlock()
    }

    private func withState(
        for pid: Int32,
        update: (inout ProcessState) -> ThreatVerdict
    ) -> ThreatVerdict {
        lock.lock()
        defer { lock.unlock() }
        var state = states[pid, default: ProcessState()]
        let result = update(&state)
        states[pid] = state
        return result
    }

    private func add(_ score: Int, _ reason: String, to state: inout ProcessState) {
        guard state.reasons.insert(reason).inserted else { return }
        state.score = min(100, state.score + score)
    }

    private func verdict(for state: ProcessState) -> ThreatVerdict {
        let action: ThreatAction
        if state.score >= 80 {
            action = .suspend
        } else if state.score >= 30 {
            action = .observe
        } else {
            action = .allow
        }
        return ThreatVerdict(score: state.score, action: action, reasons: state.reasons.sorted())
    }

    private func isUserWritableExecutionPath(_ path: String) -> Bool {
        path.hasPrefix("/tmp/")
            || path.hasPrefix("/private/tmp/")
            || path.contains("/downloads/")
            || path.contains("/library/caches/")
            || path.contains("/var/folders/")
    }

    private func containsObfuscatedInterpreterCommand(_ command: String) -> Bool {
        let usesInterpreter = ["osascript", "python", "perl", "ruby", "bash", "zsh", "sh "]
            .contains { command.contains($0) }
        let encodedPayload = command.contains("base64")
            || command.contains("frombase64string")
            || command.contains("eval(")
        return usesInterpreter && encodedPayload
    }

    private func isTrustedSystemProcess(_ path: String) -> Bool {
        path.hasPrefix("/System/Library/") || path.hasPrefix("/usr/libexec/")
    }

    private func isPersistencePath(_ path: String) -> Bool {
        path.contains("/library/launchagents/")
            || path.contains("/library/launchdaemons/")
            || path.hasSuffix("/.zshrc")
            || path.hasSuffix("/.bash_profile")
            || path.hasSuffix("/.config/autostart")
    }

    private func isCredentialPath(_ path: String) -> Bool {
        path.contains("/.ssh/")
            || path.contains("/keychains/")
            || path.hasSuffix("/.aws/credentials")
            || path.hasSuffix("/.config/gcloud/credentials.db")
    }

    private func isSecurityControlPath(_ path: String) -> Bool {
        path == "/etc/pf.conf"
            || path.contains("/library/application support/sekretsauce/")
            || path.contains("/library/launchdaemons/com.sekretsauce.")
    }

    private func isCanaryPath(_ path: String) -> Bool {
        path.contains("/.sekretsauce-canary/")
            || URL(fileURLWithPath: path).lastPathComponent.hasPrefix(".sekretsauce-canary-")
    }
}
