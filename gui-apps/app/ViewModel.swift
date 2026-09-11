import Foundation
import SwiftUI

// MARK: - Data Models

struct Finding: Hashable {
    let title: String
    let category: String
    let severity: String

    var severityColor: Color {
        switch severity.lowercased() {
        case "critical": return .red
        case "high": return .orange
        case "medium": return .yellow
        case "low": return .blue
        default: return .gray
        }
    }
}

struct BrowserResult: Codable {
    let browser: String
    let profiles: [BrowserProfile]
}

struct BrowserProfile: Codable {
    let name: String
    let bookmarkCount: Int
    let historyCount: Int

    enum CodingKeys: String, CodingKey {
        case name
        case bookmarkCount = "bookmarks"
        case historyCount = "history"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decode(String.self, forKey: .name)

        // Handle both array and count formats
        if let bookmarks = try? container.decode([AnyDecodable].self, forKey: .bookmarkCount) {
            bookmarkCount = bookmarks.count
        } else {
            bookmarkCount = try container.decodeIfPresent(Int.self, forKey: .bookmarkCount) ?? 0
        }

        if let history = try? container.decode([AnyDecodable].self, forKey: .historyCount) {
            historyCount = history.count
        } else {
            historyCount = try container.decodeIfPresent(Int.self, forKey: .historyCount) ?? 0
        }
    }
}

struct AnyDecodable: Decodable {
    init(from decoder: Decoder) throws {
        // Just consume the value, we only need the count
    }
}

struct KeychainItem: Identifiable {
    let id = UUID()
    let itemClass: String
    let service: String
    let account: String
    let isWeak: Bool
}

struct Certificate: Identifiable {
    let id = UUID()
    let subject: String
    let issuer: String
    let serialNumber: String
    let notBefore: String
    let notAfter: String
    let isSuspicious: Bool
}

struct SuspiciousProcess: Identifiable {
    let id = UUID()
    let pid: Int
    let name: String
    let path: String
    let reason: String
    let severity: String
}

struct SuspiciousAgent: Identifiable {
    let id = UUID()
    let label: String
    let program: String
    let reason: String
    let severity: String
}

struct AppIssue: Identifiable {
    let id = UUID()
    let appName: String
    let category: String
    let description: String
    let severity: String
}

struct BreachResult: Identifiable {
    let id = UUID()
    let account: String
    let breachNames: [String]
    let dataTypes: [String]
}

// MARK: - View Model

@MainActor
class SeKretSauceViewModel: ObservableObject {
    @Published var isScanning = false
    @Published var scanStatus = ""
    @Published var findings: [Finding] = []
    @Published var keychainCount = 0
    @Published var launchAgentCount = 0
    @Published var appCount = 0
    @Published var browserResults: [BrowserResult] = []
    @Published var keychainItems: [KeychainItem] = []
    @Published var certificates: [Certificate] = []
    @Published var suspiciousProcesses: [SuspiciousProcess] = []
    @Published var suspiciousAgents: [SuspiciousAgent] = []
    @Published var appIssues: [AppIssue] = []
    @Published var breaches: [BreachResult] = []
    @Published var breachCheckComplete = false
    @Published var components: [ScanReport.Component] = []
    @Published var scanHistory: [ScanReport] = []
    @Published var changes: ScanChanges?
    private let history: ScanHistory
    @AppStorage("cliPath") private var cliPath = ""
    private var scanTask: Task<Void, Never>?
    private var runID: UUID?
    private let executor: (@Sendable ([String]) async throws -> Data)?

    init(
        executor: (@Sendable ([String]) async throws -> Data)? = nil,
        history: ScanHistory = ScanHistory()
    ) {
        self.executor = executor
        self.history = history
        if executor == nil { scanHistory = (try? history.load()) ?? [] }
    }

    private func runCLI(args: [String]) async throws -> Data {
        if let executor { return try await executor(args) }
        let executablePath = try resolvedCLIPath()
        return try await CLIProcess.run(path: executablePath, arguments: args + ["--json"])
    }

    private func resolvedCLIPath() throws -> String {
        var paths = [cliPath]
        if let bundled = Bundle.main.url(forResource: "sekretsauce", withExtension: nil) {
            paths.append(bundled.path)
        }
        paths += ["/opt/homebrew/bin/sekretsauce", "/usr/local/bin/sekretsauce"]
        for path in paths where !path.isEmpty {
            let url = URL(fileURLWithPath: path).resolvingSymlinksInPath()
            if FileManager.default.isExecutableFile(atPath: url.path) { return url.path }
        }
        throw CLIError.notFound
    }

    private func start(_ label: String, operation: @escaping @MainActor () async throws -> Void) {
        guard !isScanning else { return }
        let id = UUID()
        runID = id
        isScanning = true
        scanStatus = label
        scanTask = Task { [self] in
            defer {
                if runID == id {
                    isScanning = false
                    scanTask = nil
                    runID = nil
                }
            }
            do {
                try await operation()
            } catch is CancellationError {
                scanStatus = "Scan cancelled. Results were not replaced."
            } catch {
                scanStatus = "Scan failed: \(error.localizedDescription)"
            }
        }
    }

    func cancelScan() { scanTask?.cancel() }

    func runFullScan() { runScan(profile: "full") }
    func runQuickScan() { runScan(profile: "quick") }

    private func runScan(profile: String) {
        start("Running \(profile) scan...") { [self] in
            let data = try await runCLI(args: ["scan", "--profile", profile])
            let report = try ScanReport.decode(data)
            let raw = try object(data)
            try Task.checkCancellation()
            // Validate and stage all data before publishing this snapshot.
            applyKeychain(raw["keychain"] as? [String: Any] ?? [:])
            applyHidden(raw["hidden_processes"] as? [String: Any] ?? [:])
            applyApps(raw["applications"] as? [String: Any] ?? [:])
            components = report.components
            findings = report.findings.map {
                Finding(title: $0.title, category: $0.category, severity: $0.severity)
            }
            changes = ScanChanges.compare(history: scanHistory, current: report)
            let failures = report.components.filter { $0.status == "failed" || $0.status == "partial" }
                .map(\.scannerID)
            scanStatus =
                failures.isEmpty
                ? "Scan completed (\(profile))."
                : "Scan \(report.status): \(failures.joined(separator: ", ")) unavailable."
            do {
                try history.save(report)
                scanHistory = try history.load()
            } catch { scanStatus += " History could not be saved: \(error.localizedDescription)" }
        }
    }

    func scanKeychain() {
        start("Scanning Keychain...") { [self] in
            let json = try await scanObject(["scan", "keychain"], required: "total_items")
            applyKeychain(json)
            findings.removeAll { $0.category == "Keychain" }
            for weak in rows(json, "weak_items") {
                let item = weak["item"] as? [String: Any] ?? [:]
                findings.append(
                    Finding(
                        title: "\(string(item, "service")): \(string(weak, "reason"))", category: "Keychain",
                        severity: string(weak, "severity", fallback: "medium")))
            }
            scanStatus = "Keychain scan completed."
        }
    }

    private func applyKeychain(_ json: [String: Any]) {
        keychainCount = json["total_items"] as? Int ?? 0
        keychainItems = rows(json, "items").map { x in
            KeychainItem(
                itemClass: string(x, "item_class"),
                service: string(x, "service", fallback: string(x, "server")), account: string(x, "account"),
                isWeak: false)
        }
    }

    func scanHidden() {
        start("Scanning processes and launch agents...") { [self] in
            let json = try await scanObject(["scan", "hidden"], required: "processes_scanned")
            applyHidden(json)
            findings.removeAll { ["Processes", "Launch Agents"].contains($0.category) }
            findings += suspiciousProcesses.map {
                Finding(title: "PID \($0.pid): \($0.reason)", category: "Processes", severity: $0.severity)
            }
            findings += suspiciousAgents.map {
                Finding(
                    title: "\($0.label): \($0.reason)", category: "Launch Agents", severity: $0.severity)
            }
            scanStatus = "Process scan completed."
        }
    }

    private func applyHidden(_ json: [String: Any]) {
        launchAgentCount = json["launch_agents_checked"] as? Int ?? 0
        suspiciousProcesses = rows(json, "suspicious_processes").map { x in
            SuspiciousProcess(
                pid: x["pid"] as? Int ?? 0, name: string(x, "name"), path: string(x, "path"),
                reason: string(x, "suspicion_reason"), severity: string(x, "severity", fallback: "medium"))
        }
        suspiciousAgents = rows(json, "suspicious_launch_agents").map { x in
            SuspiciousAgent(
                label: string(x, "label"), program: string(x, "program"),
                reason: string(x, "suspicion_reason"), severity: string(x, "severity", fallback: "medium"))
        }
    }

    func scanApps() {
        start("Inspecting applications...") { [self] in
            let json = try await scanObject(["scan", "apps"], required: "total_apps")
            let categories = Set(appIssues.map(\.category))
            applyApps(json)
            findings.removeAll { categories.contains($0.category) }
            findings += appIssues.map {
                Finding(
                    title: "\($0.appName): \($0.description)", category: $0.category, severity: $0.severity)
            }
            scanStatus = "Application scan completed."
        }
    }

    private func applyApps(_ json: [String: Any]) {
        appCount = json["total_apps"] as? Int ?? 0
        appIssues = rows(json, "issues").map { x in
            AppIssue(
                appName: string(x, "app_name"), category: string(x, "category"),
                description: string(x, "description"), severity: string(x, "severity", fallback: "medium"))
        }
    }

    func checkBreach(email: String? = nil, domain: String? = nil) {
        guard !isScanning else { return }
        breachCheckComplete = false
        start("Checking breaches...") { [self] in
            var args = ["scan", "breach"]
            if let email {
                args += ["--email", email]
            } else if let domain {
                args += ["--domain", domain]
            }
            let json = try await scanObject(args, required: "total_checked")
            breaches = rows(json, "compromised").map { x in
                BreachResult(
                    account: string(x, "account"), breachNames: x["breach_names"] as? [String] ?? [],
                    dataTypes: x["data_types"] as? [String] ?? [])
            }
            findings.removeAll { $0.category == "Breach" }
            findings += breaches.map {
                Finding(
                    title: "\($0.account): Found in \($0.breachNames.count) breach(es)", category: "Breach",
                    severity: "critical")
            }
            breachCheckComplete = true
            scanStatus = "Breach check completed."
        }
    }

    func checkCertificates(_ domain: String) {
        start("Checking certificates...") { [self] in
            let json = try await scanObject(["scan", "certs", "--domain", domain], required: "domain")
            certificates = rows(json, "certificates").map { x in
                Certificate(
                    subject: string(x, "subject"), issuer: string(x, "issuer"),
                    serialNumber: string(x, "serial_number"), notBefore: string(x, "not_before"),
                    notAfter: string(x, "not_after"), isSuspicious: false)
            }
            findings.removeAll { $0.category == "Certificates" }
            findings += rows(json, "suspicious").map {
                Finding(
                    title: string($0, "reason"), category: "Certificates",
                    severity: string($0, "severity", fallback: "medium"))
            }
            scanStatus = "Certificate check completed."
        }
    }

    func exportBrowser(_ browser: String) {
        start("Exporting browser data...") { [self] in
            let data = try await runCLI(args: browser == "all" ? ["export"] : ["export", browser])
            let json = try object(data)
            try Task.checkCancellation()
            browserResults = try json.keys.sorted().map { name in
                guard let value = json[name] as? [String: Any],
                    let profiles = value["profiles"] as? [[String: Any]]
                else { throw CLIError.invalidResponse }
                return BrowserResult(
                    browser: name,
                    profiles: profiles.map {
                        BrowserProfile(
                            name: string($0, "name"), bookmarkCount: ($0["bookmarks"] as? [Any])?.count ?? 0,
                            historyCount: ($0["history"] as? [Any])?.count ?? 0)
                    })
            }
            scanStatus = "Browser export completed."
        }
    }

    private func scanObject(_ args: [String], required: String) async throws -> [String: Any] {
        let data = try await runCLI(args: args)
        let json = try object(data)
        if required == "domain" {
            guard json[required] is String else { throw CLIError.invalidResponse }
        } else {
            guard json[required] is Int else { throw CLIError.invalidResponse }
        }
        for key in [
            "items", "weak_items", "issues", "compromised", "certificates", "suspicious",
            "suspicious_processes", "suspicious_launch_agents",
        ] {
            if let value = json[key], !(value is NSNull), !(value is [[String: Any]]) {
                throw CLIError.invalidResponse
            }
        }
        try Task.checkCancellation()
        return json
    }
    private func object(_ data: Data) throws -> [String: Any] {
        guard let result = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw CLIError.invalidResponse
        }
        return result
    }
    private func rows(_ json: [String: Any], _ key: String) -> [[String: Any]] {
        json[key] as? [[String: Any]] ?? []
    }
    private func string(_ json: [String: Any], _ key: String, fallback: String = "") -> String {
        json[key] as? String ?? fallback
    }
}

enum CLIError: LocalizedError {
    case failed(Int32)
    case notFound
    case invalidResponse
    case timeout
    var errorDescription: String? {
        switch self {
        case .failed(let code): return "CLI exited with status \(code)."
        case .notFound: return "SeKretSauce CLI not found. Install it or set its path in preferences."
        case .invalidResponse:
            return "CLI returned an invalid or unsupported report. Update the CLI and try again."
        case .timeout: return "CLI exceeded the operation deadline."
        }
    }
}

extension BrowserProfile {
    init(name: String, bookmarkCount: Int, historyCount: Int) {
        self.name = name
        self.bookmarkCount = bookmarkCount
        self.historyCount = historyCount
    }
}
