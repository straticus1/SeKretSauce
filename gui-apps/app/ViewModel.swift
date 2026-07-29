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

    // Stats
    @Published var keychainCount = 0
    @Published var launchAgentCount = 0
    @Published var appCount = 0

    // Browser
    @Published var browserResults: [BrowserResult] = []

    // Keychain
    @Published var keychainItems: [KeychainItem] = []

    // Certificates
    @Published var certificates: [Certificate] = []

    // Hidden
    @Published var suspiciousProcesses: [SuspiciousProcess] = []
    @Published var suspiciousAgents: [SuspiciousAgent] = []

    // Apps
    @Published var appIssues: [AppIssue] = []

    // Breach
    @Published var breaches: [BreachResult] = []
    @Published var breachCheckComplete = false

    @AppStorage("cliPath") private var cliPath = ""

    // MARK: - CLI Execution

    private func runCLI(args: [String]) async throws -> Data {
        let executablePath = try resolvedCLIPath()
        return try await Task.detached {
            let process = Process()
            let pipe = Pipe()

            process.executableURL = URL(fileURLWithPath: executablePath)
            process.arguments = args + ["--json"]
            process.standardOutput = pipe
            process.standardError = pipe

            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationReason == .exit, process.terminationStatus == 0 else {
                let message = String(data: data, encoding: .utf8) ?? "CLI failed"
                throw CLIError.failed(status: process.terminationStatus, message: message)
            }
            return data
        }.value
    }

    private func resolvedCLIPath() throws -> String {
        var candidates: [URL] = []
        if !cliPath.isEmpty {
            candidates.append(URL(fileURLWithPath: cliPath))
        }
        if let bundled = Bundle.main.url(forResource: "sekretsauce", withExtension: nil) {
            candidates.append(bundled)
        }
        candidates.append(URL(fileURLWithPath: "/opt/homebrew/bin/sekretsauce"))
        candidates.append(URL(fileURLWithPath: "/usr/local/bin/sekretsauce"))

        for candidate in candidates {
            let resolved = candidate.resolvingSymlinksInPath()
            var isDirectory: ObjCBool = false
            if FileManager.default.fileExists(atPath: resolved.path, isDirectory: &isDirectory),
               !isDirectory.boolValue,
               FileManager.default.isExecutableFile(atPath: resolved.path) {
                return resolved.path
            }
        }
        throw CLIError.notFound
    }

    // MARK: - Full Scan

    func runFullScan() {
        Task {
            isScanning = true
            scanStatus = "Starting full scan..."

            findings.removeAll()
            await performKeychainScan()
            await performHiddenScan()
            await performAppsScan()
            scanStatus = "Scan complete!"

            isScanning = false
        }
    }

    // MARK: - Browser Export

    func exportBrowser(_ browser: String) {
        Task {
            isScanning = true
            scanStatus = "Exporting browser data..."

            do {
                var args = ["export"]
                if browser != "all" {
                    args.append(browser)
                }

                let data = try await runCLI(args: args)

                if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    var results: [BrowserResult] = []

                    for (browserName, value) in json {
                        if let browserData = value as? [String: Any],
                           let profilesData = browserData["profiles"] as? [[String: Any]] {
                            var profiles: [BrowserProfile] = []
                            for profileData in profilesData {
                                let name = profileData["name"] as? String ?? "Unknown"
                                let bookmarks = (profileData["bookmarks"] as? [Any])?.count ?? 0
                                let history = (profileData["history"] as? [Any])?.count ?? 0
                                profiles.append(BrowserProfile(name: name, bookmarkCount: bookmarks, historyCount: history))
                            }
                            results.append(BrowserResult(browser: browserName, profiles: profiles))
                        }
                    }

                    browserResults = results
                }
            } catch {
                scanStatus = "Export failed: \(error.localizedDescription)"
            }

            isScanning = false
        }
    }

    // Helper initializer for BrowserProfile
    init() {}

    // MARK: - Keychain Scan

    func scanKeychain() {
        Task {
            await performKeychainScan()
        }
    }

    private func performKeychainScan() async {
        isScanning = true
        scanStatus = "Scanning Keychain..."
        findings.removeAll { $0.category == "Keychain" }

        do {
            let data = try await runCLI(args: ["scan", "keychain"])

            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    keychainCount = json["total_items"] as? Int ?? 0

                    if let items = json["items"] as? [[String: Any]] {
                        keychainItems = items.map { item in
                            KeychainItem(
                                itemClass: item["item_class"] as? String ?? "",
                                service: item["service"] as? String ?? item["server"] as? String ?? "",
                                account: item["account"] as? String ?? "",
                                isWeak: false
                            )
                        }
                    }

                    if let weakItems = json["weak_items"] as? [[String: Any]] {
                        for weakItem in weakItems {
                            if let item = weakItem["item"] as? [String: Any],
                               let service = item["service"] as? String ?? item["server"] as? String,
                               let reason = weakItem["reason"] as? String {
                                findings.append(Finding(
                                    title: "\(service): \(reason)",
                                    category: "Keychain",
                                    severity: weakItem["severity"] as? String ?? "medium"
                                ))
                            }
                        }
                    }
            }
        } catch {
            scanStatus = "Keychain scan failed: \(error.localizedDescription)"
        }
        isScanning = false
    }

    // MARK: - Certificate Check

    func checkCertificates(_ domain: String) {
        Task {
            isScanning = true
            scanStatus = "Checking certificates for \(domain)..."

            do {
                let data = try await runCLI(args: ["scan", "certs", "--domain", domain])

                if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    if let certs = json["certificates"] as? [[String: Any]] {
                        certificates = certs.map { cert in
                            Certificate(
                                subject: cert["subject"] as? String ?? "",
                                issuer: cert["issuer"] as? String ?? "",
                                serialNumber: cert["serial_number"] as? String ?? "",
                                notBefore: cert["not_before"] as? String ?? "",
                                notAfter: cert["not_after"] as? String ?? "",
                                isSuspicious: false
                            )
                        }
                    }

                    if let suspicious = json["suspicious"] as? [[String: Any]] {
                        for sus in suspicious {
                            if let cert = sus["certificate"] as? [String: Any],
                               let reason = sus["reason"] as? String {
                                findings.append(Finding(
                                    title: "\(cert["issuer"] ?? "Unknown"): \(reason)",
                                    category: "Certificates",
                                    severity: sus["severity"] as? String ?? "medium"
                                ))
                            }
                        }
                    }
                }
            } catch {
                scanStatus = "Certificate check failed: \(error.localizedDescription)"
            }

            isScanning = false
        }
    }

    // MARK: - Hidden Scan

    func scanHidden() {
        Task {
            await performHiddenScan()
        }
    }

    private func performHiddenScan() async {
        isScanning = true
        scanStatus = "Hunting hidden processes..."
        findings.removeAll { $0.category == "Processes" || $0.category == "Launch Agents" }

        do {
            let data = try await runCLI(args: ["scan", "hidden"])

            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    launchAgentCount = json["launch_agents_checked"] as? Int ?? 0

                    if let procs = json["suspicious_processes"] as? [[String: Any]] {
                        suspiciousProcesses = procs.map { proc in
                            SuspiciousProcess(
                                pid: proc["pid"] as? Int ?? 0,
                                name: proc["name"] as? String ?? "",
                                path: proc["path"] as? String ?? "",
                                reason: proc["suspicion_reason"] as? String ?? "",
                                severity: proc["severity"] as? String ?? "medium"
                            )
                        }

                        for proc in suspiciousProcesses {
                            findings.append(Finding(
                                title: "PID \(proc.pid): \(proc.reason)",
                                category: "Processes",
                                severity: proc.severity
                            ))
                        }
                    }

                    if let agents = json["suspicious_launch_agents"] as? [[String: Any]] {
                        suspiciousAgents = agents.map { agent in
                            SuspiciousAgent(
                                label: agent["label"] as? String ?? "",
                                program: agent["program"] as? String ?? "",
                                reason: agent["suspicion_reason"] as? String ?? "",
                                severity: agent["severity"] as? String ?? "medium"
                            )
                        }

                        for agent in suspiciousAgents {
                            findings.append(Finding(
                                title: "\(agent.label): \(agent.reason)",
                                category: "Launch Agents",
                                severity: agent.severity
                            ))
                        }
                    }
            }
        } catch {
            scanStatus = "Hidden scan failed: \(error.localizedDescription)"
        }
        isScanning = false
    }

    // MARK: - App Scan

    func scanApps() {
        Task {
            await performAppsScan()
        }
    }

    private func performAppsScan() async {
        isScanning = true
        scanStatus = "Inspecting applications..."
        let previousCategories = Set(appIssues.map(\.category))
        findings.removeAll { previousCategories.contains($0.category) }

        do {
            let data = try await runCLI(args: ["scan", "apps"])

            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    appCount = json["total_apps"] as? Int ?? 0

                    if let issues = json["issues"] as? [[String: Any]] {
                        appIssues = issues.map { issue in
                            AppIssue(
                                appName: issue["app_name"] as? String ?? "",
                                category: issue["category"] as? String ?? "",
                                description: issue["description"] as? String ?? "",
                                severity: issue["severity"] as? String ?? "medium"
                            )
                        }

                        for issue in appIssues {
                            findings.append(Finding(
                                title: "\(issue.appName): \(issue.description)",
                                category: issue.category,
                                severity: issue.severity
                            ))
                        }
                    }
            }
        } catch {
            scanStatus = "App scan failed: \(error.localizedDescription)"
        }
        isScanning = false
    }

    // MARK: - Breach Check

    func checkBreach(email: String? = nil, domain: String? = nil) {
        Task {
            isScanning = true
            breachCheckComplete = false
            scanStatus = "Checking for breaches..."

            do {
                var args = ["scan", "breach"]
                if let email = email {
                    args += ["--email", email]
                } else if let domain = domain {
                    args += ["--domain", domain]
                }

                let data = try await runCLI(args: args)

                if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    if let compromised = json["compromised"] as? [[String: Any]] {
                        breaches = compromised.map { item in
                            BreachResult(
                                account: item["account"] as? String ?? "",
                                breachNames: item["breach_names"] as? [String] ?? [],
                                dataTypes: item["data_types"] as? [String] ?? []
                            )
                        }

                        for breach in breaches {
                            findings.append(Finding(
                                title: "\(breach.account): Found in \(breach.breachNames.count) breach(es)",
                                category: "Breach",
                                severity: "critical"
                            ))
                        }
                    }
                }

                breachCheckComplete = true
            } catch {
                scanStatus = "Breach check failed: \(error.localizedDescription)"
            }

            isScanning = false
        }
    }
}

private enum CLIError: LocalizedError {
    case failed(status: Int32, message: String)
    case notFound

    var errorDescription: String? {
        switch self {
        case let .failed(status, message):
            return "CLI exited with status \(status): \(message)"
        case .notFound:
            return "SeKretSauce CLI not found. Install it or set the CLI path in preferences."
        }
    }
}

// Extension to create BrowserProfile directly
extension BrowserProfile {
    init(name: String, bookmarkCount: Int, historyCount: Int) {
        self.name = name
        self.bookmarkCount = bookmarkCount
        self.historyCount = historyCount
    }
}
