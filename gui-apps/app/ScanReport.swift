import Foundation

struct ScanReport: Codable {
    struct ReportFinding: Codable, Identifiable {
        let id: String
        let scannerID: String
        let targetID: String
        let category: String
        let severity: String
        let title: String
        let remediation: String
        enum CodingKeys: String, CodingKey {
            case id, category, severity, title, remediation
            case scannerID = "scanner_id"
            case targetID = "target_id"
        }
    }
    struct Component: Codable, Identifiable {
        var id: String { scannerID }
        let scannerID: String
        let version: Int
        let status: String
        let errors: [String]
        let skippedReason: String
        let findings: [ReportFinding]
        enum CodingKeys: String, CodingKey {
            case version, status, errors, findings
            case scannerID = "scanner_id"
            case skippedReason = "skipped_reason"
        }
    }
    let target: String
    let schemaVersion: Int
    let runID: String
    let profile: String
    let startedAt: String
    let finishedAt: String
    let status: String
    let components: [Component]
    let findings: [ReportFinding]
    enum CodingKeys: String, CodingKey {
        case target, profile, status, components, findings
        case schemaVersion = "schema_version"
        case runID = "run_id"
        case startedAt = "started_at"
        case finishedAt = "finished_at"
    }
    static func decode(_ data: Data) throws -> ScanReport {
        let result = try JSONDecoder().decode(ScanReport.self, from: data)
        guard result.schemaVersion == 1, !result.runID.isEmpty, !result.target.isEmpty,
            !result.components.isEmpty,
            Set(result.findings.map(\.id)).count == result.findings.count,
            ["completed", "partial", "failed", "cancelled"].contains(result.status),
            Set(result.components.map(\.scannerID)).count == result.components.count,
            result.components.allSatisfy({
                ["completed", "partial", "failed", "skipped", "cancelled"].contains($0.status)
            })
        else {
            throw CLIError.invalidResponse
        }
        return result
    }
}
