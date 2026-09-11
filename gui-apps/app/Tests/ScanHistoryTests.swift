import XCTest

@testable import SeKretSauceGUI

final class ScanHistoryTests: XCTestCase {
    func testSharedGoProducerFixture() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let report = try ScanReport.decode(
            Data(contentsOf: root.appendingPathComponent("Tests/Fixtures/scan-report-v1.json")))
        XCTAssertEqual(report.status, "partial")
        XCTAssertEqual(report.components.first?.errors, ["permission denied"])
        XCTAssertTrue(report.findings.isEmpty)
    }
    private func report(
        _ id: String, status: String = "completed", finding: Bool = false, version: Int = 1
    ) throws -> ScanReport {
        let item: [String: Any] = [
            "id": "f1", "scanner_id": "apps", "target_id": "/example", "category": "Signing",
            "severity": "high", "title": "Unsigned", "remediation": "Review",
        ]
        let findings = finding ? [item] : []
        let object: [String: Any] = [
            "schema_version": 1, "target": "test:501", "run_id": id, "profile": "full", "started_at": id,
            "finished_at": id, "status": status,
            "components": [
                [
                    "scanner_id": "apps", "version": version, "status": status, "errors": [],
                    "skipped_reason": "", "findings": findings,
                ]
            ], "findings": findings,
        ]
        return try ScanReport.decode(JSONSerialization.data(withJSONObject: object))
    }
    func testUnavailableRunPreservesSuccessfulBaseline() throws {
        let old = try report("1", finding: true)
        let unavailable = try report("2", status: "failed")
        XCTAssertEqual(ScanChanges.compare(previous: old, current: unavailable).unobserved.count, 1)
        let next = try report("3")
        XCTAssertEqual(
            ScanChanges.compare(history: [unavailable, old], current: next)?.resolved.count, 1)
        XCTAssertEqual(
            ScanChanges.compare(previous: old, current: try report("4", version: 2)).unobserved.count, 1)
    }
    func testPrivateHistoryRetentionAndSymlinkRejection() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let history = ScanHistory(directory: directory, retention: 2)
        for id in ["1", "2", "3"] { try history.save(report(id)) }
        XCTAssertEqual(try history.load().map(\.runID), ["3", "2"])
        let attributes = try FileManager.default.attributesOfItem(
            atPath: directory.appendingPathComponent("3.json").path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        try FileManager.default.createSymbolicLink(
            at: directory.appendingPathComponent("evil.json"),
            withDestinationURL: directory.appendingPathComponent("3.json"))
        XCTAssertThrowsError(try history.load())
    }
}
