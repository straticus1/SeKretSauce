import XCTest

@testable import SeKretSauceGUI

private actor Responses {
    var values: [Data]
    init(_ strings: [String]) { values = strings.map { Data($0.utf8) } }
    func next() throws -> Data {
        guard !values.isEmpty else { throw CLIError.invalidResponse }
        return values.removeFirst()
    }
}
final class ScanTests: XCTestCase {
    @MainActor private func finish(_ model: SeKretSauceViewModel) async throws {
        for _ in 0..<1000 where model.isScanning { try await Task.sleep(nanoseconds: 1_000_000) }
        XCTAssertFalse(model.isScanning)
    }
    @MainActor func testCleanAccountClearsEarlierBreachAndFindings() async throws {
        let responses = Responses([
            #"{"total_checked":1,"compromised":[{"account":"a@example.test","breach_names":["Example"],"data_types":[]}]}"#,
            #"{"total_checked":1,"clean":1}"#,
        ])
        let model = SeKretSauceViewModel(executor: { _ in try await responses.next() })
        model.checkBreach(email: "a@example.test")
        try await finish(model)
        XCTAssertEqual(model.breaches.count, 1)
        model.checkBreach(email: "b@example.test")
        try await finish(model)
        XCTAssertTrue(model.breaches.isEmpty)
        XCTAssertTrue(model.findings.isEmpty)
        XCTAssertTrue(model.breachCheckComplete)
    }
    @MainActor func testCleanApplicationScanClearsEarlierIssues() async throws {
        let responses = Responses([
            #"{"total_apps":1,"issues":[{"app_name":"Example","category":"Code Signing","description":"Unsigned","severity":"high"}]}"#,
            #"{"total_apps":1}"#,
        ])
        let model = SeKretSauceViewModel(executor: { _ in try await responses.next() })
        model.scanApps()
        try await finish(model)
        XCTAssertEqual(model.appIssues.count, 1)
        model.scanApps()
        try await finish(model)
        XCTAssertTrue(model.appIssues.isEmpty)
        XCTAssertTrue(model.findings.isEmpty)
    }
    @MainActor func testInvalidReportAndFailedCLIStayFailed() async throws {
        for output in ["not json", "{}", #"{"schema_version":99}"#] {
            let model = SeKretSauceViewModel(executor: { _ in Data(output.utf8) })
            model.runFullScan()
            try await finish(model)
            XCTAssertTrue(model.scanStatus.hasPrefix("Scan failed:"))
        }
        let model = SeKretSauceViewModel(executor: { _ in throw CLIError.notFound })
        model.runFullScan()
        try await finish(model)
        XCTAssertTrue(model.scanStatus.hasPrefix("Scan failed:"))
    }
    @MainActor func testCancellationDoesNotPublishLateResults() async throws {
        let model = SeKretSauceViewModel(executor: { _ in
            try? await Task.sleep(nanoseconds: 50_000_000)
            return Data(#"{"total_apps":12}"#.utf8)
        })
        model.scanApps()
        XCTAssertTrue(model.isScanning)
        model.cancelScan()
        try await finish(model)
        XCTAssertEqual(model.appCount, 0)
        XCTAssertTrue(model.scanStatus.contains("cancelled"))
    }
    func testCLISeparatesDiagnosticsAndBoundsExecution() async throws {
        let data = try await CLIProcess.run(
            path: "/bin/sh", arguments: ["-c", "printf '{}'; printf 'diagnostic' >&2"])
        XCTAssertEqual(String(decoding: data, as: UTF8.self), "{}")
        do {
            _ = try await CLIProcess.run(path: "/bin/sleep", arguments: ["3"], timeout: 0.05)
            XCTFail("Expected timeout")
        } catch CLIError.timeout {}
    }
}
