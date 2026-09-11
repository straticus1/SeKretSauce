import Darwin
import XCTest

@testable import Common
@testable import EndpointSecurityMonitor

final class AgentControlTests: XCTestCase {
    func testSigningRequirementRejectsUntrustedInputAndScopesPeers() throws {
        let result = try AgentControl.signingRequirement(
            team: "ABC1234567", identifiers: [AgentControl.guiIdentifier])
        XCTAssertTrue(result.contains("anchor apple generic"))
        XCTAssertTrue(result.contains("identifier \"com.afterdarktech.sekretsauce\""))
        XCTAssertThrowsError(
            try AgentControl.signingRequirement(team: "", identifiers: [AgentControl.guiIdentifier]))
        XCTAssertThrowsError(
            try AgentControl.signingRequirement(team: "ABC1234567", identifiers: ["app\" or true"]))
    }
    func testOnlyDaemonPIDBypassesCanaryMutationEvaluation() {
        XCTAssertFalse(ProcessMonitor.shouldEvaluateMutation(pid: 100, daemonPID: 100))
        XCTAssertTrue(ProcessMonitor.shouldEvaluateMutation(pid: 101, daemonPID: 100))
    }
    func testCanaryMaintenanceAndSymlinkRejection() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let documents = home.appendingPathComponent("Documents")
        try FileManager.default.createDirectory(at: documents, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        try CanaryManager.install(home: home.path, uid: getuid())
        try CanaryManager.install(home: home.path, uid: getuid())
        XCTAssertTrue(CanaryManager.installed(home: home.path, uid: getuid()))
        let file = documents.appendingPathComponent(".sekretsauce-canary/important-documents.txt")
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o400)
        XCTAssertTrue(try String(contentsOf: file).contains("canary"))
        try FileManager.default.removeItem(at: documents.appendingPathComponent(".sekretsauce-canary"))
        try FileManager.default.createSymbolicLink(
            atPath: documents.appendingPathComponent(".sekretsauce-canary").path,
            withDestinationPath: home.path)
        XCTAssertFalse(CanaryManager.installed(home: home.path, uid: getuid()))
        XCTAssertThrowsError(try CanaryManager.install(home: home.path, uid: getuid()))
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: home.appendingPathComponent("important-documents.txt").path))
    }
}
