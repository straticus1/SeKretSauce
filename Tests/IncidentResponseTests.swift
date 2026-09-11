import Darwin
import ThreatDetection
import XCTest

@testable import EndpointSecurityMonitor

final class IncidentResponseTests: XCTestCase {
    final class Controller: TaskControlling {
        var suspends = 0
        var resumes = 0
        var denied = false
        func suspend(_ identity: ExecutionIdentity) throws -> mach_port_t {
            if denied { throw NSError(domain: "denied", code: 1) }
            suspends += 1
            return 42
        }
        func resume(_ token: mach_port_t) throws {
            XCTAssertEqual(token, 42)
            resumes += 1
        }
    }
    func testOwnershipIdempotencyAndRestart() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let controller = Controller()
        let store = IncidentResponse(directory: directory, controller: controller)
        var token = audit_token_t()
        token.val.3 = 501
        token.val.5 = 123
        token.val.7 = 1
        let identity = ExecutionIdentity(auditToken: token)
        let verdict = ThreatVerdict(score: 100, action: .suspend, reasons: ["canary"])
        let first = try store.observe(verdict, identity: identity, path: "/test")
        XCTAssertEqual(first.responseState, "applied")
        XCTAssertEqual(try store.observe(verdict, identity: identity, path: "/test").id, first.id)
        XCTAssertEqual(controller.suspends, 1)
        XCTAssertTrue(try store.list(uid: 502).isEmpty)
        XCTAssertThrowsError(try store.resume(id: first.id, uid: 502))
        try store.resume(id: first.id, uid: 501)
        try store.resume(id: first.id, uid: 501)
        XCTAssertEqual(controller.resumes, 1)
        token.val.7 = 2
        let second = try store.observe(
            verdict, identity: ExecutionIdentity(auditToken: token), path: "/test")
        XCTAssertNotEqual(first.id, second.id)
        let restarted = IncidentResponse(directory: directory, controller: Controller())
        XCTAssertEqual(
            try restarted.list(uid: 501).first(where: { $0.id == second.id })?.responseState,
            "interrupted")
        XCTAssertThrowsError(try restarted.resume(id: second.id, uid: 501))
    }
    func testUnvalidatedDeploymentOnlyObserves() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let controller = Controller()
        let store = IncidentResponse(
            directory: directory, controller: controller, automaticResponseEnabled: false)
        let record = try store.observe(
            ThreatVerdict(score: 100, action: .suspend, reasons: ["canary"]),
            identity: ExecutionIdentity(auditToken: audit_token_t()), path: "/test")
        XCTAssertEqual(record.recommendedAction, "suspend")
        XCTAssertEqual(record.responseState, "observed")
        XCTAssertEqual(controller.suspends, 0)
    }
    func testDeniedSuspensionIsRecordedAsFailure() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let controller = Controller()
        controller.denied = true
        let store = IncidentResponse(directory: directory, controller: controller)
        let record = try store.observe(
            ThreatVerdict(score: 100, action: .suspend, reasons: ["canary"]),
            identity: ExecutionIdentity(auditToken: audit_token_t()), path: "/test")
        XCTAssertEqual(record.responseState, "failed")
        XCTAssertNotNil(record.responseError)
        XCTAssertEqual(controller.suspends, 0)
    }
}
