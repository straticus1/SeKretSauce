import XCTest

@testable import FirewallKit

private final class PFRunner: SystemCommandRunning {
    var invocations: [CommandInvocation] = []
    var failNextLoad = false
    var failingLoads = 0
    func run(_ invocation: CommandInvocation) throws -> CommandResult {
        invocations.append(invocation)
        let args = invocation.arguments
        if args.contains("-n"), let path = args.last {
            let content = try String(contentsOfFile: path)
            for line in content.split(separator: "\n") where line.contains("load anchor") {
                let referenced = String(line.split(separator: "\"", omittingEmptySubsequences: false)[3])
                guard FileManager.default.fileExists(atPath: referenced) else {
                    throw PFError.configurationFailed("Missing referenced anchor")
                }
            }
        }
        if args.contains("-f"), !args.contains("-n"), failingLoads > 0 {
            failingLoads -= 1
            throw PFError.writeFailed("Injected repeated kernel failure")
        }
        if args.contains("-f"), !args.contains("-n"), failNextLoad {
            failNextLoad = false
            throw PFError.writeFailed("Injected kernel load failure")
        }
        return CommandResult(
            output: args == ["-s", "info"] ? "Status: Enabled" : "", terminationStatus: 0)
    }
}

final class PFTransactionTests: XCTestCase {
    func testSupportedSyntaxRoundTripsAndUnknownSyntaxFails() throws {
        for port: PFRule.Port in [.single(443), .range(8000, 9000), .list([80, 443])] {
            let rule = PFRule(
                action: .pass, direction: .in, networkProtocol: .tcp, source: .network("192.0.2.0", 24),
                port: port, flags: "S/SA", state: .keepState)
            let decoded = try XCTUnwrap(PFRule.parse(rule.toPFSyntax()))
            XCTAssertEqual(decoded.toPFSyntax(), rule.toPFSyntax())
        }
        XCTAssertEqual(
            PFRule.parse("pass in proto tcp from any to any port = 443 flags S/SA keep state")?.port,
            .single(443))
        for invalid in [
            "bogus from any to any", "pass from any to any port = nonsense", "pass quick from any to any",
            "pass from any to any port { 80, }",
        ] { XCTAssertNil(PFRule.parse(invalid)) }
    }

    func testFirstInstallPersistsIdentityAndDoesNotReparseKernelText() throws {
        try fixture { runner, manager, config, anchor in
            let rule = PFRule(
                action: .pass, direction: .in, networkProtocol: .tcp, port: .list([80, 443]))
            try manager.addRule(rule)
            XCTAssertEqual(manager.revision, 1)
            let reloaded = PFManager(
                runner: runner, pfConfPath: config, anchorPath: anchor, authorize: {})
            XCTAssertEqual(reloaded.rules, [rule])
            XCTAssertFalse(
                runner.invocations.contains {
                    $0.arguments.contains("rules") && $0.arguments.contains("-s")
                })
            XCTAssertFalse(FileManager.default.fileExists(atPath: anchor + ".journal"))
            XCTAssertTrue(try String(contentsOfFile: config).hasPrefix("set skip on lo0\n"))
        }
    }

    func testFailedLoadRollsBackBothPolicyAndAnchor() throws {
        try fixture { runner, manager, config, anchor in
            let first = PFRule.block(from: "192.0.2.1")
            try manager.addRule(first)
            let previous = try Data(contentsOf: URL(fileURLWithPath: anchor))
            runner.failNextLoad = true
            XCTAssertThrowsError(try manager.addRule(.block(from: "192.0.2.2")))
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: anchor)), previous)
            let restored = PFManager(
                runner: runner, pfConfPath: config, anchorPath: anchor, authorize: {})
            XCTAssertEqual(restored.rules, [first])
            XCTAssertEqual(restored.revision, 1)
        }
    }

    func testFailedRollbackLeavesJournalForStartupRecovery() throws {
        try fixture { runner, manager, config, anchor in
            let first = PFRule.block(from: "192.0.2.1")
            try manager.addRule(first)
            runner.failingLoads = 2
            XCTAssertThrowsError(try manager.addRule(.block(from: "192.0.2.2")))
            XCTAssertTrue(FileManager.default.fileExists(atPath: anchor + ".journal"))
            XCTAssertThrowsError(try manager.snapshot())
            let restarted = PFManager(runner: runner, pfConfPath: config, anchorPath: anchor, authorize: {})
            XCTAssertNil(restarted.lastError)
            XCTAssertEqual(restarted.rules, [first])
            XCTAssertEqual(restarted.revision, 1)
            XCTAssertFalse(FileManager.default.fileExists(atPath: anchor + ".journal"))
        }
    }

    func testStaleRevisionAndExternalDriftRefuseEdits() throws {
        try fixture { runner, manager, config, anchor in
            try manager.addRule(.block(from: "192.0.2.1"))
            XCTAssertThrowsError(try manager.apply([], expectedRevision: 0))
            try Data("pass from any to any\n".utf8).write(to: URL(fileURLWithPath: anchor))
            XCTAssertThrowsError(try manager.addRule(.block(from: "192.0.2.2")))
        }
    }

    private func fixture(_ body: (PFRunner, PFManager, String, String) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let config = directory.appendingPathComponent("pf.conf").path
        let anchor = directory.appendingPathComponent("anchor").path
        try "set skip on lo0\n".write(toFile: config, atomically: true, encoding: .utf8)
        let runner = PFRunner()
        try body(
            runner, PFManager(runner: runner, pfConfPath: config, anchorPath: anchor, authorize: {}),
            config, anchor)
    }
}
