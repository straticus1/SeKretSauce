import XCTest
@testable import FirewallKit

final class FirewallSecurityTests: XCTestCase {
    func testApplicationPathIsPassedAsOneArgument() {
        let maliciousPath = "/Applications/Example\"; touch /tmp/owned; #.app"

        let invocation = AppFirewallCommand.add(path: maliciousPath)

        XCTAssertEqual(invocation.executable, "/usr/libexec/ApplicationFirewall/socketfilterfw")
        XCTAssertEqual(invocation.arguments, ["--add", maliciousPath])
    }

    func testPFRuleRejectsDirectiveInjectionInHost() {
        let rule = PFRule(
            action: .block,
            source: .host("192.0.2.1\npass all")
        )

        XCTAssertThrowsError(try rule.validate())
    }

    func testPFRuleRejectsDirectiveInjectionInInterface() {
        let rule = PFRule(
            action: .block,
            interface: "en0\npass all"
        )

        XCTAssertThrowsError(try rule.validate())
    }

    func testPFRuleAcceptsConstrainedValues() throws {
        let rule = PFRule(
            action: .pass,
            direction: .out,
            networkProtocol: .tcp,
            interface: "en0",
            source: .network("192.0.2.0", 24),
            destination: .table("trusted_hosts"),
            port: .range(443, 8443),
            flags: "S/SA",
            state: .keepState,
            log: true
        )

        XCTAssertNoThrow(try rule.validate())
    }

    func testManagedAnchorInsertionPreservesExistingConfiguration() throws {
        let existing = """
        set skip on lo0
        anchor "com.apple/*"
        load anchor "com.apple" from "/etc/pf.anchors/com.apple"
        """

        let updated = ManagedPFConfiguration.installAnchorReferences(in: existing)

        XCTAssertTrue(updated.hasPrefix(existing))
        XCTAssertTrue(updated.contains("anchor \"com.afterdark.protectx\""))
        XCTAssertTrue(updated.contains(
            "load anchor \"com.afterdark.protectx\" from \"/etc/pf.anchors/com.afterdark.protectx\""
        ))
    }

    func testManagedAnchorInsertionIsIdempotent() {
        let existing = "set skip on lo0\n"
        let once = ManagedPFConfiguration.installAnchorReferences(in: existing)
        let twice = ManagedPFConfiguration.installAnchorReferences(in: once)

        XCTAssertEqual(once, twice)
    }
}
