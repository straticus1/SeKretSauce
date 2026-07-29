import XCTest
@testable import FirewallHelperCore

final class ClientCodeSigningPolicyTests: XCTestCase {
    private let policy = ClientCodeSigningPolicy(
        allowedBundleIdentifiers: ["com.rampart.Rampart"]
    )

    func testAllowsExactBundleAndTeam() {
        XCTAssertTrue(policy.allows(
            client: CodeSigningIdentity(
                bundleIdentifier: "com.rampart.Rampart",
                teamIdentifier: "TEAM123456"
            ),
            helperTeamIdentifier: "TEAM123456"
        ))
    }

    func testRejectsDifferentTeam() {
        XCTAssertFalse(policy.allows(
            client: CodeSigningIdentity(
                bundleIdentifier: "com.rampart.Rampart",
                teamIdentifier: "ATTACKER00"
            ),
            helperTeamIdentifier: "TEAM123456"
        ))
    }

    func testRejectsUnapprovedBundleIdentifier() {
        XCTAssertFalse(policy.allows(
            client: CodeSigningIdentity(
                bundleIdentifier: "com.attacker.Tool",
                teamIdentifier: "TEAM123456"
            ),
            helperTeamIdentifier: "TEAM123456"
        ))
    }

    func testRejectsMissingSigningIdentity() {
        XCTAssertFalse(policy.allows(
            client: CodeSigningIdentity(bundleIdentifier: nil, teamIdentifier: nil),
            helperTeamIdentifier: "TEAM123456"
        ))
    }
}
