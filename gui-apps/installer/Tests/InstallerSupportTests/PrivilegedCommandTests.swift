import XCTest
@testable import InstallerSupport

final class PrivilegedCommandTests: XCTestCase {
    func testShellCommandQuotesMaliciousPathAsOneArgument() {
        let path = "/tmp/Installer\"; touch /tmp/owned; $(id); 'quoted'.app"
        let command = PrivilegedCommand(
            executable: "/usr/bin/install",
            arguments: ["-m", "0755", path, "/Library/Application Support/App"]
        )

        XCTAssertEqual(
            command.shellCommand,
            "'/usr/bin/install' '-m' '0755' '/tmp/Installer\"; touch /tmp/owned; $(id); '\"'\"'quoted'\"'\"'.app' '/Library/Application Support/App'"
        )
    }

    func testAppleScriptSourceEscapesQuotesAndBackslashes() {
        let command = PrivilegedCommand(
            executable: "/bin/echo",
            arguments: ["a\"b\\c"]
        )

        XCTAssertEqual(
            command.appleScriptSource,
            "do shell script \"'/bin/echo' 'a\\\"b\\\\c'\" with administrator privileges"
        )
    }
}
