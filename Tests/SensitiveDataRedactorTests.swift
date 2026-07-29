import XCTest
@testable import Common

final class SensitiveDataRedactorTests: XCTestCase {
    func testRedactsSeparateAndInlineSecrets() {
        let result = SensitiveDataRedactor.redact(arguments: [
            "tool", "--password", "hunter2", "--api-key=abc123", "safe"
        ])

        XCTAssertEqual(result, [
            "tool", "--password", "<redacted>", "--api-key=<redacted>", "safe"
        ])
    }

    func testRedactsCredentialsEmbeddedInURL() {
        let result = SensitiveDataRedactor.redact(arguments: [
            "https://alice:secret@example.com/path"
        ])

        XCTAssertEqual(result, ["https://%3Credacted%3E:%3Credacted%3E@example.com/path"])
    }
}
