import XCTest
@testable import ThreatDetection

final class BehavioralThreatDetectorTests: XCTestCase {
    func testBenignPlatformProcessIsAllowed() {
        let detector = BehavioralThreatDetector()
        let verdict = detector.observeProcess(
            ProcessObservation(
                pid: 10,
                path: "/usr/bin/true",
                arguments: ["true"],
                isPlatformBinary: true,
                isCodeSigned: true
            )
        )

        XCTAssertEqual(verdict, .clean)
    }

    func testLivingOffTheLandObfuscationIsStillObserved() {
        let detector = BehavioralThreatDetector()
        let verdict = detector.observeProcess(
            ProcessObservation(
                pid: 11,
                path: "/usr/bin/osascript",
                arguments: ["osascript", "eval(base64(payload))"],
                isPlatformBinary: true,
                isCodeSigned: true
            )
        )

        XCTAssertEqual(verdict.action, .observe)
        XCTAssertTrue(verdict.reasons.contains("encoded or obfuscated interpreter command"))
    }

    func testCorrelatedMalwareBehaviorsRecommendSuspension() {
        let detector = BehavioralThreatDetector()
        let processVerdict = detector.observeProcess(
            ProcessObservation(
                pid: 42,
                path: "/private/tmp/update",
                arguments: ["update", "osascript", "base64", "eval(payload)"],
                isPlatformBinary: false,
                isCodeSigned: false
            )
        )
        XCTAssertEqual(processVerdict.action, .observe)

        let finalVerdict = detector.observeFileMutation(
            FileMutationObservation(
                pid: 42,
                processPath: "/private/tmp/update",
                targetPath: "/Users/me/Library/LaunchAgents/com.bad.plist",
                kind: .write
            )
        )
        XCTAssertEqual(finalVerdict.action, .suspend)
        XCTAssertGreaterThanOrEqual(finalVerdict.score, 80)
    }

    func testRansomwareBurstRecommendsSuspension() {
        let detector = BehavioralThreatDetector(ransomwareWindow: 5, ransomwareFileThreshold: 4)
        let start = Date()
        _ = detector.observeProcess(
            ProcessObservation(
                pid: 99,
                path: "/Users/me/Downloads/editor",
                arguments: ["editor"],
                isPlatformBinary: false,
                isCodeSigned: false
            )
        )
        var verdict = ThreatVerdict.clean

        for index in 0..<4 {
            verdict = detector.observeFileMutation(
                FileMutationObservation(
                    pid: 99,
                    processPath: "/Users/me/Downloads/editor",
                    targetPath: "/Users/me/Documents/file-\(index).docx",
                    kind: .write,
                    timestamp: start.addingTimeInterval(Double(index))
                )
            )
        }

        XCTAssertEqual(verdict.action, .suspend)
        XCTAssertTrue(verdict.reasons.contains { $0.contains("rapidly modified") })
    }

    func testSignedBulkEditorIsObservedWithoutAutomaticSuspension() {
        let detector = BehavioralThreatDetector(ransomwareWindow: 5, ransomwareFileThreshold: 3)
        let start = Date()
        _ = detector.observeProcess(
            ProcessObservation(
                pid: 100,
                path: "/Applications/Editor.app/Contents/MacOS/Editor",
                arguments: ["Editor"],
                isPlatformBinary: false,
                isCodeSigned: true
            )
        )
        var verdict = ThreatVerdict.clean
        for index in 0..<3 {
            verdict = detector.observeFileMutation(
                FileMutationObservation(
                    pid: 100,
                    processPath: "/Applications/Editor.app/Contents/MacOS/Editor",
                    targetPath: "/Users/me/Documents/file-\(index).txt",
                    kind: .write,
                    timestamp: start.addingTimeInterval(Double(index))
                )
            )
        }

        XCTAssertEqual(verdict.action, .observe)
    }

    func testOldMutationsFallOutOfRansomwareWindow() {
        let detector = BehavioralThreatDetector(ransomwareWindow: 2, ransomwareFileThreshold: 3)
        let start = Date()
        _ = detector.observeFileMutation(
            FileMutationObservation(pid: 7, processPath: "/tmp/tool", targetPath: "/Users/me/a.docx", kind: .write, timestamp: start)
        )
        _ = detector.observeFileMutation(
            FileMutationObservation(pid: 7, processPath: "/tmp/tool", targetPath: "/Users/me/b.docx", kind: .write, timestamp: start.addingTimeInterval(1))
        )
        let verdict = detector.observeFileMutation(
            FileMutationObservation(pid: 7, processPath: "/tmp/tool", targetPath: "/Users/me/c.docx", kind: .write, timestamp: start.addingTimeInterval(10))
        )

        XCTAssertNotEqual(verdict.action, .suspend)
    }

    func testCanaryMutationImmediatelyRecommendsSuspension() {
        let detector = BehavioralThreatDetector()
        let verdict = detector.observeFileMutation(
            FileMutationObservation(
                pid: 55,
                processPath: "/Users/me/Downloads/unknown",
                targetPath: "/Users/me/Documents/.sekretsauce-canary-budget.xlsx",
                kind: .write
            )
        )

        XCTAssertEqual(verdict.action, .suspend)
        XCTAssertEqual(verdict.score, 100)
    }

    func testExitClearsAccumulatedBehavior() {
        let detector = BehavioralThreatDetector()
        _ = detector.observeProcess(
            ProcessObservation(
                pid: 101,
                path: "/tmp/tool",
                arguments: ["tool"],
                isPlatformBinary: false,
                isCodeSigned: false
            )
        )
        detector.processExited(pid: 101)
        let verdict = detector.observeFileMutation(
            FileMutationObservation(
                pid: 101,
                processPath: "/tmp/tool",
                targetPath: "/Users/me/Documents/a.txt",
                kind: .write
            )
        )

        XCTAssertEqual(verdict, .clean)
    }
}
