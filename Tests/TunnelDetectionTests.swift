import XCTest
@testable import Common
@testable import TunnelDetection

final class TunnelDetectionTests: XCTestCase {

    var detector: TunnelDetectionEngine!

    override func setUp() {
        super.setUp()
        detector = TunnelDetectionEngine.shared
    }

    // MARK: - DNS Detection Tests

    func testDetectsCloudflaredDomain() {
        let result = detector.analyzeDNS(
            query: "myapp.trycloudflare.com",
            type: .a,
            sourceApp: "com.example.app"
        )

        XCTAssertTrue(result.isTunnel)
        XCTAssertEqual(result.tunnelType, .cloudflareTunnel)
        XCTAssertEqual(result.confidence, 1.0)
    }

    func testDetectsNgrokDomain() {
        let result = detector.analyzeDNS(
            query: "abc123.ngrok.io",
            type: .a,
            sourceApp: nil
        )

        XCTAssertTrue(result.isTunnel)
        XCTAssertEqual(result.tunnelType, .ngrok)
        XCTAssertEqual(result.confidence, 1.0)
    }

    func testDetectsTailscaleDomain() {
        let result = detector.analyzeDNS(
            query: "myhost.ts.net",
            type: .a,
            sourceApp: nil
        )

        XCTAssertTrue(result.isTunnel)
        XCTAssertEqual(result.tunnelType, .tailscale)
    }

    func testDetectsDNSTunneling() {
        // High entropy subdomain typical of DNS tunneling
        let result = detector.analyzeDNS(
            query: "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.tunnel.example.com",
            type: .txt,
            sourceApp: nil
        )

        XCTAssertGreaterThan(result.confidence, 0.5)
    }

    func testDoesNotFlagNormalDomain() {
        let result = detector.analyzeDNS(
            query: "www.google.com",
            type: .a,
            sourceApp: nil
        )

        XCTAssertFalse(result.isTunnel)
        XCTAssertEqual(result.confidence, 0)
    }

    // MARK: - Process Detection Tests

    func testDetectsCloudflaredProcess() {
        let result = detector.analyzeProcess(
            path: "/usr/local/bin/cloudflared",
            arguments: ["cloudflared", "tunnel", "run"],
            pid: 1234,
            user: "testuser"
        )

        XCTAssertTrue(result.isTunnel)
        XCTAssertEqual(result.tunnelType, .cloudflareTunnel)
    }

    func testDetectsNgrokProcess() {
        let result = detector.analyzeProcess(
            path: "/usr/local/bin/ngrok",
            arguments: ["ngrok", "http", "8080"],
            pid: 1234,
            user: "testuser"
        )

        XCTAssertTrue(result.isTunnel)
        XCTAssertEqual(result.tunnelType, .ngrok)
    }

    func testDetectsSSHLocalForward() {
        let result = detector.analyzeProcess(
            path: "/usr/bin/ssh",
            arguments: ["ssh", "-L", "8080:localhost:80", "user@server.com"],
            pid: 1234,
            user: "testuser"
        )

        XCTAssertTrue(result.isTunnel)
        XCTAssertEqual(result.tunnelType, .sshTunnel)
        XCTAssertTrue(result.evidence.contains { $0.contains("-L") })
    }

    func testDetectsSSHRemoteForward() {
        let result = detector.analyzeProcess(
            path: "/usr/bin/ssh",
            arguments: ["ssh", "-R", "80:localhost:8080", "user@server.com"],
            pid: 1234,
            user: "testuser"
        )

        XCTAssertTrue(result.isTunnel)
        XCTAssertEqual(result.tunnelType, .sshTunnel)
        XCTAssertTrue(result.evidence.contains { $0.contains("-R") })
    }

    func testDetectsSSHDynamicProxy() {
        let result = detector.analyzeProcess(
            path: "/usr/bin/ssh",
            arguments: ["ssh", "-D", "1080", "user@server.com"],
            pid: 1234,
            user: "testuser"
        )

        XCTAssertTrue(result.isTunnel)
        XCTAssertEqual(result.tunnelType, .sshTunnel)
        XCTAssertTrue(result.evidence.contains { $0.contains("-D") })
    }

    func testDoesNotFlagNormalSSH() {
        let result = detector.analyzeProcess(
            path: "/usr/bin/ssh",
            arguments: ["ssh", "user@server.com"],
            pid: 1234,
            user: "testuser"
        )

        XCTAssertFalse(result.isTunnel)
    }

    // MARK: - Connection Detection Tests

    func testDetectsCloudflarePort() {
        let result = detector.analyzeConnection(
            host: "tunnel.example.com",
            port: 7844,
            protocol: .tcp,
            sourceApp: nil
        )

        XCTAssertGreaterThan(result.confidence, 0)
        XCTAssertTrue(result.evidence.contains { $0.contains("7844") || $0.contains("Cloudflare") })
    }

    func testDetectsNgrokConnection() {
        let result = detector.analyzeConnection(
            host: "tunnel.ngrok.io",
            port: 443,
            protocol: .tcp,
            sourceApp: nil
        )

        XCTAssertTrue(result.isTunnel)
        XCTAssertEqual(result.tunnelType, .ngrok)
    }

    // MARK: - SSH Argument Parser Tests

    func testSSHArgumentParserBasic() {
        let parser = SSHArgumentParser()
        let result = parser.parse(["ssh", "user@host.com"])

        XCTAssertNotNil(result)
        XCTAssertEqual(result?.user, "user")
        XCTAssertEqual(result?.host, "host.com")
        XCTAssertEqual(result?.port, 22)
        XCTAssertTrue(result?.tunnels.isEmpty ?? false)
    }

    func testSSHArgumentParserWithPort() {
        let parser = SSHArgumentParser()
        let result = parser.parse(["ssh", "-p", "2222", "user@host.com"])

        XCTAssertNotNil(result)
        XCTAssertEqual(result?.port, 2222)
    }

    func testSSHArgumentParserWithLocalForward() {
        let parser = SSHArgumentParser()
        let result = parser.parse(["ssh", "-L", "8080:localhost:80", "user@host.com"])

        XCTAssertNotNil(result)
        XCTAssertEqual(result?.tunnels.count, 1)
        XCTAssertEqual(result?.tunnels.first?.type, .localForward)
        XCTAssertEqual(result?.tunnels.first?.bindPort, 8080)
        XCTAssertEqual(result?.tunnels.first?.targetHost, "localhost")
        XCTAssertEqual(result?.tunnels.first?.targetPort, 80)
    }

    func testSSHArgumentParserWithDynamicForward() {
        let parser = SSHArgumentParser()
        let result = parser.parse(["ssh", "-D", "1080", "user@host.com"])

        XCTAssertNotNil(result)
        XCTAssertEqual(result?.tunnels.count, 1)
        XCTAssertEqual(result?.tunnels.first?.type, .dynamicSOCKS)
        XCTAssertEqual(result?.tunnels.first?.bindPort, 1080)
    }

    func testSSHArgumentParserMultipleTunnels() {
        let parser = SSHArgumentParser()
        let result = parser.parse([
            "ssh",
            "-L", "8080:localhost:80",
            "-R", "9090:localhost:90",
            "-D", "1080",
            "user@host.com"
        ])

        XCTAssertNotNil(result)
        XCTAssertEqual(result?.tunnels.count, 3)
    }

    // MARK: - Cloudflare Detector Tests

    func testCloudflareDetectorProcess() {
        let detector = CloudflareTunnelDetector.shared

        let alert = detector.detectProcess(
            path: "/usr/local/bin/cloudflared",
            arguments: ["cloudflared", "tunnel", "run", "mytunnel"]
        )

        XCTAssertNotNil(alert)
        XCTAssertEqual(alert?.type, .cloudflareTunnel)
    }

    func testCloudflareDetectorDNS() {
        let detector = CloudflareTunnelDetector.shared

        let alert = detector.detectDNS(query: "myapp.trycloudflare.com")

        XCTAssertNotNil(alert)
        XCTAssertEqual(alert?.type, .cloudflareTunnel)
        XCTAssertEqual(alert?.severity, .critical)  // trycloudflare is quick tunnel
    }

    func testCloudflareDetectorConnection() {
        let detector = CloudflareTunnelDetector.shared

        let alert = detector.detectConnection(
            host: "tunnel.argotunnel.com",
            port: 7844
        )

        XCTAssertNotNil(alert)
        XCTAssertEqual(alert?.type, .cloudflareTunnel)
    }
}

// MARK: - Model Tests

final class ModelTests: XCTestCase {

    func testTunnelAlertCoding() throws {
        let alert = TunnelAlert(
            type: .sshTunnel,
            evidence: "SSH tunnel detected",
            severity: .high,
            processInfo: ProcessMetadata(
                pid: 1234,
                ppid: 1,
                path: "/usr/bin/ssh",
                arguments: ["ssh", "-L", "8080:localhost:80", "user@host"],
                user: "testuser"
            ),
            networkInfo: NetworkMetadata(
                destinationIP: "192.168.1.1",
                destinationPort: 22,
                protocol: .tcp
            )
        )

        let encoder = JSONEncoder()
        let data = try encoder.encode(alert)

        let decoder = JSONDecoder()
        let decoded = try decoder.decode(TunnelAlert.self, from: data)

        XCTAssertEqual(decoded.type, alert.type)
        XCTAssertEqual(decoded.evidence, alert.evidence)
        XCTAssertEqual(decoded.severity, alert.severity)
        XCTAssertEqual(decoded.processInfo?.pid, alert.processInfo?.pid)
        XCTAssertEqual(decoded.networkInfo?.destinationPort, alert.networkInfo?.destinationPort)
    }

    func testSSHSessionCoding() throws {
        let session = SSHSession(
            user: "testuser",
            sourceHost: "localhost",
            destinationHost: "server.com",
            destinationPort: 22,
            command: "ssh",
            arguments: ["ssh", "-L", "8080:localhost:80", "server.com"],
            tunnelFlags: [
                SSHTunnelFlag(
                    type: .localForward,
                    bindPort: 8080,
                    targetHost: "localhost",
                    targetPort: 80
                )
            ]
        )

        let encoder = JSONEncoder()
        let data = try encoder.encode(session)

        let decoder = JSONDecoder()
        let decoded = try decoder.decode(SSHSession.self, from: data)

        XCTAssertEqual(decoded.user, session.user)
        XCTAssertEqual(decoded.destinationHost, session.destinationHost)
        XCTAssertEqual(decoded.tunnelFlags.count, 1)
        XCTAssertEqual(decoded.tunnelFlags.first?.type, .localForward)
    }

    func testAuditEventCoding() throws {
        let event = AuditEvent(
            eventType: .tunnelAlertRaised,
            severity: .high,
            source: "TunnelDetection",
            message: "SSH tunnel detected",
            metadata: ["pid": "1234", "user": "testuser"]
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(event)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(AuditEvent.self, from: data)

        XCTAssertEqual(decoded.eventType, event.eventType)
        XCTAssertEqual(decoded.severity, event.severity)
        XCTAssertEqual(decoded.metadata["pid"], "1234")
    }
}
