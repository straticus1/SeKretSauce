import Foundation
import NetworkExtension

/// Transparent Proxy Provider - Monitors TCP connections for tunnel detection
/// Provides visibility into HTTP/HTTPS destinations and connection metadata
public class TransparentProxyProvider: NETransparentProxyProvider {

    private let auditLogger = AuditLogger.shared
    private var connectionCount: UInt64 = 0
    private var activeFlows: [UUID: FlowMetadata] = [:]
    private let flowLock = NSLock()

    // MARK: - Lifecycle

    override public func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        auditLogger.log(
            eventType: .systemStart,
            severity: .info,
            source: "TransparentProxy",
            message: "Transparent Proxy starting"
        )

        completionHandler(nil)
    }

    override public func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        auditLogger.log(
            eventType: .systemStop,
            severity: .info,
            source: "TransparentProxy",
            message: "Transparent Proxy stopping, reason: \(reason.rawValue), connections: \(connectionCount)"
        )

        completionHandler()
    }

    // MARK: - Flow Handling

    override public func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        connectionCount += 1

        let metadata = flow.metaData
        let sourceApp = metadata.sourceAppSigningIdentifier
        let sourceAppAuditToken = metadata.sourceAppAuditToken

        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            return handleTCPFlow(tcpFlow, sourceApp: sourceApp)
        } else if let udpFlow = flow as? NEAppProxyUDPFlow {
            return handleUDPFlow(udpFlow, sourceApp: sourceApp)
        }

        return false
    }

    // MARK: - TCP Flow Handling

    private func handleTCPFlow(_ flow: NEAppProxyTCPFlow, sourceApp: String?) -> Bool {
        guard let remoteEndpoint = flow.remoteEndpoint as? NWHostEndpoint else {
            return false
        }

        let host = remoteEndpoint.hostname
        let port = UInt16(remoteEndpoint.port) ?? 0

        // Create flow metadata
        let flowID = UUID()
        let flowMeta = FlowMetadata(
            id: flowID,
            startTime: Date(),
            sourceApp: sourceApp,
            destinationHost: host,
            destinationPort: port,
            protocol: .tcp
        )

        flowLock.lock()
        activeFlows[flowID] = flowMeta
        flowLock.unlock()

        // Check for tunnel indicators
        checkForTunnelIndicators(host: host, port: port, sourceApp: sourceApp, flow: flow)

        // Log significant connections
        logConnection(flowMeta)

        // Open the flow and start proxying
        flow.open(withLocalEndpoint: flow.localEndpoint) { [weak self] error in
            if let error = error {
                self?.auditLogger.logError(error, source: "TransparentProxy", context: "TCP flow open failed")
                return
            }

            self?.proxyTCPFlow(flow, flowID: flowID)
        }

        return true
    }

    private func proxyTCPFlow(_ flow: NEAppProxyTCPFlow, flowID: UUID) {
        // Read from flow and write back (transparent proxy)
        readAndForwardTCP(flow, flowID: flowID)
    }

    private func readAndForwardTCP(_ flow: NEAppProxyTCPFlow, flowID: UUID) {
        flow.readData { [weak self] data, error in
            guard let self = self else { return }

            if let error = error {
                // Flow closed or error
                self.flowEnded(flowID: flowID)
                return
            }

            guard let data = data, !data.isEmpty else {
                // No more data
                self.flowEnded(flowID: flowID)
                return
            }

            // Analyze initial data for protocol detection
            self.analyzeTraffic(data, flowID: flowID)

            // Write data back to flow (forward to destination)
            flow.write(data) { writeError in
                if let writeError = writeError {
                    self.auditLogger.logError(writeError, source: "TransparentProxy", context: "TCP write failed")
                    return
                }

                // Continue reading
                self.readAndForwardTCP(flow, flowID: flowID)
            }
        }
    }

    // MARK: - UDP Flow Handling

    private func handleUDPFlow(_ flow: NEAppProxyUDPFlow, sourceApp: String?) -> Bool {
        // For UDP, we mainly care about QUIC (HTTP/3) which uses port 443
        // and other potentially tunneled protocols

        let flowID = UUID()
        let flowMeta = FlowMetadata(
            id: flowID,
            startTime: Date(),
            sourceApp: sourceApp,
            destinationHost: "UDP",
            destinationPort: 0,
            protocol: .udp
        )

        flowLock.lock()
        activeFlows[flowID] = flowMeta
        flowLock.unlock()

        flow.open(withLocalEndpoint: nil) { [weak self] error in
            if let error = error {
                self?.auditLogger.logError(error, source: "TransparentProxy", context: "UDP flow open failed")
                return
            }

            self?.proxyUDPFlow(flow, flowID: flowID)
        }

        return true
    }

    private func proxyUDPFlow(_ flow: NEAppProxyUDPFlow, flowID: UUID) {
        flow.readDatagrams { [weak self] datagrams, endpoints, error in
            guard let self = self else { return }

            if let error = error {
                self.flowEnded(flowID: flowID)
                return
            }

            guard let datagrams = datagrams, let endpoints = endpoints else {
                return
            }

            // Forward datagrams
            flow.writeDatagrams(datagrams, sentBy: endpoints) { _ in }

            // Continue reading
            self.proxyUDPFlow(flow, flowID: flowID)
        }
    }

    // MARK: - Traffic Analysis

    private func analyzeTraffic(_ data: Data, flowID: UUID) {
        flowLock.lock()
        guard var flowMeta = activeFlows[flowID] else {
            flowLock.unlock()
            return
        }
        flowLock.unlock()

        // Check for TLS Client Hello (HTTPS)
        if data.count > 5 && data[0] == 0x16 && data[1] == 0x03 {
            // TLS record - try to extract SNI from Client Hello
            if let sni = extractSNI(from: data) {
                flowMeta.tlsSNI = sni

                flowLock.lock()
                activeFlows[flowID] = flowMeta
                flowLock.unlock()

                // Check SNI against tunnel indicators
                checkForTunnelIndicators(
                    host: sni,
                    port: flowMeta.destinationPort,
                    sourceApp: flowMeta.sourceApp,
                    flow: nil
                )
            }
        }

        // Check for HTTP (unencrypted)
        if let httpInfo = parseHTTPRequest(data) {
            flowMeta.httpHost = httpInfo.host
            flowMeta.httpMethod = httpInfo.method
            flowMeta.httpPath = httpInfo.path

            flowLock.lock()
            activeFlows[flowID] = flowMeta
            flowLock.unlock()

            // Check for CONNECT method (HTTP tunnel)
            if httpInfo.method == "CONNECT" {
                let alert = TunnelAlert(
                    type: .httpTunnel,
                    evidence: "HTTP CONNECT tunnel detected to \(httpInfo.host ?? "unknown")",
                    severity: .high,
                    networkInfo: NetworkMetadata(
                        destinationIP: flowMeta.destinationHost,
                        destinationPort: flowMeta.destinationPort,
                        protocol: .tcp
                    )
                )
                auditLogger.logTunnelAlert(alert)
            }
        }

        // Check for WebSocket upgrade
        if isWebSocketUpgrade(data) {
            // WebSocket connections are commonly used for tunneling
            auditLogger.log(
                eventType: .networkConnection,
                severity: .medium,
                source: "TransparentProxy",
                message: "WebSocket connection detected",
                metadata: [
                    "destination": flowMeta.destinationHost,
                    "port": String(flowMeta.destinationPort),
                    "source_app": flowMeta.sourceApp ?? "unknown"
                ]
            )
        }
    }

    // MARK: - SNI Extraction

    private func extractSNI(from data: Data) -> String? {
        // TLS Client Hello SNI extraction
        // This is a simplified parser - production code should be more robust

        guard data.count > 43 else { return nil }

        // Check TLS record type (0x16 = Handshake)
        guard data[0] == 0x16 else { return nil }

        // Skip TLS record header (5 bytes) and handshake header (4 bytes)
        var offset = 5 + 4

        // Skip client version (2), random (32), session ID
        offset += 2 + 32
        guard offset < data.count else { return nil }

        let sessionIDLength = Int(data[offset])
        offset += 1 + sessionIDLength
        guard offset + 2 <= data.count else { return nil }

        // Skip cipher suites
        let cipherSuitesLength = Int(data[offset]) << 8 | Int(data[offset + 1])
        offset += 2 + cipherSuitesLength
        guard offset + 1 <= data.count else { return nil }

        // Skip compression methods
        let compressionLength = Int(data[offset])
        offset += 1 + compressionLength
        guard offset + 2 <= data.count else { return nil }

        // Extensions length
        let extensionsLength = Int(data[offset]) << 8 | Int(data[offset + 1])
        offset += 2

        let extensionsEnd = offset + extensionsLength

        // Parse extensions looking for SNI (type 0x0000)
        while offset + 4 <= extensionsEnd && offset + 4 <= data.count {
            let extType = Int(data[offset]) << 8 | Int(data[offset + 1])
            let extLength = Int(data[offset + 2]) << 8 | Int(data[offset + 3])
            offset += 4

            if extType == 0x0000 { // SNI extension
                guard offset + 5 <= data.count else { return nil }

                // Skip list length (2) and name type (1)
                offset += 2 + 1

                let nameLength = Int(data[offset]) << 8 | Int(data[offset + 1])
                offset += 2

                guard offset + nameLength <= data.count else { return nil }

                return String(data: data[offset..<(offset + nameLength)], encoding: .utf8)
            }

            offset += extLength
        }

        return nil
    }

    // MARK: - HTTP Parsing

    private struct HTTPRequestInfo {
        let method: String
        let path: String
        let host: String?
    }

    private func parseHTTPRequest(_ data: Data) -> HTTPRequestInfo? {
        guard let str = String(data: data.prefix(2048), encoding: .utf8) else {
            return nil
        }

        let lines = str.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else { return nil }

        let parts = requestLine.split(separator: " ")
        guard parts.count >= 2 else { return nil }

        let method = String(parts[0])
        let path = String(parts[1])

        // Common HTTP methods
        let httpMethods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT", "PATCH"]
        guard httpMethods.contains(method) else { return nil }

        // Find Host header
        var host: String?
        for line in lines.dropFirst() {
            if line.lowercased().hasPrefix("host:") {
                host = String(line.dropFirst(5)).trimmingCharacters(in: .whitespaces)
                break
            }
        }

        return HTTPRequestInfo(method: method, path: path, host: host)
    }

    private func isWebSocketUpgrade(_ data: Data) -> Bool {
        guard let str = String(data: data.prefix(1024), encoding: .utf8)?.lowercased() else {
            return false
        }

        return str.contains("upgrade: websocket") && str.contains("connection: upgrade")
    }

    // MARK: - Tunnel Detection

    private func checkForTunnelIndicators(host: String, port: UInt16, sourceApp: String?, flow: NEAppProxyFlow?) {
        // Check against known tunnel service domains
        for indicator in TunnelDatabase.indicators {
            for pattern in indicator.dnsPatterns {
                if host.lowercased().contains(pattern.lowercased()) {
                    let alert = TunnelAlert(
                        type: indicator.tunnelType,
                        evidence: "Connection to known tunnel service: \(host):\(port)",
                        severity: indicator.severity,
                        processInfo: sourceApp != nil ? ProcessMetadata(
                            pid: 0,
                            ppid: 0,
                            path: sourceApp!,
                            arguments: [],
                            user: "unknown"
                        ) : nil,
                        networkInfo: NetworkMetadata(
                            destinationIP: host,
                            destinationPort: port,
                            protocol: .tcp
                        )
                    )

                    auditLogger.logTunnelAlert(alert)
                    return
                }
            }

            // Check ports
            if indicator.ports.contains(port) {
                // Log as suspicious but lower severity
                auditLogger.log(
                    eventType: .networkConnection,
                    severity: .medium,
                    source: "TransparentProxy",
                    message: "Connection to port associated with \(indicator.name)",
                    metadata: [
                        "host": host,
                        "port": String(port),
                        "indicator": indicator.name
                    ]
                )
            }
        }
    }

    // MARK: - Logging

    private func logConnection(_ flow: FlowMetadata) {
        // Only log connections to interesting ports or suspicious destinations
        let interestingPorts: [UInt16] = [22, 80, 443, 8080, 8443, 3128, 1080, 7844, 4443]

        if interestingPorts.contains(flow.destinationPort) {
            auditLogger.log(
                eventType: .networkConnection,
                severity: .info,
                source: "TransparentProxy",
                message: "TCP connection: \(flow.destinationHost):\(flow.destinationPort)",
                metadata: [
                    "source_app": flow.sourceApp ?? "unknown",
                    "destination": flow.destinationHost,
                    "port": String(flow.destinationPort)
                ]
            )
        }
    }

    private func flowEnded(flowID: UUID) {
        flowLock.lock()
        if let flow = activeFlows.removeValue(forKey: flowID) {
            flowLock.unlock()

            // Could log flow statistics here if needed
        } else {
            flowLock.unlock()
        }
    }
}

// MARK: - Flow Metadata

private struct FlowMetadata {
    let id: UUID
    let startTime: Date
    let sourceApp: String?
    var destinationHost: String
    var destinationPort: UInt16
    var `protocol`: NetworkProtocol
    var tlsSNI: String?
    var httpHost: String?
    var httpMethod: String?
    var httpPath: String?
    var bytesIn: UInt64 = 0
    var bytesOut: UInt64 = 0
}
