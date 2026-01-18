import Foundation
import NetworkExtension

/// DNS Proxy Provider - Intercepts and monitors all DNS queries
/// Enables detection of DNS tunneling and tunnel service domains
public class DNSProxyProvider: NEDNSProxyProvider {

    private let auditLogger = AuditLogger.shared
    private var tunnelDetector: DNSTunnelDetector!
    private var blockedDomains: Set<String> = []
    private var queryCount: UInt64 = 0

    // MARK: - Lifecycle

    override public func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        auditLogger.log(
            eventType: .systemStart,
            severity: .info,
            source: "DNSProxy",
            message: "DNS Proxy starting"
        )

        // Initialize tunnel detector
        tunnelDetector = DNSTunnelDetector()

        // Load blocked domains from configuration
        loadBlockedDomains()

        completionHandler(nil)
    }

    override public func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        auditLogger.log(
            eventType: .systemStop,
            severity: .info,
            source: "DNSProxy",
            message: "DNS Proxy stopping, reason: \(reason.rawValue), queries processed: \(queryCount)"
        )

        completionHandler()
    }

    // MARK: - DNS Flow Handling

    override public func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let udpFlow = flow as? NEAppProxyUDPFlow else {
            return false
        }

        // Handle the UDP flow for DNS
        handleDNSFlow(udpFlow)
        return true
    }

    private func handleDNSFlow(_ flow: NEAppProxyUDPFlow) {
        // Open the flow
        flow.open(withLocalEndpoint: nil) { [weak self] error in
            if let error = error {
                self?.auditLogger.logError(error, source: "DNSProxy", context: "Failed to open flow")
                return
            }

            self?.readDNSPackets(from: flow)
        }
    }

    private func readDNSPackets(from flow: NEAppProxyUDPFlow) {
        flow.readDatagrams { [weak self] datagrams, endpoints, error in
            guard let self = self else { return }

            if let error = error {
                self.auditLogger.logError(error, source: "DNSProxy", context: "Read error")
                return
            }

            guard let datagrams = datagrams, let endpoints = endpoints else {
                return
            }

            for (datagram, endpoint) in zip(datagrams, endpoints) {
                self.processDNSPacket(datagram, endpoint: endpoint, flow: flow)
            }

            // Continue reading
            self.readDNSPackets(from: flow)
        }
    }

    private func processDNSPacket(_ data: Data, endpoint: NWEndpoint, flow: NEAppProxyUDPFlow) {
        queryCount += 1

        // Parse DNS query
        guard let query = parseDNSQuery(data) else {
            // Can't parse, forward as-is
            forwardDNSPacket(data, endpoint: endpoint, flow: flow)
            return
        }

        // Get source app bundle ID
        let sourceApp = flow.metaData.sourceAppSigningIdentifier

        // Check for tunnel indicators
        let analysis = tunnelDetector.analyze(query: query.queryName, type: query.queryType)

        // Create DNS query record
        let dnsQuery = DNSQuery(
            queryName: query.queryName,
            queryType: query.queryType,
            sourceApp: sourceApp,
            blocked: false,
            tunnelSuspicion: analysis.suspicionScore
        )

        // Check if should block
        if shouldBlock(query: query.queryName) {
            var blockedQuery = dnsQuery
            blockedQuery = DNSQuery(
                id: dnsQuery.id,
                timestamp: dnsQuery.timestamp,
                queryName: dnsQuery.queryName,
                queryType: dnsQuery.queryType,
                sourceApp: dnsQuery.sourceApp,
                sourceIP: dnsQuery.sourceIP,
                response: nil,
                blocked: true,
                tunnelSuspicion: dnsQuery.tunnelSuspicion
            )
            auditLogger.logDNSQuery(blockedQuery)

            // Return NXDOMAIN response
            if let response = createNXDomainResponse(for: data) {
                flow.writeDatagrams([response], sentBy: [endpoint]) { _ in }
            }
            return
        }

        // Check for tunnel detection alerts
        if let alert = analysis.alert {
            auditLogger.logTunnelAlert(alert)
        }

        // Log the query (only if suspicious or configured to log all)
        if analysis.suspicionScore > 0.3 {
            auditLogger.logDNSQuery(dnsQuery)
        }

        // Forward the packet
        forwardDNSPacket(data, endpoint: endpoint, flow: flow)
    }

    private func forwardDNSPacket(_ data: Data, endpoint: NWEndpoint, flow: NEAppProxyUDPFlow) {
        flow.writeDatagrams([data], sentBy: [endpoint]) { [weak self] error in
            if let error = error {
                self?.auditLogger.logError(error, source: "DNSProxy", context: "Forward error")
            }
        }
    }

    // MARK: - DNS Parsing

    private struct ParsedDNSQuery {
        let queryName: String
        let queryType: DNSQueryType
        let transactionID: UInt16
    }

    private func parseDNSQuery(_ data: Data) -> ParsedDNSQuery? {
        guard data.count >= 12 else { return nil }

        // Transaction ID
        let transactionID = UInt16(data[0]) << 8 | UInt16(data[1])

        // Skip to question section (after 12-byte header)
        var offset = 12
        var queryName = ""

        // Parse domain name (labels)
        while offset < data.count {
            let labelLength = Int(data[offset])
            if labelLength == 0 {
                offset += 1
                break
            }

            if labelLength >= 0xC0 {
                // Compression pointer - not handling for now
                offset += 2
                break
            }

            if !queryName.isEmpty {
                queryName += "."
            }

            let labelStart = offset + 1
            let labelEnd = labelStart + labelLength

            guard labelEnd <= data.count else { return nil }

            if let label = String(data: data[labelStart..<labelEnd], encoding: .utf8) {
                queryName += label
            }

            offset = labelEnd
        }

        // Query type (2 bytes after name)
        guard offset + 2 <= data.count else { return nil }
        let queryTypeRaw = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
        let queryType = DNSQueryType(rawValue: queryTypeRaw)

        return ParsedDNSQuery(
            queryName: queryName,
            queryType: queryType,
            transactionID: transactionID
        )
    }

    // MARK: - Response Generation

    private func createNXDomainResponse(for query: Data) -> Data? {
        guard query.count >= 12 else { return nil }

        var response = query
        // Set QR bit (response) and RCODE = NXDOMAIN (3)
        response[2] = 0x81 // QR=1, OPCODE=0, AA=0, TC=0, RD=1
        response[3] = 0x83 // RA=1, Z=0, RCODE=3 (NXDOMAIN)

        return response
    }

    // MARK: - Blocking

    private func loadBlockedDomains() {
        // Load from configuration
        do {
            let config = try SecureStorage.shared.retrieveConfiguration()
            blockedDomains = Set(config.blockedDomains)
        } catch {
            // Load defaults - known tunnel services
            blockedDomains = Set(TunnelDatabase.indicators.flatMap { $0.dnsPatterns })
        }
    }

    private func shouldBlock(query: String) -> Bool {
        let lowercaseQuery = query.lowercased()

        for blocked in blockedDomains {
            if lowercaseQuery.hasSuffix(blocked) || lowercaseQuery == blocked {
                return true
            }
        }

        return false
    }
}

// MARK: - DNS Tunnel Detector

class DNSTunnelDetector {

    struct AnalysisResult {
        let suspicionScore: Double
        let alert: TunnelAlert?
    }

    // Entropy threshold for detecting encoded data in subdomains
    private let entropyThreshold: Double = 3.5
    // Minimum subdomain length to consider suspicious
    private let minSuspiciousLength: Int = 20

    func analyze(query: String, type: DNSQueryType) -> AnalysisResult {
        var suspicionScore: Double = 0
        var reasons: [String] = []

        // Check for known tunnel service domains
        for indicator in TunnelDatabase.indicators {
            for pattern in indicator.dnsPatterns {
                if query.lowercased().contains(pattern.lowercased()) {
                    let alert = TunnelAlert(
                        type: indicator.tunnelType,
                        evidence: "DNS query to known tunnel service: \(query)",
                        severity: indicator.severity
                    )
                    return AnalysisResult(suspicionScore: 1.0, alert: alert)
                }
            }
        }

        // Extract subdomain (everything before the registered domain)
        let parts = query.split(separator: ".")
        guard parts.count >= 2 else {
            return AnalysisResult(suspicionScore: 0, alert: nil)
        }

        // Check subdomain characteristics
        let subdomain = parts.dropLast(2).joined(separator: ".")

        // Long subdomain
        if subdomain.count > minSuspiciousLength {
            suspicionScore += 0.3
            reasons.append("Long subdomain (\(subdomain.count) chars)")
        }

        // High entropy (encoded data)
        let entropy = calculateEntropy(subdomain)
        if entropy > entropyThreshold {
            suspicionScore += 0.4
            reasons.append("High entropy subdomain (\(String(format: "%.2f", entropy)))")
        }

        // Suspicious query types
        let suspiciousTypes: [DNSQueryType] = [.txt, .null, .any]
        if suspiciousTypes.contains(type) {
            suspicionScore += 0.2
            reasons.append("Suspicious query type (\(type))")
        }

        // Contains hex-like patterns
        let hexPattern = try? NSRegularExpression(pattern: "[0-9a-f]{16,}", options: .caseInsensitive)
        if let range = hexPattern?.firstMatch(in: subdomain, range: NSRange(subdomain.startIndex..., in: subdomain)) {
            suspicionScore += 0.3
            reasons.append("Hex-like pattern in subdomain")
        }

        // Contains base64-like patterns
        let base64Pattern = try? NSRegularExpression(pattern: "[A-Za-z0-9+/]{20,}={0,2}", options: [])
        if let _ = base64Pattern?.firstMatch(in: subdomain, range: NSRange(subdomain.startIndex..., in: subdomain)) {
            suspicionScore += 0.3
            reasons.append("Base64-like pattern in subdomain")
        }

        // Cap at 1.0
        suspicionScore = min(suspicionScore, 1.0)

        // Generate alert if suspicious enough
        var alert: TunnelAlert?
        if suspicionScore >= 0.6 {
            alert = TunnelAlert(
                type: .dnsTunnel,
                evidence: "Suspicious DNS query: \(query) - \(reasons.joined(separator: ", "))",
                severity: suspicionScore >= 0.8 ? .high : .medium
            )
        }

        return AnalysisResult(suspicionScore: suspicionScore, alert: alert)
    }

    private func calculateEntropy(_ string: String) -> Double {
        guard !string.isEmpty else { return 0 }

        var freq = [Character: Int]()
        for char in string {
            freq[char, default: 0] += 1
        }

        let len = Double(string.count)
        var entropy: Double = 0

        for count in freq.values {
            let p = Double(count) / len
            entropy -= p * log2(p)
        }

        return entropy
    }
}
