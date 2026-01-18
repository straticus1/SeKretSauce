import Foundation

/// Comprehensive tunnel detection engine
/// Correlates data from multiple sources to detect tunneling activity
public final class TunnelDetectionEngine {

    public static let shared = TunnelDetectionEngine()

    private let auditLogger = AuditLogger.shared
    private let queue = DispatchQueue(label: "com.sekretsauce.tunneldetection", qos: .userInitiated)

    // Detection state
    private var recentDNSQueries: [String: [Date]] = [:]
    private var recentConnections: [ConnectionKey: ConnectionStats] = [:]
    private var suspiciousProcesses: Set<Int32> = []

    // Thresholds
    private let dnsQueryRateThreshold: Int = 100  // queries per minute to same domain
    private let connectionDurationThreshold: TimeInterval = 3600  // 1 hour
    private let dataThroughputThreshold: UInt64 = 100_000_000  // 100MB

    private init() {
        // Start periodic analysis
        startPeriodicAnalysis()
    }

    // MARK: - Public API

    /// Analyze a DNS query for tunnel indicators
    public func analyzeDNS(query: String, type: DNSQueryType, sourceApp: String?) -> TunnelAnalysisResult {
        var result = TunnelAnalysisResult()

        // Check known tunnel domains
        for indicator in TunnelDatabase.indicators {
            for pattern in indicator.dnsPatterns {
                if query.lowercased().contains(pattern.lowercased()) {
                    result.isTunnel = true
                    result.tunnelType = indicator.tunnelType
                    result.confidence = 1.0
                    result.evidence.append("DNS query to known tunnel service: \(pattern)")
                    return result
                }
            }
        }

        // Analyze for DNS tunneling
        let dnsAnalysis = analyzeDNSTunneling(query: query, type: type)
        if dnsAnalysis.confidence > 0.5 {
            result.isTunnel = true
            result.tunnelType = .dnsTunnel
            result.confidence = dnsAnalysis.confidence
            result.evidence.append(contentsOf: dnsAnalysis.evidence)
        }

        // Track query rate
        trackDNSQueryRate(query: query)

        return result
    }

    /// Analyze a network connection for tunnel indicators
    public func analyzeConnection(
        host: String,
        port: UInt16,
        protocol: NetworkProtocol,
        sourceApp: String?,
        bytesIn: UInt64 = 0,
        bytesOut: UInt64 = 0
    ) -> TunnelAnalysisResult {
        var result = TunnelAnalysisResult()

        // Check known tunnel service domains
        for indicator in TunnelDatabase.indicators {
            for pattern in indicator.dnsPatterns {
                if host.lowercased().contains(pattern.lowercased()) {
                    result.isTunnel = true
                    result.tunnelType = indicator.tunnelType
                    result.confidence = 1.0
                    result.evidence.append("Connection to known tunnel service: \(host)")
                    return result
                }
            }

            // Check ports
            if indicator.ports.contains(port) {
                result.confidence += 0.3
                result.evidence.append("Connection to port associated with \(indicator.name)")
            }
        }

        // Analyze connection patterns
        let key = ConnectionKey(host: host, port: port)
        trackConnection(key: key, bytesIn: bytesIn, bytesOut: bytesOut)

        // Check for long-running high-throughput connections (tunnel characteristic)
        if let stats = recentConnections[key] {
            if stats.duration > connectionDurationThreshold {
                result.confidence += 0.2
                result.evidence.append("Long-running connection: \(Int(stats.duration / 60)) minutes")
            }

            if stats.totalBytes > dataThroughputThreshold {
                result.confidence += 0.2
                result.evidence.append("High data transfer: \(stats.totalBytes / 1_000_000)MB")
            }
        }

        if result.confidence > 0.6 && result.tunnelType == nil {
            result.tunnelType = .unknown
            result.isTunnel = true
        }

        return result
    }

    /// Analyze a process for tunnel indicators
    public func analyzeProcess(
        path: String,
        arguments: [String],
        pid: Int32,
        user: String
    ) -> TunnelAnalysisResult {
        var result = TunnelAnalysisResult()

        let processName = (path as NSString).lastPathComponent.lowercased()

        // Check known tunnel process names
        for indicator in TunnelDatabase.indicators {
            for knownProcess in indicator.processNames {
                if processName == knownProcess.lowercased() || processName.contains(knownProcess.lowercased()) {
                    result.isTunnel = true
                    result.tunnelType = indicator.tunnelType
                    result.confidence = 1.0
                    result.evidence.append("Known tunnel process: \(processName)")

                    suspiciousProcesses.insert(pid)
                    return result
                }
            }
        }

        // Check for SSH with tunnel flags
        if processName == "ssh" || path == "/usr/bin/ssh" {
            let argsString = arguments.joined(separator: " ")

            // Local forward
            if argsString.contains("-L") {
                result.confidence += 0.5
                result.evidence.append("SSH local port forward (-L)")
            }

            // Remote forward
            if argsString.contains("-R") {
                result.confidence += 0.6
                result.evidence.append("SSH remote port forward (-R)")
            }

            // Dynamic SOCKS
            if argsString.contains("-D") {
                result.confidence += 0.7
                result.evidence.append("SSH dynamic SOCKS proxy (-D)")
            }

            // TUN device
            if argsString.contains("-w") {
                result.confidence += 0.8
                result.evidence.append("SSH TUN/TAP device (-w)")
            }

            if result.confidence > 0 {
                result.isTunnel = true
                result.tunnelType = .sshTunnel
            }
        }

        // Check for netcat/socat (common tunnel tools)
        if ["nc", "ncat", "netcat", "socat"].contains(processName) {
            result.confidence += 0.4
            result.evidence.append("Network utility that can be used for tunneling: \(processName)")

            // Check for -e or -c flags (command execution)
            let argsString = arguments.joined(separator: " ")
            if argsString.contains("-e") || argsString.contains("-c") {
                result.confidence += 0.3
                result.evidence.append("Network utility with command execution")
            }
        }

        if result.confidence > 0.6 && result.tunnelType == nil {
            result.tunnelType = .unknown
            result.isTunnel = true
            suspiciousProcesses.insert(pid)
        }

        return result
    }

    // MARK: - DNS Tunneling Analysis

    private func analyzeDNSTunneling(query: String, type: DNSQueryType) -> (confidence: Double, evidence: [String]) {
        var confidence: Double = 0
        var evidence: [String] = []

        let parts = query.split(separator: ".")
        guard parts.count >= 2 else {
            return (0, [])
        }

        // Get subdomain (everything except TLD and registered domain)
        let subdomain = parts.dropLast(2).joined(separator: ".")

        // Long subdomain
        if subdomain.count > 30 {
            confidence += 0.3
            evidence.append("Unusually long subdomain: \(subdomain.count) characters")
        }

        // High entropy
        let entropy = calculateEntropy(subdomain)
        if entropy > 3.8 {
            confidence += 0.4
            evidence.append("High entropy subdomain: \(String(format: "%.2f", entropy))")
        }

        // Suspicious query types
        let tunnelQueryTypes: [DNSQueryType] = [.txt, .null, .any]
        if tunnelQueryTypes.contains(type) {
            confidence += 0.2
            evidence.append("Suspicious query type: \(type)")
        }

        // Base64-like content
        if containsBase64Pattern(subdomain) {
            confidence += 0.3
            evidence.append("Base64-like encoding detected in subdomain")
        }

        // Hex-like content
        if containsHexPattern(subdomain) {
            confidence += 0.2
            evidence.append("Hex-like encoding detected in subdomain")
        }

        // Numeric subdomain labels
        let numericLabels = subdomain.split(separator: ".").filter { $0.allSatisfy { $0.isNumber } }
        if numericLabels.count > 2 {
            confidence += 0.2
            evidence.append("Multiple numeric subdomain labels")
        }

        return (min(confidence, 1.0), evidence)
    }

    // MARK: - Tracking

    private func trackDNSQueryRate(query: String) {
        let domain = extractBaseDomain(from: query)

        queue.async { [weak self] in
            guard let self = self else { return }

            var queries = self.recentDNSQueries[domain] ?? []
            queries.append(Date())

            // Keep only last minute
            let cutoff = Date().addingTimeInterval(-60)
            queries = queries.filter { $0 > cutoff }

            self.recentDNSQueries[domain] = queries

            // Check for high query rate
            if queries.count > self.dnsQueryRateThreshold {
                let alert = TunnelAlert(
                    type: .dnsTunnel,
                    evidence: "High DNS query rate to \(domain): \(queries.count) queries/minute",
                    severity: .high
                )
                self.auditLogger.logTunnelAlert(alert)
            }
        }
    }

    private func trackConnection(key: ConnectionKey, bytesIn: UInt64, bytesOut: UInt64) {
        queue.async { [weak self] in
            guard let self = self else { return }

            if var stats = self.recentConnections[key] {
                stats.totalBytes += bytesIn + bytesOut
                stats.lastSeen = Date()
                self.recentConnections[key] = stats
            } else {
                self.recentConnections[key] = ConnectionStats(
                    firstSeen: Date(),
                    lastSeen: Date(),
                    totalBytes: bytesIn + bytesOut
                )
            }
        }
    }

    // MARK: - Periodic Analysis

    private func startPeriodicAnalysis() {
        Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            self?.performPeriodicAnalysis()
        }
    }

    private func performPeriodicAnalysis() {
        queue.async { [weak self] in
            guard let self = self else { return }

            // Clean up old data
            let cutoff = Date().addingTimeInterval(-300) // 5 minutes

            self.recentDNSQueries = self.recentDNSQueries.filter { _, dates in
                dates.contains { $0 > cutoff }
            }

            // Analyze long-running connections
            for (key, stats) in self.recentConnections {
                if stats.duration > self.connectionDurationThreshold &&
                   stats.totalBytes > self.dataThroughputThreshold {
                    let alert = TunnelAlert(
                        type: .unknown,
                        evidence: "Suspicious long-running connection to \(key.host):\(key.port) - Duration: \(Int(stats.duration / 60))min, Data: \(stats.totalBytes / 1_000_000)MB",
                        severity: .medium,
                        networkInfo: NetworkMetadata(
                            destinationIP: key.host,
                            destinationPort: key.port,
                            protocol: .tcp
                        )
                    )
                    self.auditLogger.logTunnelAlert(alert)
                }
            }
        }
    }

    // MARK: - Helpers

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

    private func containsBase64Pattern(_ string: String) -> Bool {
        let pattern = "[A-Za-z0-9+/]{20,}={0,2}"
        return string.range(of: pattern, options: .regularExpression) != nil
    }

    private func containsHexPattern(_ string: String) -> Bool {
        let pattern = "[0-9a-fA-F]{16,}"
        return string.range(of: pattern, options: .regularExpression) != nil
    }

    private func extractBaseDomain(from query: String) -> String {
        let parts = query.split(separator: ".")
        if parts.count >= 2 {
            return parts.suffix(2).joined(separator: ".")
        }
        return query
    }
}

// MARK: - Supporting Types

public struct TunnelAnalysisResult {
    public var isTunnel: Bool = false
    public var tunnelType: TunnelType?
    public var confidence: Double = 0
    public var evidence: [String] = []

    public var alert: TunnelAlert? {
        guard isTunnel, let type = tunnelType else { return nil }

        let severity: AlertSeverity
        switch confidence {
        case 0.9...1.0: severity = .critical
        case 0.7..<0.9: severity = .high
        case 0.5..<0.7: severity = .medium
        default: severity = .low
        }

        return TunnelAlert(
            type: type,
            evidence: evidence.joined(separator: "; "),
            severity: severity
        )
    }
}

private struct ConnectionKey: Hashable {
    let host: String
    let port: UInt16
}

private struct ConnectionStats {
    var firstSeen: Date
    var lastSeen: Date
    var totalBytes: UInt64

    var duration: TimeInterval {
        lastSeen.timeIntervalSince(firstSeen)
    }
}
