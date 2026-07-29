import Foundation
import Common

/// Specialized detector for Cloudflare Tunnel (cloudflared)
/// Detects both the process and network indicators
public final class CloudflareTunnelDetector: @unchecked Sendable {

    public static let shared = CloudflareTunnelDetector()

    private let auditLogger = AuditLogger.shared

    // Cloudflare tunnel indicators
    private let cloudflareDomains = [
        "argotunnel.com",
        "cftunnel.com",
        "cloudflareaccess.com",
        "trycloudflare.com",
        "cloudflare-dns.com",
        "one.one.one.one",
        "cloudflare.com"
    ]

    // Cloudflare IP ranges (WARP/Tunnel)
    private let cloudflareIPRanges = [
        "104.16.0.0/12",
        "172.64.0.0/13",
        "131.0.72.0/22",
        "198.41.128.0/17"
    ]

    // Known cloudflared ports
    private let cloudflarePorts: [UInt16] = [
        7844,  // Default cloudflared port
        443,   // HTTPS (often used)
        80     // HTTP fallback
    ]

    private init() {}

    // MARK: - Process Detection

    /// Check if a process is cloudflared or related
    public func detectProcess(path: String, arguments: [String]) -> TunnelAlert? {
        let processName = (path as NSString).lastPathComponent.lowercased()

        // Direct cloudflared detection
        if processName == "cloudflared" {
            return createAlert(
                evidence: "Cloudflare Tunnel process detected: \(path)",
                severity: .high,
                processPath: path,
                arguments: arguments
            )
        }

        // Check for cloudflared in arguments (e.g., running via shell)
        let argsString = arguments.joined(separator: " ")
        if argsString.contains("cloudflared") {
            return createAlert(
                evidence: "Cloudflare Tunnel executable referenced by command arguments",
                severity: .high,
                processPath: path,
                arguments: arguments
            )
        }

        // Check for tunnel subcommand patterns
        let tunnelPatterns = [
            "tunnel run",
            "tunnel --url",
            "tunnel --hostname",
            "access tcp",
            "access ssh"
        ]

        for pattern in tunnelPatterns {
            if argsString.lowercased().contains(pattern) {
                return createAlert(
                    evidence: "Cloudflare Tunnel command pattern detected: \(pattern)",
                    severity: .high,
                    processPath: path,
                    arguments: arguments
                )
            }
        }

        return nil
    }

    // MARK: - DNS Detection

    /// Check DNS query for Cloudflare tunnel indicators
    public func detectDNS(query: String) -> TunnelAlert? {
        let lowercaseQuery = query.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))

        if lowercaseQuery == "trycloudflare.com"
            || lowercaseQuery.hasSuffix(".trycloudflare.com") {
            return createAlert(
                evidence: "Quick Cloudflare Tunnel detected: \(query)",
                severity: .critical,
                dnsQuery: query
            )
        }

        for domain in cloudflareDomains {
            if lowercaseQuery == domain || lowercaseQuery.hasSuffix(".\(domain)") {
                // Higher confidence for tunnel-specific domains
                let severity: AlertSeverity
                if domain == "argotunnel.com" || domain == "cftunnel.com" || domain == "trycloudflare.com" {
                    severity = .high
                } else {
                    severity = .medium
                }

                return createAlert(
                    evidence: "DNS query to Cloudflare Tunnel domain: \(query)",
                    severity: severity,
                    dnsQuery: query
                )
            }
        }

        return nil
    }

    // MARK: - Connection Detection

    /// Check network connection for Cloudflare tunnel indicators
    public func detectConnection(host: String, port: UInt16, destinationIP: String? = nil) -> TunnelAlert? {
        let lowercaseHost = host.lowercased()

        // Check hostname
        for domain in cloudflareDomains {
            if lowercaseHost.hasSuffix(domain) {
                let severity: AlertSeverity = cloudflarePorts.contains(port) ? .high : .medium

                return createAlert(
                    evidence: "Connection to Cloudflare domain: \(host):\(port)",
                    severity: severity,
                    networkHost: host,
                    networkPort: port
                )
            }
        }

        // Check for default cloudflared port
        if port == 7844 {
            return createAlert(
                evidence: "Connection to Cloudflare Tunnel default port: \(host):7844",
                severity: .high,
                networkHost: host,
                networkPort: port
            )
        }

        // Check IP ranges (if provided)
        if let ip = destinationIP, isCloudflareIP(ip) {
            // Only alert if combined with suspicious port
            if cloudflarePorts.contains(port) {
                return createAlert(
                    evidence: "Connection to Cloudflare IP range: \(ip):\(port)",
                    severity: .medium,
                    networkHost: host,
                    networkPort: port
                )
            }
        }

        return nil
    }

    // MARK: - TLS Detection

    /// Check TLS SNI for Cloudflare tunnel indicators
    public func detectTLS(sni: String) -> TunnelAlert? {
        let lowercaseSNI = sni.lowercased()

        for domain in cloudflareDomains {
            if lowercaseSNI.hasSuffix(domain) || lowercaseSNI == domain {
                let severity: AlertSeverity
                if domain == "argotunnel.com" || domain == "cftunnel.com" || domain == "trycloudflare.com" {
                    severity = .high
                } else {
                    severity = .low  // Regular Cloudflare usage
                }

                return createAlert(
                    evidence: "TLS connection with Cloudflare SNI: \(sni)",
                    severity: severity,
                    tlsSNI: sni
                )
            }
        }

        return nil
    }

    // MARK: - Configuration File Detection

    /// Check if a file path is a cloudflared config
    public func detectConfigFile(path: String) -> TunnelAlert? {
        let configPatterns = [
            ".cloudflared",
            "cloudflared.yml",
            "cloudflared.yaml",
            "config.yml",  // in cloudflared directory
            "cert.pem"     // cloudflared certificate
        ]

        let lowercasePath = path.lowercased()

        for pattern in configPatterns {
            if lowercasePath.contains(pattern) && lowercasePath.contains("cloudflare") {
                return createAlert(
                    evidence: "Cloudflare Tunnel configuration file accessed: \(path)",
                    severity: .medium,
                    filePath: path
                )
            }
        }

        // Check for cloudflared home directory
        if lowercasePath.contains(".cloudflared") {
            return createAlert(
                evidence: "Cloudflare Tunnel configuration directory accessed: \(path)",
                severity: .medium,
                filePath: path
            )
        }

        return nil
    }

    // MARK: - Helpers

    private func isCloudflareIP(_ ip: String) -> Bool {
        // Simplified check - in production use proper CIDR matching
        let cloudflareRanges = [
            "104.16.", "104.17.", "104.18.", "104.19.",
            "104.20.", "104.21.", "104.22.", "104.23.",
            "104.24.", "104.25.", "104.26.", "104.27.",
            "172.64.", "172.65.", "172.66.", "172.67.",
            "131.0.72.", "131.0.73.", "131.0.74.", "131.0.75.",
            "198.41."
        ]

        for range in cloudflareRanges {
            if ip.hasPrefix(range) {
                return true
            }
        }

        return false
    }

    private func createAlert(
        evidence: String,
        severity: AlertSeverity,
        processPath: String? = nil,
        arguments: [String]? = nil,
        dnsQuery: String? = nil,
        networkHost: String? = nil,
        networkPort: UInt16? = nil,
        tlsSNI: String? = nil,
        filePath: String? = nil
    ) -> TunnelAlert {
        var processInfo: ProcessMetadata?
        if let path = processPath {
            processInfo = ProcessMetadata(
                pid: 0,
                ppid: 0,
                path: path,
                arguments: SensitiveDataRedactor.redact(arguments: arguments ?? []),
                user: ProcessInfo.processInfo.environment["USER"] ?? "unknown"
            )
        }

        var networkInfo: NetworkMetadata?
        if let host = networkHost {
            networkInfo = NetworkMetadata(
                destinationIP: host,
                destinationPort: networkPort,
                protocol: .tcp
            )
        }

        return TunnelAlert(
            type: .cloudflareTunnel,
            evidence: evidence,
            severity: severity,
            processInfo: processInfo,
            networkInfo: networkInfo
        )
    }
}
