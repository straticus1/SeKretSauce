import Foundation
import NetworkExtension

/// Content Filter Provider - Provides deep packet inspection capabilities
/// For WebKit-based traffic and URL filtering
public class ContentFilterDataProvider: NEFilterDataProvider {

    private let auditLogger = AuditLogger.shared
    private var flowCount: UInt64 = 0

    // MARK: - Lifecycle

    override public func startFilter(completionHandler: @escaping (Error?) -> Void) {
        auditLogger.log(
            eventType: .systemStart,
            severity: .info,
            source: "ContentFilter",
            message: "Content Filter starting"
        )

        completionHandler(nil)
    }

    override public func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        auditLogger.log(
            eventType: .systemStop,
            severity: .info,
            source: "ContentFilter",
            message: "Content Filter stopping, reason: \(reason.rawValue), flows: \(flowCount)"
        )

        completionHandler()
    }

    // MARK: - Flow Handling

    override public func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        flowCount += 1

        // Get flow metadata
        let sourceAppIdentifier = flow.sourceAppIdentifier ?? "unknown"

        // Check if this is a browser flow with URL info
        if let browserFlow = flow as? NEFilterBrowserFlow {
            return handleBrowserFlow(browserFlow, sourceApp: sourceAppIdentifier)
        }

        // Check socket flow
        if let socketFlow = flow as? NEFilterSocketFlow {
            return handleSocketFlow(socketFlow, sourceApp: sourceAppIdentifier)
        }

        return .allow()
    }

    // MARK: - Browser Flow Handling

    private func handleBrowserFlow(_ flow: NEFilterBrowserFlow, sourceApp: String) -> NEFilterNewFlowVerdict {
        guard let url = flow.url else {
            return .allow()
        }

        let urlString = url.absoluteString
        let host = url.host ?? ""

        // Check against tunnel indicators
        for indicator in TunnelDatabase.indicators {
            for pattern in indicator.dnsPatterns {
                if host.lowercased().contains(pattern.lowercased()) {
                    // Log tunnel alert
                    let alert = TunnelAlert(
                        type: indicator.tunnelType,
                        evidence: "Browser access to tunnel service: \(urlString)",
                        severity: indicator.severity,
                        processInfo: ProcessMetadata(
                            pid: 0,
                            ppid: 0,
                            path: sourceApp,
                            arguments: [],
                            user: "unknown"
                        ),
                        networkInfo: NetworkMetadata(
                            destinationIP: host,
                            destinationPort: UInt16(url.port ?? 443),
                            protocol: .tcp
                        )
                    )

                    auditLogger.logTunnelAlert(alert)

                    // Optionally block
                    // return .drop()
                }
            }
        }

        // Log interesting URLs
        if shouldLogURL(url) {
            auditLogger.log(
                eventType: .networkConnection,
                severity: .info,
                source: "ContentFilter",
                message: "Browser request: \(urlString)",
                metadata: [
                    "source_app": sourceApp,
                    "host": host,
                    "scheme": url.scheme ?? "unknown"
                ]
            )
        }

        return .allow()
    }

    // MARK: - Socket Flow Handling

    private func handleSocketFlow(_ flow: NEFilterSocketFlow, sourceApp: String) -> NEFilterNewFlowVerdict {
        guard let remoteEndpoint = flow.remoteEndpoint as? NWHostEndpoint else {
            return .allow()
        }

        let host = remoteEndpoint.hostname
        let port = UInt16(remoteEndpoint.port) ?? 0

        // Check for tunnel indicators
        for indicator in TunnelDatabase.indicators {
            // Check domains
            for pattern in indicator.dnsPatterns {
                if host.lowercased().contains(pattern.lowercased()) {
                    let alert = TunnelAlert(
                        type: indicator.tunnelType,
                        evidence: "Socket connection to tunnel service: \(host):\(port)",
                        severity: indicator.severity,
                        processInfo: ProcessMetadata(
                            pid: 0,
                            ppid: 0,
                            path: sourceApp,
                            arguments: [],
                            user: "unknown"
                        ),
                        networkInfo: NetworkMetadata(
                            destinationIP: host,
                            destinationPort: port,
                            protocol: .tcp
                        )
                    )

                    auditLogger.logTunnelAlert(alert)
                }
            }

            // Check ports
            if indicator.ports.contains(port) {
                auditLogger.log(
                    eventType: .networkConnection,
                    severity: .medium,
                    source: "ContentFilter",
                    message: "Connection to \(indicator.name) port",
                    metadata: [
                        "host": host,
                        "port": String(port),
                        "source_app": sourceApp
                    ]
                )
            }
        }

        return .allow()
    }

    // MARK: - Data Handling

    override public func handleInboundData(from flow: NEFilterFlow, readBytesStartOffset: Int, readBytes: Data) -> NEFilterDataVerdict {
        // Could inspect response data here
        return .allow()
    }

    override public func handleOutboundData(from flow: NEFilterFlow, readBytesStartOffset: Int, readBytes: Data) -> NEFilterDataVerdict {
        // Could inspect request data here
        return .allow()
    }

    override public func handleRemediation(for flow: NEFilterFlow) -> NEFilterRemediationVerdict {
        return .allow()
    }

    // MARK: - Helpers

    private func shouldLogURL(_ url: URL) -> Bool {
        // Log URLs to potentially interesting services
        let interestingPatterns = [
            "tunnel", "proxy", "vpn", "ngrok", "cloudflare",
            "localtunnel", "serveo", "bore", "frp"
        ]

        let urlLower = url.absoluteString.lowercased()
        return interestingPatterns.contains { urlLower.contains($0) }
    }
}

// MARK: - Content Filter Control Provider

public class ContentFilterControlProvider: NEFilterControlProvider {

    override public func startFilter(completionHandler: @escaping (Error?) -> Void) {
        completionHandler(nil)
    }

    override public func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override public func handleNewFlow(_ flow: NEFilterFlow, completionHandler: @escaping (NEFilterControlVerdict) -> Void) {
        // Default to allowing - the data provider will do detailed inspection
        completionHandler(.allow(withUpdateRules: false))
    }
}
