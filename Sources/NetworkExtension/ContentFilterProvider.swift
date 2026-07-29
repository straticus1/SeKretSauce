import Foundation
import NetworkExtension
import Common
import TunnelDetection

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

        if let socketFlow = flow as? NEFilterSocketFlow {
            return handleSocketFlow(socketFlow, sourceApp: "unknown")
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
                let normalizedHost = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
                let normalizedPattern = pattern.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
                if normalizedHost == normalizedPattern
                    || normalizedHost.hasSuffix("." + normalizedPattern) {
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

}
