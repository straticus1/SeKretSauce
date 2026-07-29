import Foundation
@preconcurrency import NetworkExtension
import Common

/// DNS interception remains disabled until the provider has a real upstream
/// resolver transport. Reflecting a query with `writeDatagrams` is not DNS
/// forwarding and can leak, loop, or corrupt user traffic.
public final class DNSProxyProvider: NEDNSProxyProvider {
    public override func startProxy(
        options: [String: Any]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        AuditLogger.shared.log(
            eventType: .error,
            severity: .high,
            source: "DNSProxy",
            message: "DNS proxy refused to start: upstream resolver unavailable"
        )
        completionHandler(DNSProxyError.upstreamResolverUnavailable)
    }

    public override func stopProxy(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        completionHandler()
    }

    public override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        false
    }
}

private enum DNSProxyError: LocalizedError {
    case upstreamResolverUnavailable

    var errorDescription: String? {
        "DNS proxy upstream resolver relay is not configured"
    }
}
