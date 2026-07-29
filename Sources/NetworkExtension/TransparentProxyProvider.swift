import Foundation
@preconcurrency import NetworkExtension
import Common

/// Safe placeholder for a transparent proxy product.
///
/// A provider must create an independent upstream connection and bridge both
/// directions. Writing data back to `NEAppProxyFlow` merely reflects it to the
/// originating application. Until a reviewed relay exists, this provider
/// refuses activation instead of corrupting or intercepting traffic.
public final class TransparentProxyProvider: NETransparentProxyProvider {
    public override func startProxy(
        options: [String: Any]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        AuditLogger.shared.log(
            eventType: .error,
            severity: .high,
            source: "TransparentProxy",
            message: "Transparent proxy refused to start: upstream relay unavailable"
        )
        completionHandler(TransparentProxyError.upstreamRelayUnavailable)
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

private enum TransparentProxyError: LocalizedError {
    case upstreamRelayUnavailable

    var errorDescription: String? {
        "Transparent proxy upstream relay is not configured"
    }
}
