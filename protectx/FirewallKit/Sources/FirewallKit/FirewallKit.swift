// FirewallKit - Core library for macOS firewall management
// Part of Rampart: "One Place to Rule Them All"

import Foundation

/// Unified interface for macOS firewall management
public final class FirewallKit {

    public let pf: PFManager
    public let appFirewall: AppFirewallManager
    public let netState: NetStateMonitor

    public init() {
        self.pf = PFManager()
        self.appFirewall = AppFirewallManager()
        self.netState = NetStateMonitor()
    }

    // MARK: - Quick Actions

    /// Block an IP address across all interfaces
    public func blockIP(_ ip: String) throws {
        try pf.addRule(.block(from: ip))
    }

    /// Allow an application through the firewall
    public func allowApp(at path: String) throws {
        try appFirewall.addRule(.allow(path: path))
    }

    /// Get current firewall status
    public func status() -> FirewallStatus {
        FirewallStatus(
            pfEnabled: pf.isEnabled,
            appFirewallEnabled: appFirewall.isEnabled,
            activeConnections: netState.connectionCount
        )
    }
}

// MARK: - Status Types

public struct FirewallStatus {
    public let pfEnabled: Bool
    public let appFirewallEnabled: Bool
    public let activeConnections: Int

    public var summary: String {
        """
        PF (Packet Filter): \(pfEnabled ? "ON" : "OFF")
        Application Firewall: \(appFirewallEnabled ? "ON" : "OFF")
        Active Connections: \(activeConnections)
        """
    }
}
