// ADS ProtectX CLI - "One Place to Rule Them All"
// Unified macOS firewall management

import ArgumentParser
import FirewallKit
import Foundation

@main
struct ProtectX: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "adsp",
        abstract: "ADS ProtectX - Unified macOS Firewall Control",
        version: "1.0.0",
        subcommands: [
            Status.self,
            PF.self,
            App.self,
            Net.self,
            Block.self,
            Allow.self,
        ],
        defaultSubcommand: Status.self
    )
}

// MARK: - Status Command

struct Status: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Show overall firewall status"
    )

    @Flag(name: .shortAndLong, help: "Show detailed status")
    var verbose = false

    func run() throws {
        let kit = FirewallKit()

        print("""

        ╔═══════════════════════════════════════════════════════════╗
        ║           ADS ProtectX - Firewall Status                  ║
        ╚═══════════════════════════════════════════════════════════╝

        """)

        print(kit.status().summary)
        print("")

        if verbose {
            print("─── Packet Filter (pf) ───")
            print("Enabled: \(kit.pf.isEnabled ? "YES" : "NO")")
            print("Rules: \(kit.pf.rules.count)")
            print("")

            print("─── Application Firewall ───")
            print(kit.appFirewall.statusDescription())
            print("")

            print("─── Network State ───")
            print(kit.netState.summaryDescription())
        }
    }
}

// MARK: - PF Commands

struct PF: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Packet Filter (pf) management",
        subcommands: [
            PFStatus.self,
            PFEnable.self,
            PFDisable.self,
            PFRules.self,
            PFReload.self,
        ]
    )
}

struct PFStatus: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "status",
        abstract: "Show pf status"
    )

    func run() throws {
        let pf = PFManager()
        print("Packet Filter Status")
        print("====================")
        print("Enabled: \(pf.isEnabled ? "YES" : "NO")")
        print("Rules: \(pf.rules.count)")
    }
}

struct PFEnable: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "enable",
        abstract: "Enable packet filter"
    )

    func run() throws {
        let pf = PFManager()
        try pf.enable()
        print("✅ Packet filter enabled")
    }
}

struct PFDisable: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "disable",
        abstract: "Disable packet filter"
    )

    func run() throws {
        let pf = PFManager()
        try pf.disable()
        print("⛔ Packet filter disabled")
    }
}

struct PFRules: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "rules",
        abstract: "List pf rules"
    )

    @Flag(name: .shortAndLong, help: "Show raw pf syntax")
    var raw = false

    func run() throws {
        let pf = PFManager()

        if pf.rules.isEmpty {
            print("No pf rules configured")
            return
        }

        print("PF Rules")
        print("========")

        if raw {
            for rule in pf.rules {
                print(rule.toPFSyntax())
            }
        } else {
            print(pf.rulesDescription())
        }
    }
}

struct PFReload: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "reload",
        abstract: "Reload pf rules from pf.conf"
    )

    func run() throws {
        let pf = PFManager()
        try pf.reload()
        print("✅ PF rules reloaded")
    }
}

// MARK: - App Firewall Commands

struct App: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Application Firewall management",
        subcommands: [
            AppStatus.self,
            AppEnable.self,
            AppDisable.self,
            AppList.self,
            AppAllow.self,
            AppBlock.self,
            AppStealth.self,
        ]
    )
}

struct AppStatus: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "status",
        abstract: "Show Application Firewall status"
    )

    func run() throws {
        let app = AppFirewallManager()
        print(app.statusDescription())
    }
}

struct AppEnable: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "enable",
        abstract: "Enable Application Firewall"
    )

    func run() throws {
        let app = AppFirewallManager()
        try app.enable()
        print("✅ Application Firewall enabled")
    }
}

struct AppDisable: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "disable",
        abstract: "Disable Application Firewall"
    )

    func run() throws {
        let app = AppFirewallManager()
        try app.disable()
        print("⛔ Application Firewall disabled")
    }
}

struct AppList: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "list",
        abstract: "List application rules"
    )

    func run() throws {
        let app = AppFirewallManager()
        print("Application Firewall Rules")
        print("==========================")
        print(app.appsDescription())
    }
}

struct AppAllow: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "allow",
        abstract: "Allow an application"
    )

    @Argument(help: "Path to application")
    var path: String

    func run() throws {
        let app = AppFirewallManager()
        try app.allowApp(at: path)
        print("✅ Allowed: \(path)")
    }
}

struct AppBlock: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "block",
        abstract: "Block an application"
    )

    @Argument(help: "Path to application")
    var path: String

    func run() throws {
        let app = AppFirewallManager()
        try app.blockApp(at: path)
        print("🚫 Blocked: \(path)")
    }
}

struct AppStealth: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "stealth",
        abstract: "Toggle stealth mode"
    )

    @Argument(help: "on/off")
    var state: String

    func run() throws {
        let app = AppFirewallManager()
        let enabled = state.lowercased() == "on"
        try app.setStealthMode(enabled)
        print(enabled ? "🥷 Stealth mode enabled" : "👀 Stealth mode disabled")
    }
}

// MARK: - Network Commands

struct Net: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Network state monitoring",
        subcommands: [
            NetConnections.self,
            NetListeners.self,
            NetSummary.self,
            NetWatch.self,
        ]
    )
}

struct NetConnections: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "connections",
        abstract: "Show active connections"
    )

    @Option(name: .shortAndLong, help: "Filter by process name")
    var process: String?

    @Option(name: .shortAndLong, help: "Filter by remote IP")
    var ip: String?

    @Option(name: .shortAndLong, help: "Filter by remote port")
    var port: UInt16?

    func run() throws {
        let net = NetStateMonitor()
        var conns = net.connections

        if let process = process {
            conns = net.connections(forProcess: process)
        }
        if let ip = ip {
            conns = conns.filter { $0.remoteAddress.contains(ip) }
        }
        if let port = port {
            conns = conns.filter { $0.remotePort == port }
        }

        print("Active Connections")
        print("==================")

        if conns.isEmpty {
            print("No connections matching filters")
        } else {
            for conn in conns {
                let service = conn.serviceName.map { " (\($0))" } ?? ""
                print("\(conn.processName) [\(conn.pid)] → \(conn.remoteAddress):\(conn.remotePort)\(service) (\(conn.state))")
            }
        }
    }
}

struct NetListeners: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "listeners",
        abstract: "Show listening ports"
    )

    func run() throws {
        let net = NetStateMonitor()
        print("Listening Ports")
        print("===============")
        print(net.listenersDescription())
    }
}

struct NetSummary: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "summary",
        abstract: "Show network state summary"
    )

    func run() throws {
        let net = NetStateMonitor()
        print(net.summaryDescription())
    }
}

struct NetWatch: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "watch",
        abstract: "Watch network connections in real-time"
    )

    @Option(name: .shortAndLong, help: "Refresh interval in seconds")
    var interval: UInt32 = 2

    func run() throws {
        let net = NetStateMonitor()

        print("Watching network connections (Ctrl+C to stop)...")
        print("")

        while true {
            // Clear screen
            print("\u{1B}[2J\u{1B}[H", terminator: "")

            net.refresh()

            print("RAMPART - Network Watch (\(Date().formatted()))")
            print(String(repeating: "=", count: 50))
            print("")
            print(net.summaryDescription())
            print("")
            print("─── Recent Connections ───")

            let recent = Array(net.getEstablishedConnections().prefix(15))
            for conn in recent {
                print("  \(conn.processName) → \(conn.remoteAddress):\(conn.remotePort)")
            }

            sleep(interval)
        }
    }
}

// MARK: - Quick Actions

struct Block: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Quick block an IP or app"
    )

    @Argument(help: "IP address or app path to block")
    var target: String

    func run() throws {
        let kit = FirewallKit()

        if target.contains("/") || target.hasSuffix(".app") {
            // App path
            try kit.appFirewall.blockApp(at: target)
            print("🚫 Blocked application: \(target)")
        } else {
            // IP address
            try kit.blockIP(target)
            print("🚫 Blocked IP: \(target)")
        }
    }
}

struct Allow: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Quick allow an app"
    )

    @Argument(help: "App path to allow")
    var path: String

    func run() throws {
        let kit = FirewallKit()
        try kit.allowApp(at: path)
        print("✅ Allowed: \(path)")
    }
}
