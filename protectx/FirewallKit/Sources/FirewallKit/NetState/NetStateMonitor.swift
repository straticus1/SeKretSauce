// NetStateMonitor - Network state monitoring for macOS
// Shows active connections, listening ports, and process network activity

import Foundation

public final class NetStateMonitor {

    // MARK: - Properties

    public private(set) var connections: [Connection] = []
    public private(set) var listeners: [Listener] = []

    public var connectionCount: Int { connections.count }

    public init() {
        refresh()
    }

    // MARK: - Refresh

    /// Refresh network state from system
    public func refresh() {
        connections = getConnections()
        listeners = getListeners()
    }

    // MARK: - Queries

    /// Get all established TCP connections
    public func getEstablishedConnections() -> [Connection] {
        connections.filter { $0.state == "ESTABLISHED" }
    }

    /// Get connections for a specific process
    public func connections(forPID pid: Int) -> [Connection] {
        connections.filter { $0.pid == pid }
    }

    /// Get connections for a specific process name
    public func connections(forProcess name: String) -> [Connection] {
        connections.filter { $0.processName.lowercased().contains(name.lowercased()) }
    }

    /// Get connections to a specific IP
    public func connections(toIP ip: String) -> [Connection] {
        connections.filter { $0.remoteAddress.contains(ip) }
    }

    /// Get connections to a specific port
    public func connections(toPort port: UInt16) -> [Connection] {
        connections.filter { $0.remotePort == port }
    }

    /// Get listeners on a specific port
    public func listeners(onPort port: UInt16) -> [Listener] {
        listeners.filter { $0.port == port }
    }

    // MARK: - Display

    public func connectionsDescription() -> String {
        if connections.isEmpty {
            return "No active connections"
        }

        let header = "PROTO  LOCAL               REMOTE                    STATE        PID    PROCESS"
        let separator = String(repeating: "-", count: 90)

        let rows = connections.map { conn in
            let proto = conn.protocol.padding(toLength: 5, withPad: " ", startingAt: 0)
            let local = "\(conn.localAddress):\(conn.localPort)".padding(toLength: 18, withPad: " ", startingAt: 0)
            let remote = "\(conn.remoteAddress):\(conn.remotePort)".padding(toLength: 24, withPad: " ", startingAt: 0)
            let state = conn.state.padding(toLength: 12, withPad: " ", startingAt: 0)
            let pid = String(conn.pid).padding(toLength: 6, withPad: " ", startingAt: 0)
            return "\(proto)  \(local)  \(remote)  \(state)  \(pid)  \(conn.processName)"
        }

        return ([header, separator] + rows).joined(separator: "\n")
    }

    public func listenersDescription() -> String {
        if listeners.isEmpty {
            return "No active listeners"
        }

        let header = "PROTO  ADDRESS             PORT    PID    PROCESS"
        let separator = String(repeating: "-", count: 70)

        let rows = listeners.map { listener in
            let proto = listener.protocol.padding(toLength: 5, withPad: " ", startingAt: 0)
            let addr = listener.address.padding(toLength: 18, withPad: " ", startingAt: 0)
            let port = String(listener.port).padding(toLength: 6, withPad: " ", startingAt: 0)
            let pid = String(listener.pid).padding(toLength: 6, withPad: " ", startingAt: 0)
            return "\(proto)  \(addr)  \(port)  \(pid)  \(listener.processName)"
        }

        return ([header, separator] + rows).joined(separator: "\n")
    }

    public func summaryDescription() -> String {
        let established = connections.filter { $0.state == "ESTABLISHED" }.count
        let waiting = connections.filter { $0.state.contains("WAIT") }.count

        return """
        Network State Summary
        =====================
        Total Connections:  \(connections.count)
        Established:        \(established)
        Waiting:            \(waiting)
        Listening Ports:    \(listeners.count)
        """
    }

    // MARK: - Private

    private func getConnections() -> [Connection] {
        // Use lsof for connection info (more reliable cross-version)
        let output = run("/usr/sbin/lsof", arguments: ["-i", "-n", "-P"])
        var conns: [Connection] = []

        for line in output.split(separator: "\n") {
            let parts = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)

            guard parts.count >= 9 else { continue }

            let processName = parts[0]
            let pid = Int(parts[1]) ?? 0
            let proto = parts[7].hasPrefix("TCP") ? "TCP" : "UDP"
            guard parts[7].hasPrefix("TCP") || parts[7].hasPrefix("UDP") else {
                continue
            }

            // Parse connection string: local->remote or *:port (LISTEN)
            let connStr = parts[8]

            if connStr.contains("->") {
                // Established connection
                let endpoints = connStr.split(separator: ">").map(String.init)
                if endpoints.count >= 2 {
                    let local = endpoints[0].replacingOccurrences(of: "-", with: "")
                    let remote = endpoints[1]

                    let (localAddr, localPort) = parseEndpoint(local)
                    let (remoteAddr, remotePort) = parseEndpoint(remote)

                    let state = parts.count > 9 ? parts[9].replacingOccurrences(of: "(", with: "").replacingOccurrences(of: ")", with: "") : "ESTABLISHED"

                    conns.append(Connection(
                        protocol: proto,
                        localAddress: localAddr,
                        localPort: localPort,
                        remoteAddress: remoteAddr,
                        remotePort: remotePort,
                        state: state,
                        pid: pid,
                        processName: processName
                    ))
                }
            }
        }

        return conns.sorted { $0.processName < $1.processName }
    }

    private func getListeners() -> [Listener] {
        let output = run("/usr/sbin/lsof", arguments: ["-i", "-n", "-P"])
        var listeners: [Listener] = []

        for line in output.split(separator: "\n") {
            let parts = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)

            guard parts.count >= 9 else { continue }
            guard parts.dropFirst(9).contains(where: { $0.contains("LISTEN") }) else {
                continue
            }

            let processName = parts[0]
            let pid = Int(parts[1]) ?? 0
            let proto = parts[7].hasPrefix("TCP") ? "TCP" : "UDP"

            // Parse listen address
            let listenStr = parts[8]
            let (addr, port) = parseEndpoint(listenStr)

            listeners.append(Listener(
                protocol: proto,
                address: addr,
                port: port,
                pid: pid,
                processName: processName
            ))
        }

        return listeners.sorted { $0.port < $1.port }
    }

    private func parseEndpoint(_ str: String) -> (String, UInt16) {
        // Format: address:port or *:port or [ipv6]:port
        if let lastColon = str.lastIndex(of: ":") {
            let addr = String(str[..<lastColon])
            let portStr = String(str[str.index(after: lastColon)...])
            let port = UInt16(portStr) ?? 0
            return (addr.isEmpty || addr == "*" ? "0.0.0.0" : addr, port)
        }
        return (str, 0)
    }

    private func run(_ executable: String, arguments: [String]) -> String {
        let task = Process()
        let pipe = Pipe()

        task.standardOutput = pipe
        task.standardError = pipe
        task.executableURL = URL(fileURLWithPath: executable)
        task.arguments = arguments

        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            return String(data: data, encoding: .utf8) ?? ""
        } catch {
            return ""
        }
    }
}

// MARK: - Models

public struct Connection: Identifiable {
    public let id = UUID()
    public var `protocol`: String
    public var localAddress: String
    public var localPort: UInt16
    public var remoteAddress: String
    public var remotePort: UInt16
    public var state: String
    public var pid: Int
    public var processName: String

    /// Common port name if known
    public var serviceName: String? {
        CommonPorts.name(for: remotePort)
    }
}

public struct Listener: Identifiable {
    public let id = UUID()
    public var `protocol`: String
    public var address: String
    public var port: UInt16
    public var pid: Int
    public var processName: String

    /// Common port name if known
    public var serviceName: String? {
        CommonPorts.name(for: port)
    }
}

// MARK: - Common Ports

public enum CommonPorts {
    private static let ports: [UInt16: String] = [
        20: "FTP Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        587: "SMTP Submission",
        993: "IMAPS",
        995: "POP3S",
        1080: "SOCKS",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP Proxy",
        8443: "HTTPS Alt",
        27017: "MongoDB"
    ]

    public static func name(for port: UInt16) -> String? {
        ports[port]
    }
}
