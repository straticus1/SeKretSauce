import Foundation

// MARK: - Tunnel Detection Models

public enum TunnelType: String, Codable, CaseIterable {
    case sshTunnel = "SSH Tunnel"
    case cloudflareTunnel = "Cloudflare Tunnel"
    case ngrok = "ngrok"
    case tailscale = "Tailscale"
    case wireguard = "WireGuard"
    case openVPN = "OpenVPN"
    case dnsTunnel = "DNS Tunnel"
    case icmpTunnel = "ICMP Tunnel"
    case httpTunnel = "HTTP CONNECT Tunnel"
    case websocketTunnel = "WebSocket Tunnel"
    case unknown = "Unknown Tunnel"
}

public enum AlertSeverity: String, Codable, Comparable {
    case info = "INFO"
    case low = "LOW"
    case medium = "MEDIUM"
    case high = "HIGH"
    case critical = "CRITICAL"

    public static func < (lhs: AlertSeverity, rhs: AlertSeverity) -> Bool {
        let order: [AlertSeverity] = [.info, .low, .medium, .high, .critical]
        guard let lhsIndex = order.firstIndex(of: lhs),
              let rhsIndex = order.firstIndex(of: rhs) else { return false }
        return lhsIndex < rhsIndex
    }
}

public struct TunnelAlert: Codable, Identifiable {
    public let id: UUID
    public let type: TunnelType
    public let evidence: String
    public let severity: AlertSeverity
    public let timestamp: Date
    public let processInfo: ProcessMetadata?
    public let networkInfo: NetworkMetadata?

    public init(
        id: UUID = UUID(),
        type: TunnelType,
        evidence: String,
        severity: AlertSeverity,
        timestamp: Date = Date(),
        processInfo: ProcessMetadata? = nil,
        networkInfo: NetworkMetadata? = nil
    ) {
        self.id = id
        self.type = type
        self.evidence = evidence
        self.severity = severity
        self.timestamp = timestamp
        self.processInfo = processInfo
        self.networkInfo = networkInfo
    }
}

public struct ProcessMetadata: Codable {
    public let pid: Int32
    public let ppid: Int32
    public let path: String
    public let arguments: [String]
    public let user: String
    public let timestamp: Date

    public init(pid: Int32, ppid: Int32, path: String, arguments: [String], user: String, timestamp: Date = Date()) {
        self.pid = pid
        self.ppid = ppid
        self.path = path
        self.arguments = arguments
        self.user = user
        self.timestamp = timestamp
    }
}

public struct NetworkMetadata: Codable {
    public let sourceIP: String?
    public let sourcePort: UInt16?
    public let destinationIP: String?
    public let destinationPort: UInt16?
    public let `protocol`: NetworkProtocol
    public let bytesIn: UInt64?
    public let bytesOut: UInt64?

    public init(
        sourceIP: String? = nil,
        sourcePort: UInt16? = nil,
        destinationIP: String? = nil,
        destinationPort: UInt16? = nil,
        protocol: NetworkProtocol = .tcp,
        bytesIn: UInt64? = nil,
        bytesOut: UInt64? = nil
    ) {
        self.sourceIP = sourceIP
        self.sourcePort = sourcePort
        self.destinationIP = destinationIP
        self.destinationPort = destinationPort
        self.protocol = `protocol`
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
    }
}

public enum NetworkProtocol: String, Codable {
    case tcp = "TCP"
    case udp = "UDP"
    case icmp = "ICMP"
    case other = "OTHER"
}

// MARK: - SSH Session Models

public struct SSHSession: Codable, Identifiable {
    public let id: UUID
    public let startTime: Date
    public var endTime: Date?
    public let user: String
    public let sourceHost: String
    public let destinationHost: String
    public let destinationPort: UInt16
    public let command: String
    public let arguments: [String]
    public let recordingPath: String?
    public var tunnelFlags: [SSHTunnelFlag]

    public init(
        id: UUID = UUID(),
        startTime: Date = Date(),
        endTime: Date? = nil,
        user: String,
        sourceHost: String,
        destinationHost: String,
        destinationPort: UInt16 = 22,
        command: String,
        arguments: [String],
        recordingPath: String? = nil,
        tunnelFlags: [SSHTunnelFlag] = []
    ) {
        self.id = id
        self.startTime = startTime
        self.endTime = endTime
        self.user = user
        self.sourceHost = sourceHost
        self.destinationHost = destinationHost
        self.destinationPort = destinationPort
        self.command = command
        self.arguments = arguments
        self.recordingPath = recordingPath
        self.tunnelFlags = tunnelFlags
    }
}

public struct SSHTunnelFlag: Codable {
    public let type: SSHTunnelType
    public let bindAddress: String?
    public let bindPort: UInt16
    public let targetHost: String?
    public let targetPort: UInt16?

    public init(type: SSHTunnelType, bindAddress: String? = nil, bindPort: UInt16, targetHost: String? = nil, targetPort: UInt16? = nil) {
        self.type = type
        self.bindAddress = bindAddress
        self.bindPort = bindPort
        self.targetHost = targetHost
        self.targetPort = targetPort
    }
}

public enum SSHTunnelType: String, Codable {
    case localForward = "Local Forward (-L)"
    case remoteForward = "Remote Forward (-R)"
    case dynamicSOCKS = "Dynamic SOCKS (-D)"
    case tunDevice = "TUN Device (-w)"
}

// MARK: - DNS Models

public struct DNSQuery: Codable {
    public let id: UUID
    public let timestamp: Date
    public let queryName: String
    public let queryType: DNSQueryType
    public let sourceApp: String?
    public let sourceIP: String?
    public let response: [String]?
    public let blocked: Bool
    public let tunnelSuspicion: Double?

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        queryName: String,
        queryType: DNSQueryType,
        sourceApp: String? = nil,
        sourceIP: String? = nil,
        response: [String]? = nil,
        blocked: Bool = false,
        tunnelSuspicion: Double? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.queryName = queryName
        self.queryType = queryType
        self.sourceApp = sourceApp
        self.sourceIP = sourceIP
        self.response = response
        self.blocked = blocked
        self.tunnelSuspicion = tunnelSuspicion
    }
}

public enum DNSQueryType: UInt16, Codable {
    case a = 1
    case ns = 2
    case cname = 5
    case soa = 6
    case ptr = 12
    case mx = 15
    case txt = 16
    case aaaa = 28
    case srv = 33
    case null = 10
    case any = 255
    case unknown = 0

    public init(rawValue: UInt16) {
        switch rawValue {
        case 1: self = .a
        case 2: self = .ns
        case 5: self = .cname
        case 6: self = .soa
        case 12: self = .ptr
        case 15: self = .mx
        case 16: self = .txt
        case 28: self = .aaaa
        case 33: self = .srv
        case 10: self = .null
        case 255: self = .any
        default: self = .unknown
        }
    }
}

// MARK: - Audit Log Models

public struct AuditEvent: Codable, Identifiable {
    public let id: UUID
    public let timestamp: Date
    public let eventType: AuditEventType
    public let severity: AlertSeverity
    public let source: String
    public let message: String
    public let metadata: [String: String]

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        eventType: AuditEventType,
        severity: AlertSeverity,
        source: String,
        message: String,
        metadata: [String: String] = [:]
    ) {
        self.id = id
        self.timestamp = timestamp
        self.eventType = eventType
        self.severity = severity
        self.source = source
        self.message = message
        self.metadata = metadata
    }
}

public enum AuditEventType: String, Codable {
    case systemStart = "SYSTEM_START"
    case systemStop = "SYSTEM_STOP"
    case authSuccess = "AUTH_SUCCESS"
    case authFailure = "AUTH_FAILURE"
    case sshSessionStart = "SSH_SESSION_START"
    case sshSessionEnd = "SSH_SESSION_END"
    case sshTunnelDetected = "SSH_TUNNEL_DETECTED"
    case tunnelAlertRaised = "TUNNEL_ALERT"
    case dnsQuery = "DNS_QUERY"
    case dnsBlocked = "DNS_BLOCKED"
    case processExec = "PROCESS_EXEC"
    case networkConnection = "NETWORK_CONNECTION"
    case configChange = "CONFIG_CHANGE"
    case error = "ERROR"
}

// MARK: - Configuration Models

public struct AgentConfiguration: Codable {
    public var serverURL: String
    public var apiKey: String?
    public var logLevel: LogLevel
    public var enableSSHRecording: Bool
    public var enableDNSMonitoring: Bool
    public var enableTunnelDetection: Bool
    public var enableProcessMonitoring: Bool
    public var blockedDomains: [String]
    public var allowedTunnelProcesses: [String]
    public var maxLogRetentionDays: Int
    public var syncIntervalSeconds: Int

    public init(
        serverURL: String = "",
        apiKey: String? = nil,
        logLevel: LogLevel = .info,
        enableSSHRecording: Bool = true,
        enableDNSMonitoring: Bool = true,
        enableTunnelDetection: Bool = true,
        enableProcessMonitoring: Bool = true,
        blockedDomains: [String] = [],
        allowedTunnelProcesses: [String] = [],
        maxLogRetentionDays: Int = 90,
        syncIntervalSeconds: Int = 60
    ) {
        self.serverURL = serverURL
        self.apiKey = apiKey
        self.logLevel = logLevel
        self.enableSSHRecording = enableSSHRecording
        self.enableDNSMonitoring = enableDNSMonitoring
        self.enableTunnelDetection = enableTunnelDetection
        self.enableProcessMonitoring = enableProcessMonitoring
        self.blockedDomains = blockedDomains
        self.allowedTunnelProcesses = allowedTunnelProcesses
        self.maxLogRetentionDays = maxLogRetentionDays
        self.syncIntervalSeconds = syncIntervalSeconds
    }
}

public enum LogLevel: String, Codable, Comparable {
    case debug = "DEBUG"
    case info = "INFO"
    case warning = "WARNING"
    case error = "ERROR"

    public static func < (lhs: LogLevel, rhs: LogLevel) -> Bool {
        let order: [LogLevel] = [.debug, .info, .warning, .error]
        guard let lhsIndex = order.firstIndex(of: lhs),
              let rhsIndex = order.firstIndex(of: rhs) else { return false }
        return lhsIndex < rhsIndex
    }
}

// MARK: - Tunnel Indicators

public struct TunnelIndicator {
    public let name: String
    public let tunnelType: TunnelType
    public let dnsPatterns: [String]
    public let processNames: [String]
    public let ports: [UInt16]
    public let severity: AlertSeverity

    public init(
        name: String,
        tunnelType: TunnelType,
        dnsPatterns: [String] = [],
        processNames: [String] = [],
        ports: [UInt16] = [],
        severity: AlertSeverity = .high
    ) {
        self.name = name
        self.tunnelType = tunnelType
        self.dnsPatterns = dnsPatterns
        self.processNames = processNames
        self.ports = ports
        self.severity = severity
    }
}

// MARK: - Known Tunnel Services Database

public struct TunnelDatabase {
    public static let indicators: [TunnelIndicator] = [
        TunnelIndicator(
            name: "Cloudflare Tunnel",
            tunnelType: .cloudflareTunnel,
            dnsPatterns: [
                "argotunnel.com",
                "cftunnel.com",
                "cloudflareaccess.com",
                "cloudflare-dns.com",
                "trycloudflare.com"
            ],
            processNames: ["cloudflared"],
            ports: [7844],
            severity: .high
        ),
        TunnelIndicator(
            name: "ngrok",
            tunnelType: .ngrok,
            dnsPatterns: [
                "ngrok.io",
                "ngrok.com",
                "ngrok-agent.com",
                "tunnel.us.ngrok.com",
                "tunnel.eu.ngrok.com",
                "tunnel.ap.ngrok.com"
            ],
            processNames: ["ngrok"],
            ports: [4443],
            severity: .high
        ),
        TunnelIndicator(
            name: "Tailscale",
            tunnelType: .tailscale,
            dnsPatterns: [
                "tailscale.com",
                "tailscale.io",
                "ts.net",
                "login.tailscale.com",
                "controlplane.tailscale.com"
            ],
            processNames: ["tailscaled", "tailscale"],
            ports: [41641],
            severity: .medium
        ),
        TunnelIndicator(
            name: "WireGuard",
            tunnelType: .wireguard,
            dnsPatterns: [],
            processNames: ["wireguard-go", "wg", "wg-quick"],
            ports: [51820],
            severity: .medium
        ),
        TunnelIndicator(
            name: "OpenVPN",
            tunnelType: .openVPN,
            dnsPatterns: [],
            processNames: ["openvpn"],
            ports: [1194],
            severity: .medium
        ),
        TunnelIndicator(
            name: "localtunnel",
            tunnelType: .unknown,
            dnsPatterns: ["localtunnel.me", "loca.lt"],
            processNames: ["lt"],
            ports: [],
            severity: .high
        ),
        TunnelIndicator(
            name: "serveo",
            tunnelType: .sshTunnel,
            dnsPatterns: ["serveo.net"],
            processNames: [],
            ports: [],
            severity: .high
        ),
        TunnelIndicator(
            name: "localhost.run",
            tunnelType: .sshTunnel,
            dnsPatterns: ["localhost.run"],
            processNames: [],
            ports: [],
            severity: .high
        ),
        TunnelIndicator(
            name: "bore",
            tunnelType: .unknown,
            dnsPatterns: ["bore.pub"],
            processNames: ["bore"],
            ports: [],
            severity: .high
        ),
        TunnelIndicator(
            name: "frp",
            tunnelType: .unknown,
            dnsPatterns: [],
            processNames: ["frpc", "frps"],
            ports: [7000, 7500],
            severity: .high
        ),
        TunnelIndicator(
            name: "chisel",
            tunnelType: .unknown,
            dnsPatterns: [],
            processNames: ["chisel"],
            ports: [],
            severity: .critical
        ),
        TunnelIndicator(
            name: "rathole",
            tunnelType: .unknown,
            dnsPatterns: [],
            processNames: ["rathole"],
            ports: [],
            severity: .critical
        )
    ]
}
