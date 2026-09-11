// PFRule - Packet filter rule model
// Represents a single pf rule with parsing and generation

import Darwin
import Foundation

public struct PFRule: Identifiable, Equatable {
    public let id: UUID
    public var action: Action
    public var direction: Direction
    public var networkProtocol: NetworkProtocol?
    public var interface: String?
    public var source: Address
    public var destination: Address
    public var port: Port?
    public var flags: String?
    public var state: State?
    public var log: Bool

    public init(
        id: UUID = UUID(),
        action: Action,
        direction: Direction = .any,
        networkProtocol: NetworkProtocol? = nil,
        interface: String? = nil,
        source: Address = .any,
        destination: Address = .any,
        port: Port? = nil,
        flags: String? = nil,
        state: State? = nil,
        log: Bool = false
    ) {
        self.id = id
        self.action = action
        self.direction = direction
        self.networkProtocol = networkProtocol
        self.interface = interface
        self.source = source
        self.destination = destination
        self.port = port
        self.flags = flags
        self.state = state
        self.log = log
    }

    // MARK: - Quick constructors

    public static func block(from ip: String) -> PFRule {
        PFRule(
            action: .block,
            direction: .in,
            source: .host(ip),
            log: true
        )
    }

    public static func block(to ip: String) -> PFRule {
        PFRule(
            action: .block,
            direction: .out,
            destination: .host(ip),
            log: true
        )
    }

    public static func allow(port: UInt16, protocol proto: NetworkProtocol = .tcp) -> PFRule {
        PFRule(
            action: .pass,
            direction: .in,
            networkProtocol: proto,
            port: .single(port),
            state: .keepState
        )
    }

    public static func allowOut(to ip: String, port: UInt16? = nil) -> PFRule {
        PFRule(
            action: .pass,
            direction: .out,
            destination: .host(ip),
            port: port.map { .single($0) },
            state: .keepState
        )
    }
}

// MARK: - Types

extension PFRule {

    public enum Action: String, CaseIterable {
        case pass
        case block
        case match
    }

    public enum Direction: String, CaseIterable {
        case `in`
        case out
        case any

        public var pfSyntax: String {
            switch self {
            case .any: return ""
            case .in: return "in"
            case .out: return "out"
            }
        }
    }

    public enum NetworkProtocol: String, CaseIterable {
        case tcp
        case udp
        case icmp
        case any

        public var pfSyntax: String {
            self == .any ? "" : "proto \(rawValue)"
        }
    }

    public enum Address: Equatable {
        case any
        case host(String)
        case network(String, Int)  // CIDR: ip, prefix
        case table(String)

        public var pfSyntax: String {
            switch self {
            case .any:
                return "any"
            case .host(let ip):
                return ip
            case .network(let ip, let prefix):
                return "\(ip)/\(prefix)"
            case .table(let name):
                return "<\(name)>"
            }
        }

        public var displayName: String {
            switch self {
            case .any:
                return "Any"
            case .host(let ip):
                return ip
            case .network(let ip, let prefix):
                return "\(ip)/\(prefix)"
            case .table(let name):
                return "Table: \(name)"
            }
        }
    }

    public enum Port: Equatable {
        case single(UInt16)
        case range(UInt16, UInt16)
        case list([UInt16])

        public var pfSyntax: String {
            switch self {
            case .single(let p):
                return "port \(p)"
            case .range(let start, let end):
                return "port \(start):\(end)"
            case .list(let ports):
                return "port { \(ports.map(String.init).joined(separator: ", ")) }"
            }
        }

        public var displayName: String {
            switch self {
            case .single(let p):
                return String(p)
            case .range(let start, let end):
                return "\(start)-\(end)"
            case .list(let ports):
                return ports.map(String.init).joined(separator: ", ")
            }
        }
    }

    public enum State: String, CaseIterable {
        case keepState = "keep state"
        case modulateState = "modulate state"
        case synproxyState = "synproxy state"
    }
}

// MARK: - PF Syntax Generation

extension PFRule {

    public func validate() throws {
        if let interface {
            guard
                interface.range(
                    of: #"^[A-Za-z0-9][A-Za-z0-9._:-]{0,31}$"#,
                    options: .regularExpression
                ) != nil
            else {
                throw PFRuleValidationError.invalidInterface
            }
        }

        try Self.validate(address: source)
        try Self.validate(address: destination)

        if let port {
            switch port {
            case .single:
                break
            case .range(let start, let end):
                guard start <= end else {
                    throw PFRuleValidationError.invalidPort
                }
            case .list(let ports):
                guard !ports.isEmpty else {
                    throw PFRuleValidationError.invalidPort
                }
            }
        }

        if let flags {
            guard networkProtocol == .tcp,
                flags.range(
                    of: #"^[FSRPAUEW]+(?:/[FSRPAUEW]+)?$"#,
                    options: [.regularExpression, .caseInsensitive]
                ) != nil
            else {
                throw PFRuleValidationError.invalidFlags
            }
        }
    }

    private static func validate(address: Address) throws {
        switch address {
        case .any:
            return
        case .host(let address):
            guard address.containsNoControlCharacters, ipFamily(address) != nil else {
                throw PFRuleValidationError.invalidAddress
            }
        case .network(let address, let prefix):
            guard address.containsNoControlCharacters,
                let family = ipFamily(address),
                (family == AF_INET && (0...32).contains(prefix))
                    || (family == AF_INET6 && (0...128).contains(prefix))
            else {
                throw PFRuleValidationError.invalidNetwork
            }
        case .table(let name):
            guard
                name.range(
                    of: #"^[A-Za-z_][A-Za-z0-9_-]{0,62}$"#,
                    options: .regularExpression
                ) != nil
            else {
                throw PFRuleValidationError.invalidTable
            }
        }
    }

    private static func ipFamily(_ address: String) -> Int32? {
        var ipv4 = in_addr()
        if address.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            return AF_INET
        }

        var ipv6 = in6_addr()
        if address.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
            return AF_INET6
        }

        return nil
    }

    public func toPFSyntax() -> String {
        var parts: [String] = []

        // Action
        parts.append(action.rawValue)

        // Direction
        if direction != .any {
            parts.append(direction.rawValue)
        }

        // Log
        if log {
            parts.append("log")
        }

        // Interface
        if let iface = interface {
            parts.append("on \(iface)")
        }

        // Protocol
        if let proto = networkProtocol, proto != .any {
            parts.append("proto \(proto.rawValue)")
        }

        // Source
        parts.append("from \(source.pfSyntax)")

        // Destination
        parts.append("to \(destination.pfSyntax)")

        // Port
        if let port = port {
            parts.append(port.pfSyntax)
        }

        // Flags (for TCP)
        if let flags = flags {
            parts.append("flags \(flags)")
        }

        // State
        if let state = state {
            parts.append(state.rawValue)
        }

        return parts.joined(separator: " ")
    }

    public var description: String {
        let actionEmoji = action == .block ? "🚫" : "✅"
        let dirArrow = direction == .in ? "←" : (direction == .out ? "→" : "↔")
        let proto = networkProtocol?.rawValue.uppercased() ?? "ANY"
        let portStr = port?.displayName ?? "*"

        return
            "\(actionEmoji) \(dirArrow) \(proto) \(source.displayName) → \(destination.displayName):\(portStr)"
    }
}

extension String {
    fileprivate var containsNoControlCharacters: Bool {
        !unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }
}

public enum PFRuleValidationError: Error, LocalizedError {
    case invalidInterface
    case invalidAddress
    case invalidNetwork
    case invalidTable
    case invalidPort
    case invalidFlags

    public var errorDescription: String? {
        switch self {
        case .invalidInterface:
            return "Invalid network interface"
        case .invalidAddress:
            return "PF host addresses must be valid IPv4 or IPv6 addresses"
        case .invalidNetwork:
            return "PF networks must contain a valid address and CIDR prefix"
        case .invalidTable:
            return "Invalid PF table name"
        case .invalidPort:
            return "Invalid PF port specification"
        case .invalidFlags:
            return "Invalid TCP flags"
        }
    }
}

// MARK: - Parsing

extension PFRule {

    /// Parse a pf rule string into a PFRule object
    public static func parse(_ line: String) -> PFRule? {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { return nil }
        let tokens = trimmed.replacingOccurrences(of: "{", with: " { ")
            .replacingOccurrences(of: "}", with: " } ")
            .replacingOccurrences(of: ",", with: " , ")
            .split(whereSeparator: { $0.isWhitespace }).map(String.init)
        guard let first = tokens.first, let action = Action(rawValue: first) else { return nil }
        var rule = PFRule(action: action)
        var index = 1
        var seen = Set<String>()
        func next() -> String? {
            guard index < tokens.count else { return nil }
            defer { index += 1 }
            return tokens[index]
        }
        while let token = next() {
            let key = ["in", "out"].contains(token) ? "direction" : token
            guard seen.insert(key).inserted else { return nil }
            switch token {
            case "in": rule.direction = .in
            case "out": rule.direction = .out
            case "log": rule.log = true
            case "on":
                guard let value = next() else { return nil }
                rule.interface = value
            case "proto":
                guard let value = next(), let proto = NetworkProtocol(rawValue: value) else { return nil }
                rule.networkProtocol = proto
            case "from", "to":
                guard let value = next(), let address = parseAddress(value) else { return nil }
                if token == "from" { rule.source = address } else { rule.destination = address }
            case "port":
                // This model supports destination ports only.
                guard seen.contains("to"), var value = next() else { return nil }
                if value == "=" {
                    guard let following = next() else { return nil }
                    value = following
                }
                if value == "{" {
                    var ports: [UInt16] = []
                    guard let first = next(), let port = UInt16(first) else { return nil }
                    ports.append(port)
                    while true {
                        guard let separator = next() else { return nil }
                        if separator == "}" { break }
                        guard separator == ",", let raw = next(), let p = UInt16(raw) else { return nil }
                        ports.append(p)
                    }
                    rule.port = .list(ports)
                } else if value.contains(":") {
                    let parts = value.split(separator: ":", omittingEmptySubsequences: false)
                    guard parts.count == 2, let start = UInt16(parts[0]), let end = UInt16(parts[1]) else {
                        return nil
                    }
                    rule.port = .range(start, end)
                } else {
                    guard let port = UInt16(value) else { return nil }
                    rule.port = .single(port)
                }
            case "flags":
                guard let value = next() else { return nil }
                rule.flags = value
            case "keep", "modulate", "synproxy":
                guard !seen.contains("state"), next() == "state" else { return nil }
                seen.insert("state")
                rule.state = State(rawValue: "\(token) state")
            default: return nil  // Never silently turn unsupported syntax into a different rule.
            }
        }
        guard seen.contains("from"), seen.contains("to"), (try? rule.validate()) != nil else {
            return nil
        }
        return rule
    }

    private static func parseAddress(_ value: String) -> Address? {
        if value == "any" { return .any }
        if value.hasPrefix("<"), value.hasSuffix(">") {
            return .table(String(value.dropFirst().dropLast()))
        }
        if value.contains("/") {
            let parts = value.split(separator: "/", omittingEmptySubsequences: false)
            guard parts.count == 2, let prefix = Int(parts[1]) else { return nil }
            return .network(String(parts[0]), prefix)
        }
        return .host(value)
    }
}
