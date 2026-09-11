import Foundation

/// Shared identifiers used by the app, launchd plist, and privileged helper.
public enum FirewallXPC {
    public static let appBundleIdentifier = "com.afterdark.protectx"
    public static let helperIdentifier = "com.afterdark.protectx.helper"
    public static let launchDaemonPlistName = "\(helperIdentifier).plist"
    public static let maximumPayloadSize = 64 * 1024
}

/// The Objective-C-compatible contract exported by the privileged helper.
///
/// Keep this protocol in FirewallKit so both the GUI and helper compile against
/// exactly the same selectors and reply signatures.
@objc public protocol FirewallHelperProtocol {
    func pfEnable(reply: @escaping (Bool, String?) -> Void)
    func pfDisable(reply: @escaping (Bool, String?) -> Void)
    func pfReload(reply: @escaping (Bool, String?) -> Void)
    func pfGetStatus(reply: @escaping (Bool, Int) -> Void)
    func pfAddRule(_ ruleData: Data, reply: @escaping (Bool, String?) -> Void)
    func pfRemoveRule(at index: Int, reply: @escaping (Bool, String?) -> Void)
    func pfGetRules(reply: @escaping (Data?) -> Void)

    func appFirewallEnable(reply: @escaping (Bool, String?) -> Void)
    func appFirewallDisable(reply: @escaping (Bool, String?) -> Void)
    func appFirewallSetStealthMode(_ enabled: Bool, reply: @escaping (Bool, String?) -> Void)
    func appFirewallSetBlockAll(_ enabled: Bool, reply: @escaping (Bool, String?) -> Void)
    func appFirewallAllowApp(at path: String, reply: @escaping (Bool, String?) -> Void)
    func appFirewallBlockApp(at path: String, reply: @escaping (Bool, String?) -> Void)
    func appFirewallRemoveApp(at path: String, reply: @escaping (Bool, String?) -> Void)
    func appFirewallGetStatus(reply: @escaping (Data?) -> Void)

    func getVersion(reply: @escaping (String) -> Void)
    func ping(reply: @escaping (Bool) -> Void)
}

public enum FirewallXPCPayloadError: Error, LocalizedError {
    case payloadTooLarge
    case invalidRule
    case invalidResponse

    public var errorDescription: String? {
        switch self {
        case .payloadTooLarge:
            return "Firewall helper payload exceeds the 64 KiB limit"
        case .invalidRule:
            return "Firewall rule contains invalid or unsupported values"
        case .invalidResponse:
            return "Firewall helper returned an invalid response"
        }
    }
}

public struct PFRulePayload: Codable, Equatable {
    public var action: String
    public var direction: String
    public var networkProtocol: String?
    public var interface: String?
    public var sourceType: String
    public var sourceValue: String?
    public var sourcePrefix: Int?
    public var destinationType: String
    public var destinationValue: String?
    public var destinationPrefix: Int?
    public var portType: String?
    public var portValue: String?
    public var flags: String?
    public var state: String?
    public var log: Bool

    public init(from rule: PFRule) {
        action = rule.action.rawValue
        direction = rule.direction.rawValue
        networkProtocol = rule.networkProtocol?.rawValue
        interface = rule.interface
        flags = rule.flags
        state = rule.state?.rawValue
        log = rule.log

        switch rule.source {
        case .any:
            sourceType = "any"
        case .host(let value):
            sourceType = "host"
            sourceValue = value
        case .network(let value, let prefix):
            sourceType = "network"
            sourceValue = value
            sourcePrefix = prefix
        case .table(let value):
            sourceType = "table"
            sourceValue = value
        }

        switch rule.destination {
        case .any:
            destinationType = "any"
        case .host(let value):
            destinationType = "host"
            destinationValue = value
        case .network(let value, let prefix):
            destinationType = "network"
            destinationValue = value
            destinationPrefix = prefix
        case .table(let value):
            destinationType = "table"
            destinationValue = value
        }

        if let port = rule.port {
            switch port {
            case .single(let value):
                portType = "single"
                portValue = String(value)
            case .range(let start, let end):
                portType = "range"
                portValue = "\(start):\(end)"
            case .list(let values):
                portType = "list"
                portValue = values.map(String.init).joined(separator: ",")
            }
        }
    }

    public func toPFRule() throws -> PFRule {
        guard let action = PFRule.Action(rawValue: action),
              let direction = PFRule.Direction(rawValue: direction) else {
            throw FirewallXPCPayloadError.invalidRule
        }

        let parsedProtocol: PFRule.NetworkProtocol?
        if let networkProtocol {
            guard let value = PFRule.NetworkProtocol(rawValue: networkProtocol) else {
                throw FirewallXPCPayloadError.invalidRule
            }
            parsedProtocol = value
        } else {
            parsedProtocol = nil
        }

        let source = try Self.address(type: sourceType, value: sourceValue, prefix: sourcePrefix)
        let destination = try Self.address(
            type: destinationType,
            value: destinationValue,
            prefix: destinationPrefix
        )
        let port = try Self.port(type: portType, value: portValue)

        let parsedState: PFRule.State?
        if let state {
            guard let value = PFRule.State(rawValue: state) else {
                throw FirewallXPCPayloadError.invalidRule
            }
            parsedState = value
        } else {
            parsedState = nil
        }

        let rule = PFRule(
            action: action,
            direction: direction,
            networkProtocol: parsedProtocol,
            interface: interface,
            source: source,
            destination: destination,
            port: port,
            flags: flags,
            state: parsedState,
            log: log
        )
        try rule.validate()
        return rule
    }

    private static func address(type: String, value: String?, prefix: Int?) throws -> PFRule.Address {
        switch type {
        case "any":
            return .any
        case "host":
            guard let value else { throw FirewallXPCPayloadError.invalidRule }
            return .host(value)
        case "network":
            guard let value, let prefix else { throw FirewallXPCPayloadError.invalidRule }
            return .network(value, prefix)
        case "table":
            guard let value else { throw FirewallXPCPayloadError.invalidRule }
            return .table(value)
        default:
            throw FirewallXPCPayloadError.invalidRule
        }
    }

    private static func port(type: String?, value: String?) throws -> PFRule.Port? {
        guard let type, let value else { return nil }
        switch type {
        case "single":
            guard let port = UInt16(value) else { throw FirewallXPCPayloadError.invalidRule }
            return .single(port)
        case "range":
            let parts = value.split(separator: ":", omittingEmptySubsequences: false)
            guard parts.count == 2,
                  let start = UInt16(parts[0]),
                  let end = UInt16(parts[1]) else {
                throw FirewallXPCPayloadError.invalidRule
            }
            return .range(start, end)
        case "list":
            let rawPorts = value.split(separator: ",", omittingEmptySubsequences: false)
            let ports = rawPorts.compactMap { UInt16($0) }
            guard !ports.isEmpty, ports.count == rawPorts.count else {
                throw FirewallXPCPayloadError.invalidRule
            }
            return .list(ports)
        default:
            throw FirewallXPCPayloadError.invalidRule
        }
    }
}

public struct AppFirewallStatusPayload: Codable, Equatable {
    public var enabled: Bool
    public var stealthMode: Bool
    public var blockAll: Bool
    public var allowSigned: Bool
    public var allowDownloadedSigned: Bool
    public var apps: [AppRulePayload]

    public init(
        enabled: Bool,
        stealthMode: Bool,
        blockAll: Bool,
        allowSigned: Bool,
        allowDownloadedSigned: Bool,
        apps: [AppRulePayload]
    ) {
        self.enabled = enabled
        self.stealthMode = stealthMode
        self.blockAll = blockAll
        self.allowSigned = allowSigned
        self.allowDownloadedSigned = allowDownloadedSigned
        self.apps = apps
    }
}

public struct AppRulePayload: Codable, Equatable {
    public var path: String
    public var name: String
    public var allowed: Bool

    public init(path: String, name: String, allowed: Bool) {
        self.path = path
        self.name = name
        self.allowed = allowed
    }
}
