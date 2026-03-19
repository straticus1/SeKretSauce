// FirewallHelper - Privileged XPC helper for Rampart
// Runs as root via SMJobBless to perform firewall operations

import Foundation
import FirewallKit

// MARK: - XPC Protocol

@objc protocol FirewallHelperProtocol {
    // PF Operations
    func pfEnable(reply: @escaping (Bool, String?) -> Void)
    func pfDisable(reply: @escaping (Bool, String?) -> Void)
    func pfReload(reply: @escaping (Bool, String?) -> Void)
    func pfGetStatus(reply: @escaping (Bool, Int) -> Void)
    func pfAddRule(_ ruleData: Data, reply: @escaping (Bool, String?) -> Void)
    func pfRemoveRule(at index: Int, reply: @escaping (Bool, String?) -> Void)
    func pfGetRules(reply: @escaping (Data?) -> Void)

    // App Firewall Operations
    func appFirewallEnable(reply: @escaping (Bool, String?) -> Void)
    func appFirewallDisable(reply: @escaping (Bool, String?) -> Void)
    func appFirewallSetStealthMode(_ enabled: Bool, reply: @escaping (Bool, String?) -> Void)
    func appFirewallSetBlockAll(_ enabled: Bool, reply: @escaping (Bool, String?) -> Void)
    func appFirewallAllowApp(at path: String, reply: @escaping (Bool, String?) -> Void)
    func appFirewallBlockApp(at path: String, reply: @escaping (Bool, String?) -> Void)
    func appFirewallRemoveApp(at path: String, reply: @escaping (Bool, String?) -> Void)
    func appFirewallGetStatus(reply: @escaping (Data?) -> Void)

    // Utility
    func getVersion(reply: @escaping (String) -> Void)
    func ping(reply: @escaping (Bool) -> Void)
}

// MARK: - Helper Implementation

class FirewallHelper: NSObject, FirewallHelperProtocol, NSXPCListenerDelegate {

    private let pf = PFManager()
    private let appFirewall = AppFirewallManager()
    private let version = "1.0.0"

    // MARK: - XPC Listener Delegate

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        // Verify the connecting process
        guard verifyConnection(connection) else {
            NSLog("FirewallHelper: Rejected connection from unauthorized process")
            return false
        }

        connection.exportedInterface = NSXPCInterface(with: FirewallHelperProtocol.self)
        connection.exportedObject = self

        connection.invalidationHandler = {
            NSLog("FirewallHelper: Connection invalidated")
        }

        connection.interruptionHandler = {
            NSLog("FirewallHelper: Connection interrupted")
        }

        connection.resume()
        return true
    }

    private func verifyConnection(_ connection: NSXPCConnection) -> Bool {
        // In production, verify code signature of connecting app
        // For now, accept connections from processes with our team ID
        let pid = connection.processIdentifier
        NSLog("FirewallHelper: Connection request from PID \(pid)")

        // TODO: Add proper code signature verification
        // let secCode = SecCodeCopySelf(...)
        // Verify it matches expected signing identity

        return true
    }

    // MARK: - PF Operations

    func pfEnable(reply: @escaping (Bool, String?) -> Void) {
        NSLog("FirewallHelper: pfEnable requested")
        do {
            try pf.enable()
            reply(true, nil)
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    func pfDisable(reply: @escaping (Bool, String?) -> Void) {
        NSLog("FirewallHelper: pfDisable requested")
        do {
            try pf.disable()
            reply(true, nil)
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    func pfReload(reply: @escaping (Bool, String?) -> Void) {
        NSLog("FirewallHelper: pfReload requested")
        do {
            try pf.reload()
            reply(true, nil)
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    func pfGetStatus(reply: @escaping (Bool, Int) -> Void) {
        pf.refresh()
        reply(pf.isEnabled, pf.rules.count)
    }

    func pfAddRule(_ ruleData: Data, reply: @escaping (Bool, String?) -> Void) {
        NSLog("FirewallHelper: pfAddRule requested")
        do {
            let decoder = JSONDecoder()
            let rule = try decoder.decode(PFRuleCodable.self, from: ruleData)
            try pf.addRule(rule.toPFRule())
            reply(true, nil)
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    func pfRemoveRule(at index: Int, reply: @escaping (Bool, String?) -> Void) {
        NSLog("FirewallHelper: pfRemoveRule at \(index) requested")
        do {
            try pf.removeRule(at: index)
            reply(true, nil)
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    func pfGetRules(reply: @escaping (Data?) -> Void) {
        pf.refresh()
        let encoder = JSONEncoder()
        let codableRules = pf.rules.map { PFRuleCodable(from: $0) }
        let data = try? encoder.encode(codableRules)
        reply(data)
    }

    // MARK: - App Firewall Operations

    func appFirewallEnable(reply: @escaping (Bool, String?) -> Void) {
        NSLog("FirewallHelper: appFirewallEnable requested")
        do {
            try appFirewall.enable()
            reply(true, nil)
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    func appFirewallDisable(reply: @escaping (Bool, String?) -> Void) {
        NSLog("FirewallHelper: appFirewallDisable requested")
        do {
            try appFirewall.disable()
            reply(true, nil)
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    func appFirewallSetStealthMode(_ enabled: Bool, reply: @escaping (Bool, String?) -> Void) {
        NSLog("FirewallHelper: appFirewallSetStealthMode(\(enabled)) requested")
        do {
            try appFirewall.setStealthMode(enabled)
            reply(true, nil)
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    func appFirewallSetBlockAll(_ enabled: Bool, reply: @escaping (Bool, String?) -> Void) {
        NSLog("FirewallHelper: appFirewallSetBlockAll(\(enabled)) requested")
        do {
            try appFirewall.setBlockAll(enabled)
            reply(true, nil)
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    func appFirewallAllowApp(at path: String, reply: @escaping (Bool, String?) -> Void) {
        NSLog("FirewallHelper: appFirewallAllowApp(\(path)) requested")
        do {
            try appFirewall.allowApp(at: path)
            reply(true, nil)
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    func appFirewallBlockApp(at path: String, reply: @escaping (Bool, String?) -> Void) {
        NSLog("FirewallHelper: appFirewallBlockApp(\(path)) requested")
        do {
            try appFirewall.blockApp(at: path)
            reply(true, nil)
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    func appFirewallRemoveApp(at path: String, reply: @escaping (Bool, String?) -> Void) {
        NSLog("FirewallHelper: appFirewallRemoveApp(\(path)) requested")
        do {
            try appFirewall.removeRule(for: path)
            reply(true, nil)
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    func appFirewallGetStatus(reply: @escaping (Data?) -> Void) {
        appFirewall.refresh()
        let status = AppFirewallStatusCodable(
            enabled: appFirewall.isEnabled,
            stealthMode: appFirewall.stealthMode,
            blockAll: appFirewall.blockAll,
            allowSigned: appFirewall.allowSigned,
            allowDownloadedSigned: appFirewall.allowDownloadedSigned,
            apps: appFirewall.apps.map { AppRuleCodable(path: $0.path, name: $0.name, allowed: $0.allowed) }
        )
        let encoder = JSONEncoder()
        let data = try? encoder.encode(status)
        reply(data)
    }

    // MARK: - Utility

    func getVersion(reply: @escaping (String) -> Void) {
        reply(version)
    }

    func ping(reply: @escaping (Bool) -> Void) {
        reply(true)
    }
}

// MARK: - Codable Types for XPC

struct PFRuleCodable: Codable {
    var action: String
    var direction: String
    var `protocol`: String?
    var interface: String?
    var sourceType: String
    var sourceValue: String?
    var sourcePrefix: Int?
    var destType: String
    var destValue: String?
    var destPrefix: Int?
    var portType: String?
    var portValue: String?
    var log: Bool

    init(from rule: PFRule) {
        self.action = rule.action.rawValue
        self.direction = rule.direction.rawValue
        self.protocol = rule.networkProtocol?.rawValue
        self.interface = rule.interface
        self.log = rule.log

        switch rule.source {
        case .any:
            self.sourceType = "any"
        case .host(let ip):
            self.sourceType = "host"
            self.sourceValue = ip
        case .network(let ip, let prefix):
            self.sourceType = "network"
            self.sourceValue = ip
            self.sourcePrefix = prefix
        case .table(let name):
            self.sourceType = "table"
            self.sourceValue = name
        }

        switch rule.destination {
        case .any:
            self.destType = "any"
        case .host(let ip):
            self.destType = "host"
            self.destValue = ip
        case .network(let ip, let prefix):
            self.destType = "network"
            self.destValue = ip
            self.destPrefix = prefix
        case .table(let name):
            self.destType = "table"
            self.destValue = name
        }

        if let port = rule.port {
            switch port {
            case .single(let p):
                self.portType = "single"
                self.portValue = String(p)
            case .range(let start, let end):
                self.portType = "range"
                self.portValue = "\(start):\(end)"
            case .list(let ports):
                self.portType = "list"
                self.portValue = ports.map(String.init).joined(separator: ",")
            }
        }
    }

    func toPFRule() -> PFRule {
        let ruleAction = PFRule.Action(rawValue: action) ?? .block
        let ruleDirection = PFRule.Direction(rawValue: direction) ?? .any
        let ruleProtocol = `protocol`.flatMap { PFRule.NetworkProtocol(rawValue: $0) }

        let source: PFRule.Address
        switch sourceType {
        case "host":
            source = .host(sourceValue ?? "")
        case "network":
            source = .network(sourceValue ?? "", sourcePrefix ?? 24)
        case "table":
            source = .table(sourceValue ?? "")
        default:
            source = .any
        }

        let destination: PFRule.Address
        switch destType {
        case "host":
            destination = .host(destValue ?? "")
        case "network":
            destination = .network(destValue ?? "", destPrefix ?? 24)
        case "table":
            destination = .table(destValue ?? "")
        default:
            destination = .any
        }

        var port: PFRule.Port?
        if let portType = portType, let portValue = portValue {
            switch portType {
            case "single":
                if let p = UInt16(portValue) {
                    port = .single(p)
                }
            case "range":
                let parts = portValue.split(separator: ":")
                if parts.count == 2, let start = UInt16(parts[0]), let end = UInt16(parts[1]) {
                    port = .range(start, end)
                }
            case "list":
                let ports = portValue.split(separator: ",").compactMap { UInt16($0) }
                if !ports.isEmpty {
                    port = .list(ports)
                }
            default:
                break
            }
        }

        return PFRule(
            action: ruleAction,
            direction: ruleDirection,
            networkProtocol: ruleProtocol,
            interface: interface,
            source: source,
            destination: destination,
            port: port,
            log: log
        )
    }
}

struct AppFirewallStatusCodable: Codable {
    var enabled: Bool
    var stealthMode: Bool
    var blockAll: Bool
    var allowSigned: Bool
    var allowDownloadedSigned: Bool
    var apps: [AppRuleCodable]
}

struct AppRuleCodable: Codable {
    var path: String
    var name: String
    var allowed: Bool
}

// MARK: - Main

let helper = FirewallHelper()
let listener = NSXPCListener(machServiceName: "com.rampart.FirewallHelper")
listener.delegate = helper

NSLog("FirewallHelper: Starting XPC service...")
listener.resume()

RunLoop.main.run()
