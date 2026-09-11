// FirewallHelper - Privileged XPC helper for Rampart
// Runs as root via an SMAppService-managed LaunchDaemon.

import Foundation
import FirewallKit
import FirewallHelperCore

// MARK: - Helper Implementation

class FirewallHelper: NSObject, FirewallHelperProtocol, NSXPCListenerDelegate {

    private let pf = PFManager()
    private let appFirewall = AppFirewallManager()
    private let connectionVerifier = ConnectionVerifier()
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
        let pid = connection.processIdentifier
        NSLog("FirewallHelper: Connection request from PID \(pid)")
        return connectionVerifier.verify(processIdentifier: pid)
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
            guard ruleData.count <= FirewallXPC.maximumPayloadSize else {
                throw FirewallXPCPayloadError.payloadTooLarge
            }
            let decoder = JSONDecoder()
            let rule = try decoder.decode(PFRulePayload.self, from: ruleData)
            try pf.addRule(try rule.toPFRule())
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
        let codableRules = pf.rules.map { PFRulePayload(from: $0) }
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
        let status = AppFirewallStatusPayload(
            enabled: appFirewall.isEnabled,
            stealthMode: appFirewall.stealthMode,
            blockAll: appFirewall.blockAll,
            allowSigned: appFirewall.allowSigned,
            allowDownloadedSigned: appFirewall.allowDownloadedSigned,
            apps: appFirewall.apps.map {
                AppRulePayload(path: $0.path, name: $0.name, allowed: $0.allowed)
            }
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

// MARK: - Main

let helper = FirewallHelper()
let listener = NSXPCListener(machServiceName: FirewallXPC.helperIdentifier)
listener.delegate = helper

NSLog("FirewallHelper: Starting XPC service...")
listener.resume()

RunLoop.main.run()
