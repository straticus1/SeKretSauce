import FirewallKit
import Foundation
import ServiceManagement

enum FirewallHelperClientError: Error, LocalizedError {
    case unavailable
    case operationFailed(String)
    case registrationRequired
    case approvalRequired

    var errorDescription: String? {
        switch self {
        case .unavailable:
            return "The ProtectX privileged helper is unavailable."
        case .operationFailed(let message):
            return message
        case .registrationRequired:
            return "Install the ProtectX privileged helper before changing firewall settings."
        case .approvalRequired:
            return "Approve ProtectX in System Settings → General → Login Items, then refresh."
        }
    }
}

enum FirewallHelperState: Equatable {
    case notInstalled
    case awaitingApproval
    case available(version: String)
    case unavailable

    var message: String {
        switch self {
        case .notInstalled:
            return "Privileged helper not installed"
        case .awaitingApproval:
            return "Privileged helper is awaiting approval"
        case .available(let version):
            return "Privileged helper \(version) connected"
        case .unavailable:
            return "Privileged helper is installed but unavailable"
        }
    }

    var canPerformPrivilegedOperations: Bool {
        if case .available = self { return true }
        return false
    }
}

final class FirewallHelperService {
    private let service = SMAppService.daemon(plistName: FirewallXPC.launchDaemonPlistName)

    var state: FirewallHelperState {
        switch service.status {
        case .notRegistered:
            return .notInstalled
        case .requiresApproval:
            return .awaitingApproval
        case .enabled:
            return .unavailable
        case .notFound:
            return .notInstalled
        @unknown default:
            return .unavailable
        }
    }

    func register() throws {
        switch service.status {
        case .enabled, .requiresApproval:
            return
        case .notRegistered, .notFound:
            try service.register()
        @unknown default:
            try service.register()
        }
    }
}

final class FirewallHelperClient {
    func ping() async throws -> String {
        let reachable: Bool = try await request { proxy, reply in
            proxy.ping(reply: reply)
        }
        guard reachable else { throw FirewallHelperClientError.unavailable }
        return try await request { proxy, reply in
            proxy.getVersion(reply: reply)
        }
    }

    func pfStatus() async throws -> (enabled: Bool, rules: [PFRule], revision: Int) {
        let response: (Data?, String?) = try await request { proxy, reply in
            proxy.pfPolicy { reply(($0, $1)) }
        }
        if let error = response.1 { throw FirewallHelperClientError.operationFailed(error) }
        guard let data = response.0 else { throw FirewallXPCPayloadError.invalidResponse }
        let status = try JSONDecoder().decode(PFStatusPayload.self, from: data)
        guard status.policy.schemaVersion == 1 else { throw FirewallXPCPayloadError.invalidResponse }
        return (
            status.enabled, try status.policy.rules.map { try $0.toPFRule() }, status.policy.revision
        )
    }

    func applyPF(_ rules: [PFRule], expectedRevision: Int) async throws {
        let data = try JSONEncoder().encode(rules.map(PFRulePayload.init))
        guard data.count <= FirewallXPC.maximumPayloadSize else {
            throw FirewallXPCPayloadError.payloadTooLarge
        }
        try await command { proxy, reply in
            proxy.pfApply(data, expectedRevision: expectedRevision, reply: reply)
        }
    }

    func appFirewallStatus() async throws -> AppFirewallStatusPayload {
        let data: Data? = try await request { proxy, reply in
            proxy.appFirewallGetStatus(reply: reply)
        }
        guard let data else { throw FirewallXPCPayloadError.invalidResponse }
        return try JSONDecoder().decode(AppFirewallStatusPayload.self, from: data)
    }

    func setPFEnabled(_ enabled: Bool) async throws {
        try await command { proxy, reply in
            if enabled {
                proxy.pfEnable(reply: reply)
            } else {
                proxy.pfDisable(reply: reply)
            }
        }
    }

    func reloadPF() async throws {
        try await command { proxy, reply in proxy.pfReload(reply: reply) }
    }

    func addPFRule(_ rule: PFRule) async throws {
        let data = try JSONEncoder().encode(PFRulePayload(from: rule))
        guard data.count <= FirewallXPC.maximumPayloadSize else {
            throw FirewallXPCPayloadError.payloadTooLarge
        }
        try await command { proxy, reply in proxy.pfAddRule(data, reply: reply) }
    }

    func removePFRule(at index: Int) async throws {
        try await command { proxy, reply in proxy.pfRemoveRule(at: index, reply: reply) }
    }

    func setAppFirewallEnabled(_ enabled: Bool) async throws {
        try await command { proxy, reply in
            if enabled {
                proxy.appFirewallEnable(reply: reply)
            } else {
                proxy.appFirewallDisable(reply: reply)
            }
        }
    }

    func setStealthMode(_ enabled: Bool) async throws {
        try await command { proxy, reply in
            proxy.appFirewallSetStealthMode(enabled, reply: reply)
        }
    }

    func setBlockAll(_ enabled: Bool) async throws {
        try await command { proxy, reply in
            proxy.appFirewallSetBlockAll(enabled, reply: reply)
        }
    }

    func allowApp(at path: String) async throws {
        try await command { proxy, reply in
            proxy.appFirewallAllowApp(at: path, reply: reply)
        }
    }

    func blockApp(at path: String) async throws {
        try await command { proxy, reply in
            proxy.appFirewallBlockApp(at: path, reply: reply)
        }
    }

    func removeApp(at path: String) async throws {
        try await command { proxy, reply in
            proxy.appFirewallRemoveApp(at: path, reply: reply)
        }
    }

    private func command(
        _ operation: @escaping (FirewallHelperProtocol, @escaping (Bool, String?) -> Void) -> Void
    ) async throws {
        let result: (Bool, String?) = try await request { proxy, reply in
            operation(proxy) { success, message in reply((success, message)) }
        }
        guard result.0 else {
            throw FirewallHelperClientError.operationFailed(
                result.1 ?? "The privileged firewall operation failed."
            )
        }
    }

    private func request<T>(
        _ operation: @escaping (FirewallHelperProtocol, @escaping (T) -> Void) -> Void
    ) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            let connection = NSXPCConnection(
                machServiceName: FirewallXPC.helperIdentifier,
                options: .privileged
            )
            connection.remoteObjectInterface = NSXPCInterface(with: FirewallHelperProtocol.self)
            let gate = ContinuationGate(continuation) {
                connection.invalidationHandler = nil
                connection.interruptionHandler = nil
                connection.invalidate()
            }
            connection.invalidationHandler = {
                gate.resume(throwing: FirewallHelperClientError.unavailable)
            }
            connection.interruptionHandler = {
                gate.resume(throwing: FirewallHelperClientError.unavailable)
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + 15) {
                gate.resume(
                    throwing: FirewallHelperClientError.operationFailed(
                        "Helper response timed out. Refresh to verify the operation outcome."))
            }
            connection.resume()
            let object = connection.remoteObjectProxyWithErrorHandler { error in
                gate.resume(throwing: error)
            }
            guard let proxy = object as? FirewallHelperProtocol else {
                gate.resume(throwing: FirewallHelperClientError.unavailable)
                return
            }
            operation(proxy) { value in
                gate.resume(returning: value)
            }
        }
    }
}

private final class ContinuationGate<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Error>?
    private let onFinish: () -> Void

    init(
        _ continuation: CheckedContinuation<Value, Error>,
        onFinish: @escaping () -> Void
    ) {
        self.continuation = continuation
        self.onFinish = onFinish
    }

    func resume(returning value: Value) {
        take()?.resume(returning: value)
    }

    func resume(throwing error: Error) {
        take()?.resume(throwing: error)
    }

    private func take() -> CheckedContinuation<Value, Error>? {
        lock.lock()
        let result = continuation
        continuation = nil
        lock.unlock()
        if result != nil {
            onFinish()
        }
        return result
    }
}
