import Common
import Darwin
import EndpointSecurityMonitor
import Foundation

final class AgentControlService: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    static let shared = AgentControlService()
    private let listener = NSXPCListener(machServiceName: AgentControl.serviceName)
    func start() {
        listener.delegate = self
        listener.resume()
    }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection)
        -> Bool
    {
        guard
            let requirement = try? AgentControl.signingRequirement(identifiers: [
                AgentControl.guiIdentifier, AgentControl.daemonIdentifier,
            ])
        else { return false }
        connection.setCodeSigningRequirement(requirement)
        connection.exportedInterface = NSXPCInterface(with: AgentControlProtocol.self)
        connection.exportedObject = AgentControlSession(uid: connection.effectiveUserIdentifier)
        connection.resume()
        return true
    }
}

private final class AgentControlSession: NSObject, AgentControlProtocol, @unchecked Sendable {
    private let uid: uid_t
    init(uid: uid_t) { self.uid = uid }
    func incidents(reply: @escaping (Data?, String?) -> Void) {
        do { reply(try JSONEncoder().encode(IncidentControl.list(uid: uid)), nil) } catch {
            reply(nil, error.localizedDescription)
        }
    }
    func resumeIncident(_ id: String, reply: @escaping (Data?, String?) -> Void) {
        do {
            guard let id = UUID(uuidString: id) else {
                throw ControlError.unavailable("Invalid incident")
            }
            try IncidentControl.resume(id: id, uid: uid)
            reply(Data(), nil)
        } catch { reply(nil, error.localizedDescription) }
    }
    func health(reply: @escaping (Data?, String?) -> Void) {
        let response = SessionReply(reply)
        Task { @MainActor in
            let status = ComponentCoordinator.shared.health(for: uid)
            response.send(try? JSONEncoder().encode(status), nil)
        }
    }
    func installCanaries(reply: @escaping (Data?, String?) -> Void) {
        let response = SessionReply(reply)
        Task { @MainActor in
            do {
                guard uid >= 500 else {
                    throw ControlError.unavailable("Canaries require a regular user account")
                }
                try CanaryManager.install(for: uid)
                let status = ComponentCoordinator.shared.health(for: uid)
                response.send(try JSONEncoder().encode(status), nil)
            } catch { response.send(nil, error.localizedDescription) }
        }
    }
}

// NSXPC reply blocks are safe to invoke once from the service's selected queue.
private final class SessionReply: @unchecked Sendable {
    private let callback: (Data?, String?) -> Void
    init(_ callback: @escaping (Data?, String?) -> Void) { self.callback = callback }
    func send(_ data: Data?, _ error: String?) { callback(data, error) }
}
