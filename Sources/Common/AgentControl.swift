import Foundation
import Security

@objc public protocol AgentControlProtocol {
    func incidents(reply: @escaping (Data?, String?) -> Void)
    func resumeIncident(_ id: String, reply: @escaping (Data?, String?) -> Void)
    func health(reply: @escaping (Data?, String?) -> Void)
    func installCanaries(reply: @escaping (Data?, String?) -> Void)
}

public struct ComponentHealth: Codable, Sendable {
    public let id: String
    public let state: String
    public let reason: String
    public init(id: String, state: String, reason: String = "") {
        self.id = id
        self.state = state
        self.reason = reason
    }
}
public struct AgentHealth: Codable, Sendable {
    public let schemaVersion: Int
    public let observedAt: Date
    public let components: [ComponentHealth]
    public let eventsReceived: UInt64
    public let eventsDropped: UInt64
    public let lastEventAt: Date?
    public init(
        components: [ComponentHealth], eventsReceived: UInt64, eventsDropped: UInt64, lastEventAt: Date?
    ) {
        schemaVersion = 1
        observedAt = Date()
        self.components = components
        self.eventsReceived = eventsReceived
        self.eventsDropped = eventsDropped
        self.lastEventAt = lastEventAt
    }
}

public enum AgentControl {
    public static let serviceName = "com.sekretsauce.daemon.control"
    public static let daemonIdentifier = "com.sekretsauce.daemon"
    public static let guiIdentifier = "com.afterdarktech.sekretsauce"

    public static func signingRequirement(identifiers: [String]) throws -> String {
        var own: SecCode?
        var staticCode: SecStaticCode?
        var info: CFDictionary?
        guard SecCodeCopySelf([], &own) == errSecSuccess, let own,
            SecCodeCopyStaticCode(own, [], &staticCode) == errSecSuccess, let staticCode,
            SecCodeCopySigningInformation(staticCode, [], &info) == errSecSuccess,
            let values = info as? [String: Any],
            let team = values[kSecCodeInfoTeamIdentifier as String] as? String,
            team.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil
        else {
            throw ControlError.unavailable("A team-signed build is required for agent control")
        }
        return try signingRequirement(team: team, identifiers: identifiers)
    }

    public static func signingRequirement(team: String, identifiers: [String]) throws -> String {
        guard team.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil else {
            throw ControlError.unavailable("Invalid signing team")
        }
        guard !identifiers.isEmpty,
            identifiers.allSatisfy({
                $0.range(of: "^[A-Za-z0-9.-]+$", options: .regularExpression) != nil
            })
        else {
            throw ControlError.unavailable("Invalid peer signing identity")
        }
        let peers = identifiers.map { "identifier \"\($0)\"" }.joined(separator: " or ")
        return "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\" and (\(peers))"
    }

    public static func request(install: Bool = false) async throws -> AgentHealth {
        let data = try await requestData(operation: install ? "install" : "health")
        let result = try JSONDecoder().decode(AgentHealth.self, from: data)
        guard result.schemaVersion == 1 else {
            throw ControlError.unavailable("Unsupported agent protocol")
        }
        return result
    }

    public static func incidents() async throws -> [IncidentRecord] {
        try JSONDecoder().decode([IncidentRecord].self, from: await requestData(operation: "incidents"))
    }

    public static func resumeIncident(_ id: UUID) async throws {
        _ = try await requestData(operation: "resume", id: id.uuidString)
    }

    private static func requestData(operation: String, id: String = "") async throws -> Data {
        let requirement = try signingRequirement(identifiers: [daemonIdentifier])
        let data: Data = try await withCheckedThrowingContinuation { continuation in
            let connection = NSXPCConnection(machServiceName: serviceName, options: .privileged)
            connection.remoteObjectInterface = NSXPCInterface(with: AgentControlProtocol.self)
            connection.setCodeSigningRequirement(requirement)
            let gate = ControlReply(continuation: continuation, connection: connection)
            connection.invalidationHandler = { gate.finish(nil, "Agent connection closed") }
            connection.interruptionHandler = { gate.finish(nil, "Agent connection interrupted") }
            connection.resume()
            DispatchQueue.global().asyncAfter(deadline: .now() + 10) {
                gate.finish(nil, "Agent response timed out")
            }
            guard
                let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
                    gate.finish(nil, error.localizedDescription)
                }) as? AgentControlProtocol
            else {
                gate.finish(nil, "Agent unavailable")
                return
            }
            if operation == "resume" {
                proxy.resumeIncident(id) { gate.finish($0, $1) }
            } else if operation == "incidents" {
                proxy.incidents { gate.finish($0, $1) }
            } else if operation == "install" {
                proxy.installCanaries { gate.finish($0, $1) }
            } else {
                proxy.health { gate.finish($0, $1) }
            }
        }
        return data
    }
}

public enum ControlError: Error, LocalizedError {
    case unavailable(String)
    public var errorDescription: String? {
        if case .unavailable(let reason) = self { return reason }
        return nil
    }
}
private final class ControlReply: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?
    private let connection: NSXPCConnection
    init(continuation: CheckedContinuation<Data, Error>, connection: NSXPCConnection) {
        self.continuation = continuation
        self.connection = connection
    }
    func finish(_ data: Data?, _ error: String?) {
        lock.lock()
        let callback = continuation
        continuation = nil
        lock.unlock()
        guard let callback else { return }
        connection.invalidationHandler = nil
        connection.interruptionHandler = nil
        connection.invalidate()
        if let error {
            callback.resume(throwing: ControlError.unavailable(error))
        } else if let data, data.count <= 1_048_576 {
            callback.resume(returning: data)
        } else {
            callback.resume(throwing: ControlError.unavailable("Invalid agent response"))
        }
    }
}
