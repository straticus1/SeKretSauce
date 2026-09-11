import Foundation

public struct IncidentRecord: Codable, Identifiable, Sendable {
    public let id: UUID
    public let executionID: String
    public let pid: Int32
    public let ownerUID: UInt32
    public let processPath: String
    public let firstSeenAt: Date
    public var lastSeenAt: Date
    public var score: Int
    public var reasons: [String]
    public var recommendedAction: String
    public var responseState: String
    public var responseError: String?
    public init(
        executionID: String, pid: Int32, ownerUID: UInt32, processPath: String, score: Int,
        reasons: [String], recommendedAction: String
    ) {
        id = UUID()
        self.executionID = executionID
        self.pid = pid
        self.ownerUID = ownerUID
        self.processPath = processPath
        firstSeenAt = Date()
        lastSeenAt = Date()
        self.score = score
        self.reasons = reasons
        self.recommendedAction = recommendedAction
        responseState = "observed"
    }
}
