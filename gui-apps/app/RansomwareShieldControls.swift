import Common
import Foundation

@MainActor
final class RansomwareShieldControls: ObservableObject {
    @Published private(set) var canaryInstalled = false
    @Published private(set) var statusMessage = "Connecting to security agent..."
    @Published private(set) var health: AgentHealth?
    @Published private(set) var busy = false
    var sensorActive: Bool {
        health?.components.contains { $0.id == "sensor" && $0.state == "active" } == true
    }

    init() { refresh() }
    func refresh() { request(install: false) }
    func installCanaries() { request(install: true) }
    private func request(install: Bool) {
        guard !busy else { return }
        busy = true
        Task {
            defer { busy = false }
            do {
                let snapshot = try await AgentControl.request(install: install)
                health = snapshot
                canaryInstalled = snapshot.components.contains {
                    $0.id == "canaries" && ["active", "degraded"].contains($0.state)
                }
                let sensor = snapshot.components.first { $0.id == "sensor" }
                statusMessage =
                    sensor?.state == "active"
                    ? "Behavioral monitoring is active."
                    : "Behavioral monitoring \(sensor?.state ?? "unavailable"): \(sensor?.reason ?? "No status available")"
            } catch {
                health = nil
                canaryInstalled = false
                statusMessage = "Agent unavailable: \(error.localizedDescription)"
            }
        }
    }
}
