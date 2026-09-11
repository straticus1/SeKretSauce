import Common
import SwiftUI

struct IncidentView: View {
    @State private var incidents: [IncidentRecord] = []
    @State private var busy = false
    @State private var error: String?
    @State private var selected: IncidentRecord?

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Incidents").font(.title)
                Spacer()
                Button("Refresh") { Task { await refresh() } }.disabled(busy)
            }
            if let error { Text(error).foregroundStyle(.red) }
            if incidents.isEmpty { Text("No incident records loaded.").foregroundStyle(.secondary) }
            List(incidents, id: \.id) { incident in
                VStack(alignment: .leading, spacing: 6) {
                    Text(incident.processPath).font(.headline)
                    Text(
                        "PID \(incident.pid) • Score \(incident.score) • Response: \(incident.responseState)")
                    Text(incident.reasons.joined(separator: "; "))
                    if let reason = incident.responseError { Text(reason).foregroundStyle(.orange) }
                    if incident.responseState == "applied" {
                        Button("Resume process…") { selected = incident }.disabled(busy)
                    }
                }.padding(.vertical, 6)
            }
        }
        .padding()
        .task { await refresh() }
        .confirmationDialog(
            "Resume this process? It may continue modifying files.",
            isPresented: Binding(get: { selected != nil }, set: { if !$0 { selected = nil } })
        ) {
            if let incident = selected {
                Button("Resume process", role: .destructive) { Task { await resume(incident.id) } }
            }
        }
    }

    @MainActor private func refresh() async {
        guard !busy else { return }
        busy = true
        defer { busy = false }
        do {
            incidents = try await AgentControl.incidents()
            error = nil
        } catch { self.error = error.localizedDescription }
    }
    @MainActor private func resume(_ id: UUID) async {
        guard !busy else { return }
        busy = true
        defer { busy = false }
        do {
            try await AgentControl.resumeIncident(id)
            incidents = try await AgentControl.incidents()
            error = nil
        } catch { self.error = error.localizedDescription }
    }
}
