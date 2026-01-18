// NetworkView - Network state monitoring view

import SwiftUI
import FirewallKit

struct NetworkView: View {
    @EnvironmentObject var viewModel: FirewallViewModel
    @State private var selectedTab: NetworkTab = .connections
    @State private var searchText = ""
    @State private var selectedConnection: Connection?

    enum NetworkTab: String, CaseIterable {
        case connections = "Connections"
        case listeners = "Listeners"
    }

    var filteredConnections: [Connection] {
        if searchText.isEmpty {
            return viewModel.connections
        }
        return viewModel.connections.filter {
            $0.processName.localizedCaseInsensitiveContains(searchText) ||
            $0.remoteAddress.contains(searchText)
        }
    }

    var filteredListeners: [Listener] {
        if searchText.isEmpty {
            return viewModel.listeners
        }
        return viewModel.listeners.filter {
            $0.processName.localizedCaseInsensitiveContains(searchText) ||
            String($0.port).contains(searchText)
        }
    }

    var establishedCount: Int {
        viewModel.connections.filter { $0.state == "ESTABLISHED" }.count
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                VStack(alignment: .leading) {
                    Text("Network Monitor")
                        .font(.title2)
                        .fontWeight(.bold)
                    Text("Active connections and listening ports")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }

                Spacer()

                Button {
                    viewModel.refresh()
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
            }
            .padding()
            .background(Color(NSColor.controlBackgroundColor))

            Divider()

            // Stats Row
            HStack(spacing: 40) {
                StatBadge(
                    title: "Total",
                    value: "\(viewModel.connections.count)",
                    color: .blue
                )
                StatBadge(
                    title: "Established",
                    value: "\(establishedCount)",
                    color: .green
                )
                StatBadge(
                    title: "Listening",
                    value: "\(viewModel.listeners.count)",
                    color: .orange
                )
                Spacer()

                TextField("Search...", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 200)
            }
            .padding()

            // Tab Picker
            Picker("View", selection: $selectedTab) {
                ForEach(NetworkTab.allCases, id: \.self) { tab in
                    Text(tab.rawValue).tag(tab)
                }
            }
            .pickerStyle(.segmented)
            .padding(.horizontal)

            Divider()
                .padding(.top)

            // Content
            if selectedTab == .connections {
                ConnectionsTable(
                    connections: filteredConnections,
                    selectedConnection: $selectedConnection,
                    onBlock: { ip in
                        viewModel.quickBlockIP(ip)
                    }
                )
            } else {
                ListenersTable(listeners: filteredListeners)
            }
        }
    }
}

// MARK: - Stat Badge

struct StatBadge: View {
    let title: String
    let value: String
    let color: Color

    var body: some View {
        VStack(spacing: 4) {
            Text(value)
                .font(.title2)
                .fontWeight(.bold)
                .foregroundColor(color)
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
    }
}

// MARK: - Connections Table

struct ConnectionsTable: View {
    let connections: [Connection]
    @Binding var selectedConnection: Connection?
    let onBlock: (String) -> Void

    @State private var selectedID: Connection.ID?

    var body: some View {
        Table(connections, selection: $selectedID) {
            TableColumn("Process") { conn in
                HStack {
                    Image(systemName: "app.fill")
                        .foregroundColor(.secondary)
                    Text(conn.processName)
                        .fontWeight(.medium)
                }
            }
            .width(min: 100, ideal: 150)

            TableColumn("PID") { conn in
                Text("\(conn.pid)")
                    .font(.system(.body, design: .monospaced))
            }
            .width(60)

            TableColumn("Local") { conn in
                Text("\(conn.localAddress):\(conn.localPort)")
                    .font(.system(.body, design: .monospaced))
            }
            .width(min: 120, ideal: 160)

            TableColumn("Remote") { conn in
                VStack(alignment: .leading) {
                    Text("\(conn.remoteAddress):\(conn.remotePort)")
                        .font(.system(.body, design: .monospaced))
                    if let service = conn.serviceName {
                        Text(service)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }
            .width(min: 150, ideal: 200)

            TableColumn("State") { conn in
                Text(conn.state)
                    .font(.caption)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .background(stateColor(conn.state).opacity(0.2))
                    .foregroundColor(stateColor(conn.state))
                    .cornerRadius(4)
            }
            .width(100)

            TableColumn("Actions") { conn in
                Button {
                    onBlock(conn.remoteAddress)
                } label: {
                    Image(systemName: "xmark.shield")
                        .foregroundColor(.red)
                }
                .buttonStyle(.plain)
                .help("Block this IP")
            }
            .width(60)
        }
    }

    func stateColor(_ state: String) -> Color {
        switch state {
        case "ESTABLISHED": return .green
        case "LISTEN": return .blue
        case "TIME_WAIT", "CLOSE_WAIT": return .orange
        case "CLOSED": return .gray
        default: return .secondary
        }
    }
}

// MARK: - Listeners Table

struct ListenersTable: View {
    let listeners: [Listener]

    var body: some View {
        Table(listeners) {
            TableColumn("Process") { listener in
                HStack {
                    Image(systemName: "server.rack")
                        .foregroundColor(.secondary)
                    Text(listener.processName)
                        .fontWeight(.medium)
                }
            }
            .width(min: 100, ideal: 150)

            TableColumn("PID") { listener in
                Text("\(listener.pid)")
                    .font(.system(.body, design: .monospaced))
            }
            .width(60)

            TableColumn("Address") { listener in
                Text(listener.address)
                    .font(.system(.body, design: .monospaced))
            }
            .width(min: 100, ideal: 120)

            TableColumn("Port") { listener in
                HStack {
                    Text("\(listener.port)")
                        .font(.system(.body, design: .monospaced))
                        .fontWeight(.bold)
                    if let service = listener.serviceName {
                        Text("(\(service))")
                            .foregroundColor(.secondary)
                    }
                }
            }
            .width(min: 100, ideal: 150)

            TableColumn("Protocol") { listener in
                Text(listener.protocol)
                    .font(.caption)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .background(listener.protocol == "TCP" ? Color.blue.opacity(0.2) : Color.green.opacity(0.2))
                    .cornerRadius(4)
            }
            .width(80)
        }
    }
}

#Preview {
    NetworkView()
        .environmentObject(FirewallViewModel())
}
