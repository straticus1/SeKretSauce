// ContentView - Main window for Rampart

import SwiftUI
import FirewallKit

struct ContentView: View {
    @EnvironmentObject var viewModel: FirewallViewModel

    var body: some View {
        NavigationSplitView {
            Sidebar()
        } detail: {
            DetailView()
        }
        .safeAreaInset(edge: .top, spacing: 0) {
            if !viewModel.helperState.canPerformPrivilegedOperations {
                HelperStatusBanner()
            }
        }
        .alert("Error", isPresented: $viewModel.showError) {
            Button("OK") { }
        } message: {
            Text(viewModel.errorMessage ?? "Unknown error")
        }
    }
}

private struct HelperStatusBanner: View {
    @EnvironmentObject var viewModel: FirewallViewModel

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "exclamationmark.shield")
                .foregroundColor(.orange)
            Text(viewModel.helperState.message)
                .font(.callout)
            Spacer()

            switch viewModel.helperState {
            case .notInstalled:
                Button("Install Helper") {
                    viewModel.installHelper()
                }
                .buttonStyle(.borderedProminent)
            case .awaitingApproval:
                Button("Open System Settings") {
                    viewModel.openHelperApprovalSettings()
                }
                .buttonStyle(.borderedProminent)
            case .unavailable:
                Button("Retry") {
                    viewModel.refresh()
                }
            case .available:
                EmptyView()
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(.bar)
        .overlay(alignment: .bottom) { Divider() }
    }
}

// MARK: - Sidebar

struct Sidebar: View {
    @EnvironmentObject var viewModel: FirewallViewModel

    var body: some View {
        List(FirewallViewModel.Tab.allCases, selection: $viewModel.selectedTab) { tab in
            Label(tab.rawValue, systemImage: tab.icon)
                .tag(tab)
        }
        .listStyle(.sidebar)
        .navigationTitle("Rampart")
        .toolbar {
            ToolbarItem {
                Button {
                    viewModel.refresh()
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Refresh")
            }
        }
    }
}

// MARK: - Detail View

struct DetailView: View {
    @EnvironmentObject var viewModel: FirewallViewModel

    var body: some View {
        Group {
            switch viewModel.selectedTab {
            case .dashboard:
                DashboardView()
            case .pf:
                PFView()
            case .appFirewall:
                AppFirewallView()
            case .network:
                NetworkView()
            case .rules:
                RulesView()
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Dashboard View

struct DashboardView: View {
    @EnvironmentObject var viewModel: FirewallViewModel

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Header
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Rampart")
                            .font(.largeTitle)
                            .fontWeight(.bold)
                        Text("One Place to Rule Them All")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                    }
                    Spacer()

                    // Overall status indicator
                    OverallStatusBadge(
                        pfEnabled: viewModel.pfEnabled,
                        appFirewallEnabled: viewModel.appFirewallEnabled
                    )
                }
                .padding()

                // Status Cards
                LazyVGrid(columns: [
                    GridItem(.flexible()),
                    GridItem(.flexible()),
                    GridItem(.flexible())
                ], spacing: 16) {
                    StatusCard(
                        title: "Packet Filter",
                        icon: "network.badge.shield.half.filled",
                        isEnabled: viewModel.pfEnabled,
                        detail: "\(viewModel.pfRules.count) rules"
                    ) {
                        viewModel.togglePF()
                    }

                    StatusCard(
                        title: "App Firewall",
                        icon: "app.badge.checkmark",
                        isEnabled: viewModel.appFirewallEnabled,
                        detail: viewModel.stealthMode ? "Stealth Mode" : "Normal Mode"
                    ) {
                        viewModel.toggleAppFirewall()
                    }

                    StatusCard(
                        title: "Network",
                        icon: "network",
                        isEnabled: true,
                        detail: "\(viewModel.connections.count) connections"
                    ) {
                        viewModel.selectedTab = .network
                    }
                }
                .padding(.horizontal)

                Divider()
                    .padding()

                // Quick Actions
                VStack(alignment: .leading, spacing: 12) {
                    Text("Quick Actions")
                        .font(.headline)
                        .padding(.horizontal)

                    HStack(spacing: 12) {
                        QuickActionButton(
                            title: "Stealth Mode",
                            icon: "eye.slash",
                            isActive: viewModel.stealthMode
                        ) {
                            viewModel.toggleStealthMode()
                        }

                        QuickActionButton(
                            title: "Block All",
                            icon: "xmark.shield",
                            isActive: viewModel.blockAll
                        ) {
                            viewModel.toggleBlockAll()
                        }

                        QuickActionButton(
                            title: "Reload Rules",
                            icon: "arrow.clockwise.circle",
                            isActive: false
                        ) {
                            viewModel.reloadPFRules()
                        }
                    }
                    .padding(.horizontal)
                }

                Divider()
                    .padding()

                // Recent Connections
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("Recent Connections")
                            .font(.headline)
                        Spacer()
                        Button("View All") {
                            viewModel.selectedTab = .network
                        }
                        .buttonStyle(.plain)
                        .foregroundColor(.accentColor)
                    }
                    .padding(.horizontal)

                    if viewModel.connections.isEmpty {
                        Text("No active connections")
                            .foregroundColor(.secondary)
                            .padding()
                    } else {
                        ForEach(Array(viewModel.connections.prefix(5))) { conn in
                            ConnectionRow(connection: conn)
                        }
                        .padding(.horizontal)
                    }
                }

                Spacer(minLength: 20)
            }
        }
        .background(Color(NSColor.windowBackgroundColor))
    }
}

// MARK: - Status Card

struct StatusCard: View {
    let title: String
    let icon: String
    let isEnabled: Bool
    let detail: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Image(systemName: icon)
                        .font(.title2)
                        .foregroundColor(isEnabled ? .green : .secondary)

                    Spacer()

                    Circle()
                        .fill(isEnabled ? Color.green : Color.red)
                        .frame(width: 10, height: 10)
                }

                Text(title)
                    .font(.headline)

                Text(detail)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .padding()
            .background(Color(NSColor.controlBackgroundColor))
            .cornerRadius(12)
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Overall Status Badge

struct OverallStatusBadge: View {
    let pfEnabled: Bool
    let appFirewallEnabled: Bool

    var status: String {
        if pfEnabled && appFirewallEnabled {
            return "Protected"
        } else if pfEnabled || appFirewallEnabled {
            return "Partial"
        } else {
            return "Unprotected"
        }
    }

    var color: Color {
        if pfEnabled && appFirewallEnabled {
            return .green
        } else if pfEnabled || appFirewallEnabled {
            return .yellow
        } else {
            return .red
        }
    }

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(color)
                .frame(width: 12, height: 12)
            Text(status)
                .font(.headline)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(color.opacity(0.15))
        .cornerRadius(20)
    }
}

// MARK: - Quick Action Button

struct QuickActionButton: View {
    let title: String
    let icon: String
    let isActive: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.title2)
                Text(title)
                    .font(.caption)
            }
            .frame(maxWidth: .infinity)
            .padding()
            .background(isActive ? Color.accentColor.opacity(0.2) : Color(NSColor.controlBackgroundColor))
            .cornerRadius(10)
            .overlay(
                RoundedRectangle(cornerRadius: 10)
                    .stroke(isActive ? Color.accentColor : Color.clear, lineWidth: 2)
            )
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Connection Row

struct ConnectionRow: View {
    let connection: Connection

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(connection.processName)
                    .font(.headline)
                Text("\(connection.remoteAddress):\(connection.remotePort)")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Spacer()

            if let service = connection.serviceName {
                Text(service)
                    .font(.caption)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color.accentColor.opacity(0.2))
                    .cornerRadius(4)
            }

            Text(connection.state)
                .font(.caption)
                .foregroundColor(connection.state == "ESTABLISHED" ? .green : .secondary)
        }
        .padding(.vertical, 8)
        .padding(.horizontal, 12)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }
}

#Preview {
    ContentView()
        .environmentObject(FirewallViewModel())
}
