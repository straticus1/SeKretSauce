// MenuBarView - Quick access menu bar extra

import SwiftUI
import FirewallKit

struct MenuBarView: View {
    @EnvironmentObject var viewModel: FirewallViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            // Header
            HStack {
                Image(systemName: "shield.checkered")
                    .font(.title2)
                Text("Rampart")
                    .font(.headline)
                Spacer()
                StatusIndicator(
                    pfEnabled: viewModel.pfEnabled,
                    appEnabled: viewModel.appFirewallEnabled
                )
            }
            .padding(.bottom, 4)

            Divider()

            // Quick Status
            VStack(spacing: 8) {
                MenuBarToggle(
                    title: "Packet Filter",
                    isEnabled: viewModel.pfEnabled
                ) {
                    viewModel.togglePF()
                }

                MenuBarToggle(
                    title: "App Firewall",
                    isEnabled: viewModel.appFirewallEnabled
                ) {
                    viewModel.toggleAppFirewall()
                }

                MenuBarToggle(
                    title: "Stealth Mode",
                    isEnabled: viewModel.stealthMode
                ) {
                    viewModel.toggleStealthMode()
                }
            }

            Divider()

            // Quick Stats
            HStack {
                QuickStat(title: "Connections", value: "\(viewModel.connections.count)")
                Spacer()
                QuickStat(title: "PF Rules", value: "\(viewModel.pfRules.count)")
                Spacer()
                QuickStat(title: "App Rules", value: "\(viewModel.appRules.count)")
            }
            .padding(.vertical, 4)

            Divider()

            // Actions
            Button {
                viewModel.refresh()
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .buttonStyle(.plain)

            Button {
                NSApp.activate(ignoringOtherApps: true)
                // Open main window
                for window in NSApp.windows {
                    if window.title.isEmpty || window.title == "Rampart" {
                        window.makeKeyAndOrderFront(nil)
                        break
                    }
                }
            } label: {
                Label("Open Rampart", systemImage: "macwindow")
            }
            .buttonStyle(.plain)

            Divider()

            Button {
                NSApp.terminate(nil)
            } label: {
                Label("Quit", systemImage: "power")
            }
            .buttonStyle(.plain)
        }
        .padding()
        .frame(width: 280)
    }
}

// MARK: - Status Indicator

struct StatusIndicator: View {
    let pfEnabled: Bool
    let appEnabled: Bool

    var color: Color {
        if pfEnabled && appEnabled { return .green }
        if pfEnabled || appEnabled { return .yellow }
        return .red
    }

    var text: String {
        if pfEnabled && appEnabled { return "Protected" }
        if pfEnabled || appEnabled { return "Partial" }
        return "Off"
    }

    var body: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(color)
                .frame(width: 8, height: 8)
            Text(text)
                .font(.caption)
                .foregroundColor(.secondary)
        }
    }
}

// MARK: - Menu Bar Toggle

struct MenuBarToggle: View {
    let title: String
    let isEnabled: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack {
                Text(title)
                Spacer()
                Image(systemName: isEnabled ? "checkmark.circle.fill" : "circle")
                    .foregroundColor(isEnabled ? .green : .secondary)
            }
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Quick Stat

struct QuickStat: View {
    let title: String
    let value: String

    var body: some View {
        VStack(spacing: 2) {
            Text(value)
                .font(.headline)
            Text(title)
                .font(.caption2)
                .foregroundColor(.secondary)
        }
    }
}

#Preview {
    MenuBarView()
        .environmentObject(FirewallViewModel())
        .frame(width: 280)
}
