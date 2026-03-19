// AppFirewallView - Application Firewall management view

import SwiftUI
import FirewallKit

struct AppFirewallView: View {
    @EnvironmentObject var viewModel: FirewallViewModel
    @State private var showAddApp = false
    @State private var searchText = ""

    var filteredApps: [AppFirewallRule] {
        if searchText.isEmpty {
            return viewModel.appRules
        }
        return viewModel.appRules.filter {
            $0.name.localizedCaseInsensitiveContains(searchText) ||
            $0.path.localizedCaseInsensitiveContains(searchText)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                VStack(alignment: .leading) {
                    Text("Application Firewall")
                        .font(.title2)
                        .fontWeight(.bold)
                    Text("Control per-application network access")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }

                Spacer()

                Toggle("Enabled", isOn: Binding(
                    get: { viewModel.appFirewallEnabled },
                    set: { _ in viewModel.toggleAppFirewall() }
                ))
                .toggleStyle(.switch)
            }
            .padding()
            .background(Color(NSColor.controlBackgroundColor))

            Divider()

            // Options Row
            HStack(spacing: 20) {
                Toggle("Stealth Mode", isOn: Binding(
                    get: { viewModel.stealthMode },
                    set: { _ in viewModel.toggleStealthMode() }
                ))
                .help("Don't respond to ping or connection attempts")

                Toggle("Block All Incoming", isOn: Binding(
                    get: { viewModel.blockAll },
                    set: { _ in viewModel.toggleBlockAll() }
                ))
                .help("Block all incoming connections except essential services")

                Spacer()
            }
            .padding()
            .background(Color(NSColor.windowBackgroundColor))

            Divider()

            // Toolbar
            HStack {
                Button {
                    showAddApp = true
                } label: {
                    Label("Add App", systemImage: "plus")
                }

                Spacer()

                TextField("Search apps...", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 200)

                Text("\(viewModel.appRules.count) apps")
                    .foregroundColor(.secondary)
            }
            .padding()

            Divider()

            // Apps List
            if viewModel.appRules.isEmpty {
                VStack(spacing: 16) {
                    Image(systemName: "app.badge.checkmark")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary)
                    Text("No application rules")
                        .font(.headline)
                    Text("Add applications to control their network access")
                        .foregroundColor(.secondary)
                    Button("Add Application") {
                        showAddApp = true
                    }
                    .buttonStyle(.borderedProminent)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    ForEach(filteredApps) { app in
                        AppRuleRow(rule: app) {
                            viewModel.removeAppRule(for: app.path)
                        } onToggle: {
                            if app.allowed {
                                viewModel.blockApp(at: app.path)
                            } else {
                                viewModel.allowApp(at: app.path)
                            }
                        }
                    }
                }
                .listStyle(.inset)
            }
        }
        .sheet(isPresented: $showAddApp) {
            AddAppSheet { path, allow in
                if allow {
                    viewModel.allowApp(at: path)
                } else {
                    viewModel.blockApp(at: path)
                }
                showAddApp = false
            }
        }
    }
}

// MARK: - App Rule Row

struct AppRuleRow: View {
    let rule: AppFirewallRule
    let onDelete: () -> Void
    let onToggle: () -> Void

    var body: some View {
        HStack {
            // App icon (if we can get it)
            Image(systemName: "app.fill")
                .font(.title)
                .foregroundColor(.secondary)
                .frame(width: 40, height: 40)
                .background(Color(NSColor.controlBackgroundColor))
                .cornerRadius(8)

            VStack(alignment: .leading, spacing: 4) {
                Text(rule.name)
                    .font(.headline)

                Text(rule.path)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Spacer()

            // Status badge
            Text(rule.allowed ? "ALLOWED" : "BLOCKED")
                .font(.caption)
                .fontWeight(.semibold)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(rule.allowed ? Color.green.opacity(0.2) : Color.red.opacity(0.2))
                .foregroundColor(rule.allowed ? .green : .red)
                .cornerRadius(4)

            // Toggle
            Toggle("", isOn: Binding(
                get: { rule.allowed },
                set: { _ in onToggle() }
            ))
            .toggleStyle(.switch)
            .labelsHidden()

            // Delete
            Button {
                onDelete()
            } label: {
                Image(systemName: "trash")
                    .foregroundColor(.red)
            }
            .buttonStyle(.plain)
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Add App Sheet

struct AddAppSheet: View {
    @State private var selectedPath: String = ""
    @State private var allowAccess = true

    let onAdd: (String, Bool) -> Void

    @Environment(\.dismiss) var dismiss

    var body: some View {
        VStack(spacing: 20) {
            Text("Add Application Rule")
                .font(.headline)

            VStack(alignment: .leading, spacing: 8) {
                Text("Application Path")
                    .font(.subheadline)

                HStack {
                    TextField("Path to application", text: $selectedPath)
                        .textFieldStyle(.roundedBorder)

                    Button("Browse...") {
                        let panel = NSOpenPanel()
                        panel.allowsMultipleSelection = false
                        panel.canChooseDirectories = false
                        panel.canChooseFiles = true
                        panel.allowedContentTypes = [.application, .unixExecutable]
                        panel.directoryURL = URL(fileURLWithPath: "/Applications")

                        if panel.runModal() == .OK {
                            selectedPath = panel.url?.path ?? ""
                        }
                    }
                }

                Picker("Access", selection: $allowAccess) {
                    Text("Allow Connections").tag(true)
                    Text("Block Connections").tag(false)
                }
                .pickerStyle(.radioGroup)
                .padding(.top)
            }
            .padding()

            HStack {
                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)

                Spacer()

                Button("Add") {
                    if !selectedPath.isEmpty {
                        onAdd(selectedPath, allowAccess)
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(selectedPath.isEmpty)
            }
            .padding()
        }
        .frame(width: 500)
        .padding()
    }
}

#Preview {
    AppFirewallView()
        .environmentObject(FirewallViewModel())
}
