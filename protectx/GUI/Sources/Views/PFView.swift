// PFView - Packet Filter management view

import SwiftUI
import FirewallKit

struct PFView: View {
    @EnvironmentObject var viewModel: FirewallViewModel
    @State private var showAddRule = false
    @State private var newRuleIP = ""
    @State private var newRuleAction: PFRule.Action = .block
    @State private var newRuleDirection: PFRule.Direction = .in

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                VStack(alignment: .leading) {
                    Text("Packet Filter (pf)")
                        .font(.title2)
                        .fontWeight(.bold)
                    Text("BSD-level network filtering")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }

                Spacer()

                Toggle("Enabled", isOn: Binding(
                    get: { viewModel.pfEnabled },
                    set: { _ in viewModel.togglePF() }
                ))
                .toggleStyle(.switch)
            }
            .padding()
            .background(Color(NSColor.controlBackgroundColor))

            Divider()

            // Toolbar
            HStack {
                Button {
                    showAddRule = true
                } label: {
                    Label("Add Rule", systemImage: "plus")
                }

                Button {
                    viewModel.reloadPFRules()
                } label: {
                    Label("Reload", systemImage: "arrow.clockwise")
                }

                Spacer()

                Text("\(viewModel.pfRules.count) rules")
                    .foregroundColor(.secondary)
            }
            .padding()

            Divider()

            // Rules List
            if viewModel.pfRules.isEmpty {
                VStack(spacing: 16) {
                    Image(systemName: "shield.slash")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary)
                    Text("No pf rules configured")
                        .font(.headline)
                    Text("Add rules to control network traffic at the packet level")
                        .foregroundColor(.secondary)
                    Button("Add First Rule") {
                        showAddRule = true
                    }
                    .buttonStyle(.borderedProminent)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    ForEach(Array(viewModel.pfRules.enumerated()), id: \.element.id) { index, rule in
                        PFRuleRow(rule: rule, index: index) {
                            viewModel.removePFRule(at: index)
                        }
                    }
                }
                .listStyle(.inset)
            }
        }
        .sheet(isPresented: $showAddRule) {
            AddPFRuleSheet(
                ip: $newRuleIP,
                action: $newRuleAction,
                direction: $newRuleDirection
            ) {
                if !newRuleIP.isEmpty {
                    let rule = PFRule(
                        action: newRuleAction,
                        direction: newRuleDirection,
                        source: newRuleDirection == .in ? .host(newRuleIP) : .any,
                        destination: newRuleDirection == .out ? .host(newRuleIP) : .any,
                        log: true
                    )
                    viewModel.addPFRule(rule)
                    newRuleIP = ""
                    showAddRule = false
                }
            }
        }
    }
}

// MARK: - PF Rule Row

struct PFRuleRow: View {
    let rule: PFRule
    let index: Int
    let onDelete: () -> Void

    var body: some View {
        HStack {
            // Action indicator
            Image(systemName: rule.action == .block ? "xmark.circle.fill" : "checkmark.circle.fill")
                .foregroundColor(rule.action == .block ? .red : .green)
                .font(.title2)

            // Direction
            Image(systemName: directionIcon)
                .foregroundColor(.secondary)

            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(rule.action.rawValue.uppercased())
                        .font(.caption)
                        .fontWeight(.semibold)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(rule.action == .block ? Color.red.opacity(0.2) : Color.green.opacity(0.2))
                        .cornerRadius(4)

                    if let proto = rule.networkProtocol {
                        Text(proto.rawValue.uppercased())
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

                Text(ruleDescription)
                    .font(.subheadline)

                Text(rule.toPFSyntax())
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }

            Spacer()

            if rule.log {
                Image(systemName: "doc.text")
                    .foregroundColor(.secondary)
                    .help("Logging enabled")
            }

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

    var directionIcon: String {
        switch rule.direction {
        case .in: return "arrow.down.circle"
        case .out: return "arrow.up.circle"
        case .any: return "arrow.up.arrow.down.circle"
        }
    }

    var ruleDescription: String {
        let src = rule.source.displayName
        let dst = rule.destination.displayName
        let port = rule.port?.displayName ?? "any"

        return "\(src) → \(dst):\(port)"
    }
}

// MARK: - Add Rule Sheet

struct AddPFRuleSheet: View {
    @Binding var ip: String
    @Binding var action: PFRule.Action
    @Binding var direction: PFRule.Direction
    let onAdd: () -> Void

    @Environment(\.dismiss) var dismiss

    var body: some View {
        VStack(spacing: 20) {
            Text("Add PF Rule")
                .font(.headline)

            Form {
                TextField("IP Address or Network", text: $ip)
                    .textFieldStyle(.roundedBorder)

                Picker("Action", selection: $action) {
                    Text("Block").tag(PFRule.Action.block)
                    Text("Allow").tag(PFRule.Action.pass)
                }
                .pickerStyle(.segmented)

                Picker("Direction", selection: $direction) {
                    Text("Incoming").tag(PFRule.Direction.in)
                    Text("Outgoing").tag(PFRule.Direction.out)
                    Text("Both").tag(PFRule.Direction.any)
                }
                .pickerStyle(.segmented)
            }
            .padding()

            HStack {
                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)

                Spacer()

                Button("Add Rule") {
                    onAdd()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(ip.isEmpty)
            }
            .padding()
        }
        .frame(width: 400)
        .padding()
    }
}

#Preview {
    PFView()
        .environmentObject(FirewallViewModel())
}
