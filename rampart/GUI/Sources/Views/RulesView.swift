// RulesView - Unified rules management view

import SwiftUI
import FirewallKit

struct RulesView: View {
    @EnvironmentObject var viewModel: FirewallViewModel
    @State private var selectedRuleType: RuleType = .all

    enum RuleType: String, CaseIterable {
        case all = "All Rules"
        case pf = "Packet Filter"
        case app = "Application"
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                VStack(alignment: .leading) {
                    Text("All Rules")
                        .font(.title2)
                        .fontWeight(.bold)
                    Text("Unified view of all firewall rules")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }

                Spacer()

                Picker("Filter", selection: $selectedRuleType) {
                    ForEach(RuleType.allCases, id: \.self) { type in
                        Text(type.rawValue).tag(type)
                    }
                }
                .pickerStyle(.segmented)
                .frame(width: 300)
            }
            .padding()
            .background(Color(NSColor.controlBackgroundColor))

            Divider()

            // Summary
            HStack(spacing: 30) {
                RuleSummaryCard(
                    title: "PF Rules",
                    count: viewModel.pfRules.count,
                    blocking: viewModel.pfRules.filter { $0.action == .block }.count,
                    icon: "network.badge.shield.half.filled",
                    color: .blue
                )

                RuleSummaryCard(
                    title: "App Rules",
                    count: viewModel.appRules.count,
                    blocking: viewModel.appRules.filter { !$0.allowed }.count,
                    icon: "app.badge.checkmark",
                    color: .purple
                )

                Spacer()
            }
            .padding()

            Divider()

            // Rules List
            List {
                if selectedRuleType == .all || selectedRuleType == .pf {
                    Section("Packet Filter Rules") {
                        if viewModel.pfRules.isEmpty {
                            Text("No PF rules configured")
                                .foregroundColor(.secondary)
                        } else {
                            ForEach(Array(viewModel.pfRules.enumerated()), id: \.element.id) { index, rule in
                                UnifiedPFRuleRow(rule: rule) {
                                    viewModel.removePFRule(at: index)
                                }
                            }
                        }
                    }
                }

                if selectedRuleType == .all || selectedRuleType == .app {
                    Section("Application Rules") {
                        if viewModel.appRules.isEmpty {
                            Text("No application rules configured")
                                .foregroundColor(.secondary)
                        } else {
                            ForEach(viewModel.appRules) { rule in
                                UnifiedAppRuleRow(rule: rule) {
                                    viewModel.removeAppRule(for: rule.path)
                                }
                            }
                        }
                    }
                }
            }
            .listStyle(.inset)
        }
    }
}

// MARK: - Rule Summary Card

struct RuleSummaryCard: View {
    let title: String
    let count: Int
    let blocking: Int
    let icon: String
    let color: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: icon)
                    .foregroundColor(color)
                Text(title)
                    .font(.headline)
            }

            HStack(spacing: 16) {
                VStack(alignment: .leading) {
                    Text("\(count)")
                        .font(.title)
                        .fontWeight(.bold)
                    Text("Total")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                VStack(alignment: .leading) {
                    Text("\(blocking)")
                        .font(.title)
                        .fontWeight(.bold)
                        .foregroundColor(.red)
                    Text("Blocking")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding()
        .background(color.opacity(0.1))
        .cornerRadius(12)
    }
}

// MARK: - Unified PF Rule Row

struct UnifiedPFRuleRow: View {
    let rule: PFRule
    let onDelete: () -> Void

    var body: some View {
        HStack {
            Image(systemName: "network.badge.shield.half.filled")
                .foregroundColor(.blue)
                .frame(width: 30)

            Image(systemName: rule.action == .block ? "xmark.circle.fill" : "checkmark.circle.fill")
                .foregroundColor(rule.action == .block ? .red : .green)

            VStack(alignment: .leading, spacing: 2) {
                Text(rule.description)
                    .font(.subheadline)

                Text(rule.toPFSyntax())
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }

            Spacer()

            Button {
                onDelete()
            } label: {
                Image(systemName: "trash")
                    .foregroundColor(.red)
            }
            .buttonStyle(.plain)
        }
    }
}

// MARK: - Unified App Rule Row

struct UnifiedAppRuleRow: View {
    let rule: AppFirewallRule
    let onDelete: () -> Void

    var body: some View {
        HStack {
            Image(systemName: "app.badge.checkmark")
                .foregroundColor(.purple)
                .frame(width: 30)

            Image(systemName: rule.allowed ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundColor(rule.allowed ? .green : .red)

            VStack(alignment: .leading, spacing: 2) {
                Text(rule.name)
                    .font(.subheadline)

                Text(rule.path)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Spacer()

            Text(rule.allowed ? "ALLOW" : "BLOCK")
                .font(.caption2)
                .fontWeight(.semibold)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(rule.allowed ? Color.green.opacity(0.2) : Color.red.opacity(0.2))
                .cornerRadius(4)

            Button {
                onDelete()
            } label: {
                Image(systemName: "trash")
                    .foregroundColor(.red)
            }
            .buttonStyle(.plain)
        }
    }
}

#Preview {
    RulesView()
        .environmentObject(FirewallViewModel())
}
