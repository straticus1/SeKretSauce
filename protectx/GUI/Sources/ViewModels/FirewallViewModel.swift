// FirewallViewModel - Central state management for Rampart GUI

import Combine
import FirewallKit
import SwiftUI

@MainActor
final class FirewallViewModel: ObservableObject {

    // MARK: - Published State

    // PF State
    @Published var pfEnabled: Bool = false
    @Published var pfRules: [PFRule] = []
    private var pfRevision = 0
    struct RulePreview: Identifiable {
        let id = UUID()
        let rules: [PFRule]
        let revision: Int
        let description: String
    }
    @Published var rulePreview: RulePreview?

    // App Firewall State
    @Published var appFirewallEnabled: Bool = false
    @Published var stealthMode: Bool = false
    @Published var blockAll: Bool = false
    @Published var appRules: [AppFirewallRule] = []

    // Network State
    @Published var connections: [Connection] = []
    @Published var listeners: [Listener] = []

    // UI State
    @Published var selectedTab: Tab = .dashboard
    @Published var isLoading: Bool = false
    @Published var errorMessage: String?
    @Published var showError: Bool = false
    @Published var helperState: FirewallHelperState = .notInstalled

    // MARK: - Managers

    private let helper = FirewallHelperClient()
    private let helperService = FirewallHelperService()
    private let netState = NetStateMonitor()
    private var refreshTimer: Timer?
    private var refreshInProgress = false

    // MARK: - Init

    init() {
        refresh()
        startAutoRefresh()
    }

    deinit {
        refreshTimer?.invalidate()
    }

    // MARK: - Tabs

    enum Tab: String, CaseIterable, Identifiable {
        case dashboard = "Dashboard"
        case pf = "Packet Filter"
        case appFirewall = "App Firewall"
        case network = "Network"
        case rules = "Rules"

        var id: String { rawValue }

        var icon: String {
            switch self {
            case .dashboard: return "gauge.with.dots.needle.bottom.50percent"
            case .pf: return "network.badge.shield.half.filled"
            case .appFirewall: return "app.badge.checkmark"
            case .network: return "network"
            case .rules: return "list.bullet.rectangle"
            }
        }
    }

    // MARK: - Refresh

    func refresh() {
        guard !refreshInProgress else { return }
        refreshInProgress = true
        Task {
            defer { refreshInProgress = false }
            netState.refresh()
            connections = netState.connections
            listeners = netState.listeners

            let serviceState = helperService.state
            guard case .unavailable = serviceState else {
                helperState = serviceState
                return
            }

            do {
                let version = try await helper.ping()
                async let pf = helper.pfStatus()
                async let app = helper.appFirewallStatus()
                let (pfStatus, appStatus) = try await (pf, app)

                helperState = .available(version: version)
                pfEnabled = pfStatus.enabled
                pfRules = pfStatus.rules
                pfRevision = pfStatus.revision
                appFirewallEnabled = appStatus.enabled
                stealthMode = appStatus.stealthMode
                blockAll = appStatus.blockAll
                appRules = appStatus.apps.map {
                    AppFirewallRule(path: $0.path, name: $0.name, allowed: $0.allowed)
                }
            } catch {
                helperState = .unavailable
            }
        }
    }

    private func startAutoRefresh() {
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.refresh()
            }
        }
    }

    // MARK: - PF Actions

    func togglePF() {
        performPrivileged {
            try await self.helper.setPFEnabled(!self.pfEnabled)
        }
    }

    func reloadPFRules() {
        Task {
            isLoading = true
            defer { isLoading = false }

            do {
                try requireHelper()
                try await helper.reloadPF()
                refresh()
            } catch {
                showError(error)
            }
        }
    }

    func addPFRule(_ rule: PFRule) {
        guard !isLoading else { return }
        rulePreview = RulePreview(
            rules: pfRules + [rule], revision: pfRevision, description: "Add: \(rule.description)")
    }

    func removePFRule(at index: Int) {
        guard !isLoading, pfRules.indices.contains(index) else { return }
        var proposed = pfRules
        let removed = proposed.remove(at: index)
        rulePreview = RulePreview(
            rules: proposed, revision: pfRevision, description: "Remove: \(removed.description)")
    }

    func applyRulePreview() {
        guard let preview = rulePreview, !isLoading else { return }
        rulePreview = nil
        performPrivileged {
            try await self.helper.applyPF(preview.rules, expectedRevision: preview.revision)
        }
    }

    // MARK: - App Firewall Actions

    func toggleAppFirewall() {
        performPrivileged {
            try await self.helper.setAppFirewallEnabled(!self.appFirewallEnabled)
        }
    }

    func toggleStealthMode() {
        performPrivileged {
            try await self.helper.setStealthMode(!self.stealthMode)
        }
    }

    func toggleBlockAll() {
        performPrivileged {
            try await self.helper.setBlockAll(!self.blockAll)
        }
    }

    func allowApp(at path: String) {
        Task {
            isLoading = true
            defer { isLoading = false }

            do {
                try requireHelper()
                try await helper.allowApp(at: path)
                refresh()
            } catch {
                showError(error)
            }
        }
    }

    func blockApp(at path: String) {
        Task {
            isLoading = true
            defer { isLoading = false }

            do {
                try requireHelper()
                try await helper.blockApp(at: path)
                refresh()
            } catch {
                showError(error)
            }
        }
    }

    func removeAppRule(for path: String) {
        Task {
            isLoading = true
            defer { isLoading = false }

            do {
                try requireHelper()
                try await helper.removeApp(at: path)
                refresh()
            } catch {
                showError(error)
            }
        }
    }

    // MARK: - Quick Actions

    func quickBlockIP(_ ip: String) { addPFRule(.block(from: ip)) }

    // MARK: - Error Handling

    func installHelper() {
        do {
            try helperService.register()
            helperState = helperService.state
            refresh()
        } catch {
            showError(error)
        }
    }

    func openHelperApprovalSettings() {
        guard
            let url = URL(
                string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"
            )
        else { return }
        NSWorkspace.shared.open(url)
    }

    private func performPrivileged(
        _ operation: @escaping @MainActor () async throws -> Void
    ) {
        guard !isLoading else { return }
        isLoading = true
        Task {
            defer { isLoading = false }
            do {
                try requireHelper()
                try await operation()
                refresh()
            } catch {
                showError(error)
            }
        }
    }

    private func requireHelper() throws {
        switch helperState {
        case .available:
            return
        case .notInstalled:
            throw FirewallHelperClientError.registrationRequired
        case .awaitingApproval:
            throw FirewallHelperClientError.approvalRequired
        case .unavailable:
            throw FirewallHelperClientError.unavailable
        }
    }

    private func showError(_ error: Error) {
        errorMessage = error.localizedDescription
        showError = true
    }
}
