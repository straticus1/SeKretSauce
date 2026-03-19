// FirewallViewModel - Central state management for Rampart GUI

import SwiftUI
import FirewallKit
import Combine

@MainActor
final class FirewallViewModel: ObservableObject {

    // MARK: - Published State

    // PF State
    @Published var pfEnabled: Bool = false
    @Published var pfRules: [PFRule] = []

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

    // MARK: - Managers

    private let kit = FirewallKit()
    private var refreshTimer: Timer?

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
        kit.pf.refresh()
        kit.appFirewall.refresh()
        kit.netState.refresh()

        pfEnabled = kit.pf.isEnabled
        pfRules = kit.pf.rules

        appFirewallEnabled = kit.appFirewall.isEnabled
        stealthMode = kit.appFirewall.stealthMode
        blockAll = kit.appFirewall.blockAll
        appRules = kit.appFirewall.apps

        connections = kit.netState.connections
        listeners = kit.netState.listeners
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
        Task {
            isLoading = true
            defer { isLoading = false }

            do {
                if pfEnabled {
                    try kit.pf.disable()
                } else {
                    try kit.pf.enable()
                }
                refresh()
            } catch {
                showError(error)
            }
        }
    }

    func reloadPFRules() {
        Task {
            isLoading = true
            defer { isLoading = false }

            do {
                try kit.pf.reload()
                refresh()
            } catch {
                showError(error)
            }
        }
    }

    func addPFRule(_ rule: PFRule) {
        Task {
            isLoading = true
            defer { isLoading = false }

            do {
                try kit.pf.addRule(rule)
                refresh()
            } catch {
                showError(error)
            }
        }
    }

    func removePFRule(at index: Int) {
        Task {
            isLoading = true
            defer { isLoading = false }

            do {
                try kit.pf.removeRule(at: index)
                refresh()
            } catch {
                showError(error)
            }
        }
    }

    // MARK: - App Firewall Actions

    func toggleAppFirewall() {
        Task {
            isLoading = true
            defer { isLoading = false }

            do {
                if appFirewallEnabled {
                    try kit.appFirewall.disable()
                } else {
                    try kit.appFirewall.enable()
                }
                refresh()
            } catch {
                showError(error)
            }
        }
    }

    func toggleStealthMode() {
        Task {
            isLoading = true
            defer { isLoading = false }

            do {
                try kit.appFirewall.setStealthMode(!stealthMode)
                refresh()
            } catch {
                showError(error)
            }
        }
    }

    func toggleBlockAll() {
        Task {
            isLoading = true
            defer { isLoading = false }

            do {
                try kit.appFirewall.setBlockAll(!blockAll)
                refresh()
            } catch {
                showError(error)
            }
        }
    }

    func allowApp(at path: String) {
        Task {
            isLoading = true
            defer { isLoading = false }

            do {
                try kit.appFirewall.allowApp(at: path)
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
                try kit.appFirewall.blockApp(at: path)
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
                try kit.appFirewall.removeRule(for: path)
                refresh()
            } catch {
                showError(error)
            }
        }
    }

    // MARK: - Quick Actions

    func quickBlockIP(_ ip: String) {
        Task {
            isLoading = true
            defer { isLoading = false }

            do {
                try kit.blockIP(ip)
                refresh()
            } catch {
                showError(error)
            }
        }
    }

    // MARK: - Error Handling

    private func showError(_ error: Error) {
        errorMessage = error.localizedDescription
        showError = true
    }
}
