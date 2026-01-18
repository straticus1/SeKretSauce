import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = SeKretSauceViewModel()
    @State private var selectedTab: ScanTab = .overview

    var body: some View {
        NavigationSplitView {
            Sidebar(selectedTab: $selectedTab)
        } detail: {
            DetailView(tab: selectedTab, viewModel: viewModel)
        }
        .frame(minWidth: 900, minHeight: 600)
    }
}

enum ScanTab: String, CaseIterable, Identifiable {
    case overview = "Overview"
    case browser = "Browser Export"
    case keychain = "Keychain"
    case certs = "Certificates"
    case hidden = "Hidden Processes"
    case apps = "App Inspector"
    case breach = "Breach Check"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .overview: return "shield.checkered"
        case .browser: return "globe"
        case .keychain: return "key.fill"
        case .certs: return "checkmark.seal.fill"
        case .hidden: return "eye.slash.fill"
        case .apps: return "app.badge.checkmark"
        case .breach: return "exclamationmark.triangle.fill"
        }
    }
}

struct Sidebar: View {
    @Binding var selectedTab: ScanTab

    var body: some View {
        List(ScanTab.allCases, selection: $selectedTab) { tab in
            Label(tab.rawValue, systemImage: tab.icon)
                .tag(tab)
        }
        .listStyle(.sidebar)
        .navigationTitle("SeKretSauce")
    }
}

struct DetailView: View {
    let tab: ScanTab
    @ObservedObject var viewModel: SeKretSauceViewModel

    var body: some View {
        VStack {
            switch tab {
            case .overview:
                OverviewView(viewModel: viewModel)
            case .browser:
                BrowserExportView(viewModel: viewModel)
            case .keychain:
                KeychainView(viewModel: viewModel)
            case .certs:
                CertificatesView(viewModel: viewModel)
            case .hidden:
                HiddenProcessView(viewModel: viewModel)
            case .apps:
                AppInspectorView(viewModel: viewModel)
            case .breach:
                BreachCheckView(viewModel: viewModel)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Overview View
struct OverviewView: View {
    @ObservedObject var viewModel: SeKretSauceViewModel

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Header
                HStack {
                    VStack(alignment: .leading) {
                        Text("SeKretSauce")
                            .font(.largeTitle)
                            .fontWeight(.bold)
                        Text("Security Swiss Army Knife for macOS")
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button(action: { viewModel.runFullScan() }) {
                        Label("Run Full Scan", systemImage: "play.fill")
                            .padding(.horizontal)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(viewModel.isScanning)
                }
                .padding()

                if viewModel.isScanning {
                    ProgressView(viewModel.scanStatus)
                        .padding()
                }

                // Stats Grid
                LazyVGrid(columns: [
                    GridItem(.flexible()),
                    GridItem(.flexible()),
                    GridItem(.flexible())
                ], spacing: 16) {
                    StatCard(
                        title: "Keychain Items",
                        value: "\(viewModel.keychainCount)",
                        icon: "key.fill",
                        color: .blue
                    )
                    StatCard(
                        title: "Launch Agents",
                        value: "\(viewModel.launchAgentCount)",
                        icon: "gearshape.2.fill",
                        color: .purple
                    )
                    StatCard(
                        title: "Apps Scanned",
                        value: "\(viewModel.appCount)",
                        icon: "app.badge.checkmark",
                        color: .green
                    )
                }
                .padding(.horizontal)

                // Findings Summary
                if !viewModel.findings.isEmpty {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Recent Findings")
                            .font(.headline)

                        ForEach(viewModel.findings.prefix(10), id: \.self) { finding in
                            FindingRow(finding: finding)
                        }
                    }
                    .padding()
                    .background(RoundedRectangle(cornerRadius: 12).fill(.background))
                    .padding(.horizontal)
                }

                Spacer()
            }
        }
    }
}

struct StatCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: icon)
                .font(.title)
                .foregroundStyle(color)
            Text(value)
                .font(.title2)
                .fontWeight(.semibold)
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding()
        .background(RoundedRectangle(cornerRadius: 12).fill(.background))
    }
}

struct FindingRow: View {
    let finding: Finding

    var body: some View {
        HStack {
            Circle()
                .fill(finding.severityColor)
                .frame(width: 8, height: 8)
            Text(finding.title)
                .font(.subheadline)
            Spacer()
            Text(finding.category)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Browser Export View
struct BrowserExportView: View {
    @ObservedObject var viewModel: SeKretSauceViewModel
    @State private var selectedBrowser: String = "all"

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Browser Export")
                .font(.title)
                .fontWeight(.bold)
                .padding(.horizontal)

            HStack {
                Picker("Browser", selection: $selectedBrowser) {
                    Text("All Browsers").tag("all")
                    Text("Firefox").tag("firefox")
                    Text("Chrome").tag("chrome")
                    Text("Safari").tag("safari")
                }
                .pickerStyle(.segmented)
                .frame(width: 400)

                Spacer()

                Button(action: { viewModel.exportBrowser(selectedBrowser) }) {
                    Label("Export", systemImage: "square.and.arrow.up")
                }
                .buttonStyle(.borderedProminent)
                .disabled(viewModel.isScanning)
            }
            .padding(.horizontal)

            if !viewModel.browserResults.isEmpty {
                List(viewModel.browserResults, id: \.browser) { result in
                    DisclosureGroup(result.browser.capitalized) {
                        ForEach(result.profiles, id: \.name) { profile in
                            VStack(alignment: .leading) {
                                Text(profile.name)
                                    .fontWeight(.medium)
                                HStack {
                                    Label("\(profile.bookmarkCount) bookmarks", systemImage: "bookmark")
                                    Label("\(profile.historyCount) history", systemImage: "clock")
                                }
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            }
                            .padding(.vertical, 4)
                        }
                    }
                }
            } else {
                ContentUnavailableView(
                    "No Browser Data",
                    systemImage: "globe",
                    description: Text("Click Export to scan browser data")
                )
            }
        }
    }
}

// MARK: - Keychain View
struct KeychainView: View {
    @ObservedObject var viewModel: SeKretSauceViewModel
    @State private var searchText = ""

    var filteredItems: [KeychainItem] {
        if searchText.isEmpty {
            return viewModel.keychainItems
        }
        return viewModel.keychainItems.filter {
            $0.service.localizedCaseInsensitiveContains(searchText) ||
            $0.account.localizedCaseInsensitiveContains(searchText)
        }
    }

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Keychain Scanner")
                    .font(.title)
                    .fontWeight(.bold)
                Spacer()
                Button(action: { viewModel.scanKeychain() }) {
                    Label("Scan", systemImage: "magnifyingglass")
                }
                .buttonStyle(.borderedProminent)
                .disabled(viewModel.isScanning)
            }
            .padding()

            if !viewModel.keychainItems.isEmpty {
                Table(filteredItems) {
                    TableColumn("Type") { item in
                        Image(systemName: item.itemClass == "generic_password" ? "key" : "globe")
                    }
                    .width(40)
                    TableColumn("Service", value: \.service)
                    TableColumn("Account", value: \.account)
                    TableColumn("Status") { item in
                        if item.isWeak {
                            Label("Warning", systemImage: "exclamationmark.triangle.fill")
                                .foregroundStyle(.yellow)
                        } else {
                            Label("OK", systemImage: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                        }
                    }
                }
                .searchable(text: $searchText)
            } else {
                ContentUnavailableView(
                    "No Keychain Data",
                    systemImage: "key.fill",
                    description: Text("Click Scan to analyze your Keychain")
                )
            }
        }
    }
}

// MARK: - Certificates View
struct CertificatesView: View {
    @ObservedObject var viewModel: SeKretSauceViewModel
    @State private var domain = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Certificate Transparency")
                .font(.title)
                .fontWeight(.bold)
                .padding(.horizontal)

            HStack {
                TextField("Enter domain to check", text: $domain)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 300)

                Button(action: { viewModel.checkCertificates(domain) }) {
                    Label("Check", systemImage: "checkmark.seal")
                }
                .buttonStyle(.borderedProminent)
                .disabled(domain.isEmpty || viewModel.isScanning)
            }
            .padding(.horizontal)

            if !viewModel.certificates.isEmpty {
                List(viewModel.certificates, id: \.serialNumber) { cert in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(cert.subject)
                            .fontWeight(.medium)
                        Text("Issuer: \(cert.issuer)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        HStack {
                            Text("Valid: \(cert.notBefore) - \(cert.notAfter)")
                            if cert.isSuspicious {
                                Label("Suspicious", systemImage: "exclamationmark.triangle.fill")
                                    .foregroundStyle(.yellow)
                            }
                        }
                        .font(.caption)
                    }
                    .padding(.vertical, 4)
                }
            } else {
                ContentUnavailableView(
                    "No Certificate Data",
                    systemImage: "checkmark.seal.fill",
                    description: Text("Enter a domain to check certificate transparency logs")
                )
            }
        }
    }
}

// MARK: - Hidden Process View
struct HiddenProcessView: View {
    @ObservedObject var viewModel: SeKretSauceViewModel

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Hidden Process Hunter")
                    .font(.title)
                    .fontWeight(.bold)
                Spacer()
                Button(action: { viewModel.scanHidden() }) {
                    Label("Hunt", systemImage: "eye.slash")
                }
                .buttonStyle(.borderedProminent)
                .disabled(viewModel.isScanning)
            }
            .padding()

            if !viewModel.suspiciousProcesses.isEmpty || !viewModel.suspiciousAgents.isEmpty {
                List {
                    if !viewModel.suspiciousProcesses.isEmpty {
                        Section("Suspicious Processes") {
                            ForEach(viewModel.suspiciousProcesses, id: \.pid) { proc in
                                VStack(alignment: .leading, spacing: 4) {
                                    HStack {
                                        Text("PID \(proc.pid): \(proc.name)")
                                            .fontWeight(.medium)
                                        Spacer()
                                        SeverityBadge(severity: proc.severity)
                                    }
                                    Text(proc.reason)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                .padding(.vertical, 4)
                            }
                        }
                    }

                    if !viewModel.suspiciousAgents.isEmpty {
                        Section("Suspicious Launch Agents") {
                            ForEach(viewModel.suspiciousAgents, id: \.label) { agent in
                                VStack(alignment: .leading, spacing: 4) {
                                    HStack {
                                        Text(agent.label)
                                            .fontWeight(.medium)
                                        Spacer()
                                        SeverityBadge(severity: agent.severity)
                                    }
                                    Text(agent.program)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                    Text(agent.reason)
                                        .font(.caption)
                                        .foregroundStyle(.orange)
                                }
                                .padding(.vertical, 4)
                            }
                        }
                    }
                }
            } else {
                ContentUnavailableView(
                    "No Hidden Threats Found",
                    systemImage: "checkmark.shield.fill",
                    description: Text("Click Hunt to scan for hidden processes and launch agents")
                )
            }
        }
    }
}

// MARK: - App Inspector View
struct AppInspectorView: View {
    @ObservedObject var viewModel: SeKretSauceViewModel

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Application Inspector")
                    .font(.title)
                    .fontWeight(.bold)
                Spacer()
                Button(action: { viewModel.scanApps() }) {
                    Label("Inspect", systemImage: "app.badge.checkmark")
                }
                .buttonStyle(.borderedProminent)
                .disabled(viewModel.isScanning)
            }
            .padding()

            if !viewModel.appIssues.isEmpty {
                List(viewModel.appIssues, id: \.id) { issue in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(issue.appName)
                                .fontWeight(.medium)
                            Spacer()
                            SeverityBadge(severity: issue.severity)
                        }
                        Text(issue.category)
                            .font(.caption)
                            .foregroundStyle(.blue)
                        Text(issue.description)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                }
            } else {
                ContentUnavailableView(
                    "No Issues Found",
                    systemImage: "app.badge.checkmark",
                    description: Text("Click Inspect to analyze installed applications")
                )
            }
        }
    }
}

// MARK: - Breach Check View
struct BreachCheckView: View {
    @ObservedObject var viewModel: SeKretSauceViewModel
    @State private var email = ""
    @State private var domain = ""
    @State private var checkType: BreachCheckType = .email

    enum BreachCheckType {
        case email, domain
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Breach Detection")
                .font(.title)
                .fontWeight(.bold)
                .padding(.horizontal)

            Picker("Check Type", selection: $checkType) {
                Text("Email").tag(BreachCheckType.email)
                Text("Domain").tag(BreachCheckType.domain)
            }
            .pickerStyle(.segmented)
            .frame(width: 200)
            .padding(.horizontal)

            HStack {
                if checkType == .email {
                    TextField("Enter email address", text: $email)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 300)
                } else {
                    TextField("Enter domain", text: $domain)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 300)
                }

                Button(action: {
                    if checkType == .email {
                        viewModel.checkBreach(email: email)
                    } else {
                        viewModel.checkBreach(domain: domain)
                    }
                }) {
                    Label("Check", systemImage: "exclamationmark.triangle")
                }
                .buttonStyle(.borderedProminent)
                .disabled((checkType == .email ? email : domain).isEmpty || viewModel.isScanning)
            }
            .padding(.horizontal)

            if !viewModel.breaches.isEmpty {
                List(viewModel.breaches, id: \.account) { breach in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(breach.account)
                                .fontWeight(.medium)
                            Spacer()
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(.red)
                        }
                        Text("Breaches: \(breach.breachNames.joined(separator: ", "))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text("Data exposed: \(breach.dataTypes.joined(separator: ", "))")
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                    .padding(.vertical, 4)
                }
            } else if viewModel.breachCheckComplete {
                ContentUnavailableView(
                    "No Breaches Found",
                    systemImage: "checkmark.shield.fill",
                    description: Text("Good news! No breaches detected for this account")
                )
            } else {
                ContentUnavailableView(
                    "Check for Breaches",
                    systemImage: "exclamationmark.triangle.fill",
                    description: Text("Enter an email or domain to check against known data breaches")
                )
            }
        }
    }
}

// MARK: - Severity Badge
struct SeverityBadge: View {
    let severity: String

    var color: Color {
        switch severity.lowercased() {
        case "critical": return .red
        case "high": return .orange
        case "medium": return .yellow
        case "low": return .blue
        default: return .gray
        }
    }

    var body: some View {
        Text(severity.uppercased())
            .font(.caption2)
            .fontWeight(.semibold)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.2))
            .foregroundStyle(color)
            .clipShape(Capsule())
    }
}

// MARK: - Settings View
struct SettingsView: View {
    @AppStorage("cliPath") private var cliPath = "/usr/local/bin/sekretsauce"
    @AppStorage("autoScan") private var autoScan = false

    var body: some View {
        Form {
            Section("CLI Tool") {
                TextField("Path to sekretsauce", text: $cliPath)
                Button("Locate...") {
                    // File picker would go here
                }
            }

            Section("Behavior") {
                Toggle("Auto-scan on launch", isOn: $autoScan)
            }
        }
        .padding()
        .frame(width: 400, height: 200)
    }
}

#Preview {
    ContentView()
}
