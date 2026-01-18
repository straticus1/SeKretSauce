// Rampart - "One Place to Rule Them All"
// Unified macOS Firewall Control Center

import SwiftUI
import FirewallKit

@main
struct RampartApp: App {
    @StateObject private var viewModel = FirewallViewModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(viewModel)
        }
        .windowStyle(.hiddenTitleBar)
        .defaultSize(width: 900, height: 650)

        // Menu Bar Extra for quick access
        MenuBarExtra("Rampart", systemImage: "shield.checkered") {
            MenuBarView()
                .environmentObject(viewModel)
        }
        .menuBarExtraStyle(.window)
    }
}
