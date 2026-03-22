import SwiftUI

@main
struct SeKretSauceApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .windowStyle(.hiddenTitleBar)
        .windowResizability(.contentSize)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About SeKretSauce") {
                    NSApplication.shared.orderFrontStandardAboutPanel(
                        options: [
                            NSApplication.AboutPanelOptionKey.credits: NSAttributedString(
                                string: "A SecretServer.io product of After Dark Systems, LLC\n\nSecurity Swiss Army Knife for macOS",
                                attributes: [NSAttributedString.Key.font: NSFont.systemFont(ofSize: 11)]
                            ),
                            NSApplication.AboutPanelOptionKey(rawValue: "Copyright"): "© 2024 After Dark Systems, LLC"
                        ]
                    )
                }
            }
        }

        Settings {
            SettingsView()
        }
    }
}
