// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SeKretSauceGUI",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "SeKretSauceGUI", targets: ["SeKretSauceGUI"])
    ],
    targets: [
        .executableTarget(
            name: "SeKretSauceGUI",
            path: ".",
            exclude: ["Package.swift"],
            sources: ["SeKretSauceApp.swift", "ContentView.swift", "ViewModel.swift"]
        )
    ]
)
