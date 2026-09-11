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
    dependencies: [.package(path: "../..")],
    targets: [
        .executableTarget(
            name: "SeKretSauceGUI",
            dependencies: [.product(name: "SeKretSauceCommon", package: "afterdark-secretsauce")],
            path: ".",
            exclude: ["Package.swift", "Tests", "Info.plist", "build.sh"],
            sources: [
                "SeKretSauceApp.swift",
                "ContentView.swift",
                "ViewModel.swift",
                "PrivacyControls.swift",
                "RansomwareShieldControls.swift",
                "ScanReport.swift",
                "ScanHistory.swift",
                "CLIProcess.swift",
                "IncidentView.swift"
            ]
        ),
        .testTarget(name: "SeKretSauceGUITests", dependencies: ["SeKretSauceGUI"], path: "Tests")
    ]
)
