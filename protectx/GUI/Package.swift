// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "ProtectXGUI",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(
            name: "ProtectX",
            targets: ["ProtectXGUI"]
        ),
    ],
    dependencies: [
        .package(path: "../FirewallKit"),
    ],
    targets: [
        .executableTarget(
            name: "ProtectXGUI",
            dependencies: ["FirewallKit"],
            path: "Sources"
        ),
    ]
)
