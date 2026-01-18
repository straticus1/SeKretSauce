// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "RampartGUI",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(
            name: "Rampart",
            targets: ["RampartGUI"]
        ),
    ],
    dependencies: [
        .package(path: "../FirewallKit"),
    ],
    targets: [
        .executableTarget(
            name: "RampartGUI",
            dependencies: ["FirewallKit"],
            path: "Sources"
        ),
    ]
)
