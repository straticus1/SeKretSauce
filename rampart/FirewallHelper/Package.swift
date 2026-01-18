// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "FirewallHelper",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(
            name: "com.rampart.FirewallHelper",
            targets: ["FirewallHelper"]
        ),
    ],
    dependencies: [
        .package(path: "../FirewallKit"),
    ],
    targets: [
        .executableTarget(
            name: "FirewallHelper",
            dependencies: ["FirewallKit"],
            path: "Sources/FirewallHelper"
        ),
    ]
)
