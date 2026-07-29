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
        .library(
            name: "FirewallHelperCore",
            targets: ["FirewallHelperCore"]
        ),
    ],
    dependencies: [
        .package(path: "../FirewallKit"),
    ],
    targets: [
        .executableTarget(
            name: "FirewallHelper",
            dependencies: ["FirewallKit", "FirewallHelperCore"],
            path: "Sources/FirewallHelper"
        ),
        .target(
            name: "FirewallHelperCore",
            dependencies: [],
            path: "Sources/FirewallHelperCore",
            linkerSettings: [
                .linkedFramework("Security")
            ]
        ),
        .testTarget(
            name: "FirewallHelperCoreTests",
            dependencies: ["FirewallHelperCore"],
            path: "Tests/FirewallHelperCoreTests"
        ),
    ]
)
