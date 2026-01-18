// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "FirewallKit",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "FirewallKit",
            targets: ["FirewallKit"]
        ),
    ],
    targets: [
        .target(
            name: "FirewallKit",
            dependencies: [],
            path: "Sources/FirewallKit"
        ),
        .testTarget(
            name: "FirewallKitTests",
            dependencies: ["FirewallKit"]
        ),
    ]
)
