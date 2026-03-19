// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "adsp",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(
            name: "adsp",
            targets: ["adsp"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.2.0"),
        .package(path: "../FirewallKit"),
    ],
    targets: [
        .executableTarget(
            name: "adsp",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                "FirewallKit",
            ],
            path: "Sources/pfm"
        ),
    ]
)
