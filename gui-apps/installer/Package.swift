// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SeKretSauceInstaller",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(
            name: "SeKretSauceInstaller",
            targets: ["SeKretSauceInstaller"]
        )
    ],
    targets: [
        .executableTarget(
            name: "SeKretSauceInstaller",
            dependencies: ["InstallerSupport"],
            path: "SeKretSauceInstaller",
            exclude: ["Assets.xcassets"],
            resources: [
                .copy("Resources")
            ],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),
        .target(
            name: "InstallerSupport",
            path: "Sources/InstallerSupport"
        ),
        .testTarget(
            name: "InstallerSupportTests",
            dependencies: ["InstallerSupport"],
            path: "Tests/InstallerSupportTests"
        ),
    ]
)
