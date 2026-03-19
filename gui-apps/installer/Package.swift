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
            path: "SeKretSauceInstaller",
            exclude: ["Assets.xcassets"],
            resources: [
                .copy("Resources")
            ],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        )
    ]
)
