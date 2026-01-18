// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SeKretSauce",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        // Main daemon executable
        .executable(
            name: "sekretsauced",
            targets: ["Daemon"]
        ),
        // SSH wrapper executable
        .executable(
            name: "ssh-wrapper",
            targets: ["SSHRecorder"]
        ),
        // Common library
        .library(
            name: "SeKretSauceCommon",
            targets: ["Common"]
        ),
        // Tunnel detection library
        .library(
            name: "TunnelDetection",
            targets: ["TunnelDetection"]
        ),
    ],
    dependencies: [
        // Add external dependencies here if needed
        // .package(url: "https://github.com/apple/swift-argument-parser", from: "1.2.0"),
    ],
    targets: [
        // Common module - shared types and utilities
        .target(
            name: "Common",
            dependencies: [],
            path: "Sources/Common",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),

        // Tunnel detection engine
        .target(
            name: "TunnelDetection",
            dependencies: ["Common"],
            path: "Sources/TunnelDetection",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),

        // Endpoint Security process monitoring
        .target(
            name: "EndpointSecurity",
            dependencies: ["Common", "TunnelDetection"],
            path: "Sources/EndpointSecurity",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ],
            linkerSettings: [
                .linkedFramework("EndpointSecurity"),
                .linkedFramework("SystemConfiguration")
            ]
        ),

        // Network Extension providers
        .target(
            name: "NetworkExtension",
            dependencies: ["Common", "TunnelDetection"],
            path: "Sources/NetworkExtension",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ],
            linkerSettings: [
                .linkedFramework("NetworkExtension")
            ]
        ),

        // SSH recorder/wrapper
        .executableTarget(
            name: "SSHRecorder",
            dependencies: ["Common", "TunnelDetection"],
            path: "Sources/SSHRecorder",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),

        // Main daemon
        .executableTarget(
            name: "Daemon",
            dependencies: [
                "Common",
                "TunnelDetection",
                "EndpointSecurity"
            ],
            path: "Sources/Daemon",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ],
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("SystemConfiguration"),
                .linkedFramework("IOKit")
            ]
        ),

        // Tests
        .testTarget(
            name: "SeKretSauceTests",
            dependencies: ["Common", "TunnelDetection"],
            path: "Tests"
        ),
    ]
)
