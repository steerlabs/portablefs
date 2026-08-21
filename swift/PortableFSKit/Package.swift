// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "PortableFSKit",
    platforms: [
        .macOS(.v26)
    ],
    products: [
        .library(name: "PortableFSKit", targets: ["PortableFSKit"]),
        .library(name: "PortableFSKitMockDaemon", targets: ["PortableFSKitMockDaemon"]),
        .library(name: "PortableFSAppCore", targets: ["PortableFSAppCore"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-protobuf.git", exact: "1.38.1")
    ],
    targets: [
        .target(
            name: "PortableFSKit",
            dependencies: [
                .product(name: "SwiftProtobuf", package: "swift-protobuf")
            ]
        ),
        .target(
            name: "PortableFSKitMockDaemon",
            dependencies: [
                "PortableFSKit"
            ]
        ),
        .target(
            name: "PortableFSAppCore",
            dependencies: [
                "PortableFSKit"
            ],
            linkerSettings: [
                .linkedLibrary("bsm", .when(platforms: [.macOS]))
            ]
        ),
        .testTarget(
            name: "PortableFSKitTests",
            dependencies: [
                "PortableFSKit",
                "PortableFSKitMockDaemon"
            ],
            resources: [
                .copy("Goldens")
            ]
        ),
        .testTarget(
            name: "PortableFSAppCoreTests",
            dependencies: [
                "PortableFSAppCore"
            ]
        )
    ]
)
