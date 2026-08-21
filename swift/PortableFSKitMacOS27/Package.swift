// swift-tools-version: 6.4

import PackageDescription

let package = Package(
    name: "PortableFSKitMacOS27",
    platforms: [
        .macOS(.v27)
    ],
    products: [
        .library(
            name: "PortableFSKitMacOS27",
            targets: ["PortableFSKitMacOS27"]
        )
    ],
    dependencies: [
        .package(path: "../PortableFSKit")
    ],
    targets: [
        .target(
            name: "PortableFSKitMacOS27",
            dependencies: [
                .product(name: "PortableFSKit", package: "PortableFSKit")
            ]
        )
    ]
)
