// swift-tools-version: 6.2

import PackageDescription

// Build-time identity only. An ordinary unconfigured SwiftPM build cannot boot
// a guest; the dev build script supplies the exact source commit before signing.
let workspaceCommit = Context.environment["PFS_WORKSPACE_BUILD_COMMIT"] ?? "unconfigured"
precondition(workspaceCommit == "unconfigured" || (workspaceCommit.count == 40 && workspaceCommit.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }))

let package = Package(
    name: "PortableFSKit",
    platforms: [
        .macOS(.v26)
    ],
    products: [
        .library(name: "PortableFSKit", targets: ["PortableFSKit"]),
        .library(name: "PortableFSKitMockDaemon", targets: ["PortableFSKitMockDaemon"]),
        .library(name: "PortableFSAppCore", targets: ["PortableFSAppCore"]),
        .library(name: "PortableFSWorkspaceCore", targets: ["PortableFSWorkspaceCore"]),
        .library(name: "PortableFSWorkspaceVM", targets: ["PortableFSWorkspaceVM"]),
        .executable(name: "portablefs-workspace-dev", targets: ["PortableFSWorkspaceDev"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-protobuf.git", exact: "1.39.0")
    ],
    targets: [
        .target(name: "CWorkspacePower", cSettings: [.define("PFS_WORKSPACE_BUILD_COMMIT", to: "\"" + workspaceCommit + "\"")]),
        .target(name: "PortableFSWorkspaceVM", dependencies: ["PortableFSWorkspaceCore", "CWorkspacePower"]),
        .executableTarget(name: "PortableFSWorkspaceDev", dependencies: ["PortableFSWorkspaceVM"]),
        .target(
            name: "PortableFSWorkspaceCore",
            dependencies: [
                .product(name: "SwiftProtobuf", package: "swift-protobuf")
            ]
        ),
        .testTarget(
            name: "PortableFSWorkspaceCoreTests",
            dependencies: ["PortableFSWorkspaceCore", "PortableFSWorkspaceVM"],
            resources: [.copy("Goldens")]
        ),
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
            ],
            resources: [
                .copy("Fixtures")
            ]
        )
    ]
)
