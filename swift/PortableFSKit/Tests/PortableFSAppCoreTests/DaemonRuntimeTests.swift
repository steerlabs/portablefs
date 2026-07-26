import Foundation
import Testing
@testable import PortableFSAppCore

@Test func backoffEscalatesAndCaps() {
    var backoff = RestartBackoff()
    var delays: [TimeInterval] = []
    for _ in 0..<15 {
        delays.append(backoff.delayAfterExit(uptime: 1))
    }
    #expect(Array(delays.prefix(4)) == [0.5, 1.0, 2.0, 4.0])
    #expect(delays.last == 30.0)
}

@Test func backoffResetsAfterHealthyRun() {
    var backoff = RestartBackoff()
    _ = backoff.delayAfterExit(uptime: 1)
    _ = backoff.delayAfterExit(uptime: 1)
    #expect(backoff.consecutiveFailures == 2)
    // A run that stayed up past the threshold starts the ladder over.
    let afterHealthy = backoff.delayAfterExit(uptime: 120)
    #expect(afterHealthy == 0.5)
    #expect(backoff.consecutiveFailures == 1)

    backoff.reset()
    #expect(backoff.consecutiveFailures == 0)
}

@Test func binaryLocatorHonorsPrecedence() {
    let executables: Set<String> = [
        "/override/portablefsd",
        "/plist/portablefsd",
        "/env/portablefsd",
        "/bundle/portablefsd",
        "/home/u/bin/portablefsd",
        "/usr/local/bin/portablefsd",
        "/opt/homebrew/bin/portablefsd"
    ]
    var locator = DaemonBinaryLocator(
        userOverride: "/override/portablefsd",
        infoPlistPath: "/plist/portablefsd",
        environment: ["PORTABLEFSD_BIN": "/env/portablefsd"],
        bundledPath: "/bundle/portablefsd",
        homeDirectory: "/home/u",
        isExecutableFile: { executables.contains($0) }
    )
    #expect(locator.locate() == "/override/portablefsd")

    locator.userOverride = nil
    #expect(locator.locate() == "/plist/portablefsd")
    locator.infoPlistPath = nil
    #expect(locator.locate() == "/env/portablefsd")
    locator.environment = [:]
    #expect(locator.locate() == "/bundle/portablefsd")
    locator.bundledPath = nil
    #expect(locator.locate() == "/home/u/bin/portablefsd")

    let missingEverything = DaemonBinaryLocator(
        environment: [:],
        homeDirectory: "/home/u",
        isExecutableFile: { _ in false }
    )
    #expect(missingEverything.locate() == nil)
    #expect(missingEverything.candidates == [
        "/home/u/bin/portablefsd",
        "/usr/local/bin/portablefsd",
        "/opt/homebrew/bin/portablefsd"
    ])
}

@Test func mountTableParsesAttachRefs() {
    #expect(MountTable.attachRef(fromMountedFrom: "pfs://att_abc123") == "att_abc123")
    #expect(MountTable.attachRef(fromMountedFrom: "pfs://att_abc123/") == "att_abc123")
    #expect(MountTable.attachRef(fromMountedFrom: "pfs://") == nil)
    #expect(MountTable.attachRef(fromMountedFrom: "/dev/disk3s1") == nil)
    #expect(MountedFilesystem(fsTypeName: "pfs", mountPoint: "/m", mountedFrom: "pfs://att_x").attachRef == "att_x")
}

@Test func mountTableSnapshotIncludesRootFilesystem() {
    let mounts = MountTable.current()
    #expect(mounts.contains { $0.mountPoint == "/" })
    #expect(MountTable.portableFSMounts().allSatisfy { $0.fsTypeName == "pfs" })
}

@Test func mountPointBuilderSanitizesVolumeIDs() {
    #expect(PortableFSAppPaths.mountPoint(baseDirectory: "/Users/u/PortableFS", volumeID: "vol-a") == "/Users/u/PortableFS/vol-a")
    #expect(PortableFSAppPaths.mountPoint(baseDirectory: "/base", volumeID: "../evil") == "/base/___evil")
    #expect(PortableFSAppPaths.mountPoint(baseDirectory: "/base", volumeID: "a/b c") == "/base/a_b_c")
}
