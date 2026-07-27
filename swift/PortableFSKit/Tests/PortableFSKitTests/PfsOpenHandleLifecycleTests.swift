import Foundation
import Testing
@testable import PortableFSKit
import PortableFSKitMockDaemon

private func lifecycleBytes(_ string: String) -> Data {
    Data(string.utf8)
}

@Test func finalCloseReleasesDaemonHandle() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "final-close")

    try await core.open(item: file, mode: .read)
    #expect(await daemon.stats().openRequests == 1)
    #expect(await daemon.stats().activeHandles == 1)

    try await core.close(item: file, retainingModes: .unspecified)
    let stats = await daemon.stats()
    #expect(stats.openRequests == 1)
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 0)
    #expect(await core.testingDebugState().openHandleCount == 0)
}

@Test func openUpgradePartialCloseAndFinalCloseAreBalanced() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "upgrade")

    try await core.open(item: file, mode: .read)
    try await core.open(item: file, mode: .readWrite)
    var stats = await daemon.stats()
    #expect(stats.openRequests == 2)
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 1)

    try await core.close(item: file, retainingModes: .read)
    stats = await daemon.stats()
    #expect(stats.openRequests == 3)
    #expect(stats.closeRequests == 2)
    #expect(stats.activeHandles == 1)

    try await core.close(item: file, retainingModes: .unspecified)
    stats = await daemon.stats()
    #expect(stats.openRequests == 3)
    #expect(stats.closeRequests == 3)
    #expect(stats.activeHandles == 0)
}

@Test func modeChangeReopenClosesPriorDaemonHandle() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "mode-change")

    try await core.open(item: file, mode: .read)
    try await core.open(item: file, mode: .write)
    var stats = await daemon.stats()
    #expect(stats.openRequests == 2)
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 1)

    try await core.close(item: file, retainingModes: .unspecified)
    stats = await daemon.stats()
    #expect(stats.closeRequests == 2)
    #expect(stats.activeHandles == 0)
}

@Test func reclaimClosesImplicitAutoOpenedHandle() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "implicit")

    _ = try await core.read(item: file, offset: 0, length: 0)
    var stats = await daemon.stats()
    #expect(stats.openRequests == 1)
    #expect(stats.activeHandles == 1)

    try await core.reclaim(item: file)
    stats = await daemon.stats()
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 0)
    #expect(await core.testingDebugState().openHandleCount == 0)
}

@Test func itemAndHandleTablesReturnToBaselineAfterChurn() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let baseline = await core.testingDebugState()

    for index in 0..<25 {
        let created = try await core.createFile(in: root, name: lifecycleBytes("churn-\(index)"), mode: 0o644)
        try await core.close(item: created.item, retainingModes: .unspecified)
        try await core.reclaim(item: created.item)
    }

    let final = await core.testingDebugState()
    #expect(final == baseline)
    #expect(await daemon.stats().activeHandles == 0)
}

private func closedTestFile(core: VolumeCore, daemon: PfsLocalMockDaemon, name: String) async throws -> PortableFSItem {
    let root = try await core.rootItem()
    let created = try await core.createFile(in: root, name: lifecycleBytes(name), mode: 0o644)
    try await core.close(item: created.item, retainingModes: .unspecified)
    await daemon.resetStats()
    return created.item
}
