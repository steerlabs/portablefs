import Foundation
import Testing
@testable import PortableFSKit
import PortableFSKitMockDaemon

private func lifecycleBytes(_ string: String) -> Data {
    Data(string.utf8)
}

extension PfsLocalMockDaemonTests {
@Test func zeroHandleCreateReplyTerminallyFencesWithoutInvalidDisposition() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(
        socketPath: daemon.socketPath,
        attachRef: "mock"
    )
    let root = try await core.rootItem()
    await daemon.omitNextCreateHandle()
    await daemon.resetStats()

    await #expect(throws: PfsLocalClientError.connectionClosed) {
        try await core.createFile(
            in: root,
            name: lifecycleBytes("missing-create-handle"),
            mode: 0o644
        )
    }
    let stats = await daemon.stats()
    #expect(stats.activeHandles == 0)
    #expect(stats.resourceAccepts == 0)
    #expect(stats.resourceAbandons == 0)
    #expect(await core.testingDebugState().openHandleCount == 0)
    await #expect(throws: PfsLocalClientError.shutdown) {
        try await core.statfs()
    }
}

@Test func finalCloseReleasesDaemonHandle() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "final-close")

    try await core.open(item: file, mode: .read)
    try await waitForLifecycleStats(daemon) { $0.resourceAccepts == 1 }
    #expect(await daemon.stats().openRequests == 1)
    #expect(await daemon.stats().activeHandles == 1)
    #expect(await daemon.stats().resourceAcceptedItemCounts == [0])

    try await core.close(item: file, retainingModes: .unspecified)
    let stats = await daemon.stats()
    #expect(stats.openRequests == 1)
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 0)
    #expect(await core.testingDebugState().openHandleCount == 0)
}

/// A resource disposition is a one-way ownership transition, but it is still
/// a production reader barrier: once the daemon replies to a following Close,
/// the earlier disposition has necessarily been applied. The injected delay
/// makes an unordered mock deterministic — Close would overtake the suspended
/// disposition and that late accept would leak across `resetStats()`.
@Test func resourceDispositionPrecedesFollowingOrdinaryReply() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(
        socketPath: daemon.socketPath,
        attachRef: "mock"
    )
    let root = try await core.rootItem()
    await daemon.delayNextResourceDisposition(nanoseconds: 250_000_000)

    let created = try await core.createFile(
        in: root,
        name: lifecycleBytes("reader-ordered-disposition"),
        mode: 0o644
    )
    try await core.close(item: created.item, retainingModes: .unspecified)
    await daemon.resetStats()

    // Give an incorrectly detached control task ample time to contaminate the
    // new epoch. Correct reader ordering has no work left to arrive here.
    try await Task.sleep(nanoseconds: 300_000_000)
    let stats = await daemon.stats()
    #expect(stats.resourceAccepts == 0)
    #expect(stats.resourceAbandons == 0)
    #expect(stats.resourceAcceptedItemCounts.isEmpty)
    #expect(stats.activeHandles == 0)
}

@Test func directLookupMappingFailureAbandonsItemAndKeepsConnectionHealthy() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(
        socketPath: daemon.socketPath,
        attachRef: "mock"
    )
    _ = try await closedTestFile(
        core: core,
        daemon: daemon,
        name: "mapping-failure"
    )
    let root = try await core.rootItem()
    let baseline = await core.testingDebugState()
    await daemon.corruptNextLookupItemIdentifier()

    do {
        _ = try await core.lookup(
            in: root,
            name: lifecycleBytes("mapping-failure")
        )
        Issue.record("reserved daemon item identifier was adopted")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == EOVERFLOW)
    }
    try await waitForLifecycleStats(daemon) { $0.resourceAbandons == 1 }
    #expect(await daemon.stats().resourceAcceptedItemCounts == [0])
    #expect(await core.testingDebugState() == baseline)
    _ = try await core.statfs()
}

@Test func directOpenCancellationAbandonsLateHandleWithoutPoisoningCore() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(
        socketPath: daemon.socketPath,
        attachRef: "mock"
    )
    let file = try await closedTestFile(
        core: core,
        daemon: daemon,
        name: "cancel-open"
    )
    await daemon.delayNextOpen(nanoseconds: 100_000_000)
    let opening = Task { try await core.open(item: file, mode: .read) }
    try await waitForLifecycleStats(daemon) { $0.openRequests == 1 }
    opening.cancel()
    await #expect(throws: PfsLocalClientError.cancelled) {
        try await opening.value
    }
    try await waitForLifecycleStats(daemon) {
        $0.resourceAbandons == 1 && $0.activeHandles == 0
    }
    #expect(await core.testingDebugState().openHandleCount == 0)
    _ = try await core.statfs()
}

@Test func zeroHandleOpenReplyTerminallyFencesWithoutInvalidDisposition() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(
        socketPath: daemon.socketPath,
        attachRef: "mock"
    )
    let file = try await closedTestFile(
        core: core,
        daemon: daemon,
        name: "missing-open-handle"
    )
    await daemon.omitNextOpenHandle()

    await #expect(throws: PfsLocalClientError.connectionClosed) {
        try await core.open(item: file, mode: .read)
    }
    let stats = await daemon.stats()
    #expect(stats.activeHandles == 0)
    #expect(stats.resourceAccepts == 0)
    #expect(stats.resourceAbandons == 0)
    #expect(await core.testingDebugState().openHandleCount == 0)
    await #expect(throws: PfsLocalClientError.shutdown) {
        try await core.statfs()
    }
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
    #expect(stats.openRequests == 2)
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 1)

    try await core.close(item: file, retainingModes: .unspecified)
    stats = await daemon.stats()
    #expect(stats.openRequests == 2)
    #expect(stats.closeRequests == 2)
    #expect(stats.activeHandles == 0)
}

@Test func partialCloseRetainsBroaderHandleAfterRenameOver() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(strictItemNamespace: true))
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let target = try await core.createFile(
        in: root,
        name: lifecycleBytes("detached-target"),
        mode: 0o644
    )
    let replacement = try await core.createFile(
        in: root,
        name: lifecycleBytes("detached-replacement"),
        mode: 0o644
    )
    try await core.close(item: replacement.item, retainingModes: .unspecified)
    await daemon.resetStats()

    try await core.rename(
        item: replacement.item,
        from: root,
        sourceName: lifecycleBytes("detached-replacement"),
        to: root,
        destinationName: lifecycleBytes("detached-target"),
        noReplace: false
    )
    try await core.close(item: target.item, retainingModes: .read)
    let retainedAttr = try await core.getattr(item: target.item)
    #expect(retainedAttr.nlink == 0)
    #expect(try await core.read(item: target.item, offset: 0, length: 0).isEmpty)

    var stats = await daemon.stats()
    #expect(stats.openRequests == 0)
    #expect(stats.closeRequests == 0)
    #expect(stats.activeHandles == 1)
    #expect(await core.testingDebugState().openHandleCount == 1)

    try await core.close(item: target.item, retainingModes: .unspecified)
    stats = await daemon.stats()
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 0)
    #expect(await core.testingDebugState().openHandleCount == 0)
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

/// O_WRONLY installs a write-only description, and a write needs nothing
/// more. The first write must reuse it, not replace it with a read/write
/// OPEN and close the original.
@Test func writeOnlyOpenWritesThroughItsOwnDescription() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "write-only")

    try await core.open(item: file, mode: .write)
    let result = try await core.write(item: file, offset: 0, data: lifecycleBytes("payload"))
    #expect(result.written == 7)
    var stats = await daemon.stats()
    #expect(stats.openModes == [.write])
    #expect(stats.writeRequests == 1)
    #expect(stats.closeRequests == 0)
    #expect(stats.activeHandles == 1)

    try await core.close(item: file, retainingModes: .unspecified)
    stats = await daemon.stats()
    #expect(stats.openModes == [.write])
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 0)
    #expect(try await core.read(item: file, offset: 0, length: 16) == lifecycleBytes("payload"))
}

/// A mode-0200 file is writable and unreadable. Its write-only description
/// must serve writes. A read cannot use it, and the mode refuses the
/// read/write replacement; that refusal must leave the write description
/// installed and usable.
@Test func writeOnlyOpenOfAnUnreadableFileWritesAndSurvivesARefusedRead() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let created = try await core.createFile(
        in: root,
        name: lifecycleBytes("unreadable"),
        mode: 0o200
    )
    try await core.close(item: created.item, retainingModes: .unspecified)
    await daemon.resetStats()
    let file = created.item

    #expect(await lifecycleErrno { try await core.open(item: file, mode: .read) } == EACCES)
    try await core.open(item: file, mode: .write)
    let result = try await core.write(item: file, offset: 0, data: lifecycleBytes("secret"))
    #expect(result.written == 6)
    #expect(result.attr.size == 6)
    var stats = await daemon.stats()
    #expect(stats.openModes == [.read, .write])
    #expect(stats.closeRequests == 0)
    #expect(stats.activeHandles == 1)

    #expect(await lifecycleErrno {
        _ = try await core.read(item: file, offset: 0, length: 6)
    } == EACCES)
    stats = await daemon.stats()
    #expect(stats.openModes == [.read, .write, .readWrite])
    #expect(stats.closeRequests == 0)
    #expect(stats.activeHandles == 1)
    #expect(await core.testingDebugState().openHandleCount == 1)

    let appended = try await core.write(item: file, offset: 6, data: lifecycleBytes("!"))
    #expect(appended.attr.size == 7)
    stats = await daemon.stats()
    #expect(stats.openModes == [.read, .write, .readWrite])
    #expect(stats.writeRequests == 2)

    try await core.close(item: file, retainingModes: .unspecified)
    stats = await daemon.stats()
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 0)
    #expect(await core.testingDebugState().openHandleCount == 0)
}

/// Access is decided when a description is opened. A chmod after the open
/// neither revokes it nor forces a reopen, for a write-only or a read/write
/// description.
@Test func chmodAfterOpenKeepsTheOpenDescription() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")

    let writeOnly = try await closedTestFile(core: core, daemon: daemon, name: "chmod-write-only")
    try await core.open(item: writeOnly, mode: .write)
    _ = try await core.setattr(item: writeOnly, attributes: PfsSetAttributes(mode: 0o000))
    let written = try await core.write(item: writeOnly, offset: 0, data: lifecycleBytes("kept"))
    #expect(written.written == 4)
    #expect(written.attr.mode & 0o777 == 0)
    var stats = await daemon.stats()
    #expect(stats.openModes == [.write])
    #expect(stats.closeRequests == 0)
    try await core.close(item: writeOnly, retainingModes: .unspecified)

    let readWrite = try await closedTestFile(core: core, daemon: daemon, name: "chmod-read-write")
    try await core.open(item: readWrite, mode: .readWrite)
    _ = try await core.setattr(item: readWrite, attributes: PfsSetAttributes(mode: 0o000))
    _ = try await core.write(item: readWrite, offset: 0, data: lifecycleBytes("both"))
    #expect(try await core.read(item: readWrite, offset: 0, length: 4) == lifecycleBytes("both"))
    stats = await daemon.stats()
    #expect(stats.openModes == [.readWrite])
    #expect(stats.closeRequests == 0)
    try await core.close(item: readWrite, retainingModes: .unspecified)
    #expect(await daemon.stats().activeHandles == 0)
}

/// A description the creation itself granted is read/write whatever mode
/// the new file carries, so writing a fresh 0444 file needs no OPEN at all.
@Test func createdFileWritesThroughItsCreationDescription() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    await daemon.resetStats()

    let created = try await core.createFile(
        in: root,
        name: lifecycleBytes("read-only-mode"),
        mode: 0o444
    )
    let result = try await core.write(item: created.item, offset: 0, data: lifecycleBytes("granted"))
    #expect(result.written == 7)
    var stats = await daemon.stats()
    #expect(stats.openModes.isEmpty)
    #expect(stats.closeRequests == 0)
    try await core.close(item: created.item, retainingModes: .unspecified)
    stats = await daemon.stats()
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 0)
}

/// An unlinked file is reachable only through descriptions that already
/// exist. A write-only description must keep serving writes after the last
/// name is gone; a replacement OPEN could not even address the item.
@Test func writeOnlyDescriptionOfAnUnlinkedFileKeepsWriting() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(strictItemNamespace: true))
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let file = try await closedTestFile(core: core, daemon: daemon, name: "unlinked-write-only")

    try await core.open(item: file, mode: .write)
    try await core.remove(
        item: file,
        named: lifecycleBytes("unlinked-write-only"),
        from: root,
        isDirectory: false
    )
    let result = try await core.write(item: file, offset: 0, data: lifecycleBytes("orphan"))
    #expect(result.written == 6)
    #expect(result.attr.nlink == 0)
    var stats = await daemon.stats()
    #expect(stats.openModes == [.write])
    #expect(stats.closeRequests == 0)
    #expect(stats.activeHandles == 1)

    try await core.close(item: file, retainingModes: .unspecified)
    stats = await daemon.stats()
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 0)
    #expect(await core.testingDebugState().openHandleCount == 0)
}

@Test func failedUpgradeCloseRemainsTrackedUntilFinalClose() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "failed-upgrade-close")

    try await core.open(item: file, mode: .read)
    await daemon.failNextClose()
    do {
        try await core.open(item: file, mode: .readWrite)
        Issue.record("expected the injected prior-handle close failure")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == EIO)
    }

    var stats = await daemon.stats()
    #expect(stats.openRequests == 2)
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 2)
    #expect(await core.testingDebugState().openHandleCount == 2)

    try await core.close(item: file, retainingModes: .unspecified)
    stats = await daemon.stats()
    #expect(stats.closeRequests == 3)
    #expect(stats.activeHandles == 0)
    #expect(await core.testingDebugState().openHandleCount == 0)
}

@Test func retiredFinalCloseErrorIsSurfacedWithoutRetainingOrRetryingHandle() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "retired-final-close")

    try await core.open(item: file, mode: .read)
    await daemon.retireNextCloseWithError()
    do {
        try await core.close(item: file, retainingModes: .unspecified)
        Issue.record("expected the terminal retired-close error")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == EIO)
    }

    var stats = await daemon.stats()
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 0)
    #expect(await core.testingDebugState().openHandleCount == 0)

    // The terminal error consumed the descriptor, so a repeated FSKit close is
    // locally complete and must not retry the retired daemon handle.
    try await core.close(item: file, retainingModes: .unspecified)
    stats = await daemon.stats()
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 0)

    try await core.reclaim(item: file)
    #expect(file.reclaimed)
}

@Test func retiredUpgradeCloseErrorRemovesOnlySupersededHandle() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "retired-upgrade-close")

    try await core.open(item: file, mode: .read)
    await daemon.retireNextCloseWithError()
    do {
        try await core.open(item: file, mode: .readWrite)
        Issue.record("expected the terminal retired-close error")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == EIO)
    }

    var stats = await daemon.stats()
    #expect(stats.openRequests == 2)
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 1)
    #expect(await core.testingDebugState().openHandleCount == 1)

    try await core.close(item: file, retainingModes: .unspecified)
    stats = await daemon.stats()
    #expect(stats.closeRequests == 2)
    #expect(stats.activeHandles == 0)
    #expect(await core.testingDebugState().openHandleCount == 0)
}

@Test func lostRetiredCloseReplyReplaysTerminalOutcomeAndReleasesSwiftHandle() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(
        socketPath: daemon.socketPath,
        attachRef: "mock",
        configuration: .init(
            maxReconnectAttempts: 10,
            reconnectBaseDelayNanoseconds: 5_000_000
        )
    )
    let file = try await closedTestFile(core: core, daemon: daemon, name: "lost-close-reply")

    try await core.open(item: file, mode: .read)
    await daemon.loseNextRetiredCloseReply(errno: EIO)
    do {
        try await core.close(item: file, retainingModes: .unspecified)
        Issue.record("expected the lost close reply to fail the first request")
    } catch let error as PfsLocalClientError {
        #expect(error == .connectionClosed)
    }

    var stats = await daemon.stats()
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 0)
    // No retirement confirmation reached Swift, so it must retain ownership.
    #expect(await core.testingDebugState().openHandleCount == 1)

    do {
        try await core.close(item: file, retainingModes: .unspecified)
        Issue.record("expected the replayed terminal close error")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == EIO)
    }

    stats = await daemon.stats()
    #expect(stats.closeRequests == 2)
    #expect(stats.activeHandles == 0)
    #expect(await core.testingDebugState().openHandleCount == 0)

    // Swift consumed the replayed confirmation, so it never sends a third
    // close for the already-retired handle.
    try await core.close(item: file, retainingModes: .unspecified)
    #expect(await daemon.stats().closeRequests == 2)
}

@Test func failedUpgradeCloseRemainsTrackedUntilReclaim() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "failed-upgrade-reclaim")

    try await core.open(item: file, mode: .read)
    await daemon.failNextClose()
    do {
        try await core.open(item: file, mode: .readWrite)
        Issue.record("expected the injected prior-handle close failure")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == EIO)
    }

    try await core.reclaim(item: file)
    let stats = await daemon.stats()
    #expect(stats.closeRequests == 3)
    #expect(stats.activeHandles == 0)
    #expect(await core.testingDebugState().openHandleCount == 0)
    #expect(file.reclaimed)
}

@Test func concurrentFinalCloseCannotInterleaveDelayedUpgrade() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "concurrent-upgrade-close")

    try await core.open(item: file, mode: .read)
    await daemon.delayNextOpen(nanoseconds: 100_000_000)
    let upgrade = Task {
        try await core.open(item: file, mode: .readWrite)
    }
    try await waitForLifecycleStats(daemon) { $0.openRequests == 2 }

    let close = Task {
        try await core.close(item: file, retainingModes: .unspecified)
    }
    try await upgrade.value
    try await close.value

    let stats = await daemon.stats()
    #expect(stats.openRequests == 2)
    #expect(stats.closeRequests == 2)
    #expect(stats.activeHandles == 0)
    #expect(await core.testingDebugState().openHandleCount == 0)
}

@Test func concurrentReopenCannotObserveHandleBeingClosed() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "concurrent-close-reopen")

    try await core.open(item: file, mode: .read)
    await daemon.delayNextClose(nanoseconds: 100_000_000)
    let close = Task {
        try await core.close(item: file, retainingModes: .unspecified)
    }
    try await waitForLifecycleStats(daemon) { $0.closeRequests == 1 }

    let reopen = Task {
        try await core.open(item: file, mode: .read)
    }
    try await close.value
    try await reopen.value

    var stats = await daemon.stats()
    #expect(stats.openRequests == 2)
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 1)
    #expect(await core.testingDebugState().openHandleCount == 1)

    try await core.close(item: file, retainingModes: .unspecified)
    stats = await daemon.stats()
    #expect(stats.closeRequests == 2)
    #expect(stats.activeHandles == 0)
}

@Test func finalCloseWaitsForCompleteMultiChunkRead() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let file = try await core.createFile(
        in: root,
        name: lifecycleBytes("read-versus-close"),
        mode: 0o644
    )
    let payload = Data(repeating: 0x5a, count: 2_500_000)
    _ = try await core.write(item: file.item, offset: 0, data: payload)
    await daemon.resetStats()

    await daemon.delayNextRead(nanoseconds: 100_000_000)
    let read = Task {
        try await core.read(
            item: file.item,
            offset: 0,
            length: UInt32(payload.count)
        )
    }
    try await waitForLifecycleStats(daemon) { $0.readRequests == 1 }
    let close = Task {
        try await core.close(item: file.item, retainingModes: .unspecified)
    }

    #expect(try await read.value == payload)
    try await close.value
    let stats = await daemon.stats()
    #expect(stats.readRequests == 3)
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 0)
    #expect(await core.testingDebugState().openHandleCount == 0)
}

@Test func finalCloseWaitsForCompleteMultiChunkWrite() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "write-versus-close")
    try await core.open(item: file, mode: .readWrite)
    await daemon.resetStats()

    let payload = Data(repeating: 0xa5, count: 2_500_000)
    await daemon.delayNextWrite(nanoseconds: 100_000_000)
    let write = Task {
        try await core.write(item: file, offset: 0, data: payload)
    }
    try await waitForLifecycleStats(daemon) { $0.writeRequests == 1 }
    let close = Task {
        try await core.close(item: file, retainingModes: .unspecified)
    }

    let result = try await write.value
    #expect(result.written == UInt32(payload.count))
    try await close.value
    let stats = await daemon.stats()
    #expect(stats.writeRequests == 3)
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 0)
    #expect(await core.testingDebugState().openHandleCount == 0)
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

private func lifecycleErrno(_ operation: () async throws -> Void) async -> Int32? {
    do {
        try await operation()
        return nil
    } catch let error as PfsLocalClientError {
        return error.posixErrno
    } catch {
        return EIO
    }
}

private struct LifecycleStatsTimeout: Error {}

private func waitForLifecycleStats(
    _ daemon: PfsLocalMockDaemon,
    predicate: (PfsLocalMockDaemon.Stats) -> Bool
) async throws {
    for _ in 0..<1_000 {
        if predicate(await daemon.stats()) {
            return
        }
        try await Task.sleep(nanoseconds: 1_000_000)
    }
    throw LifecycleStatsTimeout()
}
}
