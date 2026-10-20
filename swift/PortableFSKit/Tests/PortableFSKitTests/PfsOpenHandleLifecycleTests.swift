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

/// A read/write open on top of a read description acquires only the missing
/// write access. A partial close retires exactly the description that no
/// longer carries retained access, and the final close retires the rest.
@Test func complementaryOpenPartialCloseAndFinalCloseAreBalanced() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "upgrade")

    try await core.open(item: file, mode: .read)
    try await core.open(item: file, mode: .readWrite)
    var stats = await daemon.stats()
    #expect(stats.openModes == [.read, .write])
    #expect(stats.closeRequests == 0)
    #expect(stats.activeHandles == 2)

    try await core.close(item: file, retainingModes: .read)
    stats = await daemon.stats()
    #expect(stats.openRequests == 2)
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 1)
    #expect(try await core.read(item: file, offset: 0, length: 0).isEmpty)
    #expect(await daemon.stats().openRequests == 2)

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

/// Complementary opens keep their own descriptions; neither is reopened or
/// closed until FSKit stops needing it.
@Test func complementaryOpenKeepsBothDescriptions() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "mode-change")

    try await core.open(item: file, mode: .read)
    try await core.open(item: file, mode: .write)
    var stats = await daemon.stats()
    #expect(stats.openModes == [.read, .write])
    #expect(stats.closeRequests == 0)
    #expect(stats.activeHandles == 2)
    #expect(await core.testingDebugState().openHandleCount == 2)

    try await core.close(item: file, retainingModes: .unspecified)
    stats = await daemon.stats()
    #expect(stats.closeRequests == 2)
    #expect(stats.activeHandles == 0)
    #expect(await core.testingDebugState().openHandleCount == 0)
}

/// V2 and uncached O_WRONLY opens install a write-only description; a write needs nothing
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
/// must serve writes. A read cannot use it and acquires a read description,
/// which the mode refuses; that refusal must leave the write description
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
    #expect(stats.openModes == [.read, .write, .read])
    #expect(stats.closeRequests == 0)
    #expect(stats.activeHandles == 1)
    #expect(await core.testingDebugState().openHandleCount == 1)

    let appended = try await core.write(item: file, offset: 6, data: lifecycleBytes("!"))
    #expect(appended.attr.size == 7)
    stats = await daemon.stats()
    #expect(stats.openModes == [.read, .write, .read])
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

/// CREATE returns a real, charged creation description even when no open
/// ever follows. It stays owned by the item until reclaim closes it: no
/// timeout, no speculative cancellation, no leak.
@Test func createWithoutAnyOpenOwnsItsCreationDescriptionUntilReclaim() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    await daemon.resetStats()

    let created = try await core.createFile(in: root, name: lifecycleBytes("never-opened"), mode: 0o600)
    try await waitForLifecycleStats(daemon) { $0.resourceAccepts == 1 }
    var stats = await daemon.stats()
    #expect(stats.openRequests == 0)
    #expect(stats.activeHandles == 1)
    #expect(await core.testingDebugState().openHandleCount == 1)

    try await core.reclaim(item: created.item)
    stats = await daemon.stats()
    #expect(stats.openRequests == 0)
    #expect(stats.closeRequests == 1)
    #expect(stats.reclaimRequests == 1)
    #expect(stats.activeHandles == 0)
    #expect(await core.testingDebugState().openHandleCount == 0)
}

/// Every access the creation description grants is served from it without
/// another OPEN. After the final close, a later open is an independent
/// access decision and issues a fresh OPEN.
@Test func compatibleOpenAfterCreateReusesTheCreationDescription() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    await daemon.resetStats()

    let created = try await core.createFile(in: root, name: lifecycleBytes("reused"), mode: 0o644)
    for mode in [PfsOpenMode.read, .write, .readWrite] {
        try await core.open(item: created.item, mode: mode)
    }
    _ = try await core.write(item: created.item, offset: 0, data: lifecycleBytes("data"))
    #expect(try await core.read(item: created.item, offset: 0, length: 4) == lifecycleBytes("data"))
    var stats = await daemon.stats()
    #expect(stats.openRequests == 0)
    #expect(stats.activeHandles == 1)

    try await core.close(item: created.item, retainingModes: .unspecified)
    stats = await daemon.stats()
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 0)

    try await core.open(item: created.item, mode: .read)
    stats = await daemon.stats()
    #expect(stats.openRequests == 1)
    #expect(stats.openModes == [.read])
    #expect(stats.activeHandles == 1)
    try await core.close(item: created.item, retainingModes: .unspecified)
    #expect(await daemon.stats().activeHandles == 0)
}

/// Only a CREATE that actually creates the file carries the creation grant.
/// A non-exclusive CREATE of an existing name is an open: its read/write
/// description must pass the ordinary access check against the existing
/// mode, and a refusal allocates nothing.
@Test func createOfAnExistingNameGetsNoCreationGrant() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let client = PfsLocalClient(socketPath: daemon.socketPath)
    let resolved = try await client.resolve(attachRef: "mock")

    func create(_ name: String, mode: UInt32) async throws -> PfsCreateReply {
        var request = PfsCreateRequest()
        request.dir = resolved.root
        request.name = lifecycleBytes(name)
        request.mode = mode
        let envelope = try await client.request(.create(request))
        guard case let .createReply(reply)? = envelope.body else {
            throw PfsLocalClientError.unexpectedReply(String(describing: envelope.body))
        }
        return reply
    }
    func close(_ handle: UInt64) async throws {
        var request = PfsCloseRequest()
        request.handle = handle
        _ = try await client.request(.close(request))
    }

    // Positive control: a genuinely new 0444 file is writable through its
    // creation description.
    let fresh = try await create("existing-read-only", mode: 0o444)
    var write = PfsWriteRequest()
    write.handle = fresh.handle
    write.data = lifecycleBytes("granted")
    _ = try await client.request(.write(write))
    try await close(fresh.handle)
    #expect(await daemon.stats().activeHandles == 0)

    // The same name again opens the existing 0444 file: read/write access
    // is refused by its mode and no handle is allocated.
    #expect(await lifecycleErrno {
        _ = try await create("existing-read-only", mode: 0o644)
    } == EACCES)
    #expect(await daemon.stats().activeHandles == 0)

    // An existing name whose mode grants read/write opens normally.
    let writable = try await create("existing-writable", mode: 0o644)
    try await close(writable.handle)
    let reopened = try await create("existing-writable", mode: 0o444)
    #expect(reopened.handle != 0)
    write.handle = reopened.handle
    _ = try await client.request(.write(write))
    try await close(reopened.handle)
    #expect(await daemon.stats().activeHandles == 0)
}

/// After the last name is gone, a write-only description keeps serving
/// writes without another OPEN. (The strict-namespace mock refuses to OPEN a
/// detached item; the real authority could reopen the retained inode, but no
/// reopen is needed.)
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

private func chmod(_ core: VolumeCore, _ file: PortableFSItem, _ mode: UInt32) async throws {
    _ = try await core.setattr(item: file, attributes: PfsSetAttributes(mode: mode))
}

/// POSIX keeps an open description's access across chmod, and judges a new
/// open by the current mode. Read-open under 0400, chmod 0200, write-open:
/// the write open must acquire only write access as its own description.
/// Reopening the union would re-check read under 0200 and fail EACCES.
@Test func writeOpenAfterChmodKeepsTheEarlierReadDescription() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "read-then-write")
    _ = try await core.write(item: file, offset: 0, data: lifecycleBytes("before"))
    try await core.close(item: file, retainingModes: .unspecified)
    try await chmod(core, file, 0o400)
    await daemon.resetStats()

    try await core.open(item: file, mode: .read)
    try await chmod(core, file, 0o200)
    try await core.open(item: file, mode: .write)
    _ = try await core.write(item: file, offset: 0, data: lifecycleBytes("after!"))
    #expect(try await core.read(item: file, offset: 0, length: 6) == lifecycleBytes("after!"))
    let stats = await daemon.stats()
    #expect(stats.openModes == [.read, .write])
    #expect(stats.closeRequests == 0)
    #expect(stats.activeHandles == 2)
    try await core.close(item: file, retainingModes: .unspecified)
    #expect(await daemon.stats().activeHandles == 0)
}

/// The symmetric order: write-open under 0200, chmod 0400, read-open.
@Test func readOpenAfterChmodKeepsTheEarlierWriteDescription() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "write-then-read")
    try await chmod(core, file, 0o200)
    await daemon.resetStats()

    try await core.open(item: file, mode: .write)
    try await chmod(core, file, 0o400)
    try await core.open(item: file, mode: .read)
    _ = try await core.write(item: file, offset: 0, data: lifecycleBytes("kept"))
    #expect(try await core.read(item: file, offset: 0, length: 4) == lifecycleBytes("kept"))
    let stats = await daemon.stats()
    #expect(stats.openModes == [.write, .read])
    #expect(stats.closeRequests == 0)
    try await core.close(item: file, retainingModes: .unspecified)
    #expect(await daemon.stats().activeHandles == 0)
}

/// I/O that needs a right no description grants acquires exactly that
/// right, implicitly, and leaves the existing description in place.
@Test func implicitIOAcquiresOnlyTheMissingAccess() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "implicit-write")
    try await chmod(core, file, 0o400)
    await daemon.resetStats()

    try await core.open(item: file, mode: .read)
    try await chmod(core, file, 0o200)
    _ = try await core.write(item: file, offset: 0, data: lifecycleBytes("implicit"))
    #expect(try await core.read(item: file, offset: 0, length: 8) == lifecycleBytes("implicit"))
    let stats = await daemon.stats()
    #expect(stats.openModes == [.read, .write])
    #expect(stats.closeRequests == 0)
    try await core.close(item: file, retainingModes: .unspecified)
    #expect(await daemon.stats().activeHandles == 0)
}

/// A refused new open changes nothing: the description an earlier open was
/// granted stays installed and serves I/O.
@Test func refusedComplementaryOpenLeavesTheHeldDescriptionUsable() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "refused-write-open")
    _ = try await core.write(item: file, offset: 0, data: lifecycleBytes("data"))
    try await core.close(item: file, retainingModes: .unspecified)
    try await chmod(core, file, 0o400)
    await daemon.resetStats()

    try await core.open(item: file, mode: .read)
    #expect(await lifecycleErrno { try await core.open(item: file, mode: .write) } == EACCES)
    #expect(await lifecycleErrno { try await core.open(item: file, mode: .readWrite) } == EACCES)
    #expect(try await core.read(item: file, offset: 0, length: 4) == lifecycleBytes("data"))
    let stats = await daemon.stats()
    #expect(stats.openModes == [.read, .write, .write])
    #expect(stats.closeRequests == 0)
    #expect(stats.activeHandles == 1)
    #expect(await core.testingDebugState().openHandleCount == 1)
    try await core.close(item: file, retainingModes: .unspecified)
    #expect(await daemon.stats().activeHandles == 0)
}

/// FSKit's partial close names the modes that stay open. Only the
/// description carrying none of them is retired; reclaim retires the rest.
@Test func partialCloseAndReclaimRetireMultiDescriptionItems() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "multi-description")

    try await core.open(item: file, mode: .read)
    try await core.open(item: file, mode: .write)
    try await core.close(item: file, retainingModes: .write)
    var stats = await daemon.stats()
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 1)
    _ = try await core.write(item: file, offset: 0, data: lifecycleBytes("still"))
    #expect(await daemon.stats().openRequests == 2)

    // A retained mode no description carries opens nothing at close; the
    // next read acquires it.
    try await core.close(item: file, retainingModes: .readWrite)
    #expect(await daemon.stats().openRequests == 2)
    #expect(try await core.read(item: file, offset: 0, length: 5) == lifecycleBytes("still"))
    stats = await daemon.stats()
    #expect(stats.openModes == [.read, .write, .read])
    #expect(stats.activeHandles == 2)

    try await core.reclaim(item: file)
    stats = await daemon.stats()
    #expect(stats.closeRequests == 3)
    #expect(stats.activeHandles == 0)
    #expect(await core.testingDebugState().openHandleCount == 0)
    #expect(file.reclaimed)
}

/// A truncate goes through a description only if it is open for writing;
/// the authority refuses one that is not. With only a read description the
/// truncate is checked against the object instead.
@Test func truncateUsesOnlyAWriteCapableDescription() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "truncate-selection")
    _ = try await core.write(item: file, offset: 0, data: lifecycleBytes("0123456789"))
    try await core.close(item: file, retainingModes: .unspecified)

    try await core.open(item: file, mode: .read)
    var attr = try await core.setattr(item: file, attributes: PfsSetAttributes(size: 4))
    #expect(attr.size == 4)

    try await core.open(item: file, mode: .write)
    try await chmod(core, file, 0o000)
    attr = try await core.setattr(item: file, attributes: PfsSetAttributes(size: 2))
    #expect(attr.size == 2)
    try await core.close(item: file, retainingModes: .unspecified)
    #expect(await daemon.stats().activeHandles == 0)
}

@Test func failedPartialCloseRemainsTrackedUntilFinalClose() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "failed-upgrade-close")

    try await core.open(item: file, mode: .read)
    try await core.open(item: file, mode: .write)
    await daemon.failNextClose()
    do {
        try await core.close(item: file, retainingModes: .read)
        Issue.record("expected the injected close failure")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == EIO)
    }

    var stats = await daemon.stats()
    #expect(stats.openRequests == 2)
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 2)
    #expect(await core.testingDebugState().openHandleCount == 2)
    // The retained read description is unaffected by its sibling's failure.
    #expect(try await core.read(item: file, offset: 0, length: 0).isEmpty)

    try await core.close(item: file, retainingModes: .unspecified)
    stats = await daemon.stats()
    #expect(stats.openRequests == 2)
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

@Test func retiredPartialCloseErrorRemovesOnlyTheRetiredDescription() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "retired-upgrade-close")

    try await core.open(item: file, mode: .read)
    try await core.open(item: file, mode: .write)
    await daemon.retireNextCloseWithError()
    do {
        try await core.close(item: file, retainingModes: .read)
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

/// A close whose reply is lost with the connection cannot be confirmed: Swift
/// keeps owning the description, the session ends, and nothing reconnects to
/// replay it. Whole-session teardown is what finally releases it.
@Test func lostRetiredCloseReplyEndsTheSessionAndKeepsOwnershipUntilTeardown() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(
        socketPath: daemon.socketPath,
        attachRef: "mock",
        configuration: .init(
            maxConnectAttempts: 10,
            connectRetryBaseDelayNanoseconds: 5_000_000
        )
    )
    let file = try await closedTestFile(core: core, daemon: daemon, name: "lost-close-reply")
    let hellos = await daemon.stats().helloRequests

    try await core.open(item: file, mode: .read)
    await daemon.loseNextRetiredCloseReply(errno: EIO)
    do {
        try await core.close(item: file, retainingModes: .unspecified)
        Issue.record("expected the lost close reply to fail the first request")
    } catch let error as PfsLocalClientError {
        #expect(error == .connectionClosed)
    }

    let stats = await daemon.stats()
    #expect(stats.closeRequests == 1)
    #expect(stats.activeHandles == 0)
    // No retirement confirmation reached Swift, so it must retain ownership.
    #expect(await core.testingDebugState().openHandleCount == 1)

    await #expect(throws: PfsLocalClientError.connectionClosed) {
        try await core.close(item: file, retainingModes: .unspecified)
    }
    #expect(await daemon.stats().closeRequests == 1)
    #expect(await daemon.stats().helloRequests == hellos)
    #expect(await core.testingDebugState().openHandleCount == 1)

    await core.shutdown()
    #expect(await core.testingDebugState().openHandleCount == 0)
}

@Test func failedPartialCloseRemainsTrackedUntilReclaim() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let file = try await closedTestFile(core: core, daemon: daemon, name: "failed-upgrade-reclaim")

    try await core.open(item: file, mode: .read)
    try await core.open(item: file, mode: .write)
    await daemon.failNextClose()
    do {
        try await core.close(item: file, retainingModes: .read)
        Issue.record("expected the injected close failure")
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

@Test func concurrentFinalCloseCannotInterleaveDelayedComplementaryOpen() async throws {
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
